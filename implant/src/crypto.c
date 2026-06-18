/*
 * crypto.c — AES-256-GCM via Windows BCrypt API (bcrypt.dll, always present)
 *
 * BCrypt is loaded dynamically so bcrypt.dll does not appear in the IAT.
 */
#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>

/* Dynamic BCrypt imports */
typedef NTSTATUS (WINAPI *pfn_BCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE*,LPCWSTR,LPCWSTR,ULONG);
typedef NTSTATUS (WINAPI *pfn_BCryptSetProperty)(BCRYPT_HANDLE,LPCWSTR,PUCHAR,ULONG,ULONG);
typedef NTSTATUS (WINAPI *pfn_BCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE,BCRYPT_KEY_HANDLE*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
typedef NTSTATUS (WINAPI *pfn_BCryptEncrypt)(BCRYPT_KEY_HANDLE,PUCHAR,ULONG,VOID*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG*,ULONG);
typedef NTSTATUS (WINAPI *pfn_BCryptDecrypt)(BCRYPT_KEY_HANDLE,PUCHAR,ULONG,VOID*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG*,ULONG);
typedef NTSTATUS (WINAPI *pfn_BCryptDestroyKey)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS (WINAPI *pfn_BCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE,ULONG);
typedef NTSTATUS (WINAPI *pfn_BCryptGenRandom)(BCRYPT_ALG_HANDLE,PUCHAR,ULONG,ULONG);

static struct {
    HMODULE                           hmod;
    pfn_BCryptOpenAlgorithmProvider   Open;
    pfn_BCryptSetProperty             SetProp;
    pfn_BCryptGenerateSymmetricKey    GenKey;
    pfn_BCryptEncrypt                 Encrypt;
    pfn_BCryptDecrypt                 Decrypt;
    pfn_BCryptDestroyKey              DestroyKey;
    pfn_BCryptCloseAlgorithmProvider  CloseAlg;
    pfn_BCryptGenRandom               GenRandom;
} g_bc = {0};

static BOOL bc_init(void) {
    if (g_bc.hmod) return TRUE;
    g_bc.hmod = LoadLibraryA("bcrypt.dll");
    if (!g_bc.hmod) return FALSE;
    g_bc.Open       = (pfn_BCryptOpenAlgorithmProvider)  GetProcAddress(g_bc.hmod, "BCryptOpenAlgorithmProvider");
    g_bc.SetProp    = (pfn_BCryptSetProperty)            GetProcAddress(g_bc.hmod, "BCryptSetProperty");
    g_bc.GenKey     = (pfn_BCryptGenerateSymmetricKey)   GetProcAddress(g_bc.hmod, "BCryptGenerateSymmetricKey");
    g_bc.Encrypt    = (pfn_BCryptEncrypt)                GetProcAddress(g_bc.hmod, "BCryptEncrypt");
    g_bc.Decrypt    = (pfn_BCryptDecrypt)                GetProcAddress(g_bc.hmod, "BCryptDecrypt");
    g_bc.DestroyKey = (pfn_BCryptDestroyKey)             GetProcAddress(g_bc.hmod, "BCryptDestroyKey");
    g_bc.CloseAlg   = (pfn_BCryptCloseAlgorithmProvider) GetProcAddress(g_bc.hmod, "BCryptCloseAlgorithmProvider");
    g_bc.GenRandom  = (pfn_BCryptGenRandom)              GetProcAddress(g_bc.hmod, "BCryptGenRandom");
    return g_bc.Open && g_bc.GenKey && g_bc.Encrypt && g_bc.Decrypt && g_bc.GenRandom;
}

/* GCM authenticated encryption info structure */
typedef struct {
    ULONG     DataType;    /* BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION */
    ULONG     cbSize;
    PUCHAR    pbNonce;
    ULONG     cbNonce;
    PUCHAR    pbAuthData;
    ULONG     cbAuthData;
    PUCHAR    pbTag;
    ULONG     cbTag;
    PUCHAR    pbMacContext;
    ULONG     cbMacContext;
    ULONG     cbAAD;
    ULONGLONG cbData;
    ULONG     dwFlags;
} BCRYPT_AUTH_TAG_LENGTHS_STRUCT_COMPAT;

/* We use the public BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO directly */

static BCRYPT_ALG_HANDLE open_aes_gcm(void) {
    BCRYPT_ALG_HANDLE h = NULL;
    if (g_bc.Open(&h, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return NULL;
    if (g_bc.SetProp(h, BCRYPT_CHAINING_MODE,
                     (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                     sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
        g_bc.CloseAlg(h, 0); return NULL;
    }
    return h;
}

BOOL crypto_encrypt(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *pt,  size_t pt_len,
                    uint8_t **out_ct,   size_t *out_len) {
    if (!bc_init()) return FALSE;
    BCRYPT_ALG_HANDLE hAlg = open_aes_gcm();
    if (!hAlg) return FALSE;

    BCRYPT_KEY_HANDLE hKey = NULL;
    if (g_bc.GenKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, AES_KEY_LEN, 0) != 0) {
        g_bc.CloseAlg(hAlg, 0); return FALSE;
    }

    uint8_t tag[AES_TAG_LEN] = {0};
    uint8_t nonce_copy[AES_NONCE_LEN];
    memcpy(nonce_copy, nonce, AES_NONCE_LEN);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce   = nonce_copy;
    info.cbNonce   = AES_NONCE_LEN;
    info.pbTag     = tag;
    info.cbTag     = AES_TAG_LEN;

    ULONG ct_len = 0;
    g_bc.Encrypt(hKey, (PUCHAR)pt, (ULONG)pt_len, &info, NULL, 0, NULL, 0, &ct_len, 0);

    uint8_t *buf = malloc(ct_len + AES_TAG_LEN);
    if (!buf) { g_bc.DestroyKey(hKey); g_bc.CloseAlg(hAlg, 0); return FALSE; }

    /* Re-init: BCryptEncrypt mutates the info struct */
    memcpy(nonce_copy, nonce, AES_NONCE_LEN);
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce_copy; info.cbNonce = AES_NONCE_LEN;
    info.pbTag   = buf + ct_len; info.cbTag  = AES_TAG_LEN;

    NTSTATUS st = g_bc.Encrypt(hKey, (PUCHAR)pt, (ULONG)pt_len, &info,
                                NULL, 0, buf, ct_len, &ct_len, 0);
    g_bc.DestroyKey(hKey);
    g_bc.CloseAlg(hAlg, 0);

    if (st != 0) { free(buf); return FALSE; }
    *out_ct  = buf;
    *out_len = ct_len + AES_TAG_LEN;
    return TRUE;
}

BOOL crypto_decrypt(const uint8_t *key,   const uint8_t *nonce,
                    const uint8_t *ct,    size_t ct_len,
                    uint8_t **out_pt,     size_t *out_len) {
    if (!bc_init() || ct_len < AES_TAG_LEN) return FALSE;
    BCRYPT_ALG_HANDLE hAlg = open_aes_gcm();
    if (!hAlg) return FALSE;

    BCRYPT_KEY_HANDLE hKey = NULL;
    if (g_bc.GenKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, AES_KEY_LEN, 0) != 0) {
        g_bc.CloseAlg(hAlg, 0); return FALSE;
    }

    size_t  pure_ct_len = ct_len - AES_TAG_LEN;
    uint8_t tag_copy[AES_TAG_LEN];
    memcpy(tag_copy, ct + pure_ct_len, AES_TAG_LEN);
    uint8_t nonce_copy[AES_NONCE_LEN];
    memcpy(nonce_copy, nonce, AES_NONCE_LEN);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce_copy; info.cbNonce = AES_NONCE_LEN;
    info.pbTag   = tag_copy;   info.cbTag   = AES_TAG_LEN;

    ULONG pt_len = 0;
    g_bc.Decrypt(hKey, (PUCHAR)ct, (ULONG)pure_ct_len, &info,
                 NULL, 0, NULL, 0, &pt_len, 0);

    uint8_t *buf = malloc(pt_len + 1);
    if (!buf) { g_bc.DestroyKey(hKey); g_bc.CloseAlg(hAlg, 0); return FALSE; }

    /* Re-init */
    memcpy(nonce_copy, nonce, AES_NONCE_LEN);
    memcpy(tag_copy,   ct + pure_ct_len, AES_TAG_LEN);
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce_copy; info.cbNonce = AES_NONCE_LEN;
    info.pbTag   = tag_copy;   info.cbTag   = AES_TAG_LEN;

    NTSTATUS st = g_bc.Decrypt(hKey, (PUCHAR)ct, (ULONG)pure_ct_len, &info,
                                NULL, 0, buf, pt_len, &pt_len, 0);
    g_bc.DestroyKey(hKey);
    g_bc.CloseAlg(hAlg, 0);

    if (st != 0) { free(buf); return FALSE; }
    buf[pt_len] = '\0';
    *out_pt  = buf;
    *out_len = pt_len;
    return TRUE;
}

BOOL crypto_rand(uint8_t *buf, size_t len) {
    if (!bc_init()) return FALSE;
    return g_bc.GenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}
