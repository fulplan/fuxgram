/*
 * crypto.h — AES-256-GCM via Windows BCrypt API
 * Zero external dependencies; BCrypt is part of Windows Vista+.
 */
#pragma once
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#define AES_KEY_LEN   32   /* 256-bit */
#define AES_NONCE_LEN 12   /* 96-bit GCM nonce */
#define AES_TAG_LEN   16   /* 128-bit GCM auth tag */

/*
 * crypto_encrypt — encrypt plaintext with AES-256-GCM.
 * key/nonce must be AES_KEY_LEN / AES_NONCE_LEN bytes.
 * out_ct receives ciphertext + 16-byte auth tag (caller frees).
 * Returns TRUE on success.
 */
BOOL crypto_encrypt(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *pt,  size_t pt_len,
                    uint8_t **out_ct,   size_t *out_len);

/*
 * crypto_decrypt — decrypt AES-256-GCM ciphertext (includes tag).
 * Returns plaintext in *out_pt (caller frees), or NULL on auth failure.
 */
BOOL crypto_decrypt(const uint8_t *key,   const uint8_t *nonce,
                    const uint8_t *ct,    size_t ct_len,
                    uint8_t **out_pt,     size_t *out_len);

/* Fill buf with cryptographically random bytes (BCryptGenRandom). */
BOOL crypto_rand(uint8_t *buf, size_t len);
