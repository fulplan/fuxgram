/*
 * nano_lsass.h — Syscall-based LSASS dump (nanodump adapter)
 *
 * Source: helpsystems/nanodump (MIT License)
 * https://github.com/helpsystems/nanodump
 *
 * Key evasion properties vs standard MiniDumpWriteDump approach:
 *   - No MiniDumpWriteDump call (heavily monitored by EDR)
 *   - All LSASS access via direct syscalls (NtOpenProcess, NtReadVirtualMemory)
 *   - Process open via handle duplication, not direct OpenProcess on lsass.exe
 *   - Output written to a caller-supplied buffer (no temp file needed)
 *
 * MITRE: T1003.001 (OS Credential Dumping: LSASS Memory)
 */
#pragma once
#include <windows.h>
#include <stdint.h>

/*
 * NanoDump_DumpLsass — dump LSASS memory into a caller-owned buffer.
 *
 * on success: returns heap-allocated buffer containing a valid minidump,
 *             sets *out_size to the buffer size. Caller must free().
 * on failure: returns NULL, sets *out_size = 0.
 *
 * dump_path: if non-NULL, also writes the dump to this file path.
 *            pass NULL to keep the dump in memory only (preferred).
 */
uint8_t *NanoDump_DumpLsass(const char *dump_path, size_t *out_size);
