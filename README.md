# Fitnah v2

> **Authorised red-team C2 framework.**  
> All usage requires explicit written authorisation from the target organisation.

---

## Overview

Fitnah v2 is a full-spectrum command-and-control framework built for authorised penetration testing and red-team operations. It provides a Telegram-primary C2 bus with Discord fallback and a stealth TURN-tunnel third channel, a plugin-based post-exploitation engine covering every MITRE ATT&CK tactic, a cross-platform implant builder pipeline, and an operator CLI built on `prompt_toolkit`.

---

## Architecture

```
Operator CLI (prompt_toolkit REPL)
        │
        ▼
    Kernel ──► Plugin Engine (103 plugins)
        │
        ▼
    Router
     ├── Telegram transport       priority 0  (api.telegram.org:443)
     ├── Discord transport        priority 1  (discord.com:443)
     └── Turnt TURN-tunnel        stealth     (*.relay.teams.microsoft.com:443)
                │
         HTTP C2 Listener (aiohttp, AES-256-GCM, TLS, malleable profiles)
                │
         3-Tier Redirector  (nginx decoy → sinkhole → real C2)
```

All three transports run in parallel once established. Telegram is used for every send. If Telegram fails after three consecutive errors the router falls back to Discord. If both are unreachable (corporate firewall blocking both) turnt activates — it routes C2 traffic over Microsoft Teams TURN relay servers, which are universally whitelisted in enterprise environments.

---

## Stack

| Layer | Technology |
|---|---|
| CLI | Python 3.10+, prompt_toolkit |
| C2 bus | python-telegram-bot 21+, discord.py 2.3+ |
| Stealth tunnel | turnt (DTLS/SCTP over Teams TURN relay) |
| HTTP listener | aiohttp, AES-256-GCM, optional TLS |
| Persistence | SQLite (loot), JSONL (audit), YAML (config) |
| Crypto | `cryptography` (Python AES-GCM), BCrypt API (C implant) |
| Implant | C99, mingw-w64 cross-compiler |
| Shellcode | donut (optional PE→shellcode) |
| Syscalls | Hell's Gate + Halo's Gate SSN resolution, ASM stubs |

---

## Directory Layout

```
fitnah/
  config.py                     YAML loader, Config class
  opsec.py                      Operator-side sandbox/VM/AV detection
  orchestration/
    kernel.py                   Top-level glue, plugin auto-discovery
    console.py                  FitnahConsole (prompt_toolkit REPL)
    session_manager.py          Session + SessionManager
    audit_log.py                Append-only JSONL audit trail
    project.py                  FuzzBunch-style operator workspaces
  c2/
    server.py                   C2Server (dispatch + ACK resolution)
    router.py                   Router (failover + dynamic fan-in)
    http_listener.py            HTTP C2 listener (aiohttp, malleable)
    profiles.py                 Malleable C2 profiles (URI/header disguise)
    redirector.py               3-tier nginx redirector
    domain_fronting.py          Domain fronting helpers
    decoy_services.py           Decoy site/service generator
    telegram_ui.py              TelegramUI (inline keyboard menus)
    transport/
      telegram.py               TelegramTransport   (priority 0)
      discord.py                DiscordTransport    (priority 1)
      turnt_transport.py        TurntTransport      (stealth, priority 2)
      encrypted_channels.py     AES-GCM message layer wrapper
      reverse_shell.py          Reverse shell transport
  sdk/
    base_plugin.py              BasePlugin ABC
    context.py                  PluginContext (sync→async bridge)
    result.py                   ModuleResult
    schema.py                   ParamSchema / Param
    testing.py                  MockSession
  loot/
    store.py                    LootStore (SQLite)
  builder/
    engine.py                   BuildEngine (orchestrates pipeline)
    apt_builder.py              APT-grade full builder
    models.py                   BuildRequest / BuildResult / enums
    compiler.py                 mingw-w64 cross-compile wrapper
    donut_wrap.py               PE→shellcode via donut
    encryptor.py                AES-256-GCM + XOR, C header emitter
    turnt.py                    Turnt relay builder (bundled/download/compile)
    stagers/
      ps1.py                    PowerShell beacon-loop stager
      advanced_ps1.py           Advanced PS1 with AMSI bypass
      https_ps1.py              HTTPS PS1 stager (malleable-aware)
      vba.py                    VBA macro wrapper
      hta.py                    HTA wrapper
  assets/
    turnt/                      Pre-bundled turnt binaries (7 files)
  plugins/
    collection/        (7)      audio_capture, clipboard_monitor, dir_list,
                                email_harvest, file_search, keylogger, webcam_snap
    credential_access/ (8)      browser_creds, clipboard, dpapi_decrypt, dump_sam,
                                golden_ticket, lsass_dump, vault_creds, wifi_creds
    defense_evasion/   (17)     amsi_bypass, behavior_mimicry, cet_cfg_bypass,
                                clear_logs, defender_exclude, disable_defender,
                                etw_patch, hardware_breakpoints, hvci_bypass,
                                memory_patch, memory_patcher, module_stomp,
                                module_trampoline, patchguard_bypass, stack_spoof,
                                timestomp, timing_evasion
    execution/         (14)     bof_exec, code_cave_inject, dll_inject,
                                early_bird_apc, execute_assembly, interactive_shell,
                                port_forwarding, powershell, process_hollow,
                                process_mirror, reflective_dll_inject, shell_exec,
                                shellshock, syscall_executor
    exfiltration/      (4)      chunked_send, dns_tunnel, upload_file, zip_exfil
    impact/            (3)      encrypt_files, service_disruption, wipe_logs
    initial_access/    (4)      delivery_server, macro_drop, phish_email, phish_link
    lateral_movement/  (19)     ad_attack_path, asrep_roasting, constrained_delegation,
                                dcom_exec, kerberoasting, kerberoasting_advanced,
                                ldap_modify, pass_the_hash, pass_the_ticket, psexec,
                                psexec_deploy, rdp_enable, smb_p2p, smb_upload,
                                ticket_manipulation, turnt_pivot_c2, turnt_relay,
                                unconstrained_delegation, wmi_exec
    persistence/       (7)      ads_hide, com_hijack, domain_persistence,
                                registry_run, scheduled_task, startup_folder,
                                wmi_subscribe
    privilege_escalation/ (9)   cve_2017_0143 (EternalBlue), cve_2018_8453 (Win32k UAF),
                                cve_2019_0808 (Win32k NULL-deref), cve_2020_1472 (Zerologon),
                                cve_2021_1732 (Win32k KCT LPE), cve_2021_21224 (type confusion),
                                exploit_chain_selector, token_theft, uac_bypass
    recon/             (11)     arp_scan, dns_enum, domain_enum, network_info,
                                port_scan, processes, screenshot, shares_enum,
                                sysinfo, turnt_credentials, users_enum
implant/
  agent.py                      Python implant agent (Telegram beacon loop)
  reflective_loader.c           Reflective loader
  process_hollowing.c           Process hollowing implementation
  core/
    beacon.py                   Beacon logic
    crypto.py                   AES-256-GCM implant crypto
    task_queue.py               Task queue
  syscall/
    direct_syscall.c            Hell's Gate + Halo's Gate SSN resolution (278 lines)
  injection/
    process_mirror.c            NtCreateSection / NtMapViewOfSection injection
    rdi_loader.c                Reflective DLL injection loader
    code_cave.c                 Code cave injection
  evasion/
    sleep_obfuscation.c         Ekko-style RC4 sleep obfuscation
    anti_analysis.c             Anti-debug, anti-VM, PEB unlinking, timestomp
    memory_patcher.c            In-memory AMSI/ETW patch
    unhook.c                    Module unhooking
  loader/
    advanced_loader.c           Advanced shellcode loader
    advanced_shellcode.py       Python shellcode stage
    shellcode.py                Shellcode utilities
  dropper/
    advanced_dropper.c          Advanced staged dropper
  collection/
    lsass_dump.c                LSASS dump via direct syscalls
  exploits/
    cve_exploits.c              Win32k exploit primitives
  impact/
    artifact_wipe.c             Forensic artifact wiper
    disk_wipe.c                 Disk wipe
  commands/
    exec.py, ps.py, info.py,    Command handlers
    screenshot.py, upload.py,
    download.py
  asm/
    syscalls.asm                x64 syscall stubs
tests/                          177 tests across 9 test files
config/
  framework.yaml                Operator config (never commit tokens)
data/
  fitnah.log                    Runtime log
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure

```bash
cp config/framework.yaml.example config/framework.yaml
# Edit: set telegram_token, operator_chat_id
# Optional: discord_token, turnt.creds_path
```

### 3. Start the framework

```bash
python -m fitnah
```

### 4. Basic REPL commands

```
sessions                        list active implant sessions
use <session_id>                attach to a session
run sysinfo                     run a plugin on the active session
run screenshot
run lsass_dump
search kerberos                 search plugins by keyword
loot -q credential              query loot database
loot --export csv --out out.csv export loot
builder -f ps1 -a <agent_id>    build a PS1 stager
builder -f turnt-relay          build turnt relay binary for agent
reload                          hot-reload all plugins
tunnel start <answer>           complete turnt tunnel handshake
tunnel offer                    show pending SDP offer
tunnel pivot                    auto-run full turnt pivot (upload+creds+handshake)
status                          show transport status table
help                            full command reference
```

---

## C2 Transports

### Telegram (primary)

Telegram is the sole primary C2 bus. Each implant gets its own private Telegram group (`Session.group_id`). The bot sends `{"type":"TASK",...}` JSON and receives `{"type":"ACK",...}` or `{"type":"CHECKIN",...}`. It never compiles or generates payloads.

### Discord (fallback)

Activates automatically after 3 consecutive Telegram send failures. Recovers back to Telegram automatically when Telegram becomes reachable again.

### Turnt TURN-tunnel (stealth)

Routes C2 traffic through Microsoft Teams TURN relay servers (`*.relay.teams.microsoft.com:443`) using WebRTC data channels over DTLS/SCTP/TCP-TLS. These servers are universally whitelisted in enterprise firewalls.

Once the tunnel is live:
- Telegram and Discord remain fully connected (turnt is a parallel channel, not a replacement)
- The agent's HTTPS beacon targets `https://127.0.0.1:4443` — traffic reaches the operator via remote port forward through the TURN data channel
- A SOCKS5 proxy on `:1080` enables lateral movement through the tunnel

**Setup flow:**

```
Step 1 — Extract Teams TURN credentials from agent:
  run turnt_credentials

Step 2 — Build and upload the relay binary to the agent:
  builder -f turnt-relay --arch amd64
  run turnt_relay action=upload

Step 3 — Start tunnel (auto-mode does all of the above):
  tunnel pivot

Step 4 — Or manually complete the SDP handshake:
  tunnel offer                  (copy the offer)
  run turnt_relay action=start offer=<base64>
  tunnel start <answer>         (paste the answer back)

Step 5 — Verify:
  status                        (shows turnt as ALIVE)

Step 6 — Use SOCKS5 proxy for lateral movement:
  proxychains nmap -sT <internal_range>
```

---

## Builder Pipeline

```bash
# PowerShell stager (basic)
builder -f ps1 -a <agent_id>

# PowerShell stager with AMSI bypass + HTTPS beacon
builder -f https-ps1 -a <agent_id> --profile jquery

# VBA macro
builder -f vba -a <agent_id>

# HTA
builder -f hta -a <agent_id>

# Turnt relay binary (from bundled assets)
builder -f turnt-relay --os windows --arch amd64
builder -f turnt-relay --os windows --arch amd64 --upx
builder -f turnt-relay --os linux
builder -f turnt-relay --go-build            # compile from source
builder -f turnt-relay --list                # list bundled assets
```

All payloads are AES-256-GCM encrypted at rest. The decryption key is embedded in the stager and never touches disk in plaintext. Optional donut wrapping converts any PE to position-independent shellcode.

---

## Implant Features

### Evasion (C layer)

| Feature | Implementation |
|---|---|
| Sleep obfuscation | Ekko-style — RC4 (SystemFunction032) encrypts entire image during sleep, decrypts on wake |
| Syscall resolution | Hell's Gate (clean stub) + Halo's Gate (hooked stub via neighbor SSN scan) |
| Direct syscalls | x64 ASM stubs (`syscalls.asm`) — no userland API calls for sensitive operations |
| Anti-debug | IsDebuggerPresent, NtQueryInformationProcess, timing checks, heap flag checks |
| Anti-VM | CPUID, RDTSC delta, VMware/VBox registry keys, process name scan |
| PE header wipe | Clears DOS+NT headers from memory after load |
| PEB unlinking | Removes module entry from InLoadOrderLinks to hide from tools |
| Module unhooking | Reads clean copy from disk, overwrites hooked .text section |

### Injection techniques

| Technique | MITRE | File |
|---|---|---|
| Process mirror (NtCreateSection) | T1055.003 | `injection/process_mirror.c` |
| Reflective DLL injection | T1055.001 | `injection/rdi_loader.c` |
| Code cave injection | T1574 | `injection/code_cave.c` |
| Process hollowing | T1055.012 | `process_hollowing.c` |
| Early bird APC | T1055.004 | plugin: `early_bird_apc` |
| Module stomping | T1055.008 | plugin: `module_stomp` |
| DLL injection | T1055.001 | plugin: `dll_inject` |

---

## Wire Protocol

```
Operator → Agent:   {"type":"TASK",    "id":"<hex8>","command":"exec","args":{"cmd":"..."}}
Agent → Operator:   {"type":"ACK",     "id":"<hex8>","status":"ok","output":"..."}
Agent → Operator:   {"type":"CHECKIN", "agent_id":"...","hostname":"...","os":"...",...}
```

All messages are plaintext JSON sent as Telegram/Discord chat messages. The bot relays them without inspection or transformation. When the encrypted channel wrapper is enabled, the JSON payload is AES-256-GCM encrypted before being sent and decrypted on receipt.

---

## Plugin Development

1. Create `fitnah/plugins/<category>/<name>.py`
2. Subclass `BasePlugin`, set `NAME`, `DESCRIPTION`, `MITRE`, `CATEGORY`
3. Implement `run(self, session, params, ctx=None) -> ModuleResult`
4. Use `ctx.exec()` / `ctx.ps()` / `ctx.send()` for live dispatch
5. Return `ModuleResult.err("Requires live session")` when `ctx is None`
6. Drop a test in `tests/` — the kernel auto-discovers the plugin on next start or `reload`

```python
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema

class MyPlugin(BasePlugin):
    NAME        = "my_plugin"
    DESCRIPTION = "Does something useful"
    MITRE       = "T1082"
    CATEGORY    = "recon"

    schema = ParamSchema().add(
        Param("timeout", int, required=False, default=30),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        r = ctx.ps("Get-Date", timeout=params.get("timeout", 30))
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
```

---

## OPSEC

The `opsec.py` module runs on the operator machine and detects analysis environments before sensitive operations:

- Process scan (x64dbg, OllyDbg, IDA, Wireshark, ProcMon, Frida, Cuckoo, sandboxie, VMware tools, etc.)
- Registry scan (AV/EDR, analysis tool install keys)
- Loaded DLL check (sbiedll, api_log, vmcheck, etc.)
- Timing/RDTSC delta analysis
- Returns threat level 0–100 with a list of detected tools

---

## Infrastructure Hardening

### 3-tier redirector (`fitnah/c2/redirector.py`)

```
Client → Edge proxy (nginx, decoy WordPress/Apache)
           ↓  X-Sync-Token header present
       Sinkhole (sandbox trap, IP/geo filter)
           ↓  passes all filters
       Real C2 listener
```

- Geofencing (configurable allowed countries)
- ASN blocklist (Google, Amazon, DigitalOcean — common scanner sources)
- Header-based routing (custom C2 header required to reach real backend)
- Decoy site returns real HTML to unauthenticated scanners

### Domain fronting (`fitnah/c2/domain_fronting.py`)

Routes C2 traffic through CDN providers (Cloudflare, Fastly, Azure CDN) by setting the `Host` header to the real C2 domain while the SNI/TLS destination points to a fronted domain.

### Malleable C2 profiles (`fitnah/c2/profiles.py`)

Customise beacon URIs, HTTP headers, and response bodies to mimic legitimate traffic patterns (jQuery updates, Office telemetry, Windows Update, etc.).

---

## Tests

```bash
# Run all 177 tests
python -m pytest tests/ -q

# Run a specific phase
python -m pytest tests/test_phase4.py -v

# Check plugin import health
python -m pytest tests/test_plugins.py -v
```

---

## Turnt Bundled Binaries

Pre-downloaded from [praetorian-inc/turnt](https://github.com/praetorian-inc/turnt) v0.1 release. Located in `fitnah/assets/turnt/`.

| Binary | Size | Purpose |
|---|---|---|
| `turnt-relay-windows-amd64.exe` | 8.4 MB | Agent relay (64-bit Windows, full) |
| `turnt-relay-windows-amd64-upx.exe` | 2.6 MB | Agent relay (64-bit Windows, UPX-compressed) |
| `turnt-relay-windows-386-upx.exe` | 2.3 MB | Agent relay (32-bit Windows, UPX-compressed) |
| `turnt-relay-linux-amd64` | 8.2 MB | Agent relay (Linux) |
| `turnt-control-linux-amd64` | 14.3 MB | Operator controller (manages tunnel) |
| `turnt-credentials-linux-amd64` | 8.0 MB | Operator credential extractor |
| `turnt-admin-linux-amd64` | 8.2 MB | Operator port-forward manager |

---

## Legal

This framework is provided for **authorised security testing only**. Unauthorised use against systems you do not own or have explicit written permission to test is illegal in most jurisdictions. The authors accept no responsibility for misuse.
