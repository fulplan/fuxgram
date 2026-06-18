# Fitnah v2 — Red Team C2 Framework

> **Authorised use only.** All operations require explicit written permission from the target organisation. Unauthorised use is illegal.

---

## What Is Fitnah

Fitnah v2 is a full-spectrum command-and-control framework for authorised penetration tests and red-team engagements. It provides:

- **Telegram-primary C2** with automatic Discord fallback and a stealth TURN-tunnel third channel that routes through Microsoft Teams relay servers — universally whitelisted in enterprise firewalls
- **Plugin engine** with 103+ post-exploitation modules mapped to every MITRE ATT&CK tactic
- **Native BOF dispatch** — 104 pre-compiled Beacon Object Files execute in-process on the implant with no PowerShell, no child process, no disk write
- **Builder pipeline** — generates PS1, VBA, HTA, EXE, DLL, and raw shellcode payloads with AES-256-GCM encryption, optional LZMA compression, and code signing
- **mTLS per-agent certs** — each implant gets a unique RSA-2048 leaf cert; burning one agent revokes only that cert, all others continue beaconing
- **Operator CLI** built on `prompt_toolkit` with session management, loot database, and hot-reloadable plugins

---

## Architecture

```
Operator CLI (prompt_toolkit REPL)
         │
         ▼
     Kernel ─────────────► Plugin Engine (103+ plugins, auto-discovered)
         │
         ▼
     Router (failover)
      ├── Telegram transport     priority 0  (api.telegram.org:443)
      ├── Discord transport      priority 1  (discord.com:443)
      └── Turnt TURN-tunnel      stealth     (*.relay.teams.microsoft.com:443)
               │
      HTTP C2 Listener (aiohttp, AES-256-GCM, optional TLS/mTLS, malleable profiles)
               │
      3-Tier Redirector (nginx decoy → sinkhole → real C2)
               │
          Implant (C99, beacon loop, BOF loader, Hell's Gate syscalls)
```

Telegram handles every outbound send. After three consecutive failures the router transparently fails over to Discord. If both are blocked by a corporate proxy, the turnt channel routes traffic through WebRTC data channels over Microsoft Teams TURN servers.

---

## Documentation

| Guide | What it covers |
|---|---|
| [Installation](docs/INSTALLATION.md) | Python deps, config, first start |
| [Operator Guide](docs/OPERATOR.md) | Full REPL reference, sessions, loot, builder |
| [Plugin Development](docs/PLUGIN_DEVELOPMENT.md) | Writing plugins, error handling, testing |
| [BOF Library](docs/BOFS.md) | 104 BOFs reference, arg packing, adding new BOFs |
| [Builder](docs/BUILDER.md) | Payload generation, stager formats, signing |
| [C2 Infrastructure](docs/C2.md) | Transports, mTLS, malleable profiles, redirector |
| [Implant Internals](docs/IMPLANT.md) | C implant, evasion, injection, syscalls |

---

## Quick Start

```bash
# 1. Install
pip install -r requirements.txt

# 2. Configure
cp config/framework.yaml.example config/framework.yaml
# Edit: set telegram.token, telegram.operator_chat_id, implant.token

# 3. Start
python -m fitnah
```

First REPL session:

```
sessions                        # list active sessions
use <session_id>                # attach
run sysinfo                     # enumerate target
run screenshot
run dump_sam
search kerberos                 # find Kerberos-related plugins
loot -q credential              # query captured credentials
builder -f ps1 -a <agent_id>   # build a PS1 stager
help                            # full command reference
```

---

## Stack

| Layer | Technology |
|---|---|
| CLI | Python 3.10+, prompt_toolkit |
| C2 bus | python-telegram-bot 21+, discord.py 2.3+ |
| Stealth channel | Turnt (DTLS/SCTP over Teams TURN relay) |
| HTTP listener | aiohttp, AES-256-GCM, TLS/mTLS |
| Crypto | `cryptography` lib (Python AES-GCM), BCrypt API (C implant) |
| Implant | C99, mingw-w64 cross-compiler |
| Syscalls | Hell's Gate + Halo's Gate, x64 ASM stubs |
| Shellcode | donut (PE → PIC shellcode) |
| BOFs | TrustedSec CS-Situational-Awareness-BOF + CS-Remote-OPs-BOF |

---

## Plugin Categories

| Category | Count | Examples |
|---|---|---|
| `recon` | 11 | sysinfo, screenshot, port_scan, domain_enum, arp_scan |
| `credential_access` | 8 | dump_sam, lsass_dump, golden_ticket, browser_creds, vault_creds |
| `execution` | 14 | shell_exec, bof_exec, dll_inject, process_hollow, early_bird_apc |
| `lateral_movement` | 19 | psexec, wmi_exec, pass_the_hash, ticket_manipulation, kerberoasting |
| `persistence` | 7 | registry_run, scheduled_task, wmi_subscribe, domain_persistence |
| `privilege_escalation` | 9 | uac_bypass, token_theft, cve_2020_1472, cve_2017_0143 |
| `defense_evasion` | 17 | amsi_bypass, etw_patch, hardware_breakpoints, stack_spoof, clear_logs |
| `collection` | 7 | keylogger, screenshot, file_search, clipboard_monitor, audio_capture |
| `exfiltration` | 4 | upload_file, chunked_send, zip_exfil, dns_tunnel |
| `initial_access` | 4 | phish_link, macro_drop, delivery_server, phish_email |
| `impact` | 3 | wipe_logs, encrypt_files, service_disruption |

---

## Wire Protocol

```json
// Operator → Agent
{"type":"TASK", "id":"a1b2c3d4", "command":"exec",  "args":{"cmd":"whoami"}}
{"type":"TASK", "id":"a1b2c3d4", "command":"bof",   "args":{"coff_b64":"...", "args_b64":"..."}}
{"type":"TASK", "id":"a1b2c3d4", "command":"shell",  "args":{"cmd":"..."}}

// Agent → Operator
{"type":"ACK",     "id":"a1b2c3d4", "status":"ok",   "output":"nt authority\\system"}
{"type":"CHECKIN", "agent_id":"...", "hostname":"WIN10", "os":"Windows 10 x64", "pid":1234}
```

All messages are JSON sent as Telegram/Discord chat messages. The bot relays without inspection. Optional AES-256-GCM wrapping encrypts the payload before send.

---

## Tests

```bash
python -m pytest tests/ -q          # all 177 tests
python -m pytest tests/test_phase4.py -v
python -m pytest tests/test_plugins.py -v
```

---

## Legal

For **authorised security testing only**. Written authorisation from the system owner is required before any use. The authors accept no liability for misuse.
