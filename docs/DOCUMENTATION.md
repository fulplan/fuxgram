# Fitnah C2 Framework - Complete Documentation Index

**Fitnah v2** is a modern, open-source APT/red team C2 framework designed for authorized penetration testing, red team engagements, and CTF competitions. It uses Telegram as the primary command channel with Discord fallback, supports multiple transport mechanisms, and includes 49 production-ready plugins across the full ATT&CK framework.

**Status:** Production-ready (9/10 red team, 8/10 CTF)

---

## Quick Navigation

### For New Users
1. **[README_SETUP.md](README_SETUP.md)** — Start here. Local lab setup, VPS deployment, prerequisites, first-time checklist.
2. **[README_TELEGRAM.md](README_TELEGRAM.md)** — Configure your Telegram bot in 5 minutes.
3. **[README_USAGE.md](README_USAGE.md)** — Learn the CLI console and execute your first plugin.

### For Operators
- **[README_USAGE.md](README_USAGE.md)** — Console commands, session management, loot database, scheduler.
- **[README_CTF_ADVANCED.md](README_CTF_ADVANCED.md)** — Automation, flag submission, multi-stage exploitation.
- **[README_DISCORD.md](README_DISCORD.md)** — Configure Discord fallback transport.

### For Developers / Plugin Authors
- **[README_PLUGINS.md](README_PLUGINS.md)** — Plugin SDK, parameter schema, real-world examples, hot-reload.
- **[README_CTF_ADVANCED.md](README_CTF_ADVANCED.md)** — Advanced features, custom plugins, optimization.

### For Red Team / Hostile Environments
- **[README_HOSTILE.md](README_HOSTILE.md)** — Evasion techniques, AV/EDR bypass, persistence, incident response.
- **[README_CTF_ADVANCED.md](README_CTF_ADVANCED.md)** — Aggressive automation, speed optimization, cleanup.

---

## Documentation Overview

| Document | Purpose | Audience | Pages |
|----------|---------|----------|-------|
| **README_SETUP.md** | Lab/VPS setup, prerequisites, first steps | Beginners, operators | 10 KB |
| **README_TELEGRAM.md** | Telegram bot creation & configuration | Operators, admins | 11 KB |
| **README_DISCORD.md** | Discord fallback transport setup | Operators, admins | 8 KB |
| **README_USAGE.md** | CLI console, session management, operations | Operators | 15 KB |
| **README_PLUGINS.md** | Plugin development, SDK, examples | Developers | 17 KB |
| **README_CTF_ADVANCED.md** | CTF automation, advanced exploitation | CTF players, red teamers | 16 KB |
| **README_HOSTILE.md** | Evasion, persistence, hostile environments | Red teamers, incident response | 21 KB |

**Total Documentation:** 3,988 lines, 95 KB, 7 comprehensive guides

---

## Feature Overview

### Transports
- **Telegram Bot API** (primary) — Uses operator's own bot for covert C2
- **Discord** (fallback) — Automatic failover when Telegram unavailable
- **HTTP Listener** — TLS-encrypted listener on custom port
- **Reverse Shell** — TCP reverse connect with AES-256-GCM

### Command & Control
- 49 production plugins across 10 ATT&CK categories
- Real-time task execution via Telegram/Discord/HTTP
- Scheduler for recurring tasks (every N seconds)
- File upload/download with streaming
- Session persistence (SQLite)
- Audit log with HMAC-SHA256 integrity

### Encryption & Evasion
- **AES-256-GCM** end-to-end on all transports
- **PowerShell obfuscation** L1-L4 (backtick, format-string, -EncodedCommand, XOR)
- **AMSI bypass** (VEH + SetThreadContext + DR0 hardware breakpoint)
- **ETW bypass** (ntdll hook)
- **Sleep masking** (NtDelayExecution)
- **PPID spoofing** (CreateProcessWithParent)

### Builder
- **Output formats:** EXE, PS1, VBA, HTA, Shellcode, DLL
- **Architectures:** x64, x86
- **Encryption:** AES-256-GCM, XOR, none
- **Obfuscation:** 4 levels (customizable)

---

## Quick Start (5 minutes)

### 1. Install
```bash
git clone https://github.com/yourusername/fitnah.git
cd fitnah
pip install -r requirements.txt
```

### 2. Configure Telegram
```bash
# Create bot via @BotFather, get token
cat > config/framework.yaml << EOF
operator:
  tag: operator1
  allowed_telegram_ids: [YOUR_TELEGRAM_ID]
telegram:
  token: YOUR_BOT_TOKEN
  operator_chat_id: YOUR_CHAT_ID
EOF
```

### 3. Start C2
```bash
python main.py --config config/framework.yaml
```

### 4. Deploy Implant
```
> builder -f ps1 -a agent-001
# (copy ps1 to target, execute)
# (bot receives CHECKIN message)
```

### 5. Control
```
> sessions                    # list agents
> sessions -i agent-001       # select
> use screenshot              # load plugin
> run                         # execute
```

---

## Command Reference

### Session Management
```bash
sessions                      # List all connected agents
sessions -i <agent_id>        # Select an agent
sessions -k <agent_id>        # Kill (disconnect) an agent
agents                        # Rich table view
```

### Plugin Execution
```bash
use <plugin>                  # Load a plugin
options                       # Show current options
set <key> <value>             # Set parameter
run                           # Execute plugin
run -s <agent_id>             # Execute on specific agent
search <keyword>              # Find plugins
plugins [category]            # List plugins by category
reload                        # Hot-reload all plugins
```

### Builder
```bash
builder -f ps1 -a <agent>     # Build PowerShell stager
builder -f exe -a <agent>     # Build Windows EXE
builder -f vba -a <agent>     # Build VBA macro
builder -f hta -a <agent>     # Build HTA application
builder -f shellcode -a <id>  # Build raw shellcode
builder --list                # Show recent builds
```

### Scheduler & Automation
```bash
schedule <plugin> <seconds> <agent>  # Create recurring task
unschedule <schedule_id>             # Remove schedule
schedules                            # List all schedules
```

### Loot & Audit
```bash
loot                          # List collected loot
loot -q <keyword>             # Search loot
loot --export csv             # Export as CSV
audit [n]                     # Show last N audit entries
audit-verify                  # Verify audit log integrity
```

### Infrastructure
```bash
profile list                  # Show available C2 profiles
profile set <name>            # Hot-swap profile (no restart)
listeners                     # Transport status
status                        # Server health
```

---

## Plugin Categories

### Collection (7)
audio_capture, clipboard_monitor, dir_list, email_harvest, file_search, keylogger, webcam_snap

### Credential Access (6)
browser_creds, clipboard, dump_sam, lsass_dump, vault_creds, wifi_creds

### Defense Evasion (5)
amsi_bypass, clear_logs, defender_exclude, disable_defender, etw_patch

### Execution (4)
dll_inject, powershell, process_hollow, shell_exec

### Exfiltration (4)
chunked_send, flag_submit, upload_file, zip_exfil

### Impact (2)
encrypt_files, wipe_logs

### Initial Access (2)
macro_drop, phish_link

### Lateral Movement (5)
psexec, psexec_deploy, rdp_enable, smb_upload, wmi_exec

### Persistence (4)
registry_run, scheduled_task, startup_folder, wmi_subscribe

### Recon (10)
arp_scan, dns_enum, domain_enum, network_info, port_scan, processes, screenshot, shares_enum, sysinfo, users_enum

---

## File Structure

```
fitnah/
├── config/
│   └── framework.yaml           # Main configuration
├── data/
│   ├── sessions.db              # SQLite agent registry
│   ├── audit.jsonl              # Audit log (HMAC-signed)
│   ├── audit.key                # HMAC key
│   ├── loot.db                  # Collected loot database
│   ├── schedules.json           # Scheduler state
│   └── http_queue.jsonl         # HTTP listener queue
├── build/                       # Output payloads
├── downloads/                   # Downloaded files
├── screenshots/                 # Screenshot captures
├── fitnah/
│   ├── c2/
│   │   ├── router.py            # Transport routing & failover
│   │   ├── http_listener.py     # HTTP C2 listener
│   │   ├── profiles.py          # Malleable C2 profiles
│   │   └── transport/
│   │       ├── telegram.py      # Telegram transport
│   │       ├── discord.py       # Discord transport
│   │       └── reverse_shell.py # Reverse shell transport
│   ├── implant/                 # C implant source
│   │   ├── fitnah_implant.c     # Main implant
│   │   ├── src/
│   │   │   ├── utils.c          # Win32 utilities
│   │   │   ├── http.c           # HTTP client
│   │   │   ├── crypto.c         # AES-256-GCM
│   │   │   ├── bypass.c         # AMSI/ETW bypass
│   │   │   └── commands.c       # Command handlers
│   │   └── Makefile             # Build implant
│   ├── plugins/                 # Plugin modules
│   │   ├── collection/          # Data collection plugins
│   │   ├── credential_access/   # Credential plugins
│   │   ├── defense_evasion/     # Evasion plugins
│   │   ├── execution/           # Execution plugins
│   │   ├── exfiltration/        # Data exfil plugins
│   │   ├── impact/              # Impact plugins
│   │   ├── initial_access/      # Initial access plugins
│   │   ├── lateral_movement/    # Lateral move plugins
│   │   ├── persistence/         # Persistence plugins
│   │   └── recon/               # Reconnaissance plugins
│   ├── orchestration/
│   │   ├── kernel.py            # Main kernel
│   │   ├── session_manager.py   # Session registry
│   │   ├── audit_log.py         # Audit logger
│   │   ├── scheduler.py         # Task scheduler
│   │   ├── console.py           # REPL console
│   │   └── project.py           # Project management
│   ├── builder/
│   │   ├── engine.py            # Build orchestration
│   │   ├── compiler.py          # C compiler (mingw)
│   │   ├── encryptor.py         # Payload encryption
│   │   ├── donut_wrap.py        # Donut shellcode gen
│   │   └── models.py            # Build models
│   ├── delivery/
│   │   ├── obfuscation/
│   │   │   └── ps_obfuscator.py # PowerShell obfuscator
│   │   └── stager/
│   │       ├── ps1_stager.py    # PS1 stager generator
│   │       ├── vba_stager.py    # VBA stager generator
│   │       └── hta_stager.py    # HTA stager generator
│   ├── config.py                # Config loader
│   └── sdk/
│       ├── base_plugin.py       # Plugin base class
│       ├── context.py           # PluginContext
│       └── schema.py            # Parameter schema
├── main.py                      # Entry point
└── requirements.txt             # Dependencies
```

---

## Deployment Scenarios

### Scenario 1: Local Lab (Single Machine)
- Windows 10/11 VM as target
- Python runs on host
- Telegram bot for C2 (mobile phone alerts)
- See [README_SETUP.md](README_SETUP.md) — "Local Lab Setup"

### Scenario 2: VPS Red Team
- Ubuntu 20.04 LTS on VPS
- Python runs on VPS (persistent)
- Telegram bot + Discord fallback
- HTTPS listener for air-gapped networks
- See [README_SETUP.md](README_SETUP.md) — "VPS Deployment"

### Scenario 3: CTF Competition
- Linux box runs Fitnah
- Telegram bot for operator notifications
- Scheduler auto-submits flags every 5 seconds
- See [README_CTF_ADVANCED.md](README_CTF_ADVANCED.md) — "CTF Workflow"

### Scenario 4: Hostile Environment
- Full evasion enabled (AMSI/ETW bypass, sleep masking)
- HTTP listener with malleable profiles
- Encrypted persistence
- See [README_HOSTILE.md](README_HOSTILE.md)

---

## Troubleshooting

### "Bot not responding to messages"
- ✓ Check `telegram.token` in config
- ✓ Verify operator chat ID (use `/start` with bot)
- ✓ Confirm bot is admin in group
- See [README_TELEGRAM.md](README_TELEGRAM.md) — "Connectivity Testing"

### "Agent doesn't checkin"
- ✓ Check agent IP can reach `api.telegram.org:443`
- ✓ Verify bot token is baked into payload
- ✓ Agent ID matches Telegram group ID
- See [README_USAGE.md](README_USAGE.md) — "Troubleshooting"

### "Build fails - mingw not found"
- ✓ Install mingw-w64: `sudo apt install mingw-w64`
- ✓ Use PS1 format instead: `builder -f ps1 -a <agent>`
- See [README_SETUP.md](README_SETUP.md) — "Prerequisites"

### "Defender blocks implant"
- ✓ Use AMSI bypass plugin on agent
- ✓ Try VBA/HTA format (macro execution)
- ✓ Use DLL injection for code execution
- See [README_HOSTILE.md](README_HOSTILE.md) — "AV/EDR Evasion"

---

## Security Considerations

### For Operators
- **NEVER commit secrets to git** — use `.env` or environment variables
- **Use strong auth** — Telegram 2FA, Discord 2FA, VPS SSH keys
- **Rotate tokens regularly** — especially after engagement
- **Monitor audit log** — for forensics and incident response
- **Use TLS for HTTP listener** — enable HTTPS with valid cert
- **Disable Discord if not needed** — reduces attack surface

### For Targets
- Fitnah respects Windows file permissions
- Does not disable Windows Firewall (stealthy)
- Does not modify system time (anti-forensics)
- Graceful shutdown option (cleanup)
- All actions logged to audit trail

### For Blue Teams
- Look for `Invoke-Expression` with Base64-encoded payloads
- Monitor `TcpClient` .NET class usage (reverse shells)
- Check Scheduled Tasks for suspicious items
- Monitor registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Check for `SetThreadContext` calls (AMSI bypass)
- Monitor `ntdll.dll` patches (ETW bypass)
- See [README_HOSTILE.md](README_HOSTILE.md) — "Blue Team Counter-Measures"

---

## Contributing

### Adding a Plugin
1. Create file: `fitnah/plugins/<category>/<plugin_name>.py`
2. Inherit from `BasePlugin`
3. Implement `run(self, ctx: PluginContext) -> ModuleResult`
4. Test locally: `python -c "from fitnah.plugins... import MyPlugin; ..."`
5. No restart needed — `reload` command hot-loads

See [README_PLUGINS.md](README_PLUGINS.md) — "Creating Plugins"

### Reporting Bugs
- Test on latest Python (3.10+)
- Include full error trace
- Specify target OS and version
- Include reproduction steps

### Feature Requests
- Check existing plugins first
- Describe the ATT&CK technique you want to automate
- Propose implementation approach

---

## Frequently Asked Questions

**Q: Can I use this for production red team engagements?**
A: Yes, with proper authorization and rules of engagement. This is production-ready (9/10 red team score). See [README_HOSTILE.md](README_HOSTILE.md) for evasion techniques and security hardening.

**Q: Does it work on Linux targets?**
A: No, the implant is Windows-only. Fitnah server runs on Linux/Mac/Windows, but the agent (implant) targets Windows 7+.

**Q: Can I use this without Telegram?**
A: Yes, use HTTP listener instead (`http_enabled: true` in config). Or use Discord fallback. See [README_USAGE.md](README_USAGE.md) — "Transports".

**Q: How do I exfiltrate large files?**
A: Use `chunked_send` plugin (splits file into 4KB chunks) or `zip_exfil` (compresses + uploads). Telegram limits 20 MB per file. See [README_USAGE.md](README_USAGE.md) — "File Operations".

**Q: Can I run multiple C2 servers?**
A: Yes, each with separate Telegram bot + config. Projects are isolated. See [README_SETUP.md](README_SETUP.md) — "Multi-Project Setup".

**Q: What if Telegram API goes down?**
A: Automatic failover to Discord (or HTTP listener). Router handles switchback when primary recovers. See [README_DISCORD.md](README_DISCORD.md) — "Failover".

---

## Version History

**Fitnah v2.0** (2025-06-17) — Production Release
- 49 production plugins
- AES-256-GCM encryption
- AMSI/ETW/sleep evasion
- Scheduler for automation
- Audit log with HMAC
- 4 malleable C2 profiles
- HTTP + reverse shell transports
- Full documentation suite

---

## License & Disclaimer

**Authorized use only.** This tool is designed for authorized penetration testing, red team engagements, and CTF competitions on systems you own or have explicit permission to test. 

Unauthorized access to computer systems is illegal. Use at your own risk. The author assumes no liability for misuse or damage caused by this tool.

---

## Links

- **GitHub:** [github.com/yourusername/fitnah](https://github.com/yourusername/fitnah)
- **Issues:** [github.com/yourusername/fitnah/issues](https://github.com/yourusername/fitnah/issues)
- **Telegram:** [@BotFather](https://t.me/botfather) — create bots
- **MITRE ATT&CK:** [mitre-attack.org](https://mitre-attack.org) — technique mapping

---

## Quick Links to Docs

| Goal | Start Here |
|------|-----------|
| Deploy locally | [README_SETUP.md](README_SETUP.md) |
| Configure Telegram | [README_TELEGRAM.md](README_TELEGRAM.md) |
| Learn the CLI | [README_USAGE.md](README_USAGE.md) |
| Build a plugin | [README_PLUGINS.md](README_PLUGINS.md) |
| Run a CTF | [README_CTF_ADVANCED.md](README_CTF_ADVANCED.md) |
| Evade AV/EDR | [README_HOSTILE.md](README_HOSTILE.md) |
| Set up Discord | [README_DISCORD.md](README_DISCORD.md) |

---

**Last Updated:** 2025-06-17  
**Status:** Production Ready ✓  
**Support:** Community  
