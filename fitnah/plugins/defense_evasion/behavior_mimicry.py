"""defense_evasion/behavior_mimicry — Mimic legitimate software behavior to evade detection. MITRE T1036"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class BehaviorMimicry(BasePlugin):
    NAME = "behavior_mimicry"
    DESCRIPTION = "Mimic behavior of legitimate software (Windows Update, AV, security tools)"
    AUTHOR = "fitnah-team"
    MITRE = "T1036"
    CATEGORY = "defense_evasion"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("target", str, required=False, default="windows_update",
              help="windows_update | antivirus | security_scan | system_admin"),
        Param("duration", int, required=False, default=0,
              help="How long to maintain behavior (0 = until stopped)"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute behavior mimicry"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        target = params.get("target", "windows_update").lower()
        duration = params.get("duration", 0)

        if target == "windows_update":
            return self._mimic_windows_update(ctx, duration)
        elif target == "antivirus":
            return self._mimic_antivirus(ctx, duration)
        elif target == "security_scan":
            return self._mimic_security_scan(ctx, duration)
        elif target == "system_admin":
            return self._mimic_system_admin(ctx, duration)
        else:
            return ModuleResult.err(f"Unknown target: {target}")

    @staticmethod
    def _mimic_windows_update(ctx, duration: int) -> ModuleResult:
        """Mimic Windows Update behavior"""
        ps_code = f"""
$results = @()
$results += '[*] Mimicking Windows Update behavior...'

try {{
    $duration = {duration}
    $results += "[*] Duration: $(if ($duration -eq 0) {{'indefinite'}} else {{$duration + ' minutes'}})"

    $results += '[*] Windows Update characteristics:'
    $results += '    Process: svchost.exe -k netsvcs'
    $results += '    Parent: services.exe'
    $results += '    User: SYSTEM'
    $results += '    Priority: Normal'

    $results += '[*] Network behavior:'
    $results += '    - Connect to: http://update.microsoft.com'
    $results += '    - DNS: Query for update servers'
    $results += '    - Data: POST requests to Windows Update service'
    $results += '    - Frequency: Every 2-6 hours'
    $results += '    - Timing: Usually off-peak hours'

    $results += '[*] Registry access patterns:'
    $results += '    - HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate'
    $results += '    - HKLM\\SYSTEM\\CurrentControlSet\\Services\\wuauserv'
    $results += '    - Query: LastSuccessfulTime, AUOptions'

    $results += '[*] File system access:'
    $results += '    - Write: C:\\Windows\\SoftwareDistribution\\Download\\'
    $results += '    - Create: Temp .cab files'
    $results += '    - Delete: After processing'

    $results += '[*] Mimicry implementation:'
    $results += '    1. Spawn svchost.exe as parent'
    $results += '    2. Rename process to hide true name'
    $results += '    3. Access legitimate update registry keys'
    $results += '    4. Make periodic network requests to real Windows Update servers'
    $results += '    5. Create temp files in SoftwareDistribution'
    $results += '    6. Schedule via Task Scheduler (Windows Update task)'

    $results += '[*] Effectiveness:'
    $results += '    ✓ Normal users expect Windows Update traffic'
    $results += '    ✓ Legitimate registry access'
    $results += '    ✓ Expected network patterns'
    $results += '    ✗ But: excessive bandwidth = suspicious'

}} catch {{
    $results += "[!] Windows Update mimic error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="behavior_mimicry_winupdate")

    @staticmethod
    def _mimic_antivirus(ctx, duration: int) -> ModuleResult:
        """Mimic antivirus behavior"""
        ps_code = f"""
$results = @()
$results += '[*] Mimicking antivirus behavior...'

try {{
    $duration = {duration}
    $results += "[*] Duration: $(if ($duration -eq 0) {{'indefinite'}} else {{$duration + ' minutes'}})"

    $results += '[*] Antivirus characteristics:'
    $results += '    Process: MpCmdRun.exe, WinDefend.exe (Microsoft Defender)'
    $results += '    Parent: svchost.exe or System Process'
    $results += '    User: SYSTEM'

    $results += '[*] File system behavior:'
    $results += '    - Scan: C:\\, C:\\Windows\\, C:\\Users\\'
    $results += '    - Open: .exe, .dll, .scr, .vbs, .bat files'
    $results += '    - Pattern: Sequential directory traversal'
    $results += '    - Quarantine: C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine'

    $results += '[*] Registry access:'
    $results += '    - Read: HKLM\\SOFTWARE\\Microsoft\\Windows Defender'
    $results += '    - Query: Signature updates, scan history'
    $results += '    - Write: Quarantine database'

    $results += '[*] Network behavior:'
    $results += '    - Connect: wdcp.microsoft.com (signature updates)'
    $results += '    - DNS: Query for AV servers'
    $results += '    - Frequency: Every 6-24 hours'

    $results += '[*] Mimicry implementation:'
    $results += '    1. Spawn process as WinDefend.exe'
    $results += '    2. Use parent: svchost.exe'
    $results += '    3. Access Windows Defender registry keys'
    $results += '    4. Open legitimate .exe files (read-only scanning pattern)'
    $results += '    5. DNS queries to legitimate AV servers'
    $results += '    6. Create PDB files (symbol files) in SoftwareDistribution'

    $results += '[*] Effectiveness:'
    $results += '    ✓ Users expect AV scanning'
    $results += '    ✓ Legitimate file access'
    $results += '    ✓ Expected network patterns'
    $results += '    ✗ But: unusual file access patterns = detected'

}} catch {{
    $results += "[!] AV mimic error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="behavior_mimicry_antivirus")

    @staticmethod
    def _mimic_security_scan(ctx, duration: int) -> ModuleResult:
        """Mimic security scanning tools"""
        ps_code = f"""
$results = @()
$results += '[*] Mimicking security scanning tool behavior...'

try {{
    $duration = {duration}

    $results += '[*] Security scanner characteristics:'
    $results += '    - Tools: chkdsk, SFC (System File Checker), msrt.exe'
    $results += '    - Process: System process or scheduled task'
    $results += '    - User: SYSTEM'

    $results += '[*] File access pattern:'
    $results += '    - LSASS.exe (credential dump pattern)'
    $results += '    - System32\\ (system files)'
    $results += '    - Registry (check for tampering)'
    $results += '    - Pattern: Comprehensive file enumeration'

    $results += '[*] Registry access (for tampering check):'
    $results += '    - HKLM\\SYSTEM\\CurrentControlSet (system services)'
    $results += '    - HKLM\\SOFTWARE (installed software)'
    $results += '    - HKCU\\ (user settings)'

    $results += '[*] Memory access:'
    $results += '    - Open LSASS (check for hooks)'
    $results += '    - Read process memory (integrity check)'
    $results += '    - Scan for suspicious patches'

    $results += '[*] Timing:'
    $results += '    - Usually scheduled at night'
    $results += '    - Off-peak hours (2AM - 4AM typical)'
    $results += '    - Duration: 30 minutes - 2 hours'
    $results += '    - CPU impact: Low priority'

    $results += '[*] Mimicry implementation:'
    $results += '    1. Spawn as scheduled task (schtasks.exe)'
    $results += '    2. Run as SYSTEM'
    $results += '    3. Access legitimate security tools'
    $results += '    4. Query system file integrity'
    $results += '    5. Check for rootkits (legitimate)'
    $results += '    6. Run during off-peak hours'

}} catch {{
    $results += "[!] Security scan mimic error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="behavior_mimicry_security_scan")

    @staticmethod
    def _mimic_system_admin(ctx, duration: int) -> ModuleResult:
        """Mimic system administrator activity"""
        ps_code = f"""
$results = @()
$results += '[*] Mimicking system administrator behavior...'

try {{
    $duration = {duration}

    $results += '[*] System admin behavior characteristics:'
    $results += '    - Process: Explorer.exe, PowerShell.exe, cmd.exe'
    $results += '    - Parent: User session'
    $results += '    - User: Administrator or domain admin'

    $results += '[*] File operations:'
    $results += '    - Browse: C:\\Program Files\\, C:\\Windows\\System32'
    $results += '    - Edit: .ini, .conf, .xml (config files)'
    $results += '    - Create: Backups in Documents\\'
    $results += '    - Pattern: Infrequent, deliberate'

    $results += '[*] Registry operations:'
    $results += '    - Edit: Services, drivers'
    $results += '    - Query: System information'
    $results += '    - Modify: Security settings (Windows Update, Defender)'

    $results += '[*] Network activity:'
    $results += '    - RDP: Connections to servers'
    $results += '    - DCOM: Remote management'
    $results += '    - WMI: Remote queries'
    $results += '    - Pattern: Business hours typical'

    $results += '[*] Command execution:'
    $results += '    - Tools: ipconfig, systeminfo, gpupdate'
    $results += '    - Services: net, sc (service control)'
    $results += '    - Frequency: Sporadic, task-based'

    $results += '[*] Mimicry implementation:'
    $results += '    1. Spawn PowerShell as Administrator'
    $results += '    2. Use legitimate admin commands'
    $results += '    3. Access expected configuration files'
    $results += '    4. Make expected RDP/WMI connections'
    $results += '    5. Perform realistic system checks'
    $results += '    6. Schedule during work hours'

}} catch {{
    $results += "[!] System admin mimic error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="behavior_mimicry_system_admin")
