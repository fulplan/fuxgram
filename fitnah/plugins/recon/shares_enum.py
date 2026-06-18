"""recon/shares_enum — local share ACLs, mapped drives, admin share access. MITRE T1135"""
from fitnah.sdk import BasePlugin, ModuleResult, mitre


class SharesEnum(BasePlugin):
    NAME        = "shares_enum"
    DESCRIPTION = "Local shares + ACLs, SYSVOL/NETLOGON, mapped drives, C$/ADMIN$ access."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1135"
    CATEGORY    = "recon"

    @mitre("T1135")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        ps = (
            "$sep = \"`n\" + (\"-\"*50) + \"`n\";"

            "Write-Output ($sep + \"[LOCAL SHARES - net share]\");"
            "net share 2>&1;"

            "Write-Output ($sep + \"[LOCAL SHARES - Get-SmbShare ACLs]\");"
            "try {"
            "  Get-SmbShare -EA Stop | ForEach-Object {"
            "    $name = $_.Name; $path = $_.Path;"
            "    $acl = Get-SmbShareAccess $name -EA SilentlyContinue | Select-Object AccountName,AccessRight | Out-String;"
            "    \"Share: $name  Path: $path`n$acl\""
            "  }"
            "} catch { 'Get-SmbShare: N/A' };"

            "Write-Output ($sep + \"[MAPPED DRIVES]\");"
            "net use 2>&1;"

            "Write-Output ($sep + \"[ADMIN SHARE ACCESS CHECK (localhost)]\");"
            "foreach ($share in @('C$','ADMIN$','IPC$')) {"
            "  $unc = \"\\\\$env:COMPUTERNAME\\$share\";"
            "  if (Test-Path $unc -EA SilentlyContinue) { \"[+] Accessible: $unc\" }"
            "  else { \"[-] Not accessible: $unc\" }"
            "};"

            "Write-Output ($sep + \"[SYSVOL / NETLOGON]\");"
            "$d = $env:USERDNSDOMAIN;"
            "foreach ($s in @('SYSVOL','NETLOGON')) {"
            "  $p = \"\\\\$d\\$s\";"
            "  if (Test-Path $p -EA SilentlyContinue) { \"[+] $p`n\"; Get-ChildItem $p -EA SilentlyContinue | Select-Object -First 10 | % { \"  $($_.FullName)\" } }"
            "  else { \"[-] $p not accessible\" }"
            "}"
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        out = r["output"]
        if len(out) > 5000:
            out = out[:5000] + "\n...[truncated]"
        return ModuleResult.ok(data=out)
