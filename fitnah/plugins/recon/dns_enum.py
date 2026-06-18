"""recon/dns_enum — AD/DNS enumeration with graceful workgroup fallback. MITRE T1018"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class DnsEnum(BasePlugin):
    NAME        = "dns_enum"
    DESCRIPTION = "Domain/forest/DC/site/trust/SPN/SYSVOL/GPO enumeration with workgroup fallback."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1018"
    CATEGORY    = "recon"
    schema      = ParamSchema().add(
        Param("domain", str, required=False, default="",
              help="Domain to query (default: current domain from env)")
    )

    @mitre("T1018")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        domain = params.get("domain", "").strip()
        domain_expr = f"'{domain}'" if domain else "$env:USERDNSDOMAIN"
        ps = (
            f"$d = {domain_expr};"
            "$sep = \"`n\" + (\"-\"*50) + \"`n\";"

            "Write-Output ($sep + \"[CURRENT DOMAIN / FOREST]\");"
            "try {"
            "  $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain();"
            "  \"Domain: $($dom.Name)  Forest: $($dom.Forest.Name)  DomainMode: $($dom.DomainMode)\";"
            "  \"DomainControllers: $(($dom.DomainControllers | % { $_.Name }) -join ', ')\";"
            "} catch { \"Not domain-joined or LDAP unavailable\" };"

            "Write-Output ($sep + \"[DC LIST]\");"
            "nltest /dclist:$d 2>&1 | Select-Object -First 30;"

            "Write-Output ($sep + \"[AD SITE]\");"
            "nltest /dsgetsite 2>&1;"

            "Write-Output ($sep + \"[DOMAIN TRUSTS]\");"
            "nltest /domain_trusts 2>&1;"

            "Write-Output ($sep + \"[SPN SCAN (current host)]\");"
            "setspn -L $env:COMPUTERNAME 2>&1 | Select-Object -First 30;"

            "Write-Output ($sep + \"[SYSVOL PATH]\");"
            "try {"
            "  $sysvol = \"\\\\$d\\SYSVOL\";"
            "  if (Test-Path $sysvol) { \"SYSVOL accessible: $sysvol\"; Get-ChildItem $sysvol -EA SilentlyContinue | Select-Object -First 10 | % { $_.FullName } }"
            "  else { \"SYSVOL not accessible: $sysvol\" }"
            "} catch { 'SYSVOL check failed' };"

            "Write-Output ($sep + \"[GPO LIST]\");"
            "try {"
            "  Get-GPO -All -EA Stop | Select-Object DisplayName,GpoStatus,CreationTime | Format-Table | Out-String"
            "} catch { 'Get-GPO not available (RSAT not installed)' };"

            "Write-Output ($sep + \"[DNS - NSLookup]\");"
            "nslookup $d 2>&1 | Select-Object -First 20"
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        out = r["output"]
        if len(out) > 5000:
            out = out[:5000] + "\n...[truncated]"
        return ModuleResult.ok(data=out)
