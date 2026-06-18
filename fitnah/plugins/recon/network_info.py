"""recon/network_info — comprehensive network enumeration. MITRE T1016"""
from fitnah.sdk import BasePlugin, ModuleResult, mitre


class NetworkInfo(BasePlugin):
    NAME        = "network_info"
    DESCRIPTION = "Enumerate interfaces, routes, DNS cache, proxy, ARP, named pipes, firewall rules."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1016"
    CATEGORY    = "recon"

    @mitre("T1016")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        ps = (
            "$sep = \"`n\" + (\"-\"*60) + \"`n\";"

            "Write-Output ($sep + \"[INTERFACES]\");"
            "ipconfig /all 2>&1;"

            "Write-Output ($sep + \"[CONNECTIONS]\");"
            "netstat -ano 2>&1;"

            "Write-Output ($sep + \"[ROUTING TABLE]\");"
            "route print 2>&1;"

            "Write-Output ($sep + \"[DNS CACHE]\");"
            "ipconfig /displaydns 2>&1 | Select-String 'Record Name|Data' | Select-Object -First 60;"

            "Write-Output ($sep + \"[PROXY]\");"
            "try {"
            "  $p = Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -EA Stop;"
            "  \"Enable=$($p.ProxyEnable) Server=$($p.ProxyServer) PAC=$($p.AutoConfigURL)\""
            "} catch { 'Proxy: N/A' };"

            "Write-Output ($sep + \"[ARP CACHE]\");"
            "arp -a 2>&1;"

            "Write-Output ($sep + \"[NAMED PIPES]\");"
            "try { [System.IO.Directory]::GetFiles('\\\\.\\pipe\\') | Select-Object -First 40 }"
            "catch { Get-ChildItem \\\\.\\pipe\\ -EA SilentlyContinue | Select-Object -First 40 | % { $_.Name } };"

            "Write-Output ($sep + \"[FIREWALL RULES (enabled)]\");"
            "try {"
            "  Get-NetFirewallRule -Enabled True -EA Stop |"
            "    Select-Object DisplayName,Direction,Action |"
            "    Format-Table -AutoSize | Out-String -Width 160 | Select-Object -First 50"
            "} catch { netsh advfirewall firewall show rule name=all 2>&1 | Select-Object -First 60 }"
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        out = r["output"]
        if len(out) > 6000:
            out = out[:6000] + "\n...[truncated]"
        return ModuleResult.ok(data=out)
