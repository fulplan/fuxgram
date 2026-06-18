"""defense_evasion/timing_evasion — delay execution until a safe window. MITRE T1497"""
import time
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class TimingEvasion(BasePlugin):
    NAME        = "timing_evasion"
    DESCRIPTION = "Delay operator action until a safe hour window — avoids SOC working-hours detection."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1497"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("safe_hour_start", int, required=False, default=2,
              help="Start of safe execution window (0-23, default 2 = 02:00)"),
        Param("safe_hour_end",   int, required=False, default=5,
              help="End of safe window (default 5 = 05:00)"),
        Param("check_only",      bool, required=False, default=True,
              help="If True, just check and report current hour (default True)"),
    )

    @mitre("T1497")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        start = int(params.get("safe_hour_start", 2))
        end   = int(params.get("safe_hour_end",   5))
        check = params.get("check_only", True)

        # Get implant-side time via whoami BOF (includes uptime/timestamp)
        r    = ctx.bof("nettime", timeout=10)
        info = r.get("output", "")

        if check:
            return ModuleResult.ok(data=f"Safe window: {start:02d}:00-{end:02d}:00 | Agent time info: {info}")

        # Active wait — operator-side only, keep implant idle with FoliageSleep
        return ModuleResult.ok(data=f"Timing check: safe window {start:02d}:00-{end:02d}:00 | {info}")
