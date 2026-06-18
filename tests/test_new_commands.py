"""
test_new_commands.py — offline unit tests for commands added in the integration sprint:

  Token impersonation : make_token, steal_token, rev2self, getsystem, token_list
  SOCKS5 proxy        : socks_start, socks_stop, socks_poll
  SMB pivot           : pivot_listen, pivot_connect, pivot_send
  .NET execution      : execute_assembly
  LSASS dump          : lsass_dump (nanodump path)
  Shellcode injection : shellcode_inject

All tests use MockPluginCtx — a thin dict-returning stub — and MockSession
from fitnah.sdk.testing, so no live C2 or implant is needed.
"""
from __future__ import annotations

import base64
import json
import pytest

from fitnah.sdk.testing import MockSession
from fitnah.sdk.result import Status


# ── Minimal PluginContext stub ────────────────────────────────────────────────

class MockPluginCtx:
    """
    Replaces PluginContext for offline tests.
    Pre-load responses with queue(command, response_dict).
    """

    def __init__(self, session: MockSession):
        self._session  = session
        self._queue: dict[str, dict] = {}

    def queue(self, command: str, response: dict) -> "MockPluginCtx":
        self._queue[command] = response
        return self

    def send(self, command: str, args: dict | None = None) -> dict:
        return self._queue.get(
            command,
            {"status": "ok", "output": f"stub:{command}"},
        )

    def exec(self, cmd: str) -> dict:
        return self.send("exec", {"cmd": cmd})

    def ps(self, cmd: str, timeout: int | None = None) -> dict:
        return self.send("ps", {"cmd": cmd})

    # expose session attributes plugins may read
    @property
    def agent_id(self):   return self._session.agent_id
    @property
    def hostname(self):   return self._session.hostname
    @property
    def os(self):         return self._session.os
    @property
    def priv(self):       return self._session.priv_level


def _sess(**kw) -> MockSession:
    defaults = dict(priv_level="SYSTEM")
    defaults.update(kw)
    return MockSession(**defaults)


# ── Token impersonation ───────────────────────────────────────────────────────

class TestTokenImpersonate:
    def _plugin(self):
        from fitnah.plugins.privilege_escalation.token_impersonate import TokenImpersonate
        return TokenImpersonate()

    def test_make_token_ok(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "make_token",
            {"status": "ok", "output": '{"status":"ok","username":"CORP\\\\admin","type":"ImpersonationToken"}'},
        )
        r = p.run(s, {"action": "make_token", "domain": "CORP",
                      "username": "admin", "password": "P@ss1"}, ctx)
        assert r.status == Status.OK

    def test_make_token_missing_username(self):
        p = self._plugin()
        s = _sess()
        ctx = MockPluginCtx(s)
        r = p.run(s, {"action": "make_token", "domain": "."}, ctx)
        assert r.status == Status.ERROR
        assert "username" in r.error.lower() or "required" in r.error.lower()

    def test_steal_token_ok(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "steal_token",
            {"status": "ok", "output": '{"status":"ok","pid":1234,"user":"NT AUTHORITY\\\\SYSTEM","integrity":"High"}'},
        )
        r = p.run(s, {"action": "steal_token", "pid": 1234}, ctx)
        assert r.status == Status.OK

    def test_steal_token_missing_pid(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s)
        r   = p.run(s, {"action": "steal_token"}, ctx)
        assert r.status == Status.ERROR
        assert "pid" in r.error.lower()

    def test_rev2self_ok(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "rev2self",
            {"status": "ok", "output": '{"status":"ok","msg":"RevToSelf: ok"}'},
        )
        r = p.run(s, {"action": "rev2self"}, ctx)
        assert r.status == Status.OK

    def test_getsystem_ok(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "getsystem",
            {"status": "ok", "output": '{"status":"ok","method":"impersonate","user":"NT AUTHORITY\\\\SYSTEM"}'},
        )
        r = p.run(s, {"action": "getsystem"}, ctx)
        assert r.status == Status.OK

    def test_token_list_ok(self):
        payload = json.dumps([
            {"pid": 4, "name": "System", "user": "NT AUTHORITY\\SYSTEM", "integrity": "System"},
            {"pid": 888, "name": "lsass.exe", "user": "NT AUTHORITY\\SYSTEM", "integrity": "System"},
        ])
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "token_list",
            {"status": "ok", "output": payload},
        )
        r = p.run(s, {"action": "token_list"}, ctx)
        assert r.status == Status.OK

    def test_no_ctx_returns_err(self):
        p = self._plugin()
        s = _sess()
        r = p.run(s, {"action": "make_token", "username": "x", "password": "x"}, ctx=None)
        assert r.status == Status.ERROR
        assert "session" in r.error.lower()


# ── SOCKS5 proxy ─────────────────────────────────────────────────────────────

class TestSocksProxy:
    def _plugin(self):
        from fitnah.plugins.lateral_movement.socks_proxy import SocksProxy
        return SocksProxy()

    def test_start_ok(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "socks_start",
            {"status": "ok", "output": '{"status":"ok","port":1080,"bind":"127.0.0.1"}'},
        )
        r = p.run(s, {"action": "start", "port": 1080}, ctx)
        assert r.status == Status.OK
        assert "1080" in str(r.data)

    def test_stop_ok(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "socks_stop",
            {"status": "ok", "output": "socks_stop: ok"},
        )
        r = p.run(s, {"action": "stop"}, ctx)
        assert r.status == Status.OK

    def test_poll_ok(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "socks_poll",
            {"status": "ok", "output": '{"running":true,"port":1080}'},
        )
        r = p.run(s, {"action": "poll"}, ctx)
        assert r.status == Status.OK

    def test_no_ctx(self):
        p = self._plugin()
        s = _sess()
        r = p.run(s, {"action": "start"}, ctx=None)
        assert r.status == Status.ERROR

    def test_invalid_action(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s)
        r   = p.run(s, {"action": "unknown_action"}, ctx)
        assert r.status == Status.ERROR


# ── SMB pivot ─────────────────────────────────────────────────────────────────

class TestSmbPivot:
    def _plugin(self):
        from fitnah.plugins.lateral_movement.smb_pivot import SmbPivot
        return SmbPivot()

    def test_listen_ok(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "smb_pivot_listen",
            {"status": "ok", "agent_id": 1},
        )
        r = p.run(s, {"action": "listen", "pipe": "agent1"}, ctx)
        assert r.status == Status.OK

    def test_connect_ok(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "smb_pivot_connect",
            {"status": "ok", "agent_id": 2},
        )
        r = p.run(s, {"action": "connect", "pipe": "\\\\.\\pipe\\fitnah_agent1"}, ctx)
        assert r.status == Status.OK

    def test_connect_missing_pipe(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s)
        r   = p.run(s, {"action": "connect"}, ctx)
        assert r.status == Status.ERROR
        assert "pipe" in r.error.lower()

    def test_list_ok(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "smb_pivot_list",
            {"status": "ok", "pivots": [{"agent_id": 1, "pipe": "fitnah_agent1"}]},
        )
        r = p.run(s, {"action": "list"}, ctx)
        assert r.status == Status.OK

    def test_send_ok(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "smb_pivot_send",
            {"status": "ok"},
        )
        data_b64 = base64.b64encode(b"test payload").decode()
        r = p.run(s, {"action": "send", "agent_id": "1", "data": data_b64}, ctx)
        assert r.status == Status.OK

    def test_no_ctx(self):
        p = self._plugin()
        s = _sess()
        r = p.run(s, {"action": "listen", "pipe": "x"}, ctx=None)
        assert r.status == Status.ERROR


# ── execute_assembly ──────────────────────────────────────────────────────────

class TestExecuteAssembly:
    def _plugin(self):
        from fitnah.plugins.execution.shell_exec import ShellExec
        # execute_assembly may be its own plugin; fall back gracefully
        try:
            from fitnah.plugins.execution.execute_assembly import ExecuteAssembly
            return ExecuteAssembly()
        except ImportError:
            pytest.skip("execute_assembly plugin not yet present")

    def test_ok(self):
        p   = self._plugin()
        s   = _sess()
        asm_b64 = base64.b64encode(b"\x4d\x5a\x90\x00dummy").decode()
        ctx = MockPluginCtx(s).queue(
            "execute_assembly",
            {"status": "ok", "output": "Seatbelt output here"},
        )
        r = p.run(s, {"assembly_b64": asm_b64, "args": "/all"}, ctx)
        assert r.status == Status.OK
        assert "Seatbelt" in str(r.data)

    def test_no_ctx(self):
        p = self._plugin()
        s = _sess()
        r = p.run(s, {"assembly_b64": "AAAA"}, ctx=None)
        assert r.status == Status.ERROR


# ── lsass_dump (nanodump path) ────────────────────────────────────────────────

class TestLsassDump:
    def _plugin(self):
        from fitnah.plugins.credential_access.lsass_dump import LsassDump
        return LsassDump()

    def _nano_response(self, size=1024 * 1024):
        data = base64.b64encode(b"\x4d\x44\x4d\x50" + b"\x00" * (size - 4)).decode()
        return {
            "status": "ok",
            "output": json.dumps({"status": "ok", "size": size, "data": data}),
        }

    def test_nanodump_ok(self):
        p   = self._plugin()
        s   = _sess(priv_level="SYSTEM")
        ctx = MockPluginCtx(s).queue("lsass_dump", self._nano_response())
        r   = p.run(s, {"method": "nanodump"}, ctx)
        assert r.status == Status.OK
        assert "nanodump" in r.data.lower()
        assert "MB" in r.data

    def test_nanodump_with_out_path(self):
        p   = self._plugin()
        s   = _sess(priv_level="SYSTEM")
        ctx = MockPluginCtx(s).queue("lsass_dump", self._nano_response())
        r   = p.run(s, {"method": "nanodump", "out_path": "C:\\Windows\\Temp\\d.dmp"}, ctx)
        assert r.status == Status.OK

    def test_nanodump_implant_error(self):
        p   = self._plugin()
        s   = _sess(priv_level="SYSTEM")
        ctx = MockPluginCtx(s).queue(
            "lsass_dump",
            {"status": "ok", "output": json.dumps({"status": "error", "msg": "NtOpenProcess failed"})},
        )
        r = p.run(s, {"method": "nanodump"}, ctx)
        assert r.status == Status.ERROR
        assert "NtOpenProcess" in r.error

    def test_requires_elevation(self):
        p   = self._plugin()
        s   = _sess(priv_level="user")
        ctx = MockPluginCtx(s)
        r   = p.run(s, {"method": "nanodump"}, ctx)
        assert r.status == Status.ERROR
        assert "elevated" in r.error.lower() or "priv" in r.error.lower()

    def test_no_ctx(self):
        p = self._plugin()
        s = _sess(priv_level="SYSTEM")
        r = p.run(s, {"method": "nanodump"}, ctx=None)
        assert r.status == Status.ERROR

    def test_default_method_is_nanodump(self):
        """Default method param must be nanodump, not comsvcs."""
        from fitnah.plugins.credential_access.lsass_dump import LsassDump
        p = LsassDump()
        schema_defaults = {
            param.name: param.default
            for param in p.schema.params
            if hasattr(param, "default")
        }
        assert schema_defaults.get("method") == "nanodump"


# ── shellcode_inject ──────────────────────────────────────────────────────────

class TestShellcodeInject:
    def _plugin(self):
        from fitnah.plugins.execution.shellcode_inject import ShellcodeInject
        return ShellcodeInject()

    def test_inject_self_ok(self):
        p       = self._plugin()
        s       = _sess()
        sc_b64  = base64.b64encode(b"\x90" * 32).decode()
        ctx     = MockPluginCtx(s).queue(
            "shellcode_inject",
            {"status": "ok", "output": json.dumps({"status": "ok", "pid": 0, "addr": "0x1234000"})},
        )
        r = p.run(s, {"pid": 0, "sc_b64": sc_b64}, ctx)
        assert r.status == Status.OK
        assert "0x1234000" in str(r.data)

    def test_inject_remote_pid(self):
        p       = self._plugin()
        s       = _sess()
        sc_b64  = base64.b64encode(b"\x90" * 8).decode()
        ctx     = MockPluginCtx(s).queue(
            "shellcode_inject",
            {"status": "ok", "output": json.dumps({"status": "ok", "pid": 4321, "addr": "0xdeadbeef"})},
        )
        r = p.run(s, {"pid": 4321, "sc_b64": sc_b64}, ctx)
        assert r.status == Status.OK
        assert "4321" in str(r.data)

    def test_inject_failure(self):
        p      = self._plugin()
        s      = _sess()
        sc_b64 = base64.b64encode(b"\x90").decode()
        ctx    = MockPluginCtx(s).queue(
            "shellcode_inject",
            {"status": "ok", "output": json.dumps({"status": "error", "msg": "NtCreateThreadEx failed"})},
        )
        r = p.run(s, {"pid": 1234, "sc_b64": sc_b64}, ctx)
        assert r.status == Status.ERROR
        assert "NtCreateThreadEx" in r.error

    def test_missing_shellcode(self):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s)
        r   = p.run(s, {"pid": 0}, ctx)
        assert r.status == Status.ERROR
        assert "sc_b64" in r.error.lower() or "shellcode" in r.error.lower()

    def test_sc_path_not_found(self, tmp_path):
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s)
        r   = p.run(s, {"sc_path": str(tmp_path / "nonexistent.bin")}, ctx)
        assert r.status == Status.ERROR
        assert "not found" in r.error.lower()

    def test_sc_path_ok(self, tmp_path):
        sc_file = tmp_path / "payload.bin"
        sc_file.write_bytes(b"\x90" * 16)
        p   = self._plugin()
        s   = _sess()
        ctx = MockPluginCtx(s).queue(
            "shellcode_inject",
            {"status": "ok", "output": json.dumps({"status": "ok", "pid": 0, "addr": "0x5000"})},
        )
        r = p.run(s, {"sc_path": str(sc_file)}, ctx)
        assert r.status == Status.OK

    def test_no_ctx(self):
        p      = self._plugin()
        s      = _sess()
        sc_b64 = base64.b64encode(b"\x90").decode()
        r      = p.run(s, {"sc_b64": sc_b64}, ctx=None)
        assert r.status == Status.ERROR
