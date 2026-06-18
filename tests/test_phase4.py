"""
Phase 4 tests — Kernel plugin engine, execute(), search_plugins().
Console commands are tested via direct method calls (no TTY needed).
"""
from __future__ import annotations

import asyncio
import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock

from fitnah.orchestration.session_manager import SessionManager, Session
from fitnah.orchestration.audit_log import AuditLog
from fitnah.orchestration.project import Project
from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.result import ModuleResult, Status
from fitnah.sdk.schema import Param, ParamSchema


# ── Minimal plugin stubs ──────────────────────────────────────────────────────

class EchoPlugin(BasePlugin):
    NAME        = "echo"
    DESCRIPTION = "Echo back the msg param."
    CATEGORY    = "recon"
    MITRE       = "T1082"
    schema      = ParamSchema().add(
        Param("msg", str, required=False, default="hello", help="Message to echo")
    )
    def run(self, session, params) -> ModuleResult:
        return ModuleResult.ok(data={"echo": params["msg"]})


class FailPlugin(BasePlugin):
    NAME        = "fail_plugin"
    DESCRIPTION = "Always fails."
    CATEGORY    = "recon"
    MITRE       = ""
    def run(self, session, params) -> ModuleResult:
        return ModuleResult.err("intentional failure")


class CrashPlugin(BasePlugin):
    NAME        = "crash_plugin"
    DESCRIPTION = "Raises an exception."
    CATEGORY    = "recon"
    MITRE       = ""
    def run(self, session, params) -> ModuleResult:
        raise RuntimeError("boom")


# ── Minimal kernel for testing (no real transports) ──────────────────────────

class MinimalKernel:
    """Kernel-like object with plugins, sessions, loot, audit wired together."""
    def __init__(self, tmp_path):
        self.sessions = SessionManager()
        self.audit    = AuditLog(tmp_path / "audit.jsonl")
        self.plugins: dict[str, BasePlugin] = {}
        self._tmp     = tmp_path

        from fitnah.loot.store import LootStore
        self.loot = LootStore(tmp_path / "loot.db")

        # mock router + c2 for execute()
        self.router = MagicMock()
        self.router.active_transport = "telegram"
        self.router.status_table.return_value = "telegram ALIVE"

        self.c2 = MagicMock()
        self.c2.stats.return_value = {"dispatched": 0, "acked": 0, "timed_out": 0}
        self.c2.pending_tasks.return_value = []
        self.c2.stats_display.return_value = ""

        # mock cfg
        self.cfg = MagicMock()
        self.cfg.task_timeout = 30
        self.cfg.operator_tag = "testop"

        self.project = None

    def register(self, *plugins):
        for p in plugins:
            instance = p()
            instance.on_load()
            self.plugins[p.NAME] = instance

    async def execute(self, agent_id, plugin_name, raw_params, operator="test"):
        plugin = self.plugins.get(plugin_name)
        if not plugin:
            return ModuleResult.err(f"Plugin not found: {plugin_name!r}")
        session = self.sessions.get(agent_id)
        if not session:
            return ModuleResult.err(f"No session: {agent_id!r}")
        try:
            params = plugin.validate(raw_params)
            result = plugin.run(session, params)
        except ValueError as exc:
            return ModuleResult.err(str(exc))
        except Exception as exc:
            return ModuleResult.err(f"Plugin error: {exc}")
        self.audit.plugin_run(operator, plugin_name, agent_id, raw_params, result.status.value)
        session.touch(plugin_name, result.status.value)
        return result

    def search_plugins(self, query):
        q = query.lower()
        return [
            p for p in self.plugins.values()
            if q in p.NAME.lower()
            or q in p.CATEGORY.lower()
            or q in (p.MITRE or "").lower()
            or q in (p.DESCRIPTION or "").lower()
        ]

    def list_plugins(self, category: str = "") -> list[dict]:
        result = []
        for p in self.plugins.values():
            if category and p.CATEGORY.lower() != category.lower():
                continue
            result.append({
                "name":        p.NAME,
                "category":    p.CATEGORY,
                "mitre":       p.MITRE or "",
                "description": p.DESCRIPTION,
                "author":      getattr(p, "AUTHOR", ""),
                "version":     getattr(p, "VERSION", "1.0"),
            })
        result.sort(key=lambda x: (x["category"], x["name"]))
        return result

    def status(self):
        return f"Transport: {self.router.active_transport}"


# ── Plugin engine tests ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_execute_ok(tmp_path):
    k = MinimalKernel(tmp_path)
    k.register(EchoPlugin)
    k.sessions.register("a1", hostname="BOX")
    result = await k.execute("a1", "echo", {"msg": "world"})
    assert result.status == Status.OK
    assert result.data["echo"] == "world"


@pytest.mark.asyncio
async def test_execute_plugin_not_found(tmp_path):
    k = MinimalKernel(tmp_path)
    k.sessions.register("a1")
    result = await k.execute("a1", "nonexistent", {})
    assert result.status == Status.ERROR
    assert "not found" in result.error


@pytest.mark.asyncio
async def test_execute_no_session(tmp_path):
    k = MinimalKernel(tmp_path)
    k.register(EchoPlugin)
    result = await k.execute("ghost", "echo", {})
    assert result.status == Status.ERROR
    assert "No session" in result.error


@pytest.mark.asyncio
async def test_execute_plugin_failure(tmp_path):
    k = MinimalKernel(tmp_path)
    k.register(FailPlugin)
    k.sessions.register("a1")
    result = await k.execute("a1", "fail_plugin", {})
    assert result.status == Status.ERROR
    assert "intentional" in result.error


@pytest.mark.asyncio
async def test_execute_plugin_crash_handled(tmp_path):
    k = MinimalKernel(tmp_path)
    k.register(CrashPlugin)
    k.sessions.register("a1")
    result = await k.execute("a1", "crash_plugin", {})
    assert result.status == Status.ERROR
    assert "boom" in result.error


@pytest.mark.asyncio
async def test_execute_records_touch_history(tmp_path):
    k = MinimalKernel(tmp_path)
    k.register(EchoPlugin)
    s, _ = k.sessions.register("a1")
    await k.execute("a1", "echo", {"msg": "test"})
    hist = s.history()
    assert len(hist) == 1
    assert hist[0]["action"] == "echo"


@pytest.mark.asyncio
async def test_execute_records_audit(tmp_path):
    k = MinimalKernel(tmp_path)
    k.register(EchoPlugin)
    k.sessions.register("a1")
    await k.execute("a1", "echo", {})
    entries = k.audit.tail()
    assert len(entries) == 1
    assert "echo" in entries[0]["action"]


@pytest.mark.asyncio
async def test_execute_default_params(tmp_path):
    k = MinimalKernel(tmp_path)
    k.register(EchoPlugin)
    k.sessions.register("a1")
    result = await k.execute("a1", "echo", {})   # no msg → uses default "hello"
    assert result.data["echo"] == "hello"


@pytest.mark.asyncio
async def test_execute_invalid_param_type(tmp_path):
    class TypedPlugin(BasePlugin):
        NAME     = "typed"
        CATEGORY = "recon"
        MITRE    = ""
        DESCRIPTION = ""
        schema   = ParamSchema().add(Param("count", int, help="a number"))
        def run(self, session, params): return ModuleResult.ok()

    k = MinimalKernel(tmp_path)
    k.register(TypedPlugin)
    k.sessions.register("a1")
    result = await k.execute("a1", "typed", {"count": "not_a_number"})
    assert result.status == Status.ERROR


# ── search_plugins tests ──────────────────────────────────────────────────────

def test_search_by_name(tmp_path):
    k = MinimalKernel(tmp_path)
    k.register(EchoPlugin, FailPlugin)
    results = k.search_plugins("echo")
    assert any(p.NAME == "echo" for p in results)
    assert all(p.NAME != "fail_plugin" for p in results)


def test_search_by_category(tmp_path):
    k = MinimalKernel(tmp_path)
    k.register(EchoPlugin, FailPlugin)
    results = k.search_plugins("recon")
    assert len(results) == 2


def test_search_by_mitre(tmp_path):
    k = MinimalKernel(tmp_path)
    k.register(EchoPlugin, FailPlugin)
    results = k.search_plugins("T1082")
    assert len(results) == 1
    assert results[0].NAME == "echo"


def test_search_no_results(tmp_path):
    k = MinimalKernel(tmp_path)
    k.register(EchoPlugin)
    results = k.search_plugins("xyzzy_nonexistent")
    assert results == []


def test_search_by_description(tmp_path):
    k = MinimalKernel(tmp_path)
    k.register(EchoPlugin)
    results = k.search_plugins("echo back")
    assert any(p.NAME == "echo" for p in results)


# ── Project tests (via kernel context) ───────────────────────────────────────

def test_project_creates_loot_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = Project(name="test_proj", operator="shadow")
    assert p.loot_dir().exists()
    assert p.audit_log_path().parent.exists()


def test_project_builds_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = Project(name="test_proj", operator="shadow")
    d = p.builds_dir()
    assert d.exists()


# ── Console dispatch tests ────────────────────────────────────────────────────

def make_console(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from fitnah.orchestration.console import FitnahConsole
    project = Project(name="test_op", operator="shadow")
    k       = MinimalKernel(tmp_path)
    k.register(EchoPlugin, FailPlugin)
    loop    = asyncio.new_event_loop()
    console = FitnahConsole(kernel=k, project=project, loop=loop)
    return console, k


def test_console_sessions_no_sessions(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_sessions([])
    out = capsys.readouterr().out
    assert "No sessions" in out


def test_console_sessions_lists_agents(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    k.sessions.register("a1", hostname="TESTBOX")
    console._do_sessions([])
    out = capsys.readouterr().out
    assert "TESTBOX" in out


def test_console_use_plugin(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_use(["echo"])
    assert console._active_module == "echo"


def test_console_use_agent(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    k.sessions.register("a1", hostname="BOX1")
    console._do_use(["a1"])
    assert console._active_agent == "a1"


def test_console_use_unknown(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_use(["nonexistent"])
    out = capsys.readouterr().out
    assert "not found" in out.lower() or "[-]" in out


def test_console_set_and_options(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_use(["echo"])
    console._do_set(["msg", "custom_value"])
    assert console._module_params.get("msg") == "custom_value"
    console._do_options([])
    out = capsys.readouterr().out
    assert "custom_value" in out


def test_console_back_clears_module(tmp_path, monkeypatch):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_use(["echo"])
    assert console._active_module == "echo"
    console._do_back([])
    assert console._active_module is None


def test_console_back_clears_agent(tmp_path, monkeypatch):
    console, k = make_console(tmp_path, monkeypatch)
    k.sessions.register("a1")
    console._do_use(["a1"])
    console._do_back([])
    assert console._active_agent is None


def test_console_search(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_search(["echo"])
    out = capsys.readouterr().out
    assert "echo" in out


def test_console_search_no_results(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_search(["xyzzy_nothing"])
    out = capsys.readouterr().out
    assert "No plugins" in out or "matched" in out


def test_console_plugins_list(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_plugins([])
    out = capsys.readouterr().out
    assert "echo" in out
    assert "fail_plugin" in out


def test_console_info(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_info(["echo"])
    out = capsys.readouterr().out
    assert "echo" in out.lower()
    assert "T1082" in out


def test_console_history_no_session(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_history([])
    out = capsys.readouterr().out
    assert "No session" in out or "selected" in out


def test_console_loot_empty(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_loot([])
    out = capsys.readouterr().out
    assert "No loot" in out


def test_console_project_info(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_project(["info"])
    out = capsys.readouterr().out
    assert "test_op" in out


def test_console_status(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_status([])
    out = capsys.readouterr().out
    assert "telegram" in out.lower() or "Transport" in out


def test_console_help(tmp_path, monkeypatch, capsys):
    console, k = make_console(tmp_path, monkeypatch)
    console._do_help([])
    out = capsys.readouterr().out
    assert "sessions" in out
    assert "use" in out
    assert "run" in out
