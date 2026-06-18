"""
Phase 3 tests — Telegram UI menu builders and operator state machine.
No real Telegram connection needed — tests operate on pure data.
"""
from __future__ import annotations

import asyncio
import time
import pytest

from fitnah.c2.telegram_ui import (
    TelegramUI, InputMode, OperatorState,
    build_main_menu, build_sessions_menu, build_agent_menu,
    build_recon_menu, build_creds_menu, build_files_menu,
    build_persist_menu, build_pivot_menu, build_evasion_menu,
    build_collect_menu, build_exfil_menu, build_loot_menu,
    build_status_menu, build_listeners_menu, build_kill_confirm_menu,
    build_history_text, build_shell_prompt, build_builder_menu,
    _escape, _chunk_text,
)
from fitnah.orchestration.session_manager import Session, SessionManager
from fitnah.orchestration.audit_log import AuditLog
from fitnah.loot.store import LootStore


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_session(**kwargs) -> Session:
    defaults = dict(
        agent_id="agent-001", hostname="CORP-PC", os="Windows 11",
        arch="x64", username="CORP\\jsmith", ip="10.0.0.5",
        priv_level="admin", transport="telegram",
    )
    defaults.update(kwargs)
    return Session(**defaults)


# ── Menu builder tests ────────────────────────────────────────────────────────

def test_main_menu_shows_alive_and_transport():
    text, kb = build_main_menu(alive=3, transport="telegram")
    assert "3" in text
    assert "telegram" in text
    assert kb.inline_keyboard


def test_main_menu_zero_agents():
    text, kb = build_main_menu(alive=0, transport="discord")
    assert "0" in text
    assert "discord" in text


def test_sessions_menu_empty():
    text, kb = build_sessions_menu([])
    assert "No active agents" in text
    # back button must exist
    assert any("Back" in btn.text for row in kb.inline_keyboard for btn in row)


def test_sessions_menu_with_agents():
    sessions = [
        make_session(agent_id="a1", hostname="PC-01", priv_level="admin"),
        make_session(agent_id="a2", hostname="SERVER", priv_level="system"),
    ]
    text, kb = build_sessions_menu(sessions)
    assert "PC-01" in text or any(
        "PC-01" in btn.text for row in kb.inline_keyboard for btn in row
    )
    # one button per agent + back
    flat = [btn for row in kb.inline_keyboard for btn in row]
    agent_btns = [b for b in flat if b.callback_data.startswith("agent:")]
    assert len(agent_btns) == 2


def test_agent_menu_contains_all_actions():
    s    = make_session()
    text, kb = build_agent_menu(s)
    assert "CORP-PC" in text
    assert "admin" in text
    flat = [btn for row in kb.inline_keyboard for btn in row]
    actions = {b.callback_data.split(":")[0] for b in flat}
    for expected in ("shell", "recon", "creds", "files", "persist",
                     "pivot", "evasion", "collect", "exfil", "history", "kill"):
        assert expected in actions, f"Missing action: {expected}"


def test_agent_menu_callback_data_has_agent_id():
    s    = make_session(agent_id="abc123")
    _, kb = build_agent_menu(s)
    flat  = [btn for row in kb.inline_keyboard for btn in row]
    for btn in flat:
        if ":" in btn.callback_data:
            parts = btn.callback_data.split(":")
            if len(parts) >= 2 and parts[0] not in ("main", "sessions"):
                assert "abc123" in btn.callback_data


def test_all_submenus_have_back_button():
    aid = "agent-001"
    menus = [
        build_recon_menu(aid),
        build_creds_menu(aid),
        build_files_menu(aid),
        build_persist_menu(aid),
        build_pivot_menu(aid),
        build_evasion_menu(aid),
        build_collect_menu(aid),
        build_exfil_menu(aid),
    ]
    for text, kb in menus:
        flat = [btn for row in kb.inline_keyboard for btn in row]
        assert any("Back" in btn.text for btn in flat), f"No Back in menu: {text[:30]}"


def test_recon_menu_plugin_callbacks():
    _, kb = build_recon_menu("a1")
    flat  = [btn for row in kb.inline_keyboard for btn in row]
    plugin_btns = [b for b in flat if b.callback_data.startswith("plugin:")]
    assert len(plugin_btns) >= 6


def test_creds_menu_plugin_callbacks():
    _, kb = build_creds_menu("a1")
    flat  = [btn for row in kb.inline_keyboard for btn in row]
    plugin_btns = [b for b in flat if b.callback_data.startswith("plugin:")]
    assert len(plugin_btns) >= 4


def test_loot_menu_shows_counts():
    counts = {"credential": 5, "file": 3, "screenshot": 12, "generic": 1}
    text, kb = build_loot_menu(counts)
    assert "5" in text
    assert "12" in text
    flat = [btn for row in kb.inline_keyboard for btn in row]
    loot_btns = [b for b in flat if b.callback_data.startswith("loot:")]
    assert len(loot_btns) >= 3


def test_loot_menu_zero_counts():
    text, kb = build_loot_menu({})
    assert "0" in text


def test_status_menu():
    text, kb = build_status_menu(
        router_status="telegram ALIVE",
        c2_stats={"dispatched": 10, "acked": 9, "timed_out": 1},
        session_count=5,
        alive_count=4,
    )
    assert "10" in text
    assert "4/5" in text


def test_listeners_menu():
    text, kb = build_listeners_menu("telegram ALIVE\ndiscord DEAD")
    assert "telegram" in text
    flat = [btn for row in kb.inline_keyboard for btn in row]
    assert any("Discord" in b.text for b in flat)
    assert any("Recover" in b.text or "TG" in b.text for b in flat)


def test_kill_confirm_menu():
    text, kb = build_kill_confirm_menu("abc123", "VICTIM-PC")
    assert "VICTIM-PC" in text
    assert "abc123" in text
    flat = [btn for row in kb.inline_keyboard for btn in row]
    confirm_btns = [b for b in flat if "kill_confirm" in b.callback_data]
    cancel_btns  = [b for b in flat if b.callback_data == "agent:abc123"]
    assert len(confirm_btns) == 1
    assert len(cancel_btns)  == 1


def test_history_text_empty():
    s    = make_session()
    text = build_history_text(s, [])
    assert "No actions" in text


def test_history_text_with_entries():
    s = make_session(hostname="MYBOX")
    entries = [
        {"time": "14:32:01", "action": "recon/sysinfo",  "result": "ok"},
        {"time": "14:33:15", "action": "creds/dump_sam", "result": "ok"},
        {"time": "14:34:00", "action": "exec:whoami",    "result": "error"},
    ]
    text = build_history_text(s, entries)
    assert "MYBOX" in text
    assert "recon/sysinfo" in text
    assert "✅" in text
    assert "❌" in text


def test_shell_prompt():
    text, kb = build_shell_prompt("TARGET-PC")
    assert "TARGET-PC" in text
    assert "cancel" in text.lower() or "Cancel" in text


def test_builder_menu():
    text, kb = build_builder_menu()
    assert "builder" in text.lower() or "Builder" in text
    flat = [btn for row in kb.inline_keyboard for btn in row]
    assert any("Back" in b.text for b in flat)


# ── Utility tests ─────────────────────────────────────────────────────────────

def test_escape_html():
    assert _escape("<script>") == "&lt;script&gt;"
    assert _escape("a & b")   == "a &amp; b"
    assert _escape("normal")  == "normal"


def test_chunk_text_splits_correctly():
    text   = "A" * 5000
    chunks = _chunk_text(text, 4096)
    assert len(chunks) == 2
    assert len(chunks[0]) == 4096
    assert len(chunks[1]) == 904


def test_chunk_text_short_message():
    chunks = _chunk_text("hello", 4096)
    assert chunks == ["hello"]


def test_chunk_text_empty():
    chunks = _chunk_text("", 4096)
    assert len(chunks) == 1


# ── State machine tests ───────────────────────────────────────────────────────

class MockRouter:
    active_transport = "telegram"
    def status_table(self): return "telegram ALIVE"
    async def force_failover(self, name): return True
    async def force_recover(self): return True


class MockC2:
    def stats(self): return {"dispatched":0,"acked":0,"timed_out":0}
    def pending_tasks(self): return []
    async def dispatch(self, **kw): return {"status":"ok","output":"result"}


class MockLoot:
    def counts(self): return {}
    def search(self, **kw): return []
    def add(self, *a, **kw): return 1


def make_ui(tmp_path) -> TelegramUI:
    sm    = SessionManager()
    audit = AuditLog(tmp_path / "audit.jsonl")
    loot  = MockLoot()
    return TelegramUI(
        sessions=sm, c2=MockC2(), router=MockRouter(),
        audit=audit, loot=loot,
        operator_chat_id=12345, operator_tag="testop",
    )


def test_state_default_is_idle(tmp_path):
    ui    = make_ui(tmp_path)
    state = ui.get_state(sender_id=999)
    assert state.mode == InputMode.IDLE


@pytest.mark.asyncio
async def test_handle_text_start_command(tmp_path):
    ui   = make_ui(tmp_path)
    msgs = []

    class FakeBot:
        async def send_message(self, chat_id, text, parse_mode=None, reply_markup=None):
            msgs.append(text)

    consumed = await ui.handle_text("12345", 999, "/start", FakeBot())
    assert consumed is True
    assert len(msgs) == 1
    assert "Fitnah" in msgs[0]


@pytest.mark.asyncio
async def test_handle_text_idle_not_consumed(tmp_path):
    ui       = make_ui(tmp_path)
    consumed = await ui.handle_text("12345", 999, "whoami", object())
    assert consumed is False


@pytest.mark.asyncio
async def test_handle_text_cancel_clears_state(tmp_path):
    ui = make_ui(tmp_path)
    # manually set shell state
    ui._states[999] = OperatorState(mode=InputMode.SHELL_CMD, agent_id="a1")

    msgs = []
    class FakeBot:
        async def send_message(self, chat_id, text, **kw):
            msgs.append(text)

    consumed = await ui.handle_text("12345", 999, "/cancel", FakeBot())
    assert consumed is True
    assert ui.get_state(999).mode == InputMode.IDLE


@pytest.mark.asyncio
async def test_handle_text_shell_dispatches(tmp_path):
    ui = make_ui(tmp_path)
    sm = ui._sessions
    sm.register("a1", hostname="BOX1", group_id="", username="user", ip="1.1.1.1")
    ui._states[999] = OperatorState(mode=InputMode.SHELL_CMD, agent_id="a1")

    msgs = []
    class FakeBot:
        async def send_message(self, chat_id, text, **kw): msgs.append(text)

    consumed = await ui.handle_text("12345", 999, "whoami", FakeBot())
    assert consumed is True
    # state is cleared after execution
    assert ui.get_state(999).mode == InputMode.IDLE
    # result message was sent
    assert any("result" in m.lower() or "whoami" in m for m in msgs)
