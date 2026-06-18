"""
Phase 1 smoke tests — config, project, session manager, audit log.
Run with: pytest tests/test_phase1.py -v
"""
import json
import os
import tempfile
import time
from pathlib import Path

import pytest

# ── Config ────────────────────────────────────────────────────────────────────

def test_config_loads_defaults():
    from fitnah.config import Config, _DEFAULTS, _deep_merge
    cfg = Config(_deep_merge(_DEFAULTS, {}))
    assert cfg.task_timeout == 120
    assert cfg.checkin_ttl == 300
    assert cfg.failover_threshold == 3


def test_config_missing_token_raises():
    from fitnah.config import Config, ConfigError, _DEFAULTS, _deep_merge
    cfg = Config(_deep_merge(_DEFAULTS, {}))
    with pytest.raises(ConfigError):
        cfg.validate()


def test_config_override_values():
    from fitnah.config import Config, _DEFAULTS, _deep_merge
    override = {
        "telegram": {"token": "bot123:ABC", "operator_chat_id": 999},
        "operator": {"allowed_telegram_ids": [999], "tag": "testop", "auth_pin": "1234"},
    }
    cfg = Config(_deep_merge(_DEFAULTS, override))
    assert cfg.telegram_token == "bot123:ABC"
    assert cfg.operator_tag == "testop"
    cfg.validate()  # should not raise


def test_config_get_nested():
    from fitnah.config import Config, _DEFAULTS, _deep_merge
    cfg = Config(_deep_merge(_DEFAULTS, {"c2": {"task_timeout": 60}}))
    assert cfg.get("c2", "task_timeout") == 60
    assert cfg.get("nonexistent", "key", default="fallback") == "fallback"


# ── Project ───────────────────────────────────────────────────────────────────

def test_project_creates_directories(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from fitnah.orchestration.project import Project
    p = Project(name="test_op", operator="shadow")
    assert (tmp_path / "data" / "projects" / "test_op" / "meta.json").exists()
    assert (tmp_path / "data" / "projects" / "test_op" / "loot").exists()


def test_project_saves_and_loads(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from fitnah.orchestration.project import Project
    p = Project(name="op_alpha", operator="shadow", notes="test engagement")
    loaded = Project.load("op_alpha")
    assert loaded.name == "op_alpha"
    assert loaded.operator == "shadow"
    assert loaded.notes == "test engagement"


def test_project_list_all(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from fitnah.orchestration.project import Project
    Project(name="op1", operator="a")
    Project(name="op2", operator="b")
    projects = Project.list_all()
    names = [p["name"] for p in projects]
    assert "op1" in names
    assert "op2" in names


def test_project_name_sanitized(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from fitnah.orchestration.project import Project
    p = Project(name="my operation", operator="shadow")
    assert p.name == "my_operation"


def test_project_empty_name_raises(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from fitnah.orchestration.project import Project, ProjectError
    with pytest.raises(ProjectError):
        Project(name="  ", operator="shadow")


# ── SessionManager ────────────────────────────────────────────────────────────

def test_session_register_new():
    from fitnah.orchestration.session_manager import SessionManager
    sm = SessionManager()
    s, is_new = sm.register("agent-001", hostname="BOX1", os="Win11", priv_level="admin")
    assert is_new is True
    assert s.hostname == "BOX1"
    assert s.priv_level == "admin"


def test_session_register_existing_not_new():
    from fitnah.orchestration.session_manager import SessionManager
    sm = SessionManager()
    sm.register("agent-001", hostname="BOX1")
    _, is_new = sm.register("agent-001", hostname="BOX1")
    assert is_new is False


def test_session_count():
    from fitnah.orchestration.session_manager import SessionManager
    sm = SessionManager()
    sm.register("a1")
    sm.register("a2")
    sm.register("a3")
    assert sm.count() == 3


def test_session_stale_detection():
    from fitnah.orchestration.session_manager import SessionManager
    sm = SessionManager(checkin_ttl=1)
    sm.register("a1")
    time.sleep(1.1)
    assert sm.stale()
    assert not sm.alive()


def test_session_touch_history():
    from fitnah.orchestration.session_manager import SessionManager
    sm = SessionManager()
    s, _ = sm.register("a1")
    s.touch("recon/sysinfo", "ok")
    s.touch("creds/dump_sam", "ok")
    hist = s.history()
    assert len(hist) == 2
    assert hist[0]["action"] == "recon/sysinfo"


def test_session_remove():
    from fitnah.orchestration.session_manager import SessionManager
    sm = SessionManager()
    sm.register("a1")
    sm.remove("a1")
    assert sm.get("a1") is None


def test_session_table_output():
    from fitnah.orchestration.session_manager import SessionManager
    sm = SessionManager()
    sm.register("a1", hostname="TESTBOX")
    table = sm.table()
    assert "TESTBOX" in table
    assert "a1" in table


# ── AuditLog ──────────────────────────────────────────────────────────────────

def test_audit_record_and_tail(tmp_path):
    from fitnah.orchestration.audit_log import AuditLog
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("shadow", "plugin:sysinfo", "agent-001", result="ok")
    log.record("shadow", "plugin:dump_sam", "agent-001", result="ok")
    entries = log.tail(10)
    assert len(entries) == 2
    assert entries[0]["action"] == "plugin:sysinfo"


def test_audit_search_by_target(tmp_path):
    from fitnah.orchestration.audit_log import AuditLog
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("shadow", "plugin:sysinfo", "agent-001", result="ok")
    log.record("shadow", "plugin:sysinfo", "agent-002", result="ok")
    results = log.search(agent_id="agent-001")
    assert all(r["target"] == "agent-001" for r in results)


def test_audit_empty_log(tmp_path):
    from fitnah.orchestration.audit_log import AuditLog
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.tail() == []
    assert log.search() == []


def test_audit_checkin_helper(tmp_path):
    from fitnah.orchestration.audit_log import AuditLog
    log = AuditLog(tmp_path / "audit.jsonl")
    log.checkin("agent-001", {"hostname": "BOX1", "os": "Win11"})
    entries = log.tail()
    assert entries[0]["action"] == "checkin"
    assert entries[0]["target"] == "agent-001"
