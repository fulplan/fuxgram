"""Phase 6 — LootStore search and export tests."""
import csv
import io
import json
import time
import tempfile
from pathlib import Path

import pytest

from fitnah.loot.store import LootStore


@pytest.fixture()
def store(tmp_path):
    s = LootStore(tmp_path / "loot.db")
    yield s
    s.close()


def _seed(store: LootStore) -> list[int]:
    ids = []
    ids.append(store.add("agent-001", "credential", "admin:password1", b"password1", ["corp"]))
    ids.append(store.add("agent-001", "sam_hive",   "SYSTEM hive",     b"binarydata"))
    ids.append(store.add("agent-002", "file",        "secrets.txt",     b"topsecret"))
    ids.append(store.add("agent-002", "screenshot",  "desktop",         b"\x89PNG"))
    ids.append(store.add("agent-001", "wifi_creds",  "HomeWifi:pass99", b"pass99"))
    return ids


# ── full_search ───────────────────────────────────────────────────────────────

def test_full_search_no_filter(store):
    _seed(store)
    rows = store.full_search()
    assert len(rows) == 5


def test_full_search_by_agent(store):
    _seed(store)
    rows = store.full_search(agent_id="agent-001")
    assert all(r["agent_id"] == "agent-001" for r in rows)
    assert len(rows) == 3


def test_full_search_by_kind(store):
    _seed(store)
    rows = store.full_search(kind="file")
    assert len(rows) == 1
    assert rows[0]["label"] == "secrets.txt"


def test_full_search_by_keyword(store):
    _seed(store)
    rows = store.full_search(query="admin")
    assert len(rows) == 1
    assert "admin" in rows[0]["label"]


def test_full_search_combined(store):
    _seed(store)
    rows = store.full_search(query="hive", agent_id="agent-001")
    assert len(rows) == 1


# ── delete ────────────────────────────────────────────────────────────────────

def test_delete_existing(store):
    ids = _seed(store)
    assert store.delete(ids[0])
    assert store.full_search(query="admin") == []


def test_delete_missing(store):
    assert not store.delete(9999)


# ── export_text ───────────────────────────────────────────────────────────────

def test_export_text_empty(store):
    out = store.export_text([])
    assert "(no results)" in out


def test_export_text_rows(store):
    _seed(store)
    rows = store.full_search()
    out  = store.export_text(rows)
    assert "agent-001" in out
    assert "agent-002" in out
    assert "credential" in out


# ── export_csv ────────────────────────────────────────────────────────────────

def test_export_csv(store):
    _seed(store)
    rows = store.full_search()
    csv_str = store.export_csv(rows)
    reader  = csv.DictReader(io.StringIO(csv_str))
    parsed  = list(reader)
    assert len(parsed) == 5
    agents = {r["agent_id"] for r in parsed}
    assert agents == {"agent-001", "agent-002"}


# ── export_bloodhound ─────────────────────────────────────────────────────────

def test_export_bloodhound_filters_kinds(store):
    _seed(store)
    rows = store.full_search()
    bh   = json.loads(store.export_bloodhound(rows))
    # only credential, sam_hive, vault_creds, wifi_creds — not file/screenshot
    assert bh["meta"]["count"] == 3
    kinds = {d["source"] for d in bh["data"]}
    assert "file" not in kinds
    assert "screenshot" not in kinds


def test_export_bloodhound_structure(store):
    _seed(store)
    rows = store.full_search()
    bh   = json.loads(store.export_bloodhound(rows))
    for entry in bh["data"]:
        assert "username" in entry
        assert "password" in entry
        assert "source"   in entry
        assert "agent_id" in entry


# ── save_export ───────────────────────────────────────────────────────────────

def test_save_export(store, tmp_path):
    _seed(store)
    rows = store.full_search()
    out  = tmp_path / "sub" / "results.csv"
    store.save_export(store.export_csv(rows), out)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "agent_id" in content
