"""SQLite loot store — cross-session credential, file, and data storage."""
from __future__ import annotations
import csv
import io
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path


DDL = """
CREATE TABLE IF NOT EXISTS loot (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL    NOT NULL,
    agent_id  TEXT    NOT NULL,
    kind      TEXT    NOT NULL,  -- credential / file / screenshot / generic
    label     TEXT    NOT NULL,
    data      BLOB    NOT NULL,
    tags      TEXT    DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_agent ON loot(agent_id);
CREATE INDEX IF NOT EXISTS idx_kind  ON loot(kind);
"""


class LootStore:
    def __init__(self, db_path: str | Path = "data/loot.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.executescript(DDL)
        self._conn.commit()

    def add(self, agent_id: str, kind: str, label: str, data: bytes | str, tags: list[str] | None = None) -> int:
        if isinstance(data, str):
            data = data.encode()
        row = (time.time(), agent_id, kind, label, data, ",".join(tags or []))
        cur = self._conn.execute(
            "INSERT INTO loot(ts, agent_id, kind, label, data, tags) VALUES (?,?,?,?,?,?)", row
        )
        self._conn.commit()
        return cur.lastrowid

    def search(self, agent_id: str | None = None, kind: str | None = None, limit: int = 50) -> list[dict]:
        q = "SELECT id, ts, agent_id, kind, label, tags FROM loot WHERE 1=1"
        params = []
        if agent_id:
            q += " AND agent_id=?"
            params.append(agent_id)
        if kind:
            q += " AND kind=?"
            params.append(kind)
        q += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(q, params).fetchall()
        keys = ("id", "ts", "agent_id", "kind", "label", "tags")
        return [dict(zip(keys, r)) for r in rows]

    def counts(self) -> dict[str, int]:
        """Return count per kind for the loot menu display."""
        rows = self._conn.execute(
            "SELECT kind, COUNT(*) FROM loot GROUP BY kind"
        ).fetchall()
        return {row[0]: row[1] for row in rows}

    def get_data(self, loot_id: int) -> bytes | None:
        row = self._conn.execute("SELECT data FROM loot WHERE id=?", (loot_id,)).fetchone()
        return row[0] if row else None

    def delete(self, loot_id: int) -> bool:
        cur = self._conn.execute("DELETE FROM loot WHERE id=?", (loot_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def full_search(
        self,
        query: str = "",
        agent_id: str | None = None,
        kind: str | None = None,
        limit: int = 200,
    ) -> list[dict]:
        """Search label and tags by keyword, optionally filtered by agent/kind."""
        q = "SELECT id, ts, agent_id, kind, label, tags FROM loot WHERE 1=1"
        params: list = []
        if agent_id:
            q += " AND agent_id=?"
            params.append(agent_id)
        if kind:
            q += " AND kind=?"
            params.append(kind)
        if query:
            q += " AND (label LIKE ? OR tags LIKE ?)"
            params += [f"%{query}%", f"%{query}%"]
        q += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(q, params).fetchall()
        keys = ("id", "ts", "agent_id", "kind", "label", "tags")
        return [dict(zip(keys, r)) for r in rows]

    # ── Export helpers ──────────────────────────────────────────────────────

    def export_text(self, rows: list[dict]) -> str:
        """Render loot rows as a plain-text table."""
        if not rows:
            return "(no results)"
        lines = [f"{'ID':>5}  {'TIME':<19}  {'AGENT':<16}  {'KIND':<18}  LABEL"]
        lines.append("-" * 80)
        for r in rows:
            ts = datetime.fromtimestamp(r["ts"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"{r['id']:>5}  {ts}  {r['agent_id']:<16}  {r['kind']:<18}  {r['label']}")
        return "\n".join(lines)

    def export_csv(self, rows: list[dict]) -> str:
        """Render loot rows as CSV string."""
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=("id", "ts", "agent_id", "kind", "label", "tags"))
        writer.writeheader()
        for r in rows:
            writer.writerow({**r, "ts": datetime.fromtimestamp(r["ts"], tz=timezone.utc).isoformat()})
        return buf.getvalue()

    def export_bloodhound(self, rows: list[dict]) -> str:
        """
        Export credential loot as a BloodHound-compatible JSON array.
        BloodHound ingests plaintext credential files in the format:
        [{"username": "...", "password": "...", "domain": "...", "source": "..."}]
        Only rows of kind 'credential' or 'sam_hive' are included.
        """
        creds = []
        for r in rows:
            if r["kind"] not in ("credential", "sam_hive", "vault_creds", "wifi_creds"):
                continue
            data = self.get_data(r["id"])
            text = data.decode(errors="replace") if data else ""
            creds.append({
                "username": r["label"],
                "password": text[:512],
                "domain":   "",
                "source":   r["kind"],
                "agent_id": r["agent_id"],
                "ts":       datetime.fromtimestamp(r["ts"], tz=timezone.utc).isoformat(),
            })
        return json.dumps({"meta": {"type": "credentials", "count": len(creds)}, "data": creds}, indent=2)

    def save_export(self, content: str, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def close(self) -> None:
        self._conn.close()
