"""
Append-only audit log — every operator action is permanently recorded.
Each entry is a JSON line signed with HMAC-SHA256. The file is never modified,
only appended to. Use verify() to detect tampering.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Optional

# HMAC key: loaded from FITNAH_AUDIT_KEY env var or auto-generated per process.
# Persist the key alongside the log (audit.key) so verify() works across restarts.
_KEY_ENV = "FITNAH_AUDIT_KEY"


class AuditLog:
    def __init__(self, path: str | Path = "data/audit.jsonl"):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._key = self._load_or_create_key()

    # ── key management ────────────────────────────────────────────────────
    def _load_or_create_key(self) -> bytes:
        env_key = os.environ.get(_KEY_ENV, "")
        if env_key:
            return env_key.encode()
        key_path = self._path.with_suffix(".key")
        if key_path.exists():
            return key_path.read_bytes()
        key = os.urandom(32)
        key_path.write_bytes(key)
        key_path.chmod(0o600)
        return key

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    # ── write ─────────────────────────────────────────────────────────────
    def record(
        self,
        operator: str,
        action: str,
        target: str = "",
        detail: dict | None = None,
        result: str = "",
    ) -> None:
        entry = {
            "ts":       time.time(),
            "time":     time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            "operator": operator,
            "action":   action,
            "target":   target,
            "result":   result,
            "detail":   detail or {},
        }
        payload = json.dumps(entry, sort_keys=True).encode()
        entry["hmac"] = self._sign(payload)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def checkin(self, agent_id: str, info: dict) -> None:
        self.record(
            operator="implant",
            action="checkin",
            target=agent_id,
            detail=info,
            result="ok",
        )

    def plugin_run(
        self,
        operator: str,
        plugin: str,
        agent_id: str,
        params: dict,
        result: str,
    ) -> None:
        self.record(
            operator=operator,
            action=f"plugin:{plugin}",
            target=agent_id,
            detail=params,
            result=result,
        )

    def session_event(self, event: str, agent_id: str, detail: dict | None = None) -> None:
        self.record(
            operator="system",
            action=f"session:{event}",
            target=agent_id,
            detail=detail,
        )

    def transport_event(self, event: str, transport: str) -> None:
        self.record(
            operator="system",
            action=f"transport:{event}",
            target=transport,
        )

    # ── read ──────────────────────────────────────────────────────────────
    def tail(self, n: int = 20) -> list[dict]:
        if not self._path.exists():
            return []
        lines = self._path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines[-n:] if line.strip()]

    def search(
        self,
        agent_id: str | None = None,
        action: str | None = None,
        operator: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        if not self._path.exists():
            return []

        results = []
        lines = self._path.read_text(encoding="utf-8").splitlines()

        for line in reversed(lines):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            if agent_id and entry.get("target") != agent_id:
                continue
            if action and action not in entry.get("action", ""):
                continue
            if operator and entry.get("operator") != operator:
                continue

            results.append(entry)
            if len(results) >= limit:
                break

        return results

    def verify(self) -> tuple[int, int]:
        """Verify HMAC on all entries. Returns (ok_count, tampered_count)."""
        if not self._path.exists():
            return 0, 0
        ok = tampered = 0
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                stored_mac = entry.pop("hmac", None)
                if stored_mac is None:
                    ok += 1  # legacy entries without HMAC
                    continue
                payload = json.dumps(entry, sort_keys=True).encode()
                expected = self._sign(payload)
                if hmac.compare_digest(stored_mac, expected):
                    ok += 1
                else:
                    tampered += 1
            except Exception:
                tampered += 1
        return ok, tampered

    def format_entry(self, entry: dict) -> str:
        return (
            f"  {entry['time']}  "
            f"{entry['action']:<35}  "
            f"{entry['target']:<20}  "
            f"{entry.get('result', '')}"
        )

    def display(self, entries: list[dict]) -> str:
        if not entries:
            return "  No audit entries found."
        header = (
            f"  {'TIME':<19}  {'ACTION':<35}  {'TARGET':<20}  RESULT\n"
            f"  {'─'*19}  {'─'*35}  {'─'*20}  {'─'*10}"
        )
        rows = "\n".join(self.format_entry(e) for e in entries)
        return f"{header}\n{rows}"
