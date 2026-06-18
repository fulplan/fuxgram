"""
Operation workspace — every engagement lives inside a named project.
Inspired by FuzzBunch's project-first workflow.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


class ProjectError(Exception):
    pass


@dataclass
class Project:
    name: str
    operator: str
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    # runtime-only (not persisted)
    _base: Path = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        # sanitize name — no spaces or path separators
        self.name = self.name.strip().replace(" ", "_")
        if not self.name:
            raise ProjectError("Project name cannot be empty.")

        self._base = Path("data") / "projects" / self.name
        self._base.mkdir(parents=True, exist_ok=True)
        (self._base / "loot").mkdir(exist_ok=True)
        self._save()

    # ── persistence ───────────────────────────────────────────────────────
    def _save(self) -> None:
        meta = {
            "name": self.name,
            "operator": self.operator,
            "notes": self.notes,
            "tags": self.tags,
            "created_at": self.created_at,
        }
        (self._base / "meta.json").write_text(
            json.dumps(meta, indent=2), encoding="utf-8"
        )

    def update_notes(self, notes: str) -> None:
        self.notes = notes
        self._save()

    def add_tag(self, tag: str) -> None:
        if tag not in self.tags:
            self.tags.append(tag)
            self._save()

    # ── path helpers ──────────────────────────────────────────────────────
    @property
    def path(self) -> Path:
        return self._base

    def loot_dir(self) -> Path:
        return self._base / "loot"

    def audit_log_path(self) -> Path:
        return self._base / "audit.jsonl"

    def builds_dir(self) -> Path:
        d = self._base / "builds"
        d.mkdir(exist_ok=True)
        return d

    def get_build_dir(self) -> Path:
        """Returns path to the 'builds' directory, creating it if needed."""
        return self.builds_dir()

    def get_sessions_db(self) -> Path:
        """Returns path to the sessions database."""
        return self._base / "sessions.db"

    # ── class methods ─────────────────────────────────────────────────────
    @classmethod
    def load(cls, name: str, base_path: str = "data/projects") -> "Project":
        path = Path(base_path) / name / "meta.json"
        if not path.exists():
            raise ProjectError(f"Project '{name}' not found.")
        meta = json.loads(path.read_text(encoding="utf-8"))
        return cls(**meta)

    @classmethod
    def list_all(cls, base_path: str = "data/projects") -> list[dict]:
        base = Path(base_path)
        if not base.exists():
            return []
        projects = []
        for p in sorted(base.iterdir()):
            if not p.is_dir():
                continue
            meta_file = p / "meta.json"
            if not meta_file.exists():
                continue
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            projects.append(meta)
        return projects

    @classmethod
    def exists(cls, name: str, base_path: str = "data/projects") -> bool:
        return (Path(base_path) / name / "meta.json").exists()

    @classmethod
    def delete(cls, name: str, base_path: str = "data/projects") -> None:
        """Remove the project directory entirely."""
        path = Path(base_path) / name
        if path.exists():
            import shutil
            shutil.rmtree(path)

    def rename(self, new_name: str) -> None:
        """Rename the project folder and update meta.json."""
        new_name = new_name.strip().replace(" ", "_")
        if not new_name:
            raise ProjectError("New project name cannot be empty.")

        new_base = self._base.parent / new_name
        if new_base.exists():
            raise ProjectError(f"Project '{new_name}' already exists.")

        self._base.rename(new_base)
        self._base = new_base
        self.name = new_name
        self._save()

    # ── display ───────────────────────────────────────────────────────────
    def summary(self) -> str:
        created = time.strftime(
            "%Y-%m-%d %H:%M", time.localtime(self.created_at)
        )
        tags = ", ".join(self.tags) if self.tags else "none"
        return (
            f"  Name     : {self.name}\n"
            f"  Operator : {self.operator}\n"
            f"  Created  : {created}\n"
            f"  Tags     : {tags}\n"
            f"  Notes    : {self.notes or '—'}\n"
            f"  Path     : {self._base}"
        )

    def __str__(self) -> str:
        return f"[{self.name}] operator={self.operator}"
