"""BasePlugin — every plugin inherits this."""
from __future__ import annotations
import inspect
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from fitnah.sdk.result import ModuleResult
from fitnah.sdk.schema import ParamSchema

if TYPE_CHECKING:
    from fitnah.orchestration.session_manager import Session


class BasePlugin(ABC):
    # ── subclasses declare these ──────────────────────────────────────────
    NAME: str = ""
    DESCRIPTION: str = ""
    AUTHOR: str = ""
    VERSION: str = "1.0.0"
    MITRE: str = ""           # e.g. "T1059.001"
    CATEGORY: str = ""        # maps to plugins/<category>/

    schema: ParamSchema = ParamSchema()

    # ── lifecycle ─────────────────────────────────────────────────────────
    def on_load(self) -> None:
        """Called once when the plugin is imported."""

    def on_unload(self) -> None:
        """Called when the plugin is removed at runtime."""

    # ── required entry point ──────────────────────────────────────────────
    @abstractmethod
    def run(self, session: "Session", params: dict, ctx=None) -> ModuleResult:
        """
        Execute the plugin against the target session.
        ctx is a PluginContext — provides .send()/.exec()/.ps() to reach implant.
        ctx is None in offline/test mode.
        """

    # ── helpers ───────────────────────────────────────────────────────────
    def validate(self, raw: dict) -> dict:
        return self.schema.parse(raw)

    def commands(self) -> dict[str, callable]:
        """Return all methods decorated with @command."""
        out = {}
        for _, method in inspect.getmembers(self, predicate=inspect.ismethod):
            if hasattr(method, "_command"):
                out[method._command] = method
        return out

    def help_text(self) -> str:
        lines = [
            f"[{self.NAME}] v{self.VERSION} — {self.DESCRIPTION}",
            f"Author : {self.AUTHOR}",
            f"MITRE  : {self.MITRE or 'N/A'}",
            "",
        ]
        for p in self.schema.params:
            req = "required" if p.required else f"optional, default={p.default!r}"
            lines.append(f"  {p.name:<20} ({req}) — {p.help}")
        return "\n".join(lines)
