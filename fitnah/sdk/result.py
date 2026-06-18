from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    OK = "ok"
    ERROR = "error"
    PARTIAL = "partial"
    TIMEOUT = "timeout"


@dataclass
class ModuleResult:
    status: Status
    data: Any = None
    error: str | None = None
    metadata: dict = field(default_factory=dict)

    # ── convenience constructors ──────────────────────────────────────────
    @classmethod
    def ok(cls, data: Any = None, **meta) -> "ModuleResult":
        return cls(status=Status.OK, data=data, metadata=meta)

    @classmethod
    def err(cls, msg: str, **meta) -> "ModuleResult":
        return cls(status=Status.ERROR, error=msg, metadata=meta)

    @classmethod
    def partial(cls, data: Any, error: str, **meta) -> "ModuleResult":
        return cls(status=Status.PARTIAL, data=data, error=error, metadata=meta)

    def __bool__(self) -> bool:
        return self.status in (Status.OK, Status.PARTIAL)
