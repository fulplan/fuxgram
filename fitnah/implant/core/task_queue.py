"""Thread-safe pending-task queue for the Python implant."""
from __future__ import annotations
import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Task:
    task_id:  str
    command:  str
    args:     dict = field(default_factory=dict)
    queued_at: float = field(default_factory=time.time)
    status:   str = "pending"    # pending | running | done | error
    output:   str = ""


class TaskQueue:
    """Thread-safe FIFO queue of C2 tasks."""

    def __init__(self) -> None:
        self._lock  = threading.Lock()
        self._tasks: dict[str, Task] = {}

    def add(self, task_id: str, command: str, args: dict | None = None) -> None:
        with self._lock:
            self._tasks[task_id] = Task(task_id=task_id, command=command, args=args or {})

    def next_pending(self) -> Task | None:
        with self._lock:
            for t in self._tasks.values():
                if t.status == "pending":
                    t.status = "running"
                    return t
        return None

    def ack(self, task_id: str, status: str, output: str) -> None:
        with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].status = status
                self._tasks[task_id].output = output

    def pending(self) -> list[Task]:
        with self._lock:
            return [t for t in self._tasks.values() if t.status == "pending"]

    def all(self) -> list[Task]:
        with self._lock:
            return list(self._tasks.values())

    def get(self, task_id: str) -> Task | None:
        with self._lock:
            return self._tasks.get(task_id)

    def prune(self, max_age_sec: int = 3600) -> int:
        """Remove completed tasks older than max_age_sec. Returns count removed."""
        now    = time.time()
        remove = []
        with self._lock:
            for tid, t in self._tasks.items():
                if t.status in ("done", "error") and (now - t.queued_at) > max_age_sec:
                    remove.append(tid)
            for tid in remove:
                del self._tasks[tid]
        return len(remove)
