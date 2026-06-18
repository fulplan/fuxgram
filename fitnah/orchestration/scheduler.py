"""
Recurring plugin scheduler — fire plugins against agents on a fixed interval.

Persists schedules to data/schedules.json so they survive restarts.
Uses asyncio — no external dependencies.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Awaitable

log = logging.getLogger(__name__)

_DEFAULT_DB = Path("data/schedules.json")


@dataclass
class PluginSchedule:
    schedule_id:      str
    agent_id:         str
    plugin_name:      str
    params:           dict
    interval_seconds: int
    enabled:          bool  = True
    run_count:        int   = 0
    last_result:      str   = ""
    next_run:         float = field(default_factory=time.time)
    created_at:       float = field(default_factory=time.time)

    def due(self) -> bool:
        return self.enabled and time.time() >= self.next_run

    def advance(self) -> None:
        self.next_run = time.time() + self.interval_seconds
        self.run_count += 1


class Scheduler:
    """
    Asyncio-based plugin scheduler.

    Usage:
        sched = Scheduler()
        sid = sched.add("agent01", "sysinfo", {}, interval_seconds=300)
        await sched.start(kernel.execute_plugin)
        ...
        sched.remove(sid)
        await sched.stop()
    """

    def __init__(self, db_path: str | Path = _DEFAULT_DB):
        self._db_path  = Path(db_path)
        self._schedules: dict[str, PluginSchedule] = {}
        self._task: asyncio.Task | None = None
        self._execute_fn: Callable | None = None
        self._load()

    # ── public API ────────────────────────────────────────────────────────

    def add(
        self,
        agent_id: str,
        plugin_name: str,
        params: dict,
        interval_seconds: int,
    ) -> str:
        sid = uuid.uuid4().hex[:12]
        schedule = PluginSchedule(
            schedule_id      = sid,
            agent_id         = agent_id,
            plugin_name      = plugin_name,
            params           = params,
            interval_seconds = max(interval_seconds, 30),  # floor 30s
            next_run         = time.time() + interval_seconds,
        )
        self._schedules[sid] = schedule
        self._save()
        log.info(
            "[scheduler] added: %s  agent=%s  plugin=%s  every=%ds",
            sid, agent_id, plugin_name, interval_seconds,
        )
        return sid

    def remove(self, schedule_id: str) -> bool:
        if schedule_id not in self._schedules:
            return False
        del self._schedules[schedule_id]
        self._save()
        log.info("[scheduler] removed: %s", schedule_id)
        return True

    def enable(self, schedule_id: str) -> bool:
        s = self._schedules.get(schedule_id)
        if not s:
            return False
        s.enabled = True
        self._save()
        return True

    def disable(self, schedule_id: str) -> bool:
        s = self._schedules.get(schedule_id)
        if not s:
            return False
        s.enabled = False
        self._save()
        return True

    def list_schedules(self) -> list[dict]:
        return sorted(
            [asdict(s) for s in self._schedules.values()],
            key=lambda x: x["next_run"],
        )

    def get(self, schedule_id: str) -> PluginSchedule | None:
        return self._schedules.get(schedule_id)

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(
        self,
        execute_fn: Callable[[str, str, dict], Awaitable[str]],
    ) -> None:
        """
        Start the scheduler loop.

        execute_fn signature: async (agent_id, plugin_name, params) -> result_str
        """
        self._execute_fn = execute_fn
        self._task = asyncio.create_task(self._loop(), name="scheduler")
        log.info("[scheduler] started with %d schedules", len(self._schedules))

    async def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("[scheduler] stopped")

    # ── internal loop ─────────────────────────────────────────────────────

    async def _loop(self) -> None:
        while True:
            now = time.time()
            due = [s for s in self._schedules.values() if s.due()]
            for schedule in due:
                asyncio.create_task(
                    self._fire(schedule),
                    name=f"schedule-{schedule.schedule_id}",
                )
            await asyncio.sleep(10)

    async def _fire(self, schedule: PluginSchedule) -> None:
        schedule.advance()  # advance next_run immediately to prevent double-fire
        self._save()

        if self._execute_fn is None:
            return

        log.info(
            "[scheduler] firing: %s  agent=%s  plugin=%s  run#%d",
            schedule.schedule_id, schedule.agent_id,
            schedule.plugin_name, schedule.run_count,
        )
        try:
            result = await self._execute_fn(
                schedule.agent_id,
                schedule.plugin_name,
                schedule.params,
            )
            schedule.last_result = str(result)[:200]
        except Exception as exc:
            schedule.last_result = f"[error] {exc}"
            log.warning(
                "[scheduler] %s failed: %s", schedule.schedule_id, exc
            )
        self._save()

    # ── persistence ───────────────────────────────────────────────────────

    def _save(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = [asdict(s) for s in self._schedules.values()]
            self._db_path.write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
        except Exception as exc:
            log.warning("[scheduler] save failed: %s", exc)

    def _load(self) -> None:
        if not self._db_path.exists():
            return
        try:
            data = json.loads(self._db_path.read_text(encoding="utf-8"))
            for item in data:
                s = PluginSchedule(**item)
                self._schedules[s.schedule_id] = s
            log.info("[scheduler] loaded %d schedules from %s", len(self._schedules), self._db_path)
        except Exception as exc:
            log.warning("[scheduler] load failed: %s", exc)

    # ── display ───────────────────────────────────────────────────────────

    def summary_table(self) -> str:
        schedules = self.list_schedules()
        if not schedules:
            return "  (no schedules)"
        lines = [
            f"  {'ID':<14}  {'AGENT':<12}  {'PLUGIN':<20}  {'EVERY':>6}  {'RUNS':>4}  {'NEXT':>8}  EN",
            "  " + "─" * 78,
        ]
        now = time.time()
        for s in schedules:
            secs_until = max(0, int(s["next_run"] - now))
            enabled    = "Y" if s["enabled"] else "N"
            lines.append(
                f"  {s['schedule_id']:<14}  {s['agent_id']:<12}  "
                f"{s['plugin_name']:<20}  {s['interval_seconds']:>5}s  "
                f"{s['run_count']:>4}  {secs_until:>6}s  {enabled}"
            )
        return "\n".join(lines)
