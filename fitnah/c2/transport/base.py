"""
AbstractTransport — contract every C2 channel must satisfy.
Telegram implements this as primary (priority=0).
Discord implements this as fallback (priority=1).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import AsyncIterator


class AbstractTransport(ABC):
    name: str = ""
    priority: int = 0       # lower = higher priority

    # ── lifecycle ─────────────────────────────────────────────────────────
    @abstractmethod
    async def connect(self) -> None:
        """Establish the channel."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Gracefully tear down the channel."""

    # ── send ──────────────────────────────────────────────────────────────
    @abstractmethod
    async def send(self, chat_id: str, text: str) -> None:
        """Send a plain text message to a chat/channel."""

    @abstractmethod
    async def send_file(self, chat_id: str, filename: str, data: bytes, caption: str = "") -> None:
        """Upload a file."""

    @abstractmethod
    async def send_photo(self, chat_id: str, data: bytes, caption: str = "") -> None:
        """Send an image."""

    # ── listen ────────────────────────────────────────────────────────────
    @abstractmethod
    def listen(self) -> AsyncIterator[dict]:
        """
        Yield incoming messages as dicts:
          {
            "chat_id"   : str,    ← where the message came from
            "sender_id" : str,    ← user/author ID
            "text"      : str,
            "raw"       : object, ← native SDK object
            "_transport": str,    ← filled by Router
          }
        """

    # ── status ────────────────────────────────────────────────────────────
    @property
    def is_alive(self) -> bool:
        return False

    def status(self) -> str:
        return "alive" if self.is_alive else "dead"
