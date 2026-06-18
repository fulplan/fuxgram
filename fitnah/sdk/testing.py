"""MockAgent and helpers for offline plugin unit tests."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MockSession:
    """Simulates a live Session for offline testing."""
    agent_id:   str = "mock-agent-001"
    hostname:   str = "TESTBOX"
    os:         str = "Windows 10"
    priv_level: str = "user"
    arch:       str = "x64"
    username:   str = "TESTBOX\\user"
    ip:         str = "127.0.0.1"
    group_id:   str = ""
    _responses: dict[str, Any] = field(default_factory=dict)

    def queue_response(self, command: str, response: Any) -> None:
        """Pre-load a fake agent response for a command."""
        self._responses[command] = response

    def send(self, command: str, args: dict | None = None) -> Any:
        """Return the pre-loaded response or a generic stub."""
        return self._responses.get(command, {"stdout": "", "returncode": 0})
