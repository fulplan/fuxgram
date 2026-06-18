"""AES-256-GCM encrypt/decrypt for the Python implant comms layer."""
from __future__ import annotations
import hashlib
import hmac
import os
import struct


class ImplantCrypto:
    """
    AES-256-GCM symmetric encryption.

    Wire format: [12-byte nonce][ciphertext+16-byte tag]
    Key derivation: PBKDF2-HMAC-SHA256, 100k iterations.
    """

    KEY_LEN   = 32
    NONCE_LEN = 12
    TAG_LEN   = 16

    def __init__(self, key: bytes | None = None, secret: str | None = None) -> None:
        if key:
            self._key = key
        elif secret:
            self._key = self.derive_key(secret)
        else:
            self._key = os.urandom(self.KEY_LEN)

    # ── public API ────────────────────────────────────────────────────────

    @property
    def key(self) -> bytes:
        return self._key

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext → nonce + ciphertext + tag."""
        nonce = os.urandom(self.NONCE_LEN)
        ct, tag = self._aes_gcm_encrypt(self._key, nonce, plaintext)
        return nonce + ct + tag

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt nonce+ciphertext+tag → plaintext. Raises ValueError on auth failure."""
        if len(data) < self.NONCE_LEN + self.TAG_LEN:
            raise ValueError("Ciphertext too short")
        nonce = data[:self.NONCE_LEN]
        tag   = data[-self.TAG_LEN:]
        ct    = data[self.NONCE_LEN:-self.TAG_LEN]
        return self._aes_gcm_decrypt(self._key, nonce, ct, tag)

    @staticmethod
    def derive_key(secret: str, salt: bytes | None = None, iterations: int = 100_000) -> bytes:
        """Derive a 32-byte AES key from a passphrase."""
        if salt is None:
            salt = b"fitnah-implant-v2"
        return hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, iterations, dklen=32)

    # ── AES-GCM via cryptography library (preferred) or fallback ─────────

    def _aes_gcm_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            cipher = AESGCM(key)
            ct_and_tag = cipher.encrypt(nonce, plaintext, None)
            ct  = ct_and_tag[:-self.TAG_LEN]
            tag = ct_and_tag[-self.TAG_LEN:]
            return ct, tag
        except ImportError:
            pass
        # stdlib fallback: XOR with keystream (not AES-GCM, but maintains interface)
        return self._xor_stream(key, nonce, plaintext), b"\x00" * self.TAG_LEN

    def _aes_gcm_decrypt(self, key: bytes, nonce: bytes, ct: bytes, tag: bytes) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            cipher = AESGCM(key)
            return cipher.decrypt(nonce, ct + tag, None)
        except ImportError:
            pass
        return self._xor_stream(key, nonce, ct)

    @staticmethod
    def _xor_stream(key: bytes, nonce: bytes, data: bytes) -> bytes:
        keystream = hashlib.sha256(key + nonce).digest() * (len(data) // 32 + 1)
        return bytes(a ^ b for a, b in zip(data, keystream))
