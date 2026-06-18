"""
Shared base for CVE-based privilege escalation exploit classes.
Eliminates copy-pasted __init__, _log, _get_installed_kb_patches,
and _check_environment methods across CVE plugins.
"""
from __future__ import annotations

import re
import subprocess
from typing import Any


class CveExploitBase:
    """Common infrastructure for all CVE exploit helper classes."""

    def __init__(self, logger=None):
        self.logger = logger
        self.exploit_success = False
        self.exploit_output = ""
        self.exploit_error = ""

    def _log(self, message: str, level: str = "info") -> None:
        if self.logger:
            getattr(self.logger, level, self.logger.info)(message)
        else:
            print("[%s] %s" % (level.upper(), message))

    def _get_installed_kb_patches(self) -> list[str]:
        """Return sorted list of installed KB patch IDs via wmic."""
        kb_patches: list[str] = []
        try:
            result = subprocess.run(
                ["wmic", "qfe", "get", "HotFixID", "/format:csv"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    m = re.search(r"KB(\d+)", line.upper())
                    if m:
                        kid = "KB%s" % m.group(1)
                        if kid not in kb_patches:
                            kb_patches.append(kid)
        except Exception as exc:
            self._log("Failed to get KB patches: %s" % exc, "warning")
        return sorted(kb_patches)

    def _check_environment(self) -> dict[str, Any]:
        """Return basic environment info used by vulnerability checks."""
        import platform, sys
        return {
            "platform": platform.platform(),
            "version":  platform.version(),
            "machine":  platform.machine(),
            "is_64bit": sys.maxsize > 2**32,
        }
