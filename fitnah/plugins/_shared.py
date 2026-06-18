"""
Shared helpers reused across multiple plugins.
Import from here rather than copy-pasting.
"""
from __future__ import annotations

import platform
import sys
from typing import Any


def get_windows_version() -> dict[str, Any]:
    """Return structured Windows version info including friendly build name."""
    info: dict[str, Any] = {
        "platform":  platform.platform(),
        "system":    platform.system(),
        "release":   platform.release(),
        "version":   platform.version(),
        "machine":   platform.machine(),
        "processor": platform.processor(),
        "is_64bit":  sys.maxsize > 2**32,
    }
    if info["system"] == "Windows":
        try:
            build = int(info["version"].split(".")[-1])
            info["build"] = build
            _BUILD_MAP = {
                22621: "Windows 11 22H2",
                22000: "Windows 11 21H2",
                19045: "Windows 10 22H2",
                19044: "Windows 10 21H2",
                19043: "Windows 10 21H1",
                19042: "Windows 10 20H2",
                19041: "Windows 10 2004",
                18363: "Windows 10 1909",
                18362: "Windows 10 1903",
                17763: "Windows 10 1809",
                17134: "Windows 10 1803",
                16299: "Windows 10 1709",
                15063: "Windows 10 1703",
                14393: "Windows 10 1607",
            }
            info["friendly_name"] = _BUILD_MAP.get(build, "Windows %s" % info["release"])
        except (ValueError, IndexError):
            info["friendly_name"] = "Windows %s" % info["release"]
    return info
