"""
Fitnah v2 — Configuration loader and validator.
Single source of truth for all framework settings.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

# ── Default config (safe fallbacks) ──────────────────────────────────────────
_DEFAULTS: dict = {
    "operator": {
        "tag": "operator",
        "auth_pin": "",
        "allowed_telegram_ids": [],
    },
    "telegram": {
        "token": "",
        "operator_chat_id": 0,
    },
    "discord": {
        "token": "",
        "operator_channel_id": 0,
        "enabled": True,
    },
    "c2": {
        "task_timeout": 120,
        "checkin_ttl": 300,
        "failover_threshold": 3,
        "max_message_chunk": 4096,
        "http_host": "0.0.0.0",
        "http_port": 8888,
        "http_enabled": True,
        "tls_cert": "",
        "tls_key": "",
        "profile": "",
        "sessions_db": "data/sessions.db",
    },
    "loot": {
        "db_path": "data/loot.db",
        "max_size_mb": 2048,
    },
    "audit": {
        "log_path": "data/audit.jsonl",
    },
    "projects": {
        "base_path": "data/projects",
    },
    "builder": {
        "output_dir": "build",
        "default_sleep": 5,
        "default_jitter": 20,
        "default_format": "exe",
        "default_arch": "x64",
        "default_encrypt": "aes-256-gcm",
    },
    "logging": {
        "level": "INFO",
        "log_file": "data/fitnah.log",
        "rotate_daily": True,
    },
}

_CONFIG_PATHS = [
    "config/framework.yaml",
    "framework.yaml",
]


class ConfigError(Exception):
    pass


class Config:
    """Loaded, validated, merged configuration."""

    def __init__(self, data: dict):
        self._data = data

    # ── dot-path access ───────────────────────────────────────────────────
    def get(self, *keys: str, default: Any = None) -> Any:
        """config.get('telegram', 'token') → value or default."""
        node = self._data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def require(self, *keys: str) -> Any:
        """Like get() but raises ConfigError if missing or empty."""
        value = self.get(*keys)
        if value is None or value == "" or value == 0:
            path = " → ".join(keys)
            raise ConfigError(f"Required config missing: {path}")
        return value

    # ── shortcut properties ───────────────────────────────────────────────
    @property
    def telegram_token(self) -> str:
        return self.require("telegram", "token")

    @property
    def telegram_operator_id(self) -> int:
        return int(self.require("telegram", "operator_chat_id"))

    @property
    def discord_token(self) -> str:
        return self.require("discord", "token")

    @property
    def discord_channel_id(self) -> int:
        return int(self.require("discord", "operator_channel_id"))

    @property
    def discord_enabled(self) -> bool:
        return bool(self.get("discord", "enabled", default=True))

    @property
    def operator_tag(self) -> str:
        return self.get("operator", "tag", default="operator")

    @property
    def operator_pin(self) -> str:
        return self.get("operator", "auth_pin", default="")

    @property
    def allowed_ids(self) -> list[int]:
        ids = self.get("operator", "allowed_telegram_ids", default=[])
        return [int(i) for i in ids]

    @property
    def task_timeout(self) -> int:
        return int(self.get("c2", "task_timeout", default=120))

    @property
    def checkin_ttl(self) -> int:
        return int(self.get("c2", "checkin_ttl", default=300))

    @property
    def failover_threshold(self) -> int:
        return int(self.get("c2", "failover_threshold", default=3))

    @property
    def max_message_chunk(self) -> int:
        return int(self.get("c2", "max_message_chunk", default=4096))

    @property
    def loot_db(self) -> str:
        return self.get("loot", "db_path", default="data/loot.db")

    @property
    def audit_log(self) -> str:
        return self.get("audit", "log_path", default="data/audit.jsonl")

    @property
    def projects_base(self) -> str:
        return self.get("projects", "base_path", default="data/projects")

    @property
    def builder_output(self) -> str:
        return self.get("builder", "output_dir", default="build")

    @property
    def build_dir(self) -> str:
        return self.builder_output

    @property
    def http_host(self) -> str:
        return self.get("c2", "http_host", default="0.0.0.0")

    @property
    def http_port(self) -> int:
        return int(self.get("c2", "http_port", default=8888))

    @property
    def http_enabled(self) -> bool:
        return bool(self.get("c2", "http_enabled", default=True))

    @property
    def c2_profile(self) -> str:
        return self.get("c2", "profile", default="")

    @property
    def sessions_db(self) -> str:
        return self.get("c2", "sessions_db", default="data/sessions.db")

    @property
    def tls_cert(self) -> str:
        return self.get("c2", "tls_cert", default="")

    @property
    def tls_key(self) -> str:
        return self.get("c2", "tls_key", default="")

    @property
    def log_level(self) -> str:
        return self.get("logging", "level", default="INFO").upper()

    @property
    def log_file(self) -> str:
        return self.get("logging", "log_file", default="data/fitnah.log")

    # ── validation ────────────────────────────────────────────────────────
    def validate(self) -> None:
        """Raise ConfigError if the minimum required fields are missing."""
        errors = []

        if not self.get("telegram", "token"):
            errors.append("telegram.token is required")
        if not self.get("telegram", "operator_chat_id"):
            errors.append("telegram.operator_chat_id is required")
        if not self.get("operator", "allowed_telegram_ids"):
            errors.append("operator.allowed_telegram_ids must have at least one ID")

        tg_token = self.get("telegram", "token", default="")
        if tg_token in ("YOUR_BOT_TOKEN_HERE", ""):
            errors.append("telegram.token has not been configured — edit config/framework.yaml")

        if errors:
            raise ConfigError(
                "Configuration errors:\n" + "\n".join(f"  • {e}" for e in errors)
            )

    def __repr__(self) -> str:
        token = self.get("telegram", "token", default="")
        masked = token[:6] + "..." if token else "NOT SET"
        return f"<Config telegram={masked} operator={self.operator_tag}>"


# ── Module-level loader ────────────────────────────────────────────────────

def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Override wins on conflict."""
    merged = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k] = _deep_merge(merged[k], v)
        else:
            merged[k] = v
    return merged


def load(path: str | Path | None = None) -> Config:
    """
    Load framework.yaml, merge with defaults, validate, return Config.
    Searches default paths if path is None.
    Raises ConfigError on validation failure.
    """
    yaml_path: Path | None = None

    if path:
        yaml_path = Path(path)
        if not yaml_path.exists():
            raise ConfigError(f"Config file not found: {path}")
    else:
        for candidate in _CONFIG_PATHS:
            p = Path(candidate)
            if p.exists():
                yaml_path = p
                break

    if yaml_path is None:
        log.warning(
            "No config file found (searched: %s). Using defaults only — "
            "Telegram will not work without a valid token.",
            ", ".join(_CONFIG_PATHS),
        )
        raw: dict = {}
    else:
        with yaml_path.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        log.info("Config loaded from %s", yaml_path)

    merged = _deep_merge(_DEFAULTS, raw)
    cfg = Config(merged)
    cfg.validate()
    return cfg


def setup_logging(cfg: Config) -> None:
    """Configure root logger from config settings."""
    import logging.handlers

    level = getattr(logging, cfg.log_level, logging.INFO)
    log_file = Path(cfg.log_file)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]

    if cfg.get("logging", "rotate_daily", default=True):
        fh = logging.handlers.TimedRotatingFileHandler(
            log_file, when="midnight", backupCount=14, encoding="utf-8"
        )
    else:
        fh = logging.FileHandler(log_file, encoding="utf-8")

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)-30s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    for h in handlers + [fh]:
        h.setFormatter(fmt)

    logging.root.setLevel(level)
    for h in handlers + [fh]:
        logging.root.addHandler(h)

    # suppress noisy third-party loggers that leak the bot token in URLs
    for noisy in ("httpx", "httpcore", "apscheduler", "telegram.ext.Application"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
