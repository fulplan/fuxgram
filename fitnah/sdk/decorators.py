"""Decorators for plugin commands."""
from __future__ import annotations
import functools
from typing import Callable


def command(name: str, help: str = ""):
    """Register a method as a plugin command."""
    def decorator(fn: Callable) -> Callable:
        fn._command = name
        fn._help = help
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def mitre(technique_id: str):
    """Tag a command with a MITRE ATT&CK technique ID."""
    def decorator(fn: Callable) -> Callable:
        fn._mitre = technique_id
        return fn
    return decorator


def requires_priv(level: str):
    """Declare minimum privilege level needed (user / admin / system)."""
    _order = {"user": 0, "admin": 1, "system": 2}

    def decorator(fn: Callable) -> Callable:
        fn._requires_priv = level

        @functools.wraps(fn)
        def wrapper(self, *args, **kwargs):
            agent = kwargs.get("agent") or (args[0] if args else None)
            current = getattr(agent, "priv_level", "user")
            if _order.get(current, 0) < _order.get(level, 0):
                from fitnah.sdk.result import ModuleResult
                return ModuleResult.err(f"Requires {level} privilege, got {current}")
            return fn(self, *args, **kwargs)
        return wrapper
    return decorator
