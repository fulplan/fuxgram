"""
recon/port_scan — TCP port scanner (T1046: Network Service Scanning).

Strategy (in order):
  1. nmap  — if available, full version scan with OS detection
  2. masscan — if available, high-speed SYN scan
  3. Test-NetConnection — pure PowerShell fallback, no extra tools needed

Results are returned as structured JSON and saved to loot.
"""
from __future__ import annotations

import json
import shutil
from typing import Any

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param as PluginParam, ParamSchema


class PortScan(BasePlugin):
    NAME        = "port_scan"
    CATEGORY    = "recon"
    DESCRIPTION = "Scan TCP ports on a target host (nmap/masscan/PS fallback)"
    AUTHOR      = "fitnah"
    MITRE       = "T1046"
    REQUIRES_PRIV = False

    schema = ParamSchema(params=[
        PluginParam("target",    str,  required=True,  help="IP address or hostname to scan"),
        PluginParam("ports",     str,  required=False, default="22,80,443,445,3389,8080,8443,1433,3306,5432",
                    help="Comma-separated ports or range (e.g. 1-1024). Default: common ports"),
        PluginParam("method",    str,  required=False, default="auto",
                    help="Scanner: auto|nmap|masscan|ps  (auto tries nmap->masscan->ps)"),
        PluginParam("timeout",   str,  required=False, default="2",
                    help="Per-port connect timeout in seconds (PS fallback only)"),
        PluginParam("rate",      str,  required=False, default="500",
                    help="Packets/second rate limit (masscan only)"),
        PluginParam("save_loot", str,  required=False, default="true",
                    help="Save results to loot database (true/false)"),
    ])

    # ── entry point ───────────────────────────────────────────────────────

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        target    = params.get("target", "").strip()
        ports     = params.get("ports",  "22,80,443,445,3389,8080,8443").strip()
        method    = params.get("method", "auto").strip().lower()
        timeout   = params.get("timeout", "2").strip()
        rate      = params.get("rate", "500").strip()
        save_loot = params.get("save_loot", "true").lower() != "false"

        if not target:
            return ModuleResult.err("target parameter is required")

        # pick scanner
        if method == "auto":
            if self._has_nmap():
                method = "nmap"
            elif self._has_masscan():
                method = "masscan"
            else:
                method = "ps"

        if method == "nmap":
            raw, results = self._scan_nmap(ctx, target, ports)
        elif method == "masscan":
            raw, results = self._scan_masscan(ctx, target, ports, rate)
        else:
            raw, results = self._scan_ps(ctx, target, ports, timeout)

        if raw is None:
            return ModuleResult.err("Scan failed")

        open_ports = [r for r in results if r.get("state") == "open"]
        summary = "%d open port(s) on %s" % (len(open_ports), target)

        structured = {
            "target":     target,
            "ports_arg":  ports,
            "method":     method,
            "results":    results,
            "open_count": len(open_ports),
        }

        return ModuleResult.ok(data=structured)

    # ── nmap ──────────────────────────────────────────────────────────────

    def _scan_nmap(
        self, ctx: PluginContext, target: str, ports: str
    ) -> tuple[str | None, list[dict]]:
        nmap_cmd = (
            f"nmap -sV -O --open -p {ports} --host-timeout 120s "
            f"-T4 {target} 2>&1"
        )
        # run on the agent via ctx.ps() — executes on the remote host
        raw = ctx.ps(nmap_cmd)
        if not raw or "failed" in raw.lower():
            ctx.send(f"[-] nmap returned: {raw[:200]}")
            return None, []

        results = self._parse_nmap(raw)
        return raw, results

    def _parse_nmap(self, raw: str) -> list[dict]:
        results = []
        for line in raw.splitlines():
            line = line.strip()
            # "80/tcp   open  http    Apache httpd 2.4.41"
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 2:
                    port_proto = parts[0]
                    state      = parts[1]
                    service    = parts[2] if len(parts) > 2 else ""
                    version    = " ".join(parts[3:]) if len(parts) > 3 else ""
                    try:
                        port = int(port_proto.split("/")[0])
                        proto = port_proto.split("/")[1]
                    except (ValueError, IndexError):
                        continue
                    results.append({
                        "port":    port,
                        "proto":   proto,
                        "state":   state,
                        "service": service,
                        "version": version,
                    })
        return results

    # ── masscan ───────────────────────────────────────────────────────────

    def _scan_masscan(
        self, ctx: PluginContext, target: str, ports: str, rate: str
    ) -> tuple[str | None, list[dict]]:
        masscan_cmd = (
            f"masscan {target} -p{ports} --rate={rate} "
            f"--wait 2 --output-format json 2>&1"
        )
        raw = ctx.ps(masscan_cmd)
        if not raw:
            return None, []

        results = self._parse_masscan(raw)
        return raw, results

    def _parse_masscan(self, raw: str) -> list[dict]:
        results = []
        # masscan JSON output: [{"ip":"x","ports":[{"port":N,"proto":"tcp","status":"open",...}]}]
        try:
            # strip leading garbage before '['
            start = raw.find("[")
            if start >= 0:
                data = json.loads(raw[start:])
                for host in data:
                    for p in host.get("ports", []):
                        results.append({
                            "port":    p.get("port"),
                            "proto":   p.get("proto", "tcp"),
                            "state":   p.get("status", "open"),
                            "service": p.get("service", {}).get("name", ""),
                            "version": "",
                        })
        except (json.JSONDecodeError, TypeError):
            # fallback: parse text output
            for line in raw.splitlines():
                if "open" in line.lower() and "/" in line:
                    parts = line.split()
                    for part in parts:
                        if "/" in part:
                            try:
                                port, proto = part.split("/")
                                results.append({
                                    "port":    int(port),
                                    "proto":   proto,
                                    "state":   "open",
                                    "service": "",
                                    "version": "",
                                })
                            except (ValueError, IndexError):
                                pass
        return results

    # ── PowerShell fallback ───────────────────────────────────────────────

    def _scan_ps(
        self, ctx: PluginContext, target: str, ports: str, timeout: str
    ) -> tuple[str | None, list[dict]]:
        port_list = self._expand_ports(ports)
        if not port_list:
            return None, []

        # PS script: Test-NetConnection loop, outputs JSON array
        ps_script = r"""
$_to = {timeout}; $_tgt = '{target}'
$_ports = @({port_list})
$_results = @()
foreach ($_p in $_ports) {{
    try {{
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($_tgt, $_p, $null, $null)
        $ok = $async.AsyncWaitHandle.WaitOne([int]($_to * 1000), $false)
        if ($ok -and !$tcp.Client.Connected) {{ $ok = $false }}
        $state = if ($ok) {{ 'open' }} else {{ 'closed' }}
        $tcp.Close()
    }} catch {{ $state = 'filtered' }}
    $banner = ''
    if ($state -eq 'open') {{
        try {{
            $tcp2 = New-Object System.Net.Sockets.TcpClient($_tgt, $_p)
            $tcp2.ReceiveTimeout = 500
            $ns = $tcp2.GetStream()
            $buf = New-Object byte[] 256
            $read = $ns.Read($buf, 0, 256)
            if ($read -gt 0) {{ $banner = [Text.Encoding]::ASCII.GetString($buf, 0, $read).Trim() }}
            $tcp2.Close()
        }} catch {{}}
    }}
    $_results += [pscustomobject]@{{ port=$_p; proto='tcp'; state=$state; service=''; version=$banner }}
}}
$_results | Where-Object {{ $_.state -eq 'open' }} | ConvertTo-Json -Compress
""".format(
            timeout=timeout,
            target=target.replace("'", "''"),
            port_list=", ".join(str(p) for p in port_list[:1024]),
        )

        raw = ctx.ps(ps_script)
        if not raw:
            return None, []

        results: list[dict] = []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                parsed = [parsed]
            for item in parsed:
                results.append({
                    "port":    item.get("port"),
                    "proto":   item.get("proto", "tcp"),
                    "state":   item.get("state", "open"),
                    "service": item.get("service", ""),
                    "version": item.get("version", ""),
                })
        except (json.JSONDecodeError, TypeError):
            # parse line by line fallback
            for line in raw.splitlines():
                if "open" in line.lower():
                    results.append({"port": "?", "proto": "tcp", "state": "open",
                                    "service": "", "version": line.strip()})
        return raw, results

    # ── helpers ───────────────────────────────────────────────────────────

    def _has_nmap(self) -> bool:
        return shutil.which("nmap") is not None

    def _has_masscan(self) -> bool:
        return shutil.which("masscan") is not None

    def _expand_ports(self, ports_str: str) -> list[int]:
        """Parse '22,80,443,8000-8100' into a flat list of ints."""
        result: list[int] = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    lo, hi = part.split("-", 1)
                    result.extend(range(int(lo), int(hi) + 1))
                except ValueError:
                    pass
            else:
                try:
                    result.append(int(part))
                except ValueError:
                    pass
        return sorted(set(result))
