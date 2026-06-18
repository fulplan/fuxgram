"""recon/arp_scan — parallel host discovery with SMB check. MITRE T1018"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ArpScan(BasePlugin):
    NAME        = "arp_scan"
    DESCRIPTION = "Parallel ping sweep (PS7) or ARP fallback; SMB check on live hosts."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1018"
    CATEGORY    = "recon"
    schema      = ParamSchema().add(
        Param("subnet",   str,  required=False, default="",
              help="Subnet prefix e.g. 192.168.1 (omit last octet). Auto-detect if empty."),
        Param("smb_check", bool, required=False, default=False,
              help="Test-NetConnection port 445 on discovered hosts"),
    )

    @mitre("T1018")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        subnet    = params.get("subnet", "").strip()
        smb_check = params.get("smb_check", False)

        # Auto-detect subnet from default gateway
        auto_detect = (
            "$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA SilentlyContinue |"
            " Sort-Object RouteMetric | Select-Object -First 1).NextHop;"
            "$subnet = if ($gw) { ($gw -split '\\.')[0..2] -join '.' } else { '192.168.1' };"
        ) if not subnet else f"$subnet = '{subnet}';"

        smb_part = (
            "Write-Output \"`n[SMB open on discovered hosts]\";"
            "$live | ForEach-Object {"
            "  $r = Test-NetConnection -ComputerName $_ -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue -EA SilentlyContinue;"
            "  if ($r) { \"SMB OPEN: $_\" }"
            "};"
        ) if smb_check else ""

        ps = (
            auto_detect
            # Try PS7 parallel, fall back to sequential
            + "Write-Output \"[Ping sweep: $subnet.1-254]\";"
            "$live = @();"
            "if ($PSVersionTable.PSVersion.Major -ge 7) {"
            "  $live = 1..254 | ForEach-Object -Parallel {"
            "    $ip = $using:subnet + '.' + $_;"
            "    if (Test-Connection $ip -Count 1 -TimeoutSeconds 1 -Quiet -EA SilentlyContinue) { $ip }"
            "  } -ThrottleLimit 50 | Where-Object { $_ };"
            "} else {"
            "  1..254 | ForEach-Object {"
            "    $ip = $subnet + '.' + $_;"
            "    if (Test-Connection $ip -Count 1 -Quiet -EA SilentlyContinue) { $live += $ip }"
            "  };"
            "};"
            "Write-Output \"Live hosts ($($live.Count)):\";"
            "$live | ForEach-Object { $_ };"
            "Write-Output \"`n[ARP cache / neighbor table]\";"
            "try { Get-NetNeighbor -EA Stop | Where-Object { $_.State -ne 'Unreachable' } | Select-Object IPAddress,LinkLayerAddress,State | Format-Table | Out-String }"
            "catch { arp -a 2>&1 };"
            + smb_part
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
