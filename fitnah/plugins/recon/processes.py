"""recon/processes — CIM-based process list with security tool detection. MITRE T1057"""
from fitnah.sdk import BasePlugin, ModuleResult, mitre
from fitnah.sdk.schema import Param, ParamSchema

# Known security tool process names (lowercase) for flagging
_SEC_TOOLS = {
    "msseces", "msmpeng", "mpcmdrun", "nissrv",          # Defender
    "csc", "bdagent", "bdredline", "vsserv",              # Bitdefender
    "cagent", "casc", "csc2",                             # Carbon Black
    "cb", "cbsensor",                                     # Carbon Black legacy
    "csfalconservice", "csfalconcontainer",               # CrowdStrike
    "cylancesvc", "cylanceui",                            # Cylance
    "sophosssp", "sophosfs", "sophosui", "savscan",       # Sophos
    "mcshield", "mcupdmgr", "mcscancheck",                # McAfee
    "avguard", "avgnt", "avscan",                         # Avira
    "bdservicehost", "bdupdater",                         # Bitdefender
    "sentinelagent", "sentinelhelper", "sentinelone",     # SentinelOne
    "xagt",                                               # FireEye
    "mbam", "mbamservice", "mbamtray",                    # Malwarebytes
    "wireshark", "procmon", "procmon64", "procexp",       # Analysis tools
    "procexp64", "autoruns", "autorunsc", "tcpview",
    "ollydbg", "x64dbg", "x32dbg", "windbg",
    "idaq", "idaq64", "idaw", "idaw64",                   # IDA Pro
    "dnspy", "de4dot",                                    # .NET analysis
    "fiddler", "charles", "burpsuite",
    "splunkd", "splunkuf",                                # Splunk SIEM
    "tdr-agent", "tdragent",                              # Trend Micro
    "pccntmon", "ntrtscan", "tmlisten",
    "taniumclient",                                       # Tanium
    "qualysagent",                                        # Qualys
    "tenable", "nessusagent",                             # Tenable
    "sysmon", "sysmon64",                                 # Sysinternals Sysmon
}


class Processes(BasePlugin):
    NAME        = "processes"
    DESCRIPTION = "CIM process list (PID, PPID, Name, Path, Owner, CmdLine) with EDR flagging."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1057"
    CATEGORY    = "recon"

    schema = ParamSchema().add(
        Param("filter_name",   str,  required=False, default="",    help="Filter process name (substring)"),
        Param("include_paths", bool, required=False, default=True,  help="Include ExecutablePath column"),
        Param("include_cmdline", bool, required=False, default=False, help="Include CommandLine column"),
    )

    @mitre("T1057")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        filter_name    = params.get("filter_name", "")
        include_paths  = bool(params.get("include_paths", True))
        include_cmdline = bool(params.get("include_cmdline", False))

        sec_tools_ps = ",".join(f"'{t}'" for t in sorted(_SEC_TOOLS))

        filter_ps = ""
        if filter_name:
            filter_ps = "| Where-Object { $_.Name -and $_.Name -like '*" + filter_name.replace("'", "''") + "*' }"

        path_col = (
            "  $pathStr = if (" + ("$true" if include_paths else "$false") + ") {"
            "    if ($_.ExecutablePath) { $_.ExecutablePath.Substring(0,[Math]::Min(50,$_.ExecutablePath.Length)) }"
            "    else { '' }"
            "  } else { '' };"
        )

        cmdline_col = (
            "  $cmdStr = if (" + ("$true" if include_cmdline else "$false") + ") {"
            "    if ($_.CommandLine) { $_.CommandLine.Substring(0,[Math]::Min(60,$_.CommandLine.Length)) }"
            "    else { '' }"
            "  } else { '' };"
        )

        ps = (
            "$secTools = @(" + sec_tools_ps + ");"
            "$procs = Get-CimInstance Win32_Process "
            + filter_ps +
            " | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,"
            "@{N='Owner';E={ $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner;"
            " if ($o.ReturnValue -eq 0) { \"$($o.Domain)\\\\$($o.User)\" } else { '' } }};"
            "$header = \"{0,-6} {1,-6} {2,-28} {3,-8} {4,-20}\" -f 'PID','PPID','Name','Flag','Owner';"
            "if (" + ("$true" if include_paths else "$false") + ") { $header += ' Path' };"
            "if (" + ("$true" if include_cmdline else "$false") + ") { $header += ' CmdLine' };"
            "$lines = @($header, ('-'*120));"
            "$secCount = 0;"
            "$procs | Sort-Object ProcessId | ForEach-Object {"
            "  $nameL = if ($_.Name) { $_.Name.ToLower().TrimEnd('.exe') } else { '' };"
            "  $flag = if ($nameL -in $secTools) { '[!SEC]' } else { '' };"
            "  if ($flag) { $secCount++ };"
            + path_col + cmdline_col +
            "  $line = \"{0,-6} {1,-6} {2,-28} {3,-8} {4,-20}\" -f $_.ProcessId,$_.ParentProcessId,$_.Name,$flag,$_.Owner;"
            "  if (" + ("$true" if include_paths else "$false") + ") { $line += ' ' + $pathStr };"
            "  if (" + ("$true" if include_cmdline else "$false") + ") { $line += ' ' + $cmdStr };"
            "  $lines += $line;"
            "};"
            "$lines += '';"
            "$lines += \"Total: $($procs.Count) processes  |  Security tools flagged: $secCount\";"
            "$lines | Out-String -Width 400"
        )

        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        out = r["output"]
        if len(out) > 8000:
            out = out[:8000] + "\n...[truncated]"
        return ModuleResult.ok(data=out)
