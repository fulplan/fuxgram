"""recon/users_enum — local/domain users, logged-on sessions, privilege check. MITRE T1087"""
from fitnah.sdk import BasePlugin, ModuleResult, mitre


class UsersEnum(BasePlugin):
    NAME        = "users_enum"
    DESCRIPTION = "Local users+groups, logged-on users, domain admins, SeDebug/DA check."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1087"
    CATEGORY    = "recon"

    @mitre("T1087")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        ps = (
            "$sep = \"`n\" + (\"-\"*50) + \"`n\";"

            "Write-Output ($sep + \"[LOCAL USERS]\");"
            "Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,Description | Format-Table | Out-String;"

            "Write-Output ($sep + \"[LOCAL GROUPS]\");"
            "Get-LocalGroup | Select-Object Name,Description | Format-Table | Out-String;"

            "Write-Output ($sep + \"[LOCAL ADMINS]\");"
            "Get-LocalGroupMember -Group Administrators -EA SilentlyContinue | Format-Table | Out-String;"

            "Write-Output ($sep + \"[LOGGED-ON USERS]\");"
            "query user 2>&1;"
            "try {"
            "  Get-CimInstance Win32_LoggedOnUser -EA Stop |"
            "    Select-Object -ExpandProperty Antecedent |"
            "    Select-Object Name,Domain -Unique | Format-Table | Out-String"
            "} catch {};"

            "Write-Output ($sep + \"[DOMAIN ADMINS (net group)]\");"
            "net group \"Domain Admins\" /domain 2>&1 | Select-Object -First 30;"

            "Write-Output ($sep + \"[CURRENT USER CONTEXT]\");"
            "whoami /all 2>&1 | Select-Object -First 50;"

            "Write-Output ($sep + \"[SeDebugPrivilege check]\");"
            "try {"
            "  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent();"
            "  $priv = $id.Groups | Where-Object { $_.IsValidTargetType([System.Security.Principal.SecurityIdentifier]) };"
            "  $isAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);"
            "  \"Running as: $($id.Name)  IsAdmin: $isAdmin\""
            "} catch { 'Privilege check failed' }"
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        out = r["output"]
        if len(out) > 5000:
            out = out[:5000] + "\n...[truncated]"
        return ModuleResult.ok(data=out)
