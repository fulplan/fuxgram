"""recon/domain_enum — Active Directory / domain enumeration. MITRE T1018, T1069, T1087"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class DomainEnum(BasePlugin):
    NAME        = "domain_enum"
    DESCRIPTION = (
        "Enumerate AD objects: users, groups, computers, trusts. "
        "Uses Get-AD* cmdlets (RSAT) with fallback to net.exe commands."
    )
    AUTHOR      = "fitnah-team"
    MITRE       = "T1018,T1069,T1087"
    CATEGORY    = "recon"
    schema      = ParamSchema().add(
        Param("action", str, required=True,
              help="What to enumerate: users | groups | computers | trusts | all"),
        Param("domain", str, required=False, default="",
              help="Target domain FQDN (empty = use current domain)"),
    )

    @mitre("T1087")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "").lower().strip()
        domain = params.get("domain", "").strip()

        valid = ("users", "groups", "computers", "trusts", "all")
        if action not in valid:
            return ModuleResult.err(f"Invalid action '{action}'. Choose from: {', '.join(valid)}")

        # Domain filter suffix for Get-AD* cmdlets
        if domain:
            safe_dom = domain.replace("'", "''")
            domain_arg = f" -Server '{safe_dom}'"
        else:
            safe_dom   = ""
            domain_arg = ""

        # RSAT availability check (run once)
        rsat_check = (
            "$rsatAvail = $null -ne (Get-Command Get-ADUser -EA SilentlyContinue);"
        )

        blocks = []

        if action in ("users", "all"):
            blocks.append(
                "Write-Output '=== Domain Users ===';"
                "if ($rsatAvail) {"
                f"  try {{"
                f"    Get-ADUser -Filter * -Properties DisplayName,SamAccountName,Enabled,PasswordLastSet{domain_arg}"
                "    | Select-Object SamAccountName,DisplayName,Enabled,PasswordLastSet"
                "    | Sort-Object SamAccountName"
                "    | ForEach-Object {"
                "      Write-Output ('{0,-24} {1,-30} Enabled={2} PwdSet={3}' -f"
                "        $_.SamAccountName, $_.DisplayName, $_.Enabled, $_.PasswordLastSet)"
                "    };"
                "  } catch {"
                "    Write-Output '  [!] Get-ADUser failed: ' + $_;"
                "    Write-Output '  [*] Falling back to net user /domain';"
                "    net user /domain 2>&1 | Select-Object -Skip 4 | ForEach-Object { Write-Output \"  $_\" }"
                "  }"
                "} else {"
                "  Write-Output '  [*] RSAT not available — using net user /domain';"
                "  net user /domain 2>&1 | ForEach-Object { Write-Output \"  $_\" }"
                "};"
            )

        if action in ("groups", "all"):
            blocks.append(
                "Write-Output '';"
                "Write-Output '=== Domain Groups ===';"
                "if ($rsatAvail) {"
                f"  try {{"
                f"    Get-ADGroup -Filter * -Properties GroupCategory,GroupScope,Description{domain_arg}"
                "    | Select-Object Name,GroupCategory,GroupScope,Description"
                "    | Sort-Object Name"
                "    | ForEach-Object {"
                "      Write-Output ('{0,-30} [{1}/{2}] {3}' -f"
                "        $_.Name, $_.GroupCategory, $_.GroupScope, $_.Description)"
                "    };"
                "  } catch {"
                "    Write-Output '  [!] Get-ADGroup failed: ' + $_;"
                "    Write-Output '  [*] Falling back to net group /domain';"
                "    net group /domain 2>&1 | Select-Object -Skip 4 | ForEach-Object { Write-Output \"  $_\" }"
                "  }"
                "} else {"
                "  Write-Output '  [*] RSAT not available — using net group /domain';"
                "  net group /domain 2>&1 | ForEach-Object { Write-Output \"  $_\" }"
                "};"
            )

        if action in ("computers", "all"):
            blocks.append(
                "Write-Output '';"
                "Write-Output '=== Domain Computers ===';"
                "if ($rsatAvail) {"
                f"  try {{"
                f"    Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate,IPv4Address{domain_arg}"
                "    | Select-Object Name,OperatingSystem,LastLogonDate,IPv4Address"
                "    | Sort-Object Name"
                "    | ForEach-Object {"
                "      Write-Output ('{0,-24} {1,-36} LastLogon={2} IP={3}' -f"
                "        $_.Name, $_.OperatingSystem, $_.LastLogonDate, $_.IPv4Address)"
                "    };"
                "  } catch {"
                "    Write-Output '  [!] Get-ADComputer failed: ' + $_;"
                "    Write-Output '  [*] No net.exe fallback for computers — try nltest /dclist';"
                "    nltest /dclist: 2>&1 | ForEach-Object { Write-Output \"  $_\" }"
                "  }"
                "} else {"
                "  Write-Output '  [*] RSAT not available — using nltest /dclist';"
                "  nltest /dclist: 2>&1 | ForEach-Object { Write-Output \"  $_\" }"
                "};"
            )

        if action in ("trusts", "all"):
            blocks.append(
                "Write-Output '';"
                "Write-Output '=== Domain Trusts ===';"
                "if ($rsatAvail) {"
                f"  try {{"
                f"    Get-ADTrust -Filter *{domain_arg}"
                "    | ForEach-Object {"
                "      Write-Output ('{0,-40} Direction={1} Type={2}' -f"
                "        $_.Name, $_.Direction, $_.TrustType)"
                "    };"
                "  } catch {"
                "    Write-Output '  [!] Get-ADTrust failed: ' + $_;"
                "    Write-Output '  [*] Falling back to nltest /domain_trusts';"
                "    nltest /domain_trusts 2>&1 | ForEach-Object { Write-Output \"  $_\" }"
                "  }"
                "} else {"
                "  Write-Output '  [*] RSAT not available — using nltest /domain_trusts';"
                "  nltest /domain_trusts 2>&1 | ForEach-Object { Write-Output \"  $_\" }"
                "};"
            )

        ps = rsat_check + " ".join(blocks)
        r  = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")

        tags = ["AD", action]
        return ModuleResult.ok(
            data=r["output"],
            loot_kind="recon",
            loot_tags=tags,
        )
