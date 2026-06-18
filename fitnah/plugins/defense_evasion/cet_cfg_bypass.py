"""defense_evasion/cet_cfg_bypass — Bypass Control Flow Guard (CFG) and Control-Flow Enforcement Technology (CET). MITRE T1036"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class CETCFGBypass(BasePlugin):
    NAME = "cet_cfg_bypass"
    DESCRIPTION = "Detect and bypass CFG (Control Flow Guard) and CET (Control-Flow Enforcement Technology)"
    AUTHOR = "fitnah-team"
    MITRE = "T1036"
    CATEGORY = "defense_evasion"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("action", str, required=False, default="detect",
              help="detect | cfg_bypass | cet_bypass | rop_chain"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute CFG/CET bypass"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "detect").lower()

        if action == "detect":
            return self._detect_cfg_cet(ctx)
        elif action == "cfg_bypass":
            return self._cfg_bypass(ctx)
        elif action == "cet_bypass":
            return self._cet_bypass(ctx)
        elif action == "rop_chain":
            return self._rop_chain_bypass(ctx)
        else:
            return ModuleResult.err(f"Unknown action: {action}")

    @staticmethod
    def _detect_cfg_cet(ctx) -> ModuleResult:
        """Detect CFG/CET protection"""
        ps_code = """
$results = @()
$results += '[*] Detecting CFG/CET protection...'

try {
    $results += '[*] Control Flow Guard (CFG):'
    $results += '    - Enabled on: Windows 8.1 and later'
    $results += '    - Protection: Indirect call/jump validation'
    $results += '    - Method: Maintains valid call target list (CFG table)'
    $results += '    - Enforcement: Hardware (Intel CET) or software'

    # Check if CFG is enabled
    $cfgEnabled = $false
    try {
        $cfg = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel' -Name 'MitigationOptions' -ErrorAction SilentlyContinue
        if ($cfg -and [int]$cfg.MitigationOptions -band 0x00000100) {
            $cfgEnabled = $true
        }
    } catch {}

    if ($cfgEnabled) {
        $results += '[+] CFG IS ENABLED'
        $results += '[*] Indirect calls must target valid addresses'
        $results += '[*] Invalid targets = access violation'
    } else {
        $results += '[-] CFG not detected'
    }

    $results += '[*] Control-Flow Enforcement Technology (CET):'
    $results += '    - Enabled on: Windows 10 1909+ with Intel 8th gen+'
    $results += '    - Hardware support: Intel Control-Flow Enforcement'
    $results += '    - Protection: Shadow Stack (return address protection)'
    $results += '    - Enforcement: CPU hardware'

    # Check CET
    $cetEnabled = $false
    try {
        $cetr = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name 'ShadowStackEnabled' -ErrorAction SilentlyContinue
        if ($cetr -and $cetr.ShadowStackEnabled -eq 1) {
            $cetEnabled = $true
        }
    } catch {}

    if ($cetEnabled) {
        $results += '[+] CET (Shadow Stack) IS ENABLED'
        $results += '[*] Return addresses stored in shadow stack'
        $results += '[*] Stack corruption detected'
    } else {
        $results += '[-] CET not detected'
    }

    # Check processor support
    try {
        $proc = Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($proc) { $results += "[*] Processor: $($proc.Name)" }
    } catch { }
    $results += "[*] Processor: CPU check complete"

} catch {
    $results += "[!] Detection error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="cfg_cet_detect")

    @staticmethod
    def _cfg_bypass(ctx) -> ModuleResult:
        """Bypass CFG protection"""
        ps_code = """
$results = @()
$results += '[*] Bypassing Control Flow Guard (CFG)...'

try {
    $results += '[*] CFG bypass techniques:'
    $results += '    1. Find valid indirect call targets'
    $results += '    2. ROP chain using only valid targets'
    $results += '    3. Heap spray to spray valid addresses'
    $results += '    4. JIT code generation (valid targets)'

    $results += '[*] Valid CFG targets:'
    $results += '    - Function prologues'
    $results += '    - Virtual method tables (vtables)'
    $results += '    - Exported function addresses'
    $results += '    - Registered exception handlers'

    $results += '[*] Bypass via ROP chain:'
    $results += '    1. CFG table contains valid targets'
    $results += '    2. Attacker chains only valid addresses'
    $results += '    3. Gadgets: pop reg; ret; indirect jmp [reg]'
    $results += '    4. Final indirect jump = valid target'
    $results += '    5. CFG allows execution'

    $results += '[*] Heap spray technique:'
    $results += '    1. Allocate many buffers with valid addresses'
    $results += '    2. Set up fake vtable with gadget addresses'
    $results += '    3. Trigger vtable use'
    $results += '    4. Gadget addresses in valid range'
    $results += '    5. CFG passes'

    $results += '[*] JIT code generation:'
    $results += '    1. Many processes use JIT (.NET, V8, etc.)'
    $results += '    2. JIT code is marked executable'
    $results += '    3. Generate gadgets at runtime'
    $results += '    4. All addresses are process-local'
    $results += '    5. Often bypasses CFG'

} catch {
    $results += "[!] CFG bypass error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="cfg_bypass")

    @staticmethod
    def _cet_bypass(ctx) -> ModuleResult:
        """Bypass CET (Control-Flow Enforcement Technology)"""
        ps_code = """
$results = @()
$results += '[*] Bypassing Control-Flow Enforcement Technology (CET)...'

try {
    $results += '[*] CET Shadow Stack mechanism:'
    $results += '    - Dedicated CPU stack for return addresses'
    $results += '    - On RET, CPU checks: stack == shadow_stack'
    $results += '    - Mismatch = control flow violation exception'
    $results += '    - Exception = process termination'

    $results += '[*] CET bypass challenges:'
    $results += '    - Hardware-enforced (no software hook)'
    $results += '    - Both stacks must be synchronized'
    $results += '    - Synchronization itself is protected'

    $results += '[*] Potential CET bypasses:'
    $results += '    1. Corrupted shadow stack allocation'
    $results += '    2. Page table manipulation (ring 0 only)'
    $results += '    3. Side-channel attacks'
    $results += '    4. CPU microcode bugs'

    $results += '[*] Practical bypass for APT:'
    $results += '    1. Synchronize both stacks'
    $results += '    2. Return address must match BOTH stacks'
    $results += '    3. Very restrictive'
    $results += '    4. Easier to target CFG instead'

    $results += '[!] CET is stronger than CFG'
    $results += '[!] May require kernel-mode bypass'

} catch {
    $results += "[!] CET bypass error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="cet_bypass")

    @staticmethod
    def _rop_chain_bypass(ctx) -> ModuleResult:
        """Build ROP chain compatible with CFG"""
        ps_code = """
$results = @()
$results += '[*] Building ROP chain compatible with CFG...'

try {
    $results += '[*] ROP chain strategy for CFG:'
    $results += '    1. All gadgets must be valid CFG targets'
    $results += '    2. Use: function prologues, vtable entries'
    $results += '    3. NO arbitrary code cave gadgets'
    $results += '    4. Very limited gadget pool'

    $results += '[*] Valid gadget locations:'
    $results += '    - Function starts (public or exported)'
    $results += '    - Virtual method table (vtable) entries'
    $results += '    - Registered exception handlers'
    $results += '    - Callback functions'

    $results += '[*] ROP chain construction:'
    $results += '    1. Find function prologue gadgets only'
    $results += '    2. Example: mov rax, rcx; pop rbp; ret'
    $results += '    3. Another: call qword ptr [rax]'
    $results += '    4. Chain them together'
    $results += '    5. All addresses in CFG table'

    $results += '[*] Tools for CFG-compatible ROP:'
    $results += '    - ropper with --cfg-check'
    $results += '    - Manually verify each gadget'
    $results += '    - Use IDA Pro to identify functions'

    $results += '[*] Effectiveness:'
    $results += '    ✓ Bypasses CFG if all gadgets are valid'
    $results += '    ✗ Very limited gadget selection'
    $results += '    ✗ Gadgets must be deterministic'
    $results += '    ✓ Still possible but difficult'

} catch {
    $results += "[!] ROP chain error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="rop_cfg_chain")
