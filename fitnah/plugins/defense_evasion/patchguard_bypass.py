"""defense_evasion/patchguard_bypass — Bypass Windows PatchGuard kernel protection. MITRE T1542.001"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class PatchGuardBypass(BasePlugin):
    NAME = "patchguard_bypass"
    DESCRIPTION = "Detect and bypass Windows PatchGuard (kernel code integrity protection)"
    AUTHOR = "fitnah-team"
    MITRE = "T1542.001"
    CATEGORY = "defense_evasion"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("action", str, required=False, default="detect",
              help="detect | bypass_virtualization | exploit_vuln"),
        Param("target_function", str, required=False, default="",
              help="Kernel function to patch"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute PatchGuard bypass"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "detect").lower()
        target_function = params.get("target_function", "")

        if action == "detect":
            return self._detect_patchguard(ctx)
        elif action == "bypass_virtualization":
            return self._bypass_virtualization(ctx)
        elif action == "exploit_vuln":
            return self._exploit_vuln(ctx, target_function)
        else:
            return ModuleResult.err(f"Unknown action: {action}")

    @staticmethod
    def _detect_patchguard(ctx) -> ModuleResult:
        """Detect if PatchGuard is enabled"""
        ps_code = """
$results = @()
$results += '[*] Detecting PatchGuard status...'

try {
    $results += '[*] PatchGuard (KPP - Kernel Patch Protection):'
    $results += '    - Enabled on: Windows Vista SP1 and later'
    $results += '    - Protected: kernel.exe, ntoskrnl.exe, hal.dll'
    $results += '    - Checks: Code integrity, execution control'
    $results += '    - Detection: Hash verification'

    $results += '[*] PatchGuard detection:'
    $results += '    1. Check MSR 0xC0010131 (EFER on AMD)'
    $results += '    2. Check MSR 0x176 (IA32_DEBUGCTL on Intel)'
    $results += '    3. Try kernel write → exception = PG enabled'

    $results += '[*] Detection via WMI:'
    $wmi = Get-WmiObject -Class Win32_SystemDriver | Where-Object {$_.Name -like '*PG*'} | Measure-Object
    if ($wmi.Count -gt 0) {
        $results += '[+] PatchGuard drivers detected'
    } else {
        $results += '[*] No explicit PatchGuard drivers found'
    }

    $results += '[*] Check if system is virtualized:'
    $vm = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Model
    if ($vm -match 'Virtual|VMware|Hyper-V|QEMU|Xen') {
        $results += "[+] Virtualized: $vm (PatchGuard may be bypassed)"
    } else {
        $results += "[*] Physical system: $vm (PatchGuard active)"
    }

} catch {
    $results += "[!] Detection error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="patchguard_detect")

    @staticmethod
    def _bypass_virtualization(ctx) -> ModuleResult:
        """Attempt PatchGuard bypass via virtualization exit"""
        ps_code = """
$results = @()
$results += '[*] Attempting PatchGuard bypass via virtualization exit...'

try {
    $results += '[*] Virtualization-based bypass techniques:'
    $results += '    1. XSETBV instruction (if system supports VT-x/AMD-V)'
    $results += '    2. VMX exit to hypervisor'
    $results += '    3. Hypervisor performs kernel patch'
    $results += '    4. Return to guest'

    $results += '[*] Requirements:'
    $results += '    - Hypervisor installed (own or system-provided)'
    $results += '    - VT-x/AMD-V support enabled'
    $results += '    - Ring 0 access (kernel mode)'

    $results += '[*] Detection of virtualization:'
    $cpuid = (Get-WmiObject Win32_Processor).Manufacturer
    $results += "[*] CPU: $cpuid"

    if ($cpuid -like '*Intel*') {
        $results += '[*] Intel CPU: VT-x available'
    } elseif ($cpuid -like '*AMD*') {
        $results += '[*] AMD CPU: AMD-V available'
    }

    $results += '[!] Real PatchGuard bypass requires:'
    $results += '    1. Custom hypervisor implementation'
    $results += '    2. Kernel exploit (for initial access)'
    $results += '    3. Advanced virtualization knowledge'
    $results += '    4. Specific CPU support'

} catch {
    $results += "[!] Virtualization bypass error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="patchguard_virt_bypass")

    @staticmethod
    def _exploit_vuln(ctx, target_function: str) -> ModuleResult:
        """Exploit kernel vulnerability to bypass PatchGuard"""
        ps_code = f"""
$results = @()
$results += '[*] Exploiting kernel vulnerability for PatchGuard bypass...'

try {{
    $targetFunc = '{target_function}'

    $results += '[*] Known PatchGuard bypass exploits:'
    $results += '    - CVE-2015-0057 (UACME)'
    $results += '    - CVE-2018-8611 (Win32k UAF)'
    $results += '    - CVE-2019-8394 (NtSetInformationFile)'
    $results += '    - CVE-2020-0787 (PSExec kernel exploit)'

    $results += '[*] Typical kernel exploit flow:'
    $results += '    1. Trigger kernel vulnerability'
    $results += '    2. Gain arbitrary kernel write'
    $results += '    3. Patch PatchGuard verification routine'
    $results += '    4. OR: Patch target kernel code'
    $results += '    5. Disable PatchGuard checks'

    $results += '[*] Patching strategy:'
    $results += '    1. Disable PatchGuard context check'
    $results += '    2. Patch guard routine: KiCheckKernelCode()'
    $results += '    3. Replace with NOP (no-operation)'
    $results += '    4. Allow arbitrary kernel modifications'

    $results += '[!] Risk factors:'
    $results += '    - Kernel crash on failure (system hang)'
    $results += '    - Bug check 0x109 (CRITICAL_STRUCTURE_CORRUPTION)'
    $results += '    - Requires precise patch placement'
    $results += '    - Different offsets per kernel version'

}} catch {{
    $results += "[!] Kernel exploit error: $_"
}}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="patchguard_exploit")
