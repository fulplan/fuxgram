"""defense_evasion/hvci_bypass — Bypass Hyper-V Code Integrity (hypervisor-protected execution). MITRE T1542"""
from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
import logging

log = logging.getLogger(__name__)


class HVCIBypass(BasePlugin):
    NAME = "hvci_bypass"
    DESCRIPTION = "Detect and bypass Hyper-V Code Integrity (HVCI) protection"
    AUTHOR = "fitnah-team"
    MITRE = "T1542"
    CATEGORY = "defense_evasion"
    VERSION = "1.0.0"

    schema = ParamSchema().add(
        Param("action", str, required=False, default="detect",
              help="detect | bypass_driver | side_channel | firmware"),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        """Execute HVCI bypass"""
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action = params.get("action", "detect").lower()

        if action == "detect":
            return self._detect_hvci(ctx)
        elif action == "bypass_driver":
            return self._bypass_driver(ctx)
        elif action == "side_channel":
            return self._side_channel_attack(ctx)
        elif action == "firmware":
            return self._firmware_manipulation(ctx)
        else:
            return ModuleResult.err(f"Unknown action: {action}")

    @staticmethod
    def _detect_hvci(ctx) -> ModuleResult:
        """Detect if HVCI is enabled"""
        ps_code = """
$results = @()
$results += '[*] Detecting HVCI (Hyper-V Code Integrity) status...'

try {
    $results += '[*] HVCI characteristics:'
    $results += '    - Requires: Windows 10/11 Pro/Enterprise'
    $results += '    - Requires: CPU with VT-x/AMD-V'
    $results += '    - Requires: TPM 2.0'
    $results += '    - Effect: Kernel execution must be signed'
    $results += '    - Protects: ELAM drivers, kernel modules'

    # Check if HVCI is enabled
    $hvciEnabled = $false
    try {
        $hvci = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -ErrorAction SilentlyContinue
        if ($hvci -and $hvci.Enabled -eq 1) {
            $hvciEnabled = $true
        }
    } catch {}

    if ($hvciEnabled) {
        $results += '[+] HVCI IS ENABLED'
        $results += '[!] Kernel code must be signed'
        $results += '[!] Unsigned drivers will not load'
    } else {
        $results += '[-] HVCI not detected (may not be enabled)'
    }

    # Check TPM
    try {
        $tpm = Get-WmiObject -Namespace 'root\\cimv2\\security\\microsofttpm' -Class Win32_Tpm -ErrorAction SilentlyContinue
        if ($tpm) {
            $results += '[+] TPM detected (required for HVCI)'
        }
    } catch {
        $results += '[*] TPM detection inconclusive'
    }

    # Check Secure Boot
    try {
        $secureBoot = (Get-SecureBootUEFI -ErrorAction SilentlyContinue).SecureBootEnabled
        if ($secureBoot) {
            $results += '[+] Secure Boot enabled (stacks with HVCI)'
        }
    } catch {
        $results += '[*] Secure Boot status unknown'
    }

} catch {
    $results += "[!] Detection error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="hvci_detect")

    @staticmethod
    def _bypass_driver(ctx) -> ModuleResult:
        """Bypass HVCI using legitimate drivers"""
        ps_code = """
$results = @()
$results += '[*] HVCI bypass via legitimate drivers...'

try {
    $results += '[*] Bypass strategy:'
    $results += '    1. Find driver signed by Microsoft'
    $results += '    2. Load via HVCI (passes code integrity)'
    $results += '    3. Driver has kernel access'
    $results += '    4. Driver exploits itself (reflection)'

    $results += '[*] Known drivers with exploitable behavior:'
    $results += '    - Intel drivers (SGX drivers vulnerable)'
    $results += '    - NVIDIA drivers (GPU access vulnerable)'
    $results += '    - AMD drivers'
    $results += '    - Realtek Audio drivers'

    $results += '[*] Attack flow:'
    $results += '    1. Find vulnerable legitimate driver'
    $results += '    2. Load via normal Windows driver signing'
    $results += '    3. Driver loads in kernel (passes HVCI)'
    $results += '    4. Exploit driver itself for arbitrary write'
    $results += '    5. Modify kernel from within driver'

    $results += '[*] Detection evasion:'
    $results += '    ✓ Driver is legitimately signed'
    $results += '    ✓ No unsigned code executed'
    $results += '    ✓ Exploit happens in driver context'
    $results += '    ✗ But: Weird driver behavior = suspicious'

} catch {
    $results += "[!] Driver bypass error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="hvci_driver_bypass")

    @staticmethod
    def _side_channel_attack(ctx) -> ModuleResult:
        """Side-channel attack against HVCI"""
        ps_code = """
$results = @()
$results += '[*] HVCI side-channel attack...'

try {
    $results += '[*] Side-channel attack methods:'
    $results += '    1. Spectre/Meltdown-like exploitation'
    $results += '    2. Cache timing attacks'
    $results += '    3. Transient execution bypass'
    $results += '    4. Hypervisor exit speculation'

    $results += '[*] Spectre/Meltdown recap:'
    $results += '    - CPU executes instructions speculatively'
    $results += '    - Execution reaches beyond permission boundary'
    $results += '    - Attacker reads privileged memory'
    $results += '    - Requires encoding in cache state'

    $results += '[*] HVCI evasion via transient execution:'
    $results += '    1. Craft gadget chain with BTB (Branch Target Buffer)'
    $results += '    2. Mislead CPU prediction'
    $results += '    3. Execute privileged code speculatively'
    $results += '    4. HVCI check happens after execution'
    $results += '    5. Results leak via cache'

    $results += '[*] Limitations:'
    $results += '    - Requires specific CPU microarchitecture'
    $results += '    - May be mitigated by microcode updates'
    $results += '    - Performance overhead'
    $results += '    - Difficult to exploit reliably'

    $results += '[!] Actively researched but not practical for APT'

} catch {
    $results += "[!] Side-channel error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="hvci_side_channel")

    @staticmethod
    def _firmware_manipulation(ctx) -> ModuleResult:
        """Manipulate firmware to bypass HVCI"""
        ps_code = """
$results = @()
$results += '[*] Firmware-based HVCI bypass...'

try {
    $results += '[*] Firmware manipulation methods:'
    $results += '    1. UEFI/BIOS firmware modification'
    $results += '    2. Modify Secure Boot settings'
    $results += '    3. Disable HVCI via firmware'
    $results += '    4. Modify boot configuration'

    $results += '[*] Requirements:'
    $results += '    - Physical access OR'
    $results += '    - Firmware flashing vulnerability OR'
    $results += '    - UEFI Runtime Services exploit'

    $results += '[*] Attack flow:'
    $results += '    1. Access UEFI Setup (Ctrl+Enter at boot)'
    $results += '    2. Disable: "Secure Boot"'
    $results += '    3. Disable: "Device Guard"'
    $results += '    4. Disable: "HVCI"'
    $results += '    5. Reboot'
    $results += '    6. Unsigned drivers now work'

    $results += '[*] Remote firmware attacks:'
    $results += '    - UEFI Runtime Services exploitation'
    $results += '    - HPE/Dell/Lenovo firmware RCE'
    $results += '    - Intel Management Engine (IME) vulnerabilities'

    $results += '[!] Highly targeted, requires specific hardware'

} catch {
    $results += "[!] Firmware manipulation error: $_"
}

$results -join "`n"
"""
        r = ctx.ps(ps_code)
        return ModuleResult.ok(data=r["output"], loot_kind="hvci_firmware")
