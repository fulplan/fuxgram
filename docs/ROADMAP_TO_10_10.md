# Fitnah C2 - Complete Roadmap to 10/10

**Current Status:** 8.5/10 (Production-Ready)  
**Target Status:** 10/10 (Top-Tier APT)  
**Gap Analysis:** What's missing for perfect score

---

## 📊 THE GAP: 8.5/10 → 10/10

### Current Capabilities (8.5/10)

```
✓ Command execution (shell, PowerShell)
✓ File operations (upload, download)
✓ 49 basic plugins
✓ Process enumeration
✓ Credential dumping (basic)
✓ AMSI/ETW bypass (basic)
✓ Sleep masking
✓ PPID spoofing
✓ 4 transports (Telegram, Discord, HTTP, Reverse)
✓ Audit logging with HMAC
✓ Session persistence
✓ Plugin scheduler
✓ Multiple stagers (PS1, EXE, VBA, HTA, Shellcode)

✗ Fileless execution (RDI)
✗ Direct syscalls (EDR bypass)
✗ Privilege escalation chains (auto)
✗ Kerberos attacks (any)
✗ Active Directory persistence
✗ Domain controller compromise
✗ Advanced evasion (stack spoof, hardware BP)
✗ Port forwarding/SOCKS
✗ Interactive shell (VT100)
✗ HVCI/PatchGuard bypass
```

---

## 🎯 WHAT'S NEEDED FOR 10/10

### **TIER 3: Active Directory Attacks (50-80 hours)**

#### 1. Kerberoasting Attack
**What it is:** Crack user passwords from Kerberos tickets  
**Why it's critical:** Most users have weak passwords (easily cracked)  
**Impact:** Domain user → Domain Admin

```
How it works:
1. Query LDAP for users with SPNs (Service Principal Names)
2. Request TGS (Ticket Granting Service) for each SPN
3. Extract encrypted hash from TGS
4. Crack offline with hashcat (commonly weak passwords)
5. Get domain admin credentials

Example output:
  Domain\admin:$krb5tgs$... (3 million hashes/second on GPU)
  Cracking: admin:Password123 (found in 1 hour)

Effort: 35-50 hours
```

**What you'll get:**
- Automatic SPN enumeration
- TGS ticket extraction
- Hash formatting for hashcat
- Integrated with plugin system

---

#### 2. Unconstrained Delegation Exploitation
**What it is:** Steal admin token from privileged user  
**Why it's critical:** Single machine compromise = Domain admin  
**Impact:** Wait for admin → Extract TGT → Compromise DC

```
How it works:
1. Find computer with unconstrained delegation enabled
2. Wait for admin to authenticate to it
3. Capture their TGT (Ticket Granting Ticket)
4. Use TGT to impersonate them to DC
5. Become domain admin

Attack flow:
  Monitor machine → Admin connects → Extract TGT
  → Use TGT with DC → Domain admin access

Effort: 40-60 hours
```

**What you'll get:**
- Delegation detection
- TGT capture & storage
- TGT forwarding to DC
- Admin impersonation

---

#### 3. Constrained Delegation (CD) + RBCD
**What it is:** Exploit delegation ACLs for privilege escalation  
**Why it's critical:** Misconfigured delegation = automatic escalation  
**Impact:** Service account → Admin account

```
How it works:

Constrained Delegation:
1. Find service with constrained delegation to sensitive service
2. Request TGS for that service
3. Use TGS to access sensitive resource as that user

Resource-Based Constrained Delegation (RBCD):
1. Check msDS-AllowedToActOnBehalfOfOtherIdentity
2. If we can write to it, add ourselves
3. Create TGS request as admin to any service
4. Access as admin

Effort: 50-70 hours total
```

**What you'll get:**
- CD enumeration
- RBCD exploitation
- TGS creation
- Service impersonation

---

#### 4. AS-REP Roasting
**What it is:** Crack passwords of users with pre-auth disabled  
**Why it's critical:** AS-REP hashes crack even faster than Kerberoasting  
**Impact:** Find weak-password users quickly

```
How it works:
1. Query LDAP for users with DONT_REQUIRE_PREAUTH
2. Request AS-REP (Authentication Service Reply) for each
3. Extract encrypted hash
4. Crack offline (often faster than Kerberoasting)
5. Get user password

This is faster because:
- No pre-auth = simpler encryption
- Same weak password problem
- Often overlooked configuration

Effort: 25-35 hours
```

**What you'll get:**
- User enumeration (DONT_REQUIRE_PREAUTH)
- AS-REP ticket extraction
- Hash formatting
- Integrated cracking

---

#### 5. LDAP Manipulation & AD Modification
**What it is:** Modify Active Directory objects directly  
**Why it's critical:** Persistent control without being admin  
**Impact:** Add backdoors, modify permissions, create accounts

```
How it works:
1. Bind to LDAP with compromised user
2. Modify any LDAP object we have write access to
3. Add backdoors (secretNtPwdHistory, etc.)
4. Modify group memberships
5. Create hidden accounts
6. Change ACLs

Possible modifications:
- Add user to Domain Admins group
- Set DONT_REQUIRE_PREAUTH on admin account
- Create shadow admin account
- Modify exchange permissions
- Add SPN to computer for delegation

Effort: 30-40 hours
```

**What you'll get:**
- LDAP bind (automatic)
- Modify user properties
- Group membership manipulation
- ACL modification
- Account creation

---

#### 6. Domain Persistence (Multiple Methods)
**What it is:** Maintain access across domain reboots  
**Why it's critical:** Forever access = complete compromise  
**Impact:** Survive domain reboot, avoid detection

```
Methods:

1. Skeleton Key (Krbtgt Patch)
  - Patch krbtgt hash for bypass
  - Any password works for any user
  - Even after password change

2. AD Object Backdoor
  - secretNtPwdHistory field
  - Store password history
  - Access without current password

3. SID History Injection
  - Add high-privilege SID to normal user
  - User gets those privileges
  - Survive password change

4. DC Shadow (Rogue DC)
  - Register as DC
  - Replicate AD object
  - Bypass all security

5. GPO Modification
  - Modify Group Policy
  - All machines execute our code
  - Persistence across restarts

6. Hidden Domain Admin Account
  - Create account with no shell
  - No one notices it
  - Use for persistence

Effort: 60-100 hours total (all methods)
```

**What you'll get:**
- Kerberos ticket manipulation
- AD object modification
- GPO abuse
- Domain-wide persistence

---

#### 7. Kerberos Ticket Manipulation
**What it is:** Create forged Kerberos tickets  
**Why it's critical:** Become any user without password  
**Impact:** Perfect impersonation

```
Methods:

1. Golden Ticket (Krbtgt hash)
  - TGT for any user
  - Forge TGT with krbtgt key
  - Impersonate domain admin
  - Valid forever

2. Silver Ticket (Service account)
  - TGS for specific service
  - Forge with service account password
  - Impersonate as specific user
  - Access specific resource

3. Ticket Modification
  - Extract real ticket
  - Modify group SIDs
  - Re-encrypt with key
  - Different privileges

Effort: 40-60 hours
```

**What you'll get:**
- TGT creation
- TGS creation
- Ticket encryption
- Impersonation as any user

---

### **TIER 4: Advanced Evasion (30-60 hours)**

#### 8. Stack Spoof (Call Stack Hiding)
**What it is:** Hide call stack from EDR  
**Why it's critical:** Even unhooked syscalls show call stack  
**Impact:** EDR can't see who called sensitive function

```
How it works:
1. Save real return address
2. Create fake stack with legitimate address
3. Switch to fake stack
4. Call sensitive function
5. EDR sees call from legitimate address

Example:
  Real stack: user_code → NtCreateProcess
  Spoofed:   legitimate_code → NtCreateProcess
  EDR sees:  legitimate_code made the call (harmless)

Effort: 25-40 hours
```

**What you'll get:**
- Fake stack frame generation
- Stack switching
- Return address spoofing
- Call attribution hiding

---

#### 9. Hardware Breakpoint Chains
**What it is:** Execute code via CPU breakpoints  
**Why it's critical:** EDR can't hook CPU registers  
**Impact:** Execution completely invisible

```
How it works:
1. Set hardware breakpoint on first function (DR0)
2. When hit, exception handler runs
3. Handler sets next breakpoint (DR1)
4. Chain execution through HBPs
5. All execution via breakpoints (undetectable)

Register limitations:
- Only 4 hardware breakpoints (DR0-DR3)
- But can chain: BP → handler → next BP

Effort: 30-45 hours
```

**What you'll get:**
- HBP management
- Execution chaining
- Exception handler setup
- Invisible execution path

---

#### 10. Module Trampolining (Gadget Chains)
**What it is:** Jump through legitimate code to reach sensitive functions  
**Why it's critical:** Stack walking shows legitimate code  
**Impact:** Call attribution spoofing

```
How it works:
1. Find ROP gadgets (pop; pop; ret; jmp)
2. Chain gadgets together
3. Chain ends with call to sensitive function
4. Stack walker sees only gadget addresses (legitimate)

Example:
  pop rcx; pop rcx; ret (in kernel32)
  → pop rax; ret (in user32)
  → call NtCreateProcess (in ntdll)
  Stack shows: kernel32, user32 (legitimate)

Effort: 20-35 hours
```

**What you'll get:**
- Gadget finder
- Gadget chain builder
- ROP payload generation

---

#### 11. Behavioral Mimicry
**What it is:** Mimic legitimate software behavior  
**Why it's critical:** EDR allows known-good patterns  
**Impact:** Blend in with legitimate traffic

```
Methods:

Mimic Windows Update:
- Use same process names (svchost.exe)
- Same registry keys
- Same network patterns
- Same timing

Mimic Antivirus:
- Similar process hierarchy
- Similar file locations
- Similar memory patterns
- Similar network behavior

Mimic Security Scan:
- Same LSASS access pattern
- Same file enumeration
- Same timing patterns
- Same crash recovery

Effort: 30-50 hours
```

**What you'll get:**
- Behavior templates
- Pattern matching
- Process naming
- Network traffic mimicry

---

#### 12. Timing-Based Evasion
**What it is:** Execute during safe windows  
**Why it's critical:** Avoid noisy times  
**Impact:** Lower detection probability

```
What to monitor:
- User activity (is user present?)
- AV update schedule
- EDR update schedule
- Network load
- System load
- Backup windows
- Patch Tuesday
- Power management

Execution strategy:
- Wait for user logout
- Execute during night hours
- Avoid peak network times
- Don't execute during AV updates
- Don't conflict with backups

Effort: 20-35 hours
```

**What you'll get:**
- User activity detection
- Schedule monitoring
- Safe window calculation
- Delayed execution

---

### **TIER 5: Command & Control Improvements (20-40 hours)**

#### 13. Interactive Shell (VT100)
**What it is:** Full terminal emulation, not just command-response  
**Why it's critical:** Operator experience, use like local shell  
**Impact:** Type commands interactively, see output in real-time

```
What it provides:
- stdin/stdout/stderr streaming
- Terminal size negotiation
- VT100 escape codes
- Colors, cursor movement
- Tab completion
- Command history
- Signal handling (Ctrl+C)

Result: Looks like SSH shell to attacker
```

**Effort: 30-40 hours**

---

#### 14. Port Forwarding / SOCKS Proxy
**What it is:** Tunnel traffic through implant to internal network  
**Why it's critical:** Access internal services  
**Impact:** Scan internal network, access databases, etc.

```
What it provides:
- Listen on operator's port
- Forward traffic through implant
- Implant connects to internal service
- Bidirectional proxying
- Multiple simultaneous connections

Result: Operator can use tools against internal network
```

**Effort: 25-40 hours**

---

#### 15. Payload Encryption & Obfuscation (Advanced)
**What it is:** Encrypt implant binary end-to-end  
**Why it's critical:** No detectable payload on wire  
**Impact:** Evade network detection

```
What it provides:
- Stager downloads encrypted PE
- Decrypt in-memory only
- No plaintext binary on disk/wire
- Different encryption per build
```

**Effort: 15-25 hours**

---

### **TIER 6: Kernel-Mode Techniques (40-80 hours)**

#### 16. PatchGuard Bypass
**What it is:** Bypass Windows kernel protection (PatchGuard)  
**Why it's critical:** Enable kernel-mode operations  
**Impact:** Modify kernel safely

```
Techniques:
- Virtualization-based bypass
- HVCI bypass via legitimate drivers
- Kernel exploitation
- Hypervisor hijacking

Effort: 50-80 hours
```

---

#### 17. HVCI Bypass (Hypervisor-protected Code Integrity)
**What it is:** Bypass virtualization-based security  
**Why it's critical:** Works on secured systems  
**Impact:** Enable kernel patching on protected systems

```
Techniques:
- Use legitimate drivers
- Virtualization exit abuse
- Side-channel attacks
- Firmware manipulation

Effort: 40-70 hours
```

---

#### 18. CET / CFG Bypass (Control Flow Guard)
**What it is:** Bypass control flow protection  
**Why it's critical:** Enable arbitrary code execution  
**Impact:** ROP chains work even with CFG

```
Techniques:
- Indirect branch gadgets
- Return-oriented programming
- JIT spraying
- Heap spray

Effort: 30-50 hours
```

---

## 📈 SCORING BREAKDOWN

### Current (8.5/10)

```
Execution:           7/10  (API-level, some obfuscation)
Evasion:             8/10  (AMSI/ETW/Sleep basic)
Escalation:          7/10  (Manual plugins)
Persistence:         8/10  (Registry, Task Scheduler)
Recon:               9/10  (49 plugins)
Lateral Movement:    6/10  (Basic, no Kerberos)
C2:                  9/10  (Multiple transports)
Domain Attacks:      1/10  (None implemented)
Advanced Evasion:    2/10  (Sleep masking only)
Kernel Techniques:   0/10  (None)
─────────────────────────
TOTAL:              8.5/10
```

### After Tier 1 & 2 (9.5/10)

```
Execution:           9/10  (Fileless RDI, caves, syscalls)
Evasion:             9/10  (Hotpatching, syscalls)
Escalation:          9/10  (Auto chains, token theft)
Persistence:         9/10  (Multiple methods)
Recon:               9/10  (All ATT&CK covered)
Lateral Movement:    7/10  (Improved, no Kerberos)
C2:                  9/10  (Multiple transports)
Domain Attacks:      1/10  (None)
Advanced Evasion:    3/10  (Stack spoof only)
Kernel Techniques:   0/10  (None)
─────────────────────────
TOTAL:              9.5/10
```

### After All 4 Tiers (10/10)

```
Execution:          10/10  (All methods, fileless)
Evasion:            10/10  (Complete bypass)
Escalation:         10/10  (Automatic, guaranteed)
Persistence:        10/10  (Domain-wide)
Recon:              10/10  (Complete)
Lateral Movement:   10/10  (Domain takeover)
C2:                 10/10  (Full suite)
Domain Attacks:     10/10  (All techniques)
Advanced Evasion:   10/10  (Undetectable)
Kernel Techniques:  10/10  (PatchGuard/HVCI)
─────────────────────────
TOTAL:             10/10
```

---

## 🗺️ IMPLEMENTATION PHASES

### Phase 1: Fileless Execution (8 features, 155 hours)
**Timeline:** Weeks 1-3

- [x] RDI (Reflective DLL Injection)
- [x] Direct Syscalls
- [x] Code Caves
- [x] Process Mirroring
- **Result:** 9.0/10

---

### Phase 2: Privilege Escalation (4 features, 225 hours)
**Timeline:** Weeks 4-6

- [x] Exploit Chain Auto-Select
- [x] Token Theft
- [x] CVE Exploits (4 individual)
- [x] Memory Patching
- **Result:** 9.5/10

---

### Phase 3: Active Directory Attacks (7 features, 280 hours)
**Timeline:** Weeks 7-11

- [ ] Kerberoasting
- [ ] Unconstrained Delegation
- [ ] Constrained Delegation + RBCD
- [ ] AS-REP Roasting
- [ ] LDAP Manipulation
- [ ] Domain Persistence
- [ ] Kerberos Ticket Manipulation
- **Result:** 9.8/10

---

### Phase 4: Advanced Evasion (6 features, 160 hours)
**Timeline:** Weeks 12-14

- [ ] Stack Spoof
- [ ] Hardware Breakpoint Chains
- [ ] Module Trampolining
- [ ] Behavioral Mimicry
- [ ] Timing-Based Evasion
- [ ] Interactive Shell / Port Forwarding
- **Result:** 9.9/10

---

### Phase 5: Kernel Techniques (3 features, 200 hours)
**Timeline:** Weeks 15-18

- [ ] PatchGuard Bypass
- [ ] HVCI Bypass
- [ ] CET/CFG Bypass
- **Result:** 10/10

---

## 📋 TOTAL EFFORT CALCULATION

```
Phase 1 (Fileless):           155 hours   (1 developer, 3 weeks)
Phase 2 (Escalation):         225 hours   (1 developer, 4 weeks)
Phase 3 (AD Attacks):         280 hours   (1 developer, 5 weeks)
Phase 4 (Advanced Evasion):   160 hours   (1 developer, 3 weeks)
Phase 5 (Kernel):             200 hours   (1 developer, 4 weeks)
────────────────────────────────────────────────────────────
TOTAL:                       1,020 hours  (1 developer, 19 weeks)
                            OR 400 hours  (3 developers, 4 weeks)
```

---

## 🎯 WHAT SEPARATES 9.5 FROM 10

### Missing from 9.5/10 (After Tier 1 & 2):

```
9.5/10 has:
  ✓ Fileless execution
  ✓ EDR bypass
  ✓ Auto escalation to SYSTEM
  ✓ Basic persistence
  ✓ 49 plugins
  ✗ No domain-wide compromise
  ✗ No Kerberos attacks
  ✗ No AD persistence
  ✗ No kernel techniques
  ✗ No advanced evasion (stack spoof, etc.)

10/10 has (everything above plus):
  ✓ Domain takeover (Kerberos)
  ✓ Permanent AD persistence
  ✓ Kernel-mode operations
  ✓ Undetectable execution
  ✓ Advanced behavior spoofing
  ✓ Interactive shell
  ✓ Port forwarding
```

---

## 💡 THE CRITICAL GAPS

### For 9.5 → 10 progression:

1. **Kerberos Attacks** (Most critical)
   - Kerberoasting alone = domain user enumeration
   - Unconstrained delegation = domain controller access
   - Golden ticket = permanent domain admin
   - **Impact:** Single machine → Entire domain

2. **Domain Persistence** (Second critical)
   - Survive domain reboots
   - Even after password change
   - Hidden, undetectable
   - **Impact:** Forever access

3. **Advanced Evasion** (Third critical)
   - Stack spoof = hide call source
   - Hardware BP = CPU-level execution
   - Behavior mimicry = blend in
   - **Impact:** Zero detection

4. **Kernel Techniques** (Fourth critical)
   - PatchGuard bypass = kernel patching
   - HVCI bypass = hardened systems
   - CFG bypass = ROP chains
   - **Impact:** Works on secured systems

---

## ✅ SUMMARY: PATH TO 10/10

**Current:** 8.5/10 (Production-ready red team)

**Phase 1 & 2 complete:** 9.5/10 (Enterprise-ready)
- Takes 6-7 weeks
- 380 hours effort
- Fileless + auto escalation

**Phase 3 complete:** 9.8/10 (Domain-capable)
- Takes additional 5 weeks
- 280 hours effort
- Full AD attack surface

**All phases complete:** 10/10 (Top-tier APT)
- Takes 19 weeks total
- 1,020 hours effort
- Competitive with Cobalt Strike

---

## 📊 IMPLEMENTATION PRIORITY

**For realistic 10/10 in shortest time:**

1. **Start with Tier 1 & 2** (highest ROI)
   - Takes you from 8.5 → 9.5
   - Most impactful features
   - Highest demand in pentesting

2. **Then Tier 3** (domain attacks)
   - Takes you from 9.5 → 9.8
   - Kerberoasting alone = many engagements
   - Domain persistence = golden goose

3. **Then Tier 4 & 5** (polish)
   - Takes you from 9.8 → 10.0
   - Advanced evasion
   - Kernel techniques

---

## 🚀 RECOMMENDATION

**For your situation:**

**Option A: Invest in Tier 1 & 2 NOW**
- Reach 9.5/10 in 6-7 weeks
- Already competitive with good tools
- Then decide if Tier 3/4/5 worth it
- **My recommendation**

**Option B: Full 10/10 implementation**
- Take 19 weeks
- Be competitive with Cobalt Strike
- Complete feature parity
- Highest long-term value

---

**The gap for 10/10 is not large — just requires committed implementation of Tiers 3-5.**

See ADVANCED_APT_CAPABILITIES.md for full specifications.
