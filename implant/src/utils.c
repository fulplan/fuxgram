/*
 * utils.c — Advanced implant utility functions
 */
#include "utils.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── String Hashing for Anti-Analysis ────────────────────────────────────── */

/**
 * hash_str: FNV-1a 32-bit hash for string obfuscation
 */
uint32_t hash_str(const char *str) {
    uint32_t hash = 2166136261u;
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 16777619u;
    }
    return hash;
}

/* ── base64 ─────────────────────────────────────────────────────────────── */

static const char B64_TBL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *b64_encode(const uint8_t *src, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char  *out     = malloc(out_len);
    if (!out) return NULL;
    size_t i, j;
    for (i = 0, j = 0; i < len;) {
        uint32_t a = i < len ? src[i++] : 0;
        uint32_t b = i < len ? src[i++] : 0;
        uint32_t c = i < len ? src[i++] : 0;
        uint32_t t = (a << 16) | (b << 8) | c;
        out[j++] = B64_TBL[(t >> 18) & 0x3F];
        out[j++] = B64_TBL[(t >> 12) & 0x3F];
        out[j++] = B64_TBL[(t >>  6) & 0x3F];
        out[j++] = B64_TBL[(t      ) & 0x3F];
    }
    size_t pad = len % 3;
    if (pad == 1) { out[j-2] = '='; out[j-1] = '='; }
    else if (pad == 2) { out[j-1] = '='; }
    out[j] = '\0';
    return out;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

uint8_t *b64_decode(const char *src, size_t *out_len) {
    size_t slen = strlen(src);
    if (slen % 4 != 0) return NULL;
    size_t   dlen = slen / 4 * 3;
    uint8_t *out  = malloc(dlen + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < slen; i += 4) {
        int a = b64_val(src[i]);
        int b = b64_val(src[i+1]);
        int c = src[i+2] == '=' ? 0 : b64_val(src[i+2]);
        int d = src[i+3] == '=' ? 0 : b64_val(src[i+3]);
        if (a < 0 || b < 0) { free(out); return NULL; }
        out[j++] = (uint8_t)((a << 2) | (b >> 4));
        if (src[i+2] != '=') out[j++] = (uint8_t)((b << 4) | (c >> 2));
        if (src[i+3] != '=') out[j++] = (uint8_t)((c << 6) | d);
    }
    if (out_len) *out_len = j;
    out[j] = '\0';
    return out;
}

/* ── JSON builder ────────────────────────────────────────────────────────── */

static int json_escape(char *buf, int pos, int cap, const char *s) {
    if (pos >= cap - 1) return pos;
    for (; *s && pos < cap - 2; s++) {
        if (*s == '"' || *s == '\\') {
            buf[pos++] = '\\';
            if (pos < cap - 1) buf[pos++] = *s;
        } else if (*s == '\n') {
            buf[pos++] = '\\'; if (pos < cap-1) buf[pos++] = 'n';
        } else if (*s == '\r') {
            buf[pos++] = '\\'; if (pos < cap-1) buf[pos++] = 'r';
        } else {
            buf[pos++] = *s;
        }
    }
    return pos;
}

int json_add_str(char *buf, int pos, int cap, const char *key, const char *val) {
    if (!val) val = "";
    pos += snprintf(buf + pos, cap - pos, "\"%s\":\"", key);
    pos  = json_escape(buf, pos, cap, val);
    if (pos < cap - 1) buf[pos++] = '"';
    return pos;
}

int json_add_int(char *buf, int pos, int cap, const char *key, long long val) {
    return pos + snprintf(buf + pos, cap - pos, "\"%s\":%lld", key, val);
}

/* ── JSON extractor ──────────────────────────────────────────────────────── */

char *json_get_str(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char pat[256];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p == ' ') p++;
    if (*p != '"') return NULL;
    p++;
    const char *start = p;
    size_t len = 0;
    while (*p && *p != '"') {
        if (*p == '\\') { p++; if (*p) p++; len++; }
        else { p++; len++; }
    }
    char *out = malloc(len + 1);
    if (!out) return NULL;
    const char *s = start;
    size_t j = 0;
    while (*s && *s != '"' && j < len) {
        if (*s == '\\') {
            s++;
            switch (*s) {
                case 'n': out[j++] = '\n'; break;
                case 'r': out[j++] = '\r'; break;
                case 't': out[j++] = '\t'; break;
                default:  out[j++] = *s;   break;
            }
            if (*s) s++;
        } else {
            out[j++] = *s++;
        }
    }
    out[j] = '\0';
    return out;
}

long long json_get_int(const char *json, const char *key) {
    if (!json || !key) return 0;
    char pat[256];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p == ' ') p++;
    return strtoll(p, NULL, 10);
}

/* ── Memory and String Utilities ────────────────────────────────────────── */

void secure_zero(void *p, size_t n) {
    if (!p) return;
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

void xor_str(char *dst, const char *src, size_t n, uint8_t key) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = src[i] ^ key;
    }
}

char* hex_to_bytes(const char *hex, size_t *out_len) {
    if (!hex) return NULL;
    size_t len = strlen(hex);
    if (len % 2 != 0) return NULL;
    
    *out_len = len / 2;
    char *bytes = malloc(*out_len);
    if (!bytes) return NULL;
    
    for (size_t i = 0; i < *out_len; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
    }
    return bytes;
}

char* str_dup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

/* ── Error Handling ──────────────────────────────────────────────────────── */

void log_error(const char *msg) {
#ifdef _DEBUG
    fprintf(stderr, "[!] ERROR: %s (Last Error: %lu)\n", msg, GetLastError());
#endif
}
