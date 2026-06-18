/*
 * utils.h — string helpers, base64, minimal JSON builder
 */
#pragma once
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

/* ── base64 ─────────────────────────────────────────────────────────────── */
char   *b64_encode(const uint8_t *src, size_t len);
uint8_t *b64_decode(const char *src, size_t *out_len);

/* ── JSON builder (minimal, no heap parsing needed) ─────────────────────── */
/* Append a key:string pair to a buffer. Returns new length. */
int json_add_str(char *buf, int pos, int cap, const char *key, const char *val);
int json_add_int(char *buf, int pos, int cap, const char *key, long long val);

/* ── simple JSON value extractor (reads first occurrence of "key":"value") */
/* Caller must free() the returned string. Returns NULL if not found.       */
char *json_get_str(const char *json, const char *key);
long long json_get_int(const char *json, const char *key);

/* ── XOR de-obfuscation for compile-time string literals ─────────────────── */
/*   Usage: XOR_STR(buf, "\x41\x42", 2, 0x13)                               */
static inline void xor_str(char *out, const char *enc, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++) out[i] = enc[i] ^ key;
    out[len] = '\0';
}

/* ── misc ────────────────────────────────────────────────────────────────── */
char *str_dup(const char *s);
void  secure_zero(void *p, size_t n);
