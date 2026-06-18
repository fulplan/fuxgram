/*
 * http.h — WinINet wrapper for Telegram Bot API calls
 * All traffic goes to api.telegram.org:443 (HTTPS).
 * No external libs — only WinINet (wininet.dll, always present on Windows).
 */
#pragma once
#include <windows.h>
#include <stddef.h>

#define TG_API_HOST    "api.telegram.org"
#define TG_API_PORT    443
#define HTTP_TIMEOUT   30000   /* ms */
#define RECV_CHUNK     4096

typedef struct {
    char  *body;     /* caller must free() */
    DWORD  status;   /* HTTP status code   */
} HttpResponse;

/*
 * tg_post — POST JSON body to /bot<TOKEN>/<method>
 * Returns HttpResponse; body is NULL on error.
 */
HttpResponse tg_post(const char *token, const char *method,
                     const char *json_body);

/* Free an HttpResponse returned by tg_post */
void http_response_free(HttpResponse *r);
