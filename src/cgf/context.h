/*
 * Copyright (C) 2026 by Open5GS Contributors
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef CGF_CONTEXT_H
#define CGF_CONTEXT_H

#include "ogs-app.h"
#include "ogs-core.h"
#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __cgf_log_domain;
#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __cgf_log_domain

#define CGF_MAX_PEERS            4
/* Parallel drain workers (cgf.workers: N). 1 = legacy single-thread
 * behaviour (default); >1 spawns independent drain threads, each with
 * its own peer sockets / GTP' sequence space / spool file. */
#define CGF_MAX_WORKERS          8
#define CGF_MAX_INFLIGHT         64
#define CGF_DEFAULT_GTPP_PORT    3386
#define CGF_DEFAULT_MAX_BYTES_PER_PACKET  1400
/* Conservative default so single-worker installs see no behaviour
 * change; operators can raise this (and cgf.workers) together. */
#define CGF_DEFAULT_MAX_INFLIGHT            16

/* One outstanding DataRecordTransferRequest slot per peer. GTP' allows
 * multiple in-flight requests distinguished by sequence number; the
 * window size is capped by max_inflight in cgf_context_t. */
typedef struct cgf_xact_s {
    bool active;
    uint16_t seq;
    /* Packet Transfer Command used in this request (TS 32.295 §6.2.4.5.2). */
    uint8_t ptc;
    uint32_t retries;
    ogs_time_t sent_at;
    ogs_pkbuf_t *pkbuf;
    struct cgf_spool_file_s *file;
    size_t batch_start;
    uint32_t records_in_batch;
} cgf_xact_t;

/* Peer role. Only the primary is used under normal conditions; failover
 * switches to a secondary when the primary stops answering echoes.
 * In send_mode=round_robin every UP peer is an equal send target and
 * role only picks the initial RR cursor. */
typedef enum {
    CGF_PEER_ROLE_PRIMARY = 0,
    CGF_PEER_ROLE_SECONDARY = 1
} cgf_peer_role_e;

/* How DTRRs are distributed across configured peers. */
typedef enum {
    /* Legacy: only active_peer_idx receives CDRs; secondaries are
     * used solely when the active peer is marked DOWN. */
    CGF_SEND_MODE_FAILOVER = 0,
    /* Active-active: each newly opened spool file is assigned to the
     * next UP peer (round-robin). A file stays pinned to that peer
     * for its lifetime (or until the peer dies, then it fails over).
     * Use workers >= number of peers for parallel drain across peers. */
    CGF_SEND_MODE_ROUND_ROBIN = 1
} cgf_send_mode_e;

typedef enum {
    CGF_PEER_STATE_DOWN = 0,   /* never alive, or gave up */
    CGF_PEER_STATE_PROBING,    /* echo in flight, not yet confirmed */
    CGF_PEER_STATE_UP          /* echo recently answered */
} cgf_peer_state_e;

typedef struct cgf_peer_s {
    cgf_peer_role_e role;
    const char *address_str;
    uint16_t port;

    ogs_sockaddr_t *addr;       /* resolved sockaddr list (first used) */
    ogs_sock_t *sock;           /* connected UDP socket */
    ogs_poll_t *poll;           /* OGS_POLLIN registration */

    cgf_peer_state_e state;

    /*
     * Per-peer GTP' sequence-number space. A single 16-bit counter is
     * shared by Echo Request and DataRecordTransferRequest, as required
     * by TS 32.295 §6.1.1. Starts at 0 on CDF (re)start and after a peer
     * Recovery change (CGF restart); increments on every transmit and
     * wraps freely.
     */
    uint16_t next_seq;

    /* Liveness bookkeeping. */
    uint32_t consecutive_missed_echoes;
    ogs_time_t last_echo_sent;
    ogs_time_t last_echo_received;
    uint8_t peer_restart_counter;   /* last Recovery IE value observed */
    bool peer_restart_counter_valid;

    cgf_xact_t xacts[CGF_MAX_INFLIGHT];
} cgf_peer_t;

typedef struct cgf_context_s {
    /* Spool layout (shared with the SMF-side writer). */
    const char *spool_dir;
    char *ready_dir;
    char *done_dir;
    char *failed_dir;
    /*
     * processing/<worker_id>/ — files claimed (atomically renamed out
     * of ready/) by a drain worker while in flight. Only used when
     * `workers` > 1; NULL/unused in legacy single-thread mode.
     */
    char *processing_dir;

    /*
     * Number of parallel drain worker threads (cgf.workers: N, 1..
     * CGF_MAX_WORKERS). 1 (default) preserves the legacy single-thread
     * main-FSM drain path exactly. >1 spawns that many worker threads,
     * each opening its own UDP sockets to the configured peers (hence
     * its own source port and GTP' sequence/xact space) and claiming
     * disjoint spool files out of ready/.
     */
    uint32_t workers;

    /* Identity. Sent as Address-of-Recording-Entity / Node Name IE
     * where relevant; also used for logging. */
    const char *node_id;

    /* Peers (primary first, then secondaries in declaration order). */
    cgf_peer_t peers[CGF_MAX_PEERS];
    uint32_t num_of_peers;
    uint32_t active_peer_idx;   /* failover active / RR cursor */
    cgf_send_mode_e send_mode;  /* failover (default) or round_robin */

    /* Timers. */
    ogs_timer_t *t_echo;        /* fires every echo_interval_s */
    ogs_timer_t *t_rto;         /* fires at request retransmit boundary */
    ogs_timer_t *t_spool;       /* fires every spool_poll_ms */

    /* Tunables (all milliseconds unless noted). */
    uint32_t echo_interval_s;
    uint32_t request_rto_ms;
    uint32_t request_retries;
    uint32_t failover_after_missed_echoes;
    uint32_t spool_poll_ms;

    /* Batching caps for DataRecordTransferRequest. */
    uint32_t max_records_per_packet;
    uint32_t max_bytes_per_packet;
    uint32_t max_inflight;      /* pipelined DTRRs per peer (1..CGF_MAX_INFLIGHT) */
    /*
     * How many spool files a drain pipeline (main thread or one worker)
     * may hold open at once. Keeping more than one file open lets the
     * GTP' window stay full while earlier files wait for ACKs — without
     * this, send_offset==EOF stalls the whole drain until every ACK
     * returns. Defaults to max_inflight; clamped to CGF_MAX_INFLIGHT.
     */
    uint32_t max_active_files;

    /*
     * Data Record Packet sub-header fields (TS 32.295 §6.2.4.2, wire
     * format as implemented by Ericsson/Nokia CGFs).
     *
     * IE 252 value layout:
     *
     *   Octet 1   : Number of Records
     *   Octet 2   : Data Record Format        (1 = BER, 2/3 = PER, 4 = XML)
     *   Octets 3-4: Data Record Format Version (big-endian, vendor-defined)
     *   then, for each record:
     *   Octets 5-6: 2-byte big-endian length of the BER record
     *   Octets 7+ : BER-encoded record (e.g. PGW-CDR [79] or SGW-CDR [78])
     *
     * There is NO Application Identifier / Release Identifier field
     * in the sub-header — omitting it is what interop captures show
     * real CGFs accepting. 0x1906 is the Format Version reported by
     * the working peer and is what we default to.
     */
    uint8_t  drp_data_record_format;
    uint16_t drp_data_record_format_version;

    /*
     * Disk retention policy for fully-delivered CDR files.
     *
     * When `purge_on_success` is true, a spool file that has been fully
     * acked by a CGF peer is unlink(2)'d instead of being moved to
     * done/. This keeps /var/spool/open5gs/cdr bounded on busy nodes
     * where the operator doesn't need a local archive. Files that fail
     * all peers are still moved to failed/ for inspection regardless.
     *
     * Defaults to false (legacy behaviour — preserve done/ archive).
     */
    bool     purge_on_success;
} cgf_context_t;

int cgf_context_init(void);
void cgf_context_final(void);
cgf_context_t *cgf_self(void);

int cgf_context_parse_config(void);

#ifdef __cplusplus
}
#endif

#endif /* CGF_CONTEXT_H */
