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
#define CGF_DEFAULT_GTPP_PORT    3386

/* Peer role. Only the primary is used under normal conditions; failover
 * switches to a secondary when the primary stops answering echoes. */
typedef enum {
    CGF_PEER_ROLE_PRIMARY = 0,
    CGF_PEER_ROLE_SECONDARY = 1
} cgf_peer_role_e;

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
     * by TS 32.295 §6.1.1. Incremented on every transmit, wraps freely.
     */
    uint16_t next_seq;

    /* Liveness bookkeeping. */
    uint32_t consecutive_missed_echoes;
    ogs_time_t last_echo_sent;
    ogs_time_t last_echo_received;
    uint8_t peer_restart_counter;   /* last Recovery IE value observed */
    bool peer_restart_counter_valid;

    /* The single in-flight DataRecordTransferRequest for this peer, if
     * any. GTP' as implemented here is strictly serial per peer: one
     * outstanding request, waiting for its matching response or for the
     * retransmit timeout. */
    struct {
        bool in_flight;
        uint16_t seq;
        uint32_t retries;
        ogs_time_t sent_at;
        ogs_pkbuf_t *pkbuf;     /* retained for retransmit */
        /* Back-reference to the active spool cursor so the response
         * handler knows which chunk of which file it just confirmed. */
        struct cgf_spool_file_s *file;
        size_t first_record_offset;
        uint32_t records_in_batch;
    } xact;
} cgf_peer_t;

typedef struct cgf_context_s {
    /* Spool layout (shared with the SMF-side writer). */
    const char *spool_dir;
    char *ready_dir;
    char *done_dir;
    char *failed_dir;

    /* Identity. Sent as Address-of-Recording-Entity / Node Name IE
     * where relevant; also used for logging. */
    const char *node_id;

    /* Peers (primary first, then secondaries in declaration order). */
    cgf_peer_t peers[CGF_MAX_PEERS];
    uint32_t num_of_peers;
    uint32_t active_peer_idx;   /* the peer being used right now */

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
