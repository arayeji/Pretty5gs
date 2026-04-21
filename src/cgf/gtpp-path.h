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

#ifndef CGF_GTPP_PATH_H
#define CGF_GTPP_PATH_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 3GPP TS 32.295 GTP' (GTP-prime) message types we care about. Prime
 * reuses the GTPv1/v2 header but drops TEID and Next-Extension-Header
 * handling.
 *
 * First-octet layout is  Version(3) | PT(1) | Spare(4) :
 *
 *     0x1e  0001 1110   v0, GSM 12.15     (20-octet header — NOT this)
 *     0x3f  0011 1111   v1, TS 32.295 strict
 *     0x30  0011 0000   v1, Spare=0 variant (Ericsson/Nokia v1 boxes)
 *     0x5f  0101 1111   v2, TS 32.295 strict
 *     0x4e  0100 1110   v2, Spare=1110 variant (Ericsson CGFs in the
 *                       field — this is what every real peer we've
 *                       seen actually emits AND accepts)
 *
 * We default to 0x4e because that interops with production CGFs out
 * of the box. The receive path (see recv check in gtpp-path.c) is
 * tolerant: it accepts Version=1 OR Version=2 regardless of the
 * low-nibble Spare pattern.
 */
#define CGF_GTPP_VERSION_FLAGS        0x4e
#define CGF_GTPP_MSGTYPE_ECHO_REQ     1
#define CGF_GTPP_MSGTYPE_ECHO_RSP     2
#define CGF_GTPP_MSGTYPE_NODE_ALIVE_REQ 4
#define CGF_GTPP_MSGTYPE_NODE_ALIVE_RSP 5
#define CGF_GTPP_MSGTYPE_REDIRECTION_REQ 6
#define CGF_GTPP_MSGTYPE_REDIRECTION_RSP 7
#define CGF_GTPP_MSGTYPE_DATA_RECORD_TRANSFER_REQ  240
#define CGF_GTPP_MSGTYPE_DATA_RECORD_TRANSFER_RSP  241

/* GTP' IE tag numbers used here. */
#define CGF_GTPP_IE_CAUSE             1       /* 1 B value */
#define CGF_GTPP_IE_RECOVERY          14      /* 1 B value */
#define CGF_GTPP_IE_PACKET_TRANSFER_CMD 126   /* 1 B value */
#define CGF_GTPP_IE_DATA_RECORD_PACKET 252    /* TLIV */

/* PacketTransferCommand values (TS 32.295 §6.2.4.5.3). */
#define CGF_GTPP_PTC_SEND_DATA_REC    1
#define CGF_GTPP_PTC_SEND_POSS_DUP    2
#define CGF_GTPP_PTC_CANCEL_DATA_REC  3
#define CGF_GTPP_PTC_RELEASE_DATA_REC 4

/* Open UDP sockets and pollset registrations for every configured peer.
 * The socket is "connected" to the peer's address so we can use send()
 * without a destination on each call. Returns OGS_OK even when some
 * peers fail DNS — the state machine will keep retrying. */
int cgf_gtpp_open(void);
void cgf_gtpp_close(void);

/* Build and transmit an Echo Request to the given peer. Updates
 * peer->last_echo_sent and peer->next_seq; on socket error returns
 * OGS_ERROR and the caller should mark the peer down. */
int cgf_gtpp_send_echo_request(cgf_peer_t *peer);

/* Build a DataRecordTransferRequest carrying the supplied encoded
 * records, transmit it, and move the parameters into peer->xact. The
 * pkbuf is retained inside peer->xact for retransmits. */
int cgf_gtpp_send_data_record_transfer(
        cgf_peer_t *peer,
        const uint8_t *records, size_t records_len,
        uint32_t records_in_batch,
        struct cgf_spool_file_s *file,
        size_t first_record_offset);

/* Re-send the packet currently stored in peer->xact.pkbuf without
 * allocating a new sequence number. Used by the RTO timer. */
int cgf_gtpp_retransmit_xact(cgf_peer_t *peer);

/* Dispatch a received datagram. Called from the main loop with an
 * OGS_POLLIN event. */
void cgf_gtpp_handle_recv(cgf_peer_t *peer, ogs_pkbuf_t *pkbuf);

/*
 * Hot-replace the peer list and/or tunables from the admin API.
 *
 * This runs on the CGF main thread so it is safe to close sockets and
 * re-register pollset entries. Peers whose (host, port) match an
 * existing entry keep their runtime state (sequence number, echo
 * history, xact). New peers are opened and registered. Peers that have
 * disappeared are closed and their in-flight xact is dropped (the
 * spool cursor retains position so records are not lost — they will be
 * re-sent to whichever peer becomes primary after reconfig).
 *
 * `hot` is the payload the watcher delivered; pointer-valued fields
 * are NOT retained across the call — the implementation dups any
 * string it needs to keep.
 */
typedef struct cgf_hot_peer_s {
    const char *host;
    uint16_t    port;
    int         is_primary;   /* 1 => CGF_PEER_ROLE_PRIMARY */
} cgf_hot_peer_t;

typedef struct cgf_hot_config_s {
    uint32_t echo_interval_s;
    uint32_t request_rto_ms;
    uint32_t request_retries;
    uint32_t failover_after_missed_echoes;
    uint32_t max_records_per_packet;
    uint32_t max_bytes_per_packet;
    /* -1 = "not provided in payload, keep current value"; 0 = off;
     * 1 = purge fully-acked files on unlink. Using a tri-state here
     * so a PUT that only adjusts e.g. timers doesn't inadvertently
     * reset the retention policy back to its default. */
    int      purge_on_success;
    cgf_hot_peer_t peers[CGF_MAX_PEERS];
    int      num_peers;
} cgf_hot_config_t;

int cgf_gtpp_apply_runtime(const cgf_hot_config_t *hot);

#ifdef __cplusplus
}
#endif

#endif /* CGF_GTPP_PATH_H */
