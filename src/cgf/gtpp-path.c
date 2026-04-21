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

#include "gtpp-path.h"
#include "event.h"
#include "spool.h"
#include "cgf-sm.h"

/* ================================================================== */
/*  GTP' header layout                                                */
/* ================================================================== */

/*
 * TS 32.295 §6.1 "Prime" header (6 octets):
 *    +-------+-------+-------+-------+-------+-------+
 *    | flags |  msg  |    length     |  sequence     |
 *    +-------+-------+-------+-------+-------+-------+
 * flags = 0x4e (Version=010b/GTP' v2, PT=0b, Spare=1110b — the
 * wire format real-world Ericsson/Nokia CGFs emit). See the comment
 * on CGF_GTPP_VERSION_FLAGS in gtpp-path.h for the full rationale
 * and for the other valid values (0x3f strict v1, 0x5f strict v2).
 * Length counts everything AFTER the header (i.e. just the payload).
 * Sequence is 16-bit big-endian.
 */
#define CGF_GTPP_HDR_LEN 6

static inline void hdr_write(uint8_t *p, uint8_t msg_type,
        uint16_t seq, uint16_t payload_len)
{
    p[0] = CGF_GTPP_VERSION_FLAGS;
    p[1] = msg_type;
    p[2] = (uint8_t)(payload_len >> 8);
    p[3] = (uint8_t)(payload_len & 0xff);
    p[4] = (uint8_t)(seq >> 8);
    p[5] = (uint8_t)(seq & 0xff);
}

/* Tag-Length-Value (TLV) IE writer for IEs with 2-byte big-endian
 * length (TS 32.295 §6.2.2). 1-byte-value "Cause" and "Recovery" IEs
 * are handled separately since they are defined as Tag+Value (no
 * length) in the spec. */
static inline size_t tlv_put_1byte(uint8_t *p, uint8_t tag, uint8_t value)
{
    p[0] = tag;
    p[1] = value;
    return 2;
}

static inline size_t tliv_put(uint8_t *p, uint8_t tag,
        const uint8_t *value, size_t value_len)
{
    p[0] = tag;
    p[1] = (uint8_t)(value_len >> 8);
    p[2] = (uint8_t)(value_len & 0xff);
    memcpy(p + 3, value, value_len);
    return 3 + value_len;
}

/* ================================================================== */
/*  Receive path                                                      */
/* ================================================================== */

static void recv_cb(short when, ogs_socket_t fd, void *data)
{
    cgf_peer_t *peer = data;
    cgf_event_t *e;
    ogs_pkbuf_t *pkbuf;
    ogs_sockaddr_t from;
    ssize_t size;

    ogs_assert(peer);
    (void)when;

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);

    size = ogs_recvfrom(fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_pkbuf_free(pkbuf);
        return;
    }
    ogs_pkbuf_trim(pkbuf, size);

    /* Post on the main queue so dispatch happens with the FSM under
     * the same lock discipline as timer events. */
    e = cgf_event_new(CGF_EVENT_GTPP_RECV);
    e->peer_idx = (int)(peer - cgf_self()->peers);
    e->pkbuf = pkbuf;
    if (ogs_queue_push(ogs_app()->queue, e) != OGS_OK) {
        ogs_warn("cgf: queue full, dropping datagram from [%s]:%u",
                peer->address_str, peer->port);
        cgf_event_free(e);
    } else {
        ogs_pollset_notify(ogs_app()->pollset);
    }
}

/* ================================================================== */
/*  Open / close                                                      */
/* ================================================================== */

/*
 * String ownership for hot-edited peer addresses. YAML-parsed peers
 * point into ogs_app()'s YAML document (never freed); hot-edited
 * peers point into these heap slots. Declared up-front so cgf_gtpp_close
 * can free them whether or not a hot reload ever happened.
 */
static char *g_cgf_owned_host[CGF_MAX_PEERS];

static int open_one_peer(cgf_peer_t *peer)
{
    int rv;

    rv = ogs_getaddrinfo(&peer->addr, AF_UNSPEC,
            peer->address_str, peer->port, 0);
    if (rv != OGS_OK || !peer->addr) {
        ogs_error("cgf: getaddrinfo('%s':%u) failed",
                peer->address_str, peer->port);
        return OGS_ERROR;
    }

    peer->sock = ogs_udp_client(peer->addr, NULL);
    if (!peer->sock) {
        ogs_error("cgf: ogs_udp_client('%s':%u) failed",
                peer->address_str, peer->port);
        return OGS_ERROR;
    }

    peer->poll = ogs_pollset_add(ogs_app()->pollset,
            OGS_POLLIN, peer->sock->fd, recv_cb, peer);
    if (!peer->poll) {
        ogs_error("cgf: pollset_add failed for peer '%s'",
                peer->address_str);
        return OGS_ERROR;
    }

    ogs_info("cgf: peer %u='%s':%u (%s) ready",
            (unsigned)(peer - cgf_self()->peers),
            peer->address_str, peer->port,
            peer->role == CGF_PEER_ROLE_PRIMARY ? "primary" : "secondary");
    return OGS_OK;
}

int cgf_gtpp_open(void)
{
    uint32_t i;
    int rv_any = OGS_ERROR;

    for (i = 0; i < cgf_self()->num_of_peers; i++) {
        if (open_one_peer(&cgf_self()->peers[i]) == OGS_OK)
            rv_any = OGS_OK;
    }
    return rv_any;
}

void cgf_gtpp_close(void)
{
    uint32_t i;
    for (i = 0; i < cgf_self()->num_of_peers; i++) {
        cgf_peer_t *p = &cgf_self()->peers[i];
        if (p->poll) { ogs_pollset_remove(p->poll); p->poll = NULL; }
        if (p->sock) { ogs_sock_destroy(p->sock); p->sock = NULL; }
    }
    /* Free any host strings we took ownership of via apply_runtime.
     * YAML-parsed strings (when no hot reload ever happened) are not
     * freed here — they live in the ogs_app() YAML document. */
    for (i = 0; i < CGF_MAX_PEERS; i++) {
        if (g_cgf_owned_host[i]) {
            ogs_free(g_cgf_owned_host[i]);
            g_cgf_owned_host[i] = NULL;
        }
    }
}

/* ================================================================== */
/*  Hot reload                                                        */
/* ================================================================== */

static void close_peer(cgf_peer_t *p)
{
    if (p->poll) { ogs_pollset_remove(p->poll); p->poll = NULL; }
    if (p->sock) { ogs_sock_destroy(p->sock); p->sock = NULL; }
    if (p->addr) { ogs_freeaddrinfo(p->addr);  p->addr = NULL; }
    if (p->xact.pkbuf) { ogs_pkbuf_free(p->xact.pkbuf); p->xact.pkbuf = NULL; }
    memset(&p->xact, 0, sizeof(p->xact));
    p->state = CGF_PEER_STATE_DOWN;
}

static int find_matching_old_peer(
        const cgf_hot_peer_t *hp, const cgf_peer_t *old, int old_n)
{
    int i;
    for (i = 0; i < old_n; i++) {
        if (!old[i].address_str) continue;
        if (old[i].port == hp->port &&
                strcmp(old[i].address_str, hp->host) == 0)
            return i;
    }
    return -1;
}

int cgf_gtpp_apply_runtime(const cgf_hot_config_t *hot)
{
    cgf_context_t *ctx = cgf_self();
    cgf_peer_t old_peers[CGF_MAX_PEERS];
    char *old_owned[CGF_MAX_PEERS];
    int old_n = (int)ctx->num_of_peers;
    int i;

    ogs_assert(hot);

    ogs_info("cgf: applying runtime config (peers=%d echo=%us rto=%ums)",
            hot->num_peers, hot->echo_interval_s, hot->request_rto_ms);

    /* Snapshot the current peer set so we can preserve runtime state
     * (sequence numbers, pending xact) for peers that stay around. */
    memcpy(old_peers, ctx->peers, sizeof(old_peers));
    memcpy(old_owned, g_cgf_owned_host, sizeof(old_owned));
    memset(ctx->peers, 0, sizeof(ctx->peers));
    memset(g_cgf_owned_host, 0, sizeof(g_cgf_owned_host));
    ctx->num_of_peers = 0;

    /* Scalars. */
    if (hot->echo_interval_s)               ctx->echo_interval_s = hot->echo_interval_s;
    if (hot->request_rto_ms)                ctx->request_rto_ms = hot->request_rto_ms;
    ctx->request_retries                    = hot->request_retries;
    if (hot->failover_after_missed_echoes)
        ctx->failover_after_missed_echoes   = hot->failover_after_missed_echoes;
    if (hot->max_records_per_packet)        ctx->max_records_per_packet = hot->max_records_per_packet;
    if (hot->max_bytes_per_packet)          ctx->max_bytes_per_packet = hot->max_bytes_per_packet;
    if (hot->purge_on_success >= 0) {
        bool new_val = hot->purge_on_success ? true : false;
        if (new_val != ctx->purge_on_success) {
            ogs_info("cgf: purge_on_success %s -> %s",
                    ctx->purge_on_success ? "true" : "false",
                    new_val ? "true" : "false");
            ctx->purge_on_success = new_val;
        }
    }

    /* Reinstate peers in the new order. For matches we steal the old
     * slot's socket/poll/xact wholesale so no datagrams in flight are
     * lost. For novel peers we open fresh. */
    for (i = 0; i < hot->num_peers && i < CGF_MAX_PEERS; i++) {
        const cgf_hot_peer_t *hp = &hot->peers[i];
        cgf_peer_t *dst = &ctx->peers[i];
        int match;

        if (!hp->host || !hp->host[0]) continue;

        match = find_matching_old_peer(hp, old_peers, old_n);
        if (match >= 0) {
            /* Adopt old socket + health state. */
            *dst = old_peers[match];
            dst->role = hp->is_primary
                    ? CGF_PEER_ROLE_PRIMARY : CGF_PEER_ROLE_SECONDARY;
            /* Re-link recv_cb's userdata from the old slot to the new. */
            if (dst->poll) {
                ogs_pollset_remove(dst->poll);
                dst->poll = ogs_pollset_add(ogs_app()->pollset,
                        OGS_POLLIN, dst->sock->fd, recv_cb, dst);
            }
            /* Hand ownership of the old heap-host string over so we can
             * free it on the next apply. If the old slot used a YAML
             * pointer (no heap string), we dup the hot-config host now. */
            if (old_owned[match]) {
                g_cgf_owned_host[i] = old_owned[match];
                old_owned[match] = NULL;
                dst->address_str = g_cgf_owned_host[i];
            } else {
                g_cgf_owned_host[i] = ogs_strdup(hp->host);
                dst->address_str = g_cgf_owned_host[i];
            }
            /* Null out the old slot so the reaping loop below doesn't
             * close it. */
            memset(&old_peers[match], 0, sizeof(old_peers[match]));
        } else {
            g_cgf_owned_host[i] = ogs_strdup(hp->host);
            dst->address_str = g_cgf_owned_host[i];
            dst->port = hp->port ? hp->port : CGF_DEFAULT_GTPP_PORT;
            dst->role = hp->is_primary
                    ? CGF_PEER_ROLE_PRIMARY : CGF_PEER_ROLE_SECONDARY;
            if (open_one_peer(dst) != OGS_OK) {
                ogs_warn("cgf: failed to open new peer '%s':%u, skipping",
                        dst->address_str, dst->port);
                close_peer(dst);
                if (g_cgf_owned_host[i]) {
                    ogs_free(g_cgf_owned_host[i]);
                    g_cgf_owned_host[i] = NULL;
                }
                memset(dst, 0, sizeof(*dst));
                continue;
            }
        }
        ctx->num_of_peers++;
    }

    /* Reap old peers that weren't adopted. */
    for (i = 0; i < old_n; i++) {
        if (old_peers[i].address_str == NULL) continue;
        ogs_info("cgf: removing stale peer '%s':%u",
                old_peers[i].address_str, old_peers[i].port);
        close_peer(&old_peers[i]);
        if (old_owned[i]) {
            ogs_free(old_owned[i]);
            old_owned[i] = NULL;
        }
    }

    /* active_peer_idx may now be out of range or point to a reaped slot. */
    if (ctx->active_peer_idx >= ctx->num_of_peers) {
        /* Pick the first primary if any, else 0. */
        uint32_t k;
        ctx->active_peer_idx = 0;
        for (k = 0; k < ctx->num_of_peers; k++) {
            if (ctx->peers[k].role == CGF_PEER_ROLE_PRIMARY) {
                ctx->active_peer_idx = k;
                break;
            }
        }
    }

    return OGS_OK;
}

/* ================================================================== */
/*  Send path                                                         */
/* ================================================================== */

static int raw_send(cgf_peer_t *peer, ogs_pkbuf_t *pkbuf)
{
    ssize_t sent;
    ogs_assert(peer && peer->sock && pkbuf);
    sent = ogs_send(peer->sock->fd, pkbuf->data, pkbuf->len, 0);
    if (sent < 0 || (size_t)sent != pkbuf->len) {
        ogs_log_message(OGS_LOG_WARN, ogs_socket_errno,
                "cgf: send to '%s' failed", peer->address_str);
        return OGS_ERROR;
    }
    return OGS_OK;
}

int cgf_gtpp_send_echo_request(cgf_peer_t *peer)
{
    uint8_t buf[CGF_GTPP_HDR_LEN];
    ogs_pkbuf_t *pkbuf;
    uint16_t seq = peer->next_seq++;

    /* Echo Request payload length is 0. */
    hdr_write(buf, CGF_GTPP_MSGTYPE_ECHO_REQ, seq, 0);

    pkbuf = ogs_pkbuf_alloc(NULL, sizeof(buf));
    ogs_assert(pkbuf);
    ogs_pkbuf_put_data(pkbuf, buf, sizeof(buf));

    peer->last_echo_sent = ogs_time_now();

    if (raw_send(peer, pkbuf) != OGS_OK) {
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }
    ogs_pkbuf_free(pkbuf);
    ogs_debug("cgf: echo_req -> '%s' seq=%u", peer->address_str, seq);
    return OGS_OK;
}

/*
 * Data Record Packet IE sub-header — 4 octets that sit between the
 * 3-byte TLIV header (tag 0xFC + 2-byte length) and the list of
 * length-prefixed BER records inside IE 252.
 *
 *   Octet 1   :  Number of Records
 *   Octet 2   :  Data Record Format          (1 = BER ASN.1)
 *   Octets 3-4:  Data Record Format Version  (big-endian, vendor)
 *
 * (TS 32.295 §6.2.4.2 spec writing has historically included an
 * Application Identifier / Release Identifier octet here, but real
 * CGFs in production — Ericsson, Nokia — do NOT transmit it and
 * reject packets that do. The working peer capture we're matching
 * has exactly these 4 octets.)
 *
 * Each record is then preceded by its own 2-byte big-endian length.
 */
#define CGF_GTPP_DRP_SUBHDR_LEN   4

static inline size_t drp_subhdr_put(uint8_t *p, uint8_t nrecords)
{
    cgf_context_t *self = cgf_self();
    uint16_t ver = self->drp_data_record_format_version;
    p[0] = nrecords;
    p[1] = self->drp_data_record_format;
    p[2] = (uint8_t)(ver >> 8);
    p[3] = (uint8_t)(ver & 0xff);
    return CGF_GTPP_DRP_SUBHDR_LEN;
}

int cgf_gtpp_send_data_record_transfer(
        cgf_peer_t *peer,
        const uint8_t *records, size_t records_len,
        uint32_t records_in_batch,
        struct cgf_spool_file_s *file,
        size_t first_record_offset)
{
    ogs_pkbuf_t *pkbuf;
    uint16_t seq;
    size_t payload_len;
    uint8_t *p;

    if (peer->xact.in_flight) {
        ogs_warn("cgf: DTRR dropped, peer '%s' already has xact in-flight",
                peer->address_str);
        return OGS_ERROR;
    }

    /* Number of Records lives in a single octet — cap the batch so
     * staging never produces more than 255 records per datagram. The
     * spool stager already enforces max_records_per_packet (typically
     * 5..32) but belt-and-braces. */
    if (records_in_batch == 0 || records_in_batch > 255) {
        ogs_error("cgf: batch record count %u out of range [1,255]",
                records_in_batch);
        return OGS_ERROR;
    }

    /* Payload layout:
     *   [Packet Transfer Command TV]  2 B  (tag 126, value 1)
     *   [Data Record Packet TLIV]     3 + 5 + records_len B
     *        tag 252 + 2-byte len + 5-byte DRP sub-header + records */
    payload_len = 2 + 3 + CGF_GTPP_DRP_SUBHDR_LEN + records_len;
    if (payload_len + CGF_GTPP_HDR_LEN > OGS_MAX_SDU_LEN) {
        ogs_error("cgf: batch too large for a single datagram (%zu B)",
                payload_len);
        return OGS_ERROR;
    }

    pkbuf = ogs_pkbuf_alloc(NULL, CGF_GTPP_HDR_LEN + payload_len);
    ogs_assert(pkbuf);
    ogs_pkbuf_put(pkbuf, CGF_GTPP_HDR_LEN + payload_len);
    p = pkbuf->data;

    seq = peer->next_seq++;
    hdr_write(p, CGF_GTPP_MSGTYPE_DATA_RECORD_TRANSFER_REQ,
            seq, (uint16_t)payload_len);
    p += CGF_GTPP_HDR_LEN;

    p += tlv_put_1byte(p, CGF_GTPP_IE_PACKET_TRANSFER_CMD,
            CGF_GTPP_PTC_SEND_DATA_REC);

    /* IE 252 = tag + 2-byte length + (sub-header + records). We write
     * the TLIV header by hand here so we can splice in the sub-header
     * without an extra scratch buffer. */
    {
        uint16_t ie_len = (uint16_t)(CGF_GTPP_DRP_SUBHDR_LEN + records_len);
        *p++ = CGF_GTPP_IE_DATA_RECORD_PACKET;
        *p++ = (uint8_t)(ie_len >> 8);
        *p++ = (uint8_t)(ie_len & 0xff);
        p += drp_subhdr_put(p, (uint8_t)records_in_batch);
        memcpy(p, records, records_len);
        p += records_len;
    }
    (void)p;

    /* Retain pkbuf for possible retransmission; duplicate only if
     * send succeeds so a failure doesn't leave orphaned state. */
    if (raw_send(peer, pkbuf) != OGS_OK) {
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    peer->xact.in_flight = true;
    peer->xact.seq = seq;
    peer->xact.retries = 0;
    peer->xact.sent_at = ogs_time_now();
    peer->xact.pkbuf = pkbuf;
    peer->xact.file = file;
    peer->xact.first_record_offset = first_record_offset;
    peer->xact.records_in_batch = records_in_batch;

    ogs_debug("cgf: dtrr -> '%s' seq=%u records=%u bytes=%zu",
            peer->address_str, seq, records_in_batch, records_len);
    return OGS_OK;
}

int cgf_gtpp_retransmit_xact(cgf_peer_t *peer)
{
    if (!peer->xact.in_flight || !peer->xact.pkbuf) return OGS_ERROR;
    peer->xact.retries++;
    peer->xact.sent_at = ogs_time_now();

    ogs_warn("cgf: retransmit dtrr seq=%u to '%s' (attempt %u/%u)",
            peer->xact.seq, peer->address_str,
            peer->xact.retries, cgf_self()->request_retries);

    /* pkbuf is already built, just re-send its bytes. */
    {
        ogs_pkbuf_t *dup = ogs_pkbuf_copy(peer->xact.pkbuf);
        int rv;
        ogs_assert(dup);
        rv = raw_send(peer, dup);
        ogs_pkbuf_free(dup);
        return rv;
    }
}

/* ================================================================== */
/*  Parse path                                                        */
/* ================================================================== */

/*
 * Walk a GTP' IE list in [data, data+len). Only the IEs we actually
 * need are recognised; anything else is skipped using the per-tag
 * fixed length for TV IEs and the 2-byte length for TLIV IEs. IEs with
 * tag < 128 are TV (fixed length per tag); tag >= 128 is TLIV.
 */
static bool parse_ies(const uint8_t *data, size_t len,
        uint8_t *out_cause, bool *out_cause_present,
        uint8_t *out_recovery, bool *out_recovery_present)
{
    size_t i = 0;
    *out_cause_present = false;
    *out_recovery_present = false;

    while (i < len) {
        uint8_t tag = data[i++];
        if (tag < 128) {
            /* TV IE. Only recognise Cause (1 B) and Recovery (1 B);
             * unknown TV IEs cannot be safely skipped because their
             * length isn't on the wire, so abort parsing to be safe. */
            if (i >= len) return false;
            if (tag == CGF_GTPP_IE_CAUSE) {
                *out_cause = data[i++];
                *out_cause_present = true;
            } else if (tag == CGF_GTPP_IE_RECOVERY) {
                *out_recovery = data[i++];
                *out_recovery_present = true;
            } else if (tag == CGF_GTPP_IE_PACKET_TRANSFER_CMD) {
                i++; /* skip 1 B */
            } else {
                ogs_debug("cgf: unknown TV IE tag=%u, aborting parse", tag);
                return false;
            }
        } else {
            /* TLIV IE. */
            if (i + 2 > len) return false;
            uint16_t il = (uint16_t)((data[i] << 8) | data[i + 1]);
            i += 2;
            if (i + il > len) return false;
            i += il;
        }
    }
    return true;
}

void cgf_gtpp_handle_recv(cgf_peer_t *peer, ogs_pkbuf_t *pkbuf)
{
    const uint8_t *p;
    uint8_t msg_type;
    uint16_t payload_len, seq;
    uint8_t cause = 0, recovery = 0;
    bool cause_p = false, recovery_p = false;

    ogs_assert(peer && pkbuf);
    if (pkbuf->len < CGF_GTPP_HDR_LEN) {
        ogs_warn("cgf: short datagram from '%s' (%u B)",
                peer->address_str, (unsigned)pkbuf->len);
        return;
    }
    p = pkbuf->data;

    /* Be liberal in what we accept: real CGFs disagree on the low
     * nibble (TS 32.295 says Spare=1111, Ericsson ships 1110, some
     * Nokia v1 boxes ship 0000) AND on the version (v1 or v2). We
     * only require the high 3 bits to be 001 or 010, i.e. Version
     * 1 or 2 — anything else is a foreign protocol we can't parse
     * with this 6-octet header. */
    {
        uint8_t ver = (p[0] >> 5) & 0x07;
        if (ver != 1 && ver != 2) {
            ogs_warn("cgf: bad GTP' flags 0x%02x from '%s' "
                    "(Version=%u; expected 1 or 2)",
                    p[0], peer->address_str, ver);
            return;
        }
    }
    msg_type = p[1];
    payload_len = (uint16_t)((p[2] << 8) | p[3]);
    seq = (uint16_t)((p[4] << 8) | p[5]);

    if ((size_t)payload_len + CGF_GTPP_HDR_LEN > pkbuf->len) {
        ogs_warn("cgf: declared length %u exceeds datagram %u",
                payload_len, (unsigned)pkbuf->len);
        return;
    }

    parse_ies(p + CGF_GTPP_HDR_LEN, payload_len,
            &cause, &cause_p, &recovery, &recovery_p);

    switch (msg_type) {
    case CGF_GTPP_MSGTYPE_ECHO_RSP:
        cgf_sm_on_echo_response(peer, seq,
                cause_p ? cause : 0,
                recovery, recovery_p);
        break;
    case CGF_GTPP_MSGTYPE_DATA_RECORD_TRANSFER_RSP:
        cgf_sm_on_dtrr_response(peer, seq, cause_p ? cause : 0);
        break;
    case CGF_GTPP_MSGTYPE_ECHO_REQ:
        /* CGFs don't normally initiate echoes against us, but if one
         * does we still answer so the link isn't considered dead. */
        {
            uint8_t buf[CGF_GTPP_HDR_LEN + 2];
            ogs_pkbuf_t *rsp;
            hdr_write(buf, CGF_GTPP_MSGTYPE_ECHO_RSP, seq, 2);
            tlv_put_1byte(buf + CGF_GTPP_HDR_LEN, CGF_GTPP_IE_RECOVERY, 0);
            rsp = ogs_pkbuf_alloc(NULL, sizeof(buf));
            ogs_assert(rsp);
            ogs_pkbuf_put_data(rsp, buf, sizeof(buf));
            raw_send(peer, rsp);
            ogs_pkbuf_free(rsp);
        }
        break;
    default:
        ogs_debug("cgf: unhandled msg_type=%u seq=%u from '%s'",
                msg_type, seq, peer->address_str);
        break;
    }
}
