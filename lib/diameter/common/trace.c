/*
 * Copyright (C) 2026 Open5GS contributors
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

#include "ogs-diameter-common.h"

/* freeDiameter leaves the per-message data layout to the application */
typedef struct diam_trace_pmd_s {
    char tx_imsi[OGS_TRACE_IMSI_LEN];   /* dump on HOOK_MESSAGE_SENT */
    int rx_fd;                          /* connection it arrived on */
    uint8_t rx_l4;
    ogs_time_t rx_ts;
} diam_trace_pmd_t;

static struct fd_hook_hdl *trace_hdl = NULL;
static struct fd_hook_data_hdl *trace_data_hdl = NULL;

static void diam_trace_pmd_init(struct fd_hook_permsgdata *pmd)
{
    diam_trace_pmd_t *d = (diam_trace_pmd_t *)pmd;

    memset(d, 0, sizeof(*d));
    d->rx_fd = -1;
}

/* Socket and L4 protocol of the peer's current connection */
static bool diam_trace_peer_cnx(struct peer_hdr *peer, int *fd, uint8_t *l4)
{
    char info[64];
    const char *soc = NULL;

    if (!peer)
        return false;
    if (fd_peer_cnx_proto_info(peer, info, sizeof(info)) != 0)
        return false;
    soc = strstr(info, "soc#");
    if (!soc)
        return false;

    *fd = atoi(soc + 4);
    *l4 = peer->info.runtime.pir_proto == IPPROTO_SCTP ?
            OGS_TRACE_L4_SCTP : OGS_TRACE_L4_TCP;
    return *fd >= 0;
}

static void diam_trace_link(ogs_trace_link_t *link, int fd, uint8_t l4,
        ogs_time_t ts)
{
    ogs_trace_link_set_fd(link, l4, fd);
    if (ts)
        link->ts = ts;
}

static void diam_trace_dump(const char *imsi_bcd, const char *dir,
        struct msg *msg, const ogs_trace_link_t *link)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    int ret;

    ret = fd_msg_update_length(msg);
    if (ret != 0) {
        ogs_warn("[IMSI:%s] PACKET diameter %s: fd_msg_update_length "
                "failed (%d)", imsi_bcd, dir, ret);
        return;
    }
    ret = fd_msg_bufferize(msg, &buf, &len);
    if (ret != 0 || !buf || !len) {
        ogs_warn("[IMSI:%s] PACKET diameter %s: fd_msg_bufferize failed "
                "(ret=%d len=%zu) — no PACKET line", imsi_bcd, dir, ret, len);
        if (buf)
            free(buf);
        return;
    }

    ogs_trace_packet_link(imsi_bcd, "diameter", dir, buf, len, link);
    free(buf);
}

static void diam_trace_hook_cb(enum fd_hook_type type, struct msg *msg,
        struct peer_hdr *peer, void *other, struct fd_hook_permsgdata *pmd,
        void *regdata)
{
    diam_trace_pmd_t *d = (diam_trace_pmd_t *)pmd;
    ogs_trace_link_t link;
    int fd = -1;
    uint8_t l4 = OGS_TRACE_L4_NONE;

    (void)other;
    (void)regdata;

    if (!msg || !d || !ogs_trace_filter_active())
        return;

    if (type == HOOK_MESSAGE_RECEIVED) {
        /* the IMSI is only known to the application: keep the link */
        if (diam_trace_peer_cnx(peer, &fd, &l4)) {
            d->rx_fd = fd;
            d->rx_l4 = l4;
            d->rx_ts = ogs_time_now();
        }
        return;
    }

    if (type != HOOK_MESSAGE_SENT || !d->tx_imsi[0])
        return;

    memset(&link, 0, sizeof(link));
    if (diam_trace_peer_cnx(peer, &fd, &l4))
        diam_trace_link(&link, fd, l4, 0);
    /* kept set: a failover resend to another peer is dumped too */
    diam_trace_dump(d->tx_imsi, "tx", msg,
            link.l4 != OGS_TRACE_L4_NONE ? &link : NULL);
}

void ogs_diam_trace_msg(const char *imsi_bcd, const char *dir, struct msg *msg)
{
    diam_trace_pmd_t *d = NULL;
    ogs_trace_link_t link;

    if (!imsi_bcd || !imsi_bcd[0] || !dir || !msg)
        return;
    if (!ogs_trace_filter_active() || !ogs_trace_filter_match(imsi_bcd))
        return;

    if (trace_data_hdl)
        d = (diam_trace_pmd_t *)fd_hook_get_pmd(trace_data_hdl, msg);

    if (!strcmp(dir, "tx") && d && trace_hdl) {
        ogs_cpystrn(d->tx_imsi, imsi_bcd, sizeof(d->tx_imsi));
        return;
    }

    memset(&link, 0, sizeof(link));
    if (d && d->rx_fd >= 0)
        diam_trace_link(&link, d->rx_fd, d->rx_l4, d->rx_ts);
    diam_trace_dump(imsi_bcd, dir, msg,
            link.l4 != OGS_TRACE_L4_NONE ? &link : NULL);
}

int ogs_diam_trace_init(void)
{
    CHECK_FCT( fd_hook_data_register(sizeof(diam_trace_pmd_t),
                diam_trace_pmd_init, NULL, &trace_data_hdl) );
    CHECK_FCT( fd_hook_register(
                HOOK_MASK(HOOK_MESSAGE_RECEIVED, HOOK_MESSAGE_SENT),
                diam_trace_hook_cb, NULL, trace_data_hdl, &trace_hdl) );

    return 0;
}

void ogs_diam_trace_final(void)
{
    if (trace_hdl) {
        CHECK_FCT_DO( fd_hook_unregister(trace_hdl), );
        trace_hdl = NULL;
    }
}
