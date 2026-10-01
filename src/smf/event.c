/*
 * Copyright (C) 2019-2022 by Sukchan Lee <acetcom@gmail.com>
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

#include "event.h"
#include "ogs-pfcp.h"
#include "ogs-sbi.h"

struct smf_event_trace_rx_s {
    uint8_t *data;
    size_t len;
    char proto[OGS_TRACE_PROC_LEN];
};

static void smf_event_trace_rx_release(smf_event_t *e)
{
    if (!e->trace_rx)
        return;
    ogs_trace_packet_free_buf(e->trace_rx->data);
    ogs_free(e->trace_rx);
    e->trace_rx = NULL;
}

/*
 * Events cross threads in SMP mode (RX router or Diameter thread
 * allocates, a shard worker frees). ogs_event_size() uses ogs_calloc,
 * whose talloc wrappers are serialized, so this is safe.
 */
smf_event_t *smf_event_new(int id)
{
    smf_event_t *e = NULL;

    e = ogs_event_size(id, sizeof(smf_event_t));
    ogs_assert(e);

    e->h.id = id;
    e->created_at = ogs_get_monotonic_time();

    return e;
}

void smf_event_free(smf_event_t *e)
{
    ogs_assert(e);

    if (e->pkbuf)
        ogs_pkbuf_free(e->pkbuf);
    if (e->pfcp_message)
        ogs_pfcp_message_free(e->pfcp_message);
    if (e->admin_upf_addr)
        ogs_freeaddrinfo(e->admin_upf_addr);
    if (e->sbi_relayed) {
        if (e->h.sbi.request)
            ogs_sbi_request_free(e->h.sbi.request);
        if (e->h.sbi.response)
            ogs_sbi_response_free(e->h.sbi.response);
    }
    smf_event_trace_rx_release(e);
    ogs_event_free(e);
}

void smf_event_trace_rx_capture(smf_event_t *e)
{
    struct smf_event_trace_rx_s *rx = NULL;
    uint8_t *data = NULL;
    size_t len = 0;
    char proto[OGS_TRACE_PROC_LEN];

    ogs_assert(e);

    smf_event_trace_rx_release(e);
    if (!ogs_trace_packet_steal_rx(&data, &len, proto, sizeof(proto)))
        return;

    rx = ogs_calloc(1, sizeof(*rx));
    if (!rx) {
        ogs_trace_packet_free_buf(data);
        return;
    }
    rx->data = data;
    rx->len = len;
    ogs_cpystrn(rx->proto, proto, sizeof(rx->proto));
    e->trace_rx = rx;
}

void smf_event_trace_rx_restore(smf_event_t *e)
{
    ogs_assert(e);

    if (!e->trace_rx)
        return;
    ogs_trace_packet_bind_rx(
            e->trace_rx->proto, e->trace_rx->data, e->trace_rx->len);
    smf_event_trace_rx_release(e);
}

int smf_event_push_main(smf_event_t *e)
{
    int rv;

    ogs_assert(e);

    rv = ogs_queue_trypush(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("smf_event_push_main(%s) failed [%d]",
                smf_event_get_name(e), rv);
        smf_event_free(e);
        return rv;
    }
    ogs_pollset_notify(ogs_app()->pollset);

    return OGS_OK;
}

int smf_event_push_local(smf_event_t *e)
{
    int rv;
    ogs_worker_t *worker = ogs_worker_self();

    ogs_assert(e);

    if (!worker)
        return smf_event_push_main(e);

    rv = ogs_worker_post(worker, e);
    if (rv != OGS_OK) {
        ogs_error("smf_event_push_local(%s) failed [%d]",
                smf_event_get_name(e), rv);
        smf_event_free(e);
    }

    return rv;
}

/*
 * Rises immediately to the worst lag seen and decays geometrically, so a
 * backlog is reported the moment it appears and clears only once
 * dispatch has caught up (same estimator as SGW-C / MME).
 */
static int64_t event_lag_usec = 0;

#define SMF_EVENT_LAG_WARN_THRESHOLD ogs_time_from_msec(1500)

void smf_event_lag_observe(const smf_event_t *e)
{
    ogs_time_t lag;
    int64_t prev, next;

    if (!e || !e->created_at)
        return;

    lag = ogs_get_monotonic_time() - e->created_at;
    if (lag < 0)
        lag = 0;

    prev = __atomic_load_n(&event_lag_usec, __ATOMIC_RELAXED);
    next = ((int64_t)lag > prev) ?
        (int64_t)lag : prev - (prev - (int64_t)lag) / 8;
    __atomic_store_n(&event_lag_usec, next, __ATOMIC_RELAXED);

    if (next >= SMF_EVENT_LAG_WARN_THRESHOLD) {
        static int64_t last_warn = 0;
        ogs_time_t now = ogs_get_monotonic_time();
        int64_t seen = __atomic_load_n(&last_warn, __ATOMIC_RELAXED);

        if (now - seen >= ogs_time_from_sec(10) &&
            __atomic_compare_exchange_n(&last_warn, &seen, (int64_t)now,
                false, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            ogs_warn("Event queue lag %dms - GTP/PFCP response timers "
                    "deferred (SMF is behind, peers are not)",
                    (int)(next / 1000));
    }
}

ogs_time_t smf_event_lag(void)
{
    return (ogs_time_t)__atomic_load_n(&event_lag_usec, __ATOMIC_RELAXED);
}

const char *smf_event_get_name(smf_event_t *e)
{
    if (e == NULL) {
        return OGS_FSM_NAME_INIT_SIG;
    }

    switch (e->h.id) {
    case OGS_FSM_ENTRY_SIG:
        return OGS_FSM_NAME_ENTRY_SIG;
    case OGS_FSM_EXIT_SIG:
        return OGS_FSM_NAME_EXIT_SIG;

    case SMF_EVT_S5C_MESSAGE:
        return "SMF_EVT_S5C_MESSAGE";
    case SMF_EVT_S6B_MESSAGE:
        return "SMF_EVT_S6B_MESSAGE";
    case SMF_EVT_GN_MESSAGE:
        return "SMF_EVT_GN_MESSAGE";
    case SMF_EVT_GX_MESSAGE:
        return "SMF_EVT_GX_MESSAGE";
    case SMF_EVT_GY_MESSAGE:
        return "SMF_EVT_GY_MESSAGE";
    case SMF_EVT_GX_PEER_CONNECT:
        return "SMF_EVT_GX_PEER_CONNECT";
    case SMF_EVT_N4_MESSAGE:
        return "SMF_EVT_N4_MESSAGE";
    case SMF_EVT_N4_TIMER:
        return "SMF_EVT_N4_TIMER";
    case SMF_EVT_N4_NO_HEARTBEAT:
        return "SMF_EVT_N4_NO_HEARTBEAT";
    case SMF_EVT_N4_REASSOCIATE:
        return "SMF_EVT_N4_REASSOCIATE";

    case OGS_EVENT_SBI_SERVER:
        return OGS_EVENT_NAME_SBI_SERVER;
    case OGS_EVENT_SBI_CLIENT:
        return OGS_EVENT_NAME_SBI_CLIENT;
    case OGS_EVENT_SBI_TIMER:
        return OGS_EVENT_NAME_SBI_TIMER;

    case SMF_EVT_NGAP_MESSAGE:
        return "SMF_EVT_NGAP_MESSAGE";
    case SMF_EVT_NGAP_TIMER:
        return "SMF_EVT_NGAP_TIMER";

    case SMF_EVT_5GSM_MESSAGE:
        return "SMF_EVT_5GSM_MESSAGE";
    case SMF_EVT_5GSM_TIMER:
        return "SMF_EVT_5GSM_TIMER";

    case SMF_EVT_SESSION_RELEASE:
        return "SMF_EVT_SESSION_RELEASE";

    case SMF_EVT_CONFIG_RELOAD:
        return "SMF_EVT_CONFIG_RELOAD";

    case SMF_EVT_ADMIN_MAINTENANCE_ENABLE:
        return "SMF_EVT_ADMIN_MAINTENANCE_ENABLE";
    case SMF_EVT_ADMIN_MAINTENANCE_DISABLE:
        return "SMF_EVT_ADMIN_MAINTENANCE_DISABLE";
    case SMF_EVT_ADMIN_MAINTENANCE_DRAIN:
        return "SMF_EVT_ADMIN_MAINTENANCE_DRAIN";
    case SMF_EVT_ADMIN_DETACH_SESSION:
        return "SMF_EVT_ADMIN_DETACH_SESSION";
    case SMF_EVT_ADMIN_DETACH_SESS_ONE:
        return "SMF_EVT_ADMIN_DETACH_SESS_ONE";
    case SMF_EVT_ADMIN_PURGE_SEID:
        return "SMF_EVT_ADMIN_PURGE_SEID";

    case SMF_EVT_ORPHAN_SWEEP:
        return "SMF_EVT_ORPHAN_SWEEP";

    case SMF_EVT_N4_RESTORE:
        return "SMF_EVT_N4_RESTORE";
    case SMF_EVT_SGW_RESTART_PURGE:
        return "SMF_EVT_SGW_RESTART_PURGE";
    case SMF_EVT_GX_RESTORE:
        return "SMF_EVT_GX_RESTORE";
    case SMF_EVT_ROUTER_SOLICIT:
        return "SMF_EVT_ROUTER_SOLICIT";
    case SMF_EVT_RADIUS_POD:
        return "SMF_EVT_RADIUS_POD";
    case SMF_EVT_XSHARD_COLLISION:
        return "SMF_EVT_XSHARD_COLLISION";
    case SMF_EVT_MAIN_CALL:
        return "SMF_EVT_MAIN_CALL";
    case SMF_EVT_SBI_SEND:
        return "SMF_EVT_SBI_SEND";

    default:
       break;
    }

    ogs_error("Unknown Event[%d]", e->h.id);
    return "UNKNOWN_EVENT";
}
