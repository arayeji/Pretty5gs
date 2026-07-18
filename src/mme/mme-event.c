/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#include "ogs-sctp.h"

#include "ogs-app.h"

#include "mme-event.h"
#include "mme-context.h"
#include "mme-workers.h"

#include "s1ap-path.h"

static bool mme_event_belongs_to_mme_ue(
        mme_event_t *e, ogs_pool_id_t mme_ue_id)
{
    ogs_assert(e);

    if (e->mme_ue_id >= OGS_MIN_POOL_ID &&
            e->mme_ue_id <= OGS_MAX_POOL_ID &&
            e->mme_ue_id == mme_ue_id)
        return true;

    if (e->enb_ue_id >= OGS_MIN_POOL_ID &&
            e->enb_ue_id <= OGS_MAX_POOL_ID) {
        enb_ue_t *enb_ue = enb_ue_find_by_id(e->enb_ue_id);
        if (enb_ue && enb_ue->mme_ue_id == mme_ue_id)
            return true;
    }

    if (e->sgw_ue_id >= OGS_MIN_POOL_ID &&
            e->sgw_ue_id <= OGS_MAX_POOL_ID) {
        sgw_ue_t *sgw_ue = sgw_ue_find_by_id(e->sgw_ue_id);
        if (sgw_ue && sgw_ue->mme_ue_id == mme_ue_id)
            return true;
    }

    return false;
}

static void mme_event_discard(mme_event_t *e)
{
    ogs_assert(e);

    if (e->addr) {
        ogs_free(e->addr);
        e->addr = NULL;
    }
    if (e->pkbuf) {
        ogs_pkbuf_free(e->pkbuf);
        e->pkbuf = NULL;
    }
    if (e->s6a_message) {
        /*
         * Match the normal free path in mme-sm.c: the IDR/ULA branches
         * sub-allocate subscription_data, so a flat free would leak it
         * when an S6a event is discarded mid-teardown.
         */
        ogs_subscription_data_free(&e->s6a_message->idr_message.subscription_data);
        ogs_subscription_data_free(&e->s6a_message->ula_message.subscription_data);
        ogs_free(e->s6a_message);
        e->s6a_message = NULL;
    }

    mme_event_free(e);
}

/*
 * Skip the queue scan entirely when the queue is deep. The scan is O(queue)
 * per removed UE: under overload (attach storm, mass drain) with tens of
 * thousands of queued events it turned every mme_ue_remove() into a full
 * pop/re-push cycle of the queue - O(N^2) overall - and wedged the main
 * thread. Correctness does not depend on the purge: every event handler
 * re-resolves contexts by pool id (returning NULL for removed UEs) and
 * frees its payload on the missing-context path. The purge is kept for
 * shallow queues only as a cheap way to drop stale work early.
 */
#define MME_EVENT_PURGE_MAX_QUEUE 2048

static int mme_event_purge_queue(ogs_queue_t *queue, ogs_pool_id_t mme_ue_id)
{
    ogs_queue_t *pending = NULL;
    mme_event_t *e = NULL;
    int rv, purged = 0;
    unsigned int n;

    ogs_assert(queue);

    n = ogs_queue_size(queue);
    if (n == 0)
        return 0;

    if (n > MME_EVENT_PURGE_MAX_QUEUE) {
        ogs_debug("Skipping event purge for MME-UE [id:%d]: "
                "queue too deep (%u); stale events are dropped at "
                "dispatch time", mme_ue_id, n);
        return 0;
    }

    pending = ogs_queue_create(n + 16);
    ogs_assert(pending);

    /*
     * Producers may keep pushing while we drain, so the queue is NOT
     * frozen at the size we snapshotted. Pop at most n events.
     */
    while (n > 0 && (rv = ogs_queue_trypop(queue, (void **)&e)) == OGS_OK) {
        n--;
        ogs_assert(e);
        if (mme_event_belongs_to_mme_ue(e, mme_ue_id)) {
            mme_event_discard(e);
            purged++;
        } else {
            rv = ogs_queue_trypush(pending, e);
            ogs_assert(rv == OGS_OK); /* sized n+16, bounded by n pops */
        }
    }
    ogs_assert(rv != OGS_ERROR);

    while ((rv = ogs_queue_trypop(pending, (void **)&e)) == OGS_OK) {
        ogs_assert(e);
        rv = ogs_queue_trypush(queue, e);
        if (rv != OGS_OK) {
            ogs_error("event purge: re-push failed (%d), dropping event "
                    "id [%d]", (int)rv, e->id);
            mme_event_discard(e);
        }
    }
    ogs_assert(rv != OGS_ERROR);

    ogs_queue_destroy(pending);
    return purged;
}

void mme_event_purge_mme_ue(ogs_pool_id_t mme_ue_id)
{
    int purged = 0;
    int wid;

    if (mme_ue_id < OGS_MIN_POOL_ID || mme_ue_id > OGS_MAX_POOL_ID)
        return;

    purged += mme_event_purge_queue(ogs_app()->queue, mme_ue_id);

    /* Stage A: UE-scoped work may already sit on the owner shard queue. */
    wid = mme_shard_from_mme_ue_id(mme_ue_id);
    if (wid >= 0) {
        ogs_worker_t *w = mme_worker_by_id(wid);
        if (w && w->queue)
            purged += mme_event_purge_queue(w->queue, mme_ue_id);
    }

    if (purged > 0) {
        ogs_debug("Purged %d queued event(s) for removed MME-UE [id:%d]",
                purged, mme_ue_id);
    }
}

void mme_event_term(void)
{
    ogs_queue_term(ogs_app()->queue);
    ogs_pollset_notify(ogs_app()->pollset);
}

mme_event_t *mme_event_new(mme_event_e id)
{
    mme_event_t *e = NULL;

    e = ogs_calloc(1, sizeof *e);
    ogs_assert(e);
    memset(e, 0, sizeof(*e));

    e->id = id;

    return e;
}

void mme_event_free(mme_event_t *e)
{
    ogs_assert(e);
    ogs_free(e);
}

const char *mme_event_get_name(mme_event_t *e)
{
    if (e == NULL)
        return OGS_FSM_NAME_INIT_SIG;

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        return OGS_FSM_NAME_ENTRY_SIG;
    case OGS_FSM_EXIT_SIG:
        return OGS_FSM_NAME_EXIT_SIG;

    case MME_EVENT_S1AP_MESSAGE:
        return "MME_EVENT_S1AP_MESSAGE";
    case MME_EVENT_S1AP_TIMER:
        return "MME_EVENT_S1AP_TIMER";
    case MME_EVENT_S1AP_LO_ACCEPT:
        return "MME_EVENT_S1AP_LO_ACCEPT";
    case MME_EVENT_S1AP_LO_SCTP_COMM_UP:
        return "MME_EVENT_S1AP_LO_SCTP_COMM_UP";
    case MME_EVENT_S1AP_LO_CONNREFUSED:
        return "MME_EVENT_S1AP_LO_CONNREFUSED";
    case MME_EVENT_S1AP_RX_SOCK_CLOSED:
        return "MME_EVENT_S1AP_RX_SOCK_CLOSED";
    case MME_EVENT_S1AP_RX_WATCH_FAILED:
        return "MME_EVENT_S1AP_RX_WATCH_FAILED";
    case MME_EVENT_S1AP_TX_READY:
        return "MME_EVENT_S1AP_TX_READY";

    case MME_EVENT_EMM_MESSAGE:
        return "MME_EVENT_EMM_MESSAGE";
    case MME_EVENT_EMM_TIMER:
        return "MME_EVENT_EMM_TIMER";
    case MME_EVENT_ESM_MESSAGE:
        return "MME_EVENT_ESM_MESSAGE";
    case MME_EVENT_ESM_TIMER:
        return "MME_EVENT_ESM_TIMER";
    case MME_EVENT_S11_MESSAGE:
        return "MME_EVENT_S11_MESSAGE";
    case MME_EVENT_S11_TIMER:
        return "MME_EVENT_S11_TIMER";
    case MME_EVENT_S6A_MESSAGE:
        return "MME_EVENT_S6A_MESSAGE";
    case MME_EVENT_S6A_TIMER:
        return "MME_EVENT_S6A_TIMER";

    case MME_EVENT_SGSAP_MESSAGE:
        return "MME_EVENT_SGSAP_MESSAGE";
    case MME_EVENT_SGSAP_TIMER:
        return "MME_EVENT_SGSAP_TIMER";
    case MME_EVENT_SGSAP_LO_SCTP_COMM_UP:
        return "MME_EVENT_SGSAP_LO_SCTP_COMM_UP";
    case MME_EVENT_SGSAP_LO_CONNREFUSED:
        return "MME_EVENT_SGSAP_LO_CONNREFUSED";

    case MME_EVENT_GN_MESSAGE:
        return "MME_EVENT_GN_MESSAGE";
    case MME_EVENT_GN_TIMER:
        return "MME_EVENT_GN_TIMER";

    case MME_EVENT_CONFIG_RELOAD:
        return "MME_EVENT_CONFIG_RELOAD";

    case MME_EVENT_ADMIN_DETACH_ENB:
        return "MME_EVENT_ADMIN_DETACH_ENB";
    case MME_EVENT_ADMIN_DETACH_UE:
        return "MME_EVENT_ADMIN_DETACH_UE";
    case MME_EVENT_ADMIN_PAGE_UE:
        return "MME_EVENT_ADMIN_PAGE_UE";
    case MME_EVENT_ADMIN_TAC_ADD:
        return "MME_EVENT_ADMIN_TAC_ADD";
    case MME_EVENT_ADMIN_MAINTENANCE_ENABLE:
        return "MME_EVENT_ADMIN_MAINTENANCE_ENABLE";
    case MME_EVENT_ADMIN_MAINTENANCE_DISABLE:
        return "MME_EVENT_ADMIN_MAINTENANCE_DISABLE";
    case MME_EVENT_ADMIN_MAINTENANCE_DRAIN:
        return "MME_EVENT_ADMIN_MAINTENANCE_DRAIN";
    case MME_EVENT_ORPHAN_SWEEP:
        return "MME_EVENT_ORPHAN_SWEEP";
    default:
       break;
    }

    return "UNKNOWN_EVENT";
}

void s1ap_event_push_decoded(void *sock, ogs_sockaddr_t *addr,
        ogs_pkbuf_t *pkbuf, ogs_s1ap_message_t *pdu)
{
    mme_event_t *e = NULL;
    int rv;

    ogs_assert(sock);
    ogs_assert(pkbuf);
    ogs_assert(pdu);

    e = mme_event_new(MME_EVENT_S1AP_MESSAGE);
    ogs_assert(e);
    e->sock = sock;
    e->addr = addr;
    e->pkbuf = pkbuf;
    e->s1ap_message = pdu;
    e->s1ap_rx_decoded = true;

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        if (e->addr)
            ogs_free(e->addr);
        ogs_pkbuf_free(e->pkbuf);
        ogs_s1ap_free(pdu);
        ogs_free(pdu);
        mme_event_free(e);
        return;
    }

    ogs_pollset_notify(ogs_app()->pollset);
}

void mme_sctp_event_push(mme_event_e id,
        void *sock, ogs_sockaddr_t *addr, ogs_pkbuf_t *pkbuf,
        uint16_t max_num_of_istreams, uint16_t max_num_of_ostreams)
{
    mme_event_t *e = NULL;
    int rv;
    bool critical;

    ogs_assert(id);
    ogs_assert(sock);

    e = mme_event_new(id);
    ogs_assert(e);
    e->sock = sock;
    e->addr = addr;
    e->pkbuf = pkbuf;
    e->max_num_of_istreams = max_num_of_istreams;
    e->max_num_of_ostreams = max_num_of_ostreams;

    /*
     * Lifecycle confirms must not be dropped when the main queue is full
     * (RX flood). Blocking ogs_queue_push from the IO thread would also
     * stall ALL S1 TX — use trypush + notify + short retry instead.
     */
    critical = (id == MME_EVENT_S1AP_IO_DRAINED ||
            id == MME_EVENT_S1AP_RX_SOCK_CLOSED ||
            id == MME_EVENT_S1AP_LO_CONNREFUSED ||
            id == MME_EVENT_S1AP_RX_WATCH_FAILED);

    if (critical && ogs_worker_self()) {
        int tries = 0;
        for (;;) {
            rv = ogs_queue_trypush(ogs_app()->queue, e);
            if (rv == OGS_OK)
                break;
            ogs_pollset_notify(ogs_app()->pollset);
            if (++tries > 10000) {
                ogs_error("mme_sctp_event_push: critical id=%d "
                        "trypush failed after retries (%d)", id, (int)rv);
                ogs_free(e->addr);
                if (e->pkbuf)
                    ogs_pkbuf_free(e->pkbuf);
                mme_event_free(e);
                return;
            }
            ogs_usleep(1000);
        }
        ogs_pollset_notify(ogs_app()->pollset);
        return;
    }

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        ogs_free(e->addr);
        if (e->pkbuf)
            ogs_pkbuf_free(e->pkbuf);
        mme_event_free(e);
        return;
    }

    if (ogs_worker_self()) {
        /* pushed from an S1AP RX worker: the main loop no longer polls
         * these sockets, so it may be asleep — wake it */
        ogs_pollset_notify(ogs_app()->pollset);
        return;
    }
#if HAVE_USRSCTP
    ogs_pollset_notify(ogs_app()->pollset);
#endif
}
