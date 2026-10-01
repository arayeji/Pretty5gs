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
#include "context.h"
#include "ngap-io.h"

#define AMF_NGAP_CONNREFUSED_QUEUE  8192

static ogs_queue_t *ngap_cr_queue = NULL;
static ogs_hash_t *ngap_cr_pending = NULL; /* key: &e->ngap.sock while queued */
static ogs_thread_mutex_t ngap_cr_lock;
static bool ngap_cr_ready = false;

amf_event_t *amf_event_new(int id)
{
    amf_event_t *e = NULL;

    e = ogs_event_size(id, sizeof(amf_event_t));
    ogs_assert(e);

    e->h.id = id;

    return e;
}

const char *amf_event_get_name(amf_event_t *e)
{
    if (e == NULL) {
        return OGS_FSM_NAME_INIT_SIG;
    }

    switch (e->h.id) {
    case OGS_FSM_ENTRY_SIG:
        return OGS_FSM_NAME_ENTRY_SIG;
    case OGS_FSM_EXIT_SIG:
        return OGS_FSM_NAME_EXIT_SIG;

    case OGS_EVENT_SBI_SERVER:
        return OGS_EVENT_NAME_SBI_SERVER;
    case OGS_EVENT_SBI_CLIENT:
        return OGS_EVENT_NAME_SBI_CLIENT;
    case OGS_EVENT_SBI_TIMER:
        return OGS_EVENT_NAME_SBI_TIMER;

    case AMF_EVENT_NGAP_MESSAGE:
        return "AMF_EVENT_NGAP_MESSAGE";
    case AMF_EVENT_NGAP_TIMER:
        return "AMF_EVENT_NGAP_TIMER";
    case AMF_EVENT_NGAP_LO_ACCEPT:
        return "AMF_EVENT_NGAP_LO_ACCEPT";
    case AMF_EVENT_NGAP_LO_SCTP_COMM_UP:
        return "AMF_EVENT_NGAP_LO_SCTP_COMM_UP";
    case AMF_EVENT_NGAP_LO_CONNREFUSED:
        return "AMF_EVENT_NGAP_LO_CONNREFUSED";
    case AMF_EVENT_NGAP_RX_SOCK_CLOSED:
        return "AMF_EVENT_NGAP_RX_SOCK_CLOSED";
    case AMF_EVENT_NGAP_RX_WATCH_FAILED:
        return "AMF_EVENT_NGAP_RX_WATCH_FAILED";
    case AMF_EVENT_NGAP_IO_DRAINED:
        return "AMF_EVENT_NGAP_IO_DRAINED";

    case AMF_EVENT_5GMM_MESSAGE:
        return "AMF_EVENT_5GMM_MESSAGE";
    case AMF_EVENT_5GMM_TIMER:
        return "AMF_EVENT_5GMM_TIMER";
    case AMF_EVENT_5GSM_MESSAGE:
        return "AMF_EVENT_5GSM_MESSAGE";
    case AMF_EVENT_5GSM_TIMER:
        return "AMF_EVENT_5GSM_TIMER";

    default:
        break;
    }

    ogs_error("Unknown Event[%d]", e->h.id);
    return "UNKNOWN_EVENT";
}

static void amf_event_discard_ngap_push(amf_event_t *e)
{
    ogs_assert(e);
    if (e->ngap.addr)
        ogs_free(e->ngap.addr);
    if (e->pkbuf)
        ogs_pkbuf_free(e->pkbuf);
    if (e->ngap.message) {
        ogs_ngap_free(e->ngap.message);
        ogs_free(e->ngap.message);
        e->ngap.message = NULL;
    }
    ogs_event_free(e);
}

/* One warning per second at most, whichever thread drops. */
static ogs_thread_mutex_t drop_log_lock;
static ogs_time_t drop_log_window_start;
static int drop_log_count;
static int drop_log_last_id;
static int drop_log_last_rv;

static void amf_event_drop_log(const char *what, int id, int rv)
{
    ogs_time_t now = ogs_time_now();

    ogs_thread_mutex_lock(&drop_log_lock);
    if (!drop_log_window_start)
        drop_log_window_start = now;
    drop_log_count++;
    drop_log_last_id = id;
    drop_log_last_rv = rv;
    if (now - drop_log_window_start >= ogs_time_from_sec(1)) {
        ogs_warn("%s: %d drop(s) in last window (last id=%d rv=%d)",
                what, drop_log_count, drop_log_last_id, drop_log_last_rv);
        drop_log_count = 0;
        drop_log_window_start = now;
    }
    ogs_thread_mutex_unlock(&drop_log_lock);
}

/*
 * Identity of the amf_main() thread. Everything running inside its
 * poll/timer callbacks inherits the flag, which is exactly the set of
 * contexts that must never wait for ogs_app()->queue to drain.
 */
static OGS_THREAD_LOCAL bool thread_is_main = false;

void amf_event_mark_main_thread(void)
{
    thread_is_main = true;
}

bool amf_event_on_main_thread(void)
{
    return thread_is_main;
}

/*
 * Events a main-thread dispatch generates for itself (NGAP -> 5GMM/5GSM
 * hand-offs) run right after it, ahead of anything already queued.
 * With RX workers several NGAP messages of one UE are often queued at
 * once; appending the hand-off to the tail would run them as
 * NGAP1 NGAP2 NAS1 NAS2 and the second InitialUEMessage would see a
 * UE context the first one has not finished with. Main thread only.
 */
#define AMF_LOCAL_EVENT_MAX 64
static void *local_events[AMF_LOCAL_EVENT_MAX];
static int local_head, local_count;
static bool main_dispatching;

void amf_event_dispatch_begin(void)
{
    ogs_assert(thread_is_main);
    main_dispatching = true;
}

void amf_event_dispatch_end(void)
{
    ogs_assert(thread_is_main);
    main_dispatching = false;
}

void *amf_event_local_pop(void)
{
    void *e;

    if (!local_count)
        return NULL;

    e = local_events[local_head];
    local_head = (local_head + 1) % AMF_LOCAL_EVENT_MAX;
    local_count--;
    return e;
}

/* ~20ms at 100us; only ever spent on non-main threads. */
#define AMF_MAIN_PUSH_MAX_TRIES 200

int amf_queue_push_main(void *event)
{
    int rv, tries = 0;

    ogs_assert(event);

    if (thread_is_main && main_dispatching &&
            local_count < AMF_LOCAL_EVENT_MAX) {
        local_events[(local_head + local_count) % AMF_LOCAL_EVENT_MAX] =
            event;
        local_count++;
        return OGS_OK;
    }

    for (;;) {
        rv = ogs_queue_trypush(ogs_app()->queue, event);
        if (rv == OGS_OK) {
            ogs_pollset_notify(ogs_app()->pollset);
            return OGS_OK;
        }
        if (rv != OGS_RETRY)
            return rv; /* terminated */

        /* Full: waking main is the only thing that can help, and on
         * main itself there is nobody left to wait for. */
        ogs_pollset_notify(ogs_app()->pollset);
        if (thread_is_main || ++tries > AMF_MAIN_PUSH_MAX_TRIES)
            return OGS_RETRY;
        ogs_usleep(100);
    }
}

void amf_event_term(void)
{
    ogs_queue_term(ogs_app()->queue);
    if (ngap_cr_ready)
        ogs_queue_term(ngap_cr_queue);
    ogs_pollset_notify(ogs_app()->pollset);
}

void amf_event_ngap_connrefused_init(void)
{
    if (ngap_cr_ready)
        return;

    ogs_thread_mutex_init(&ngap_cr_lock);
    ogs_thread_mutex_init(&drop_log_lock);
    ngap_cr_queue = ogs_queue_create(AMF_NGAP_CONNREFUSED_QUEUE);
    ogs_assert(ngap_cr_queue);
    ngap_cr_pending = ogs_hash_make();
    ogs_assert(ngap_cr_pending);
    ngap_cr_ready = true;
}

void amf_event_ngap_connrefused_final(void)
{
    if (!ngap_cr_ready)
        return;

    /* The queue was terminated in amf_event_term(); events still in it
     * are abandoned at process shutdown, like the app queue. */
    ogs_queue_destroy(ngap_cr_queue);
    ngap_cr_queue = NULL;
    ogs_hash_destroy(ngap_cr_pending);
    ngap_cr_pending = NULL;
    ogs_thread_mutex_destroy(&ngap_cr_lock);
    ogs_thread_mutex_destroy(&drop_log_lock);
    ngap_cr_ready = false;
}

int amf_event_ngap_connrefused_trypop(amf_event_t **e)
{
    int rv;

    ogs_assert(e);
    *e = NULL;

    if (!ngap_cr_ready)
        return OGS_RETRY;

    ogs_thread_mutex_lock(&ngap_cr_lock);
    rv = ogs_queue_trypop(ngap_cr_queue, (void **)e);
    if (rv == OGS_OK && *e)
        ogs_hash_set(ngap_cr_pending,
                &(*e)->ngap.sock, sizeof((*e)->ngap.sock), NULL);
    ogs_thread_mutex_unlock(&ngap_cr_lock);
    return rv;
}

static void amf_sctp_connrefused_enqueue(amf_event_t *e)
{
    void *sock;
    int rv;

    ogs_assert(e);
    ogs_assert(e->h.id == AMF_EVENT_NGAP_LO_CONNREFUSED);

    if (!ngap_cr_ready) {
        amf_event_discard_ngap_push(e);
        return;
    }

    sock = e->ngap.sock;

    ogs_thread_mutex_lock(&ngap_cr_lock);
    if (ogs_hash_get(ngap_cr_pending, &sock, sizeof(sock))) {
        /* already queued for this association: coalesce */
        ogs_thread_mutex_unlock(&ngap_cr_lock);
        amf_event_discard_ngap_push(e);
        return;
    }

    rv = ogs_queue_trypush(ngap_cr_queue, e);
    if (rv == OGS_OK) {
        ogs_hash_set(ngap_cr_pending,
                &e->ngap.sock, sizeof(e->ngap.sock), e);
        ogs_thread_mutex_unlock(&ngap_cr_lock);
        ogs_pollset_notify(ogs_app()->pollset);
        return;
    }
    ogs_thread_mutex_unlock(&ngap_cr_lock);

    amf_event_drop_log("ngap CONNREFUSED side-queue", e->h.id, (int)rv);
    amf_event_discard_ngap_push(e);
    ogs_pollset_notify(ogs_app()->pollset);
}

void ngap_event_push_decoded(void *sock, ogs_sockaddr_t *addr,
        ogs_pkbuf_t *pkbuf, ogs_ngap_message_t *pdu)
{
    amf_event_t *e = NULL;
    int rv;

    ogs_assert(sock);
    ogs_assert(pkbuf);
    ogs_assert(pdu);

    e = amf_event_new(AMF_EVENT_NGAP_MESSAGE);
    ogs_assert(e);
    e->ngap.sock = sock;
    e->ngap.addr = addr;
    e->pkbuf = pkbuf;
    e->ngap.message = pdu;
    e->ngap.rx_decoded = true;

    /*
     * Never block an RX worker on the main queue: a blocked worker
     * stops polling every gNB it owns and their SCTP Recv-Q grows
     * while the gauges still look stable.
     */
    rv = ogs_queue_trypush(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        amf_event_drop_log("ngap decoded push", e->h.id, (int)rv);
        amf_event_discard_ngap_push(e);
    }
    ogs_pollset_notify(ogs_app()->pollset);
}

void amf_sctp_event_push(int id,
        void *sock, ogs_sockaddr_t *addr, ogs_pkbuf_t *pkbuf,
        uint16_t max_num_of_istreams, uint16_t max_num_of_ostreams)
{
    amf_event_t *e = NULL;
    int rv;

    ogs_assert(id);
    ogs_assert(sock);

    e = amf_event_new(id);
    ogs_assert(e);

    e->pkbuf = pkbuf;

    e->ngap.sock = sock;
    e->ngap.addr = addr;
    e->ngap.max_num_of_istreams = max_num_of_istreams;
    e->ngap.max_num_of_ostreams = max_num_of_ostreams;

    /* lifecycle teardowns never share the NGAP flood path */
    if (id == AMF_EVENT_NGAP_LO_CONNREFUSED) {
        amf_sctp_connrefused_enqueue(e);
        return;
    }

    if (ogs_worker_self()) {
        /*
         * Close confirms get a short trypush burst; losing one would
         * wedge the close registry. Everything else drops on a full
         * queue rather than freezing the worker's pollset.
         */
        bool must_deliver = (id == AMF_EVENT_NGAP_IO_DRAINED ||
                id == AMF_EVENT_NGAP_RX_SOCK_CLOSED ||
                id == AMF_EVENT_NGAP_RX_WATCH_FAILED);

        if (must_deliver) {
            int tries = 0;
            for (;;) {
                rv = ogs_queue_trypush(ogs_app()->queue, e);
                if (rv == OGS_OK)
                    break;
                ogs_pollset_notify(ogs_app()->pollset);
                if (++tries > AMF_MAIN_PUSH_MAX_TRIES) {
                    ogs_error("amf_sctp_event_push: must-deliver id=%d "
                            "dropped after short retry (%d)", id, (int)rv);
                    if (id == AMF_EVENT_NGAP_IO_DRAINED)
                        ngap_sock_close_confirm(sock, NGAP_SOCK_CONFIRM_IO);
                    else if (id == AMF_EVENT_NGAP_RX_SOCK_CLOSED)
                        ngap_sock_close_confirm(sock, NGAP_SOCK_CONFIRM_RX);
                    amf_event_discard_ngap_push(e);
                    return;
                }
                ogs_usleep(100);
            }
        } else {
            rv = ogs_queue_trypush(ogs_app()->queue, e);
            if (rv != OGS_OK) {
                amf_event_drop_log("amf_sctp_event_push", id, (int)rv);
                amf_event_discard_ngap_push(e);
                ogs_pollset_notify(ogs_app()->pollset);
                return;
            }
        }
        ogs_pollset_notify(ogs_app()->pollset);
        return;
    }

    rv = amf_queue_push_main(e);
    if (rv != OGS_OK) {
        amf_event_drop_log("amf_sctp_event_push (main)", id, (int)rv);
        amf_event_discard_ngap_push(e);
    }
}
