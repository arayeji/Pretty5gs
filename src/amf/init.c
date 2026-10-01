/*
 * Copyright (C) 2019-2025 by Sukchan Lee <acetcom@gmail.com>
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

#include "sbi-path.h"
#include "ngap-path.h"
#include "ngap-rx.h"
#include "ngap-io.h"
#include "ngap-free.h"
#include "metrics.h"

#include "ogs-metrics.h"
#include "metrics/prometheus/json_pager.h"
#include "gnb-info.h"
#include "ue-info.h"

static ogs_thread_t *thread;
static void amf_main(void *data);
static int initialized = 0;

int amf_initialize(void)
{
    int rv;

#define APP_NAME "amf"
    rv = ogs_app_parse_local_conf(APP_NAME);
    if (rv != OGS_OK) return rv;

    amf_metrics_init();

    ogs_sbi_context_init(OpenAPI_nf_type_AMF);
    amf_context_init();

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    rv = ogs_sbi_context_parse_config(APP_NAME, "nrf", "scp");
    if (rv != OGS_OK) return rv;

    rv = ogs_metrics_context_parse_config(APP_NAME);
    if (rv != OGS_OK) return rv;

    rv = amf_context_parse_config();
    if (rv != OGS_OK) return rv;

    rv = amf_context_nf_info();
    if (rv != OGS_OK) return rv;

    ogs_metrics_context_open(ogs_metrics_self());

    /* dumpers /gnb-info /ue-info */
    ogs_metrics_register_custom_ep(amf_dump_gnb_info, "/gnb-info");
    ogs_metrics_register_custom_ep(amf_dump_ue_info, "/ue-info");

    rv = amf_sbi_open();
    if (rv != OGS_OK) return rv;

    /* UE shards before any NGAP thread can route to them */
    rv = amf_workers_start(amf_self()->workers);
    if (rv != OGS_OK) return rv;

    /*
     * Side queue and close registry must exist before any thread can
     * post or confirm into them.
     */
    amf_event_ngap_connrefused_init();
    ngap_sock_close_init();

    /* RX workers before ngap_open(): sockets are assigned at accept */
    if (amf_self()->ngap_rx_workers > 0) {
        rv = ngap_rx_workers_start(amf_self()->ngap_rx_workers);
        if (rv != OGS_OK) return rv;
        rv = ngap_free_start();
        if (rv != OGS_OK) return rv;
    }

    /* IO threads before the first accept */
    if (amf_self()->ngap_io_thread > 0) {
        rv = ngap_io_start(amf_self()->ngap_io_thread);
        if (rv != OGS_OK) return rv;
    }

    rv = ngap_open();
    if (rv != OGS_OK) return rv;

    thread = ogs_thread_create(amf_main, NULL);
    if (!thread) return OGS_ERROR;

    initialized = 1;

    return OGS_OK;
}

static ogs_timer_t *t_termination_holding = NULL;

static void event_termination(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    /* runs beside amf_main() and the shards */
    ogs_sbi_lock();

    /* Sending NF Instance De-registration to NRF */
    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance)
        ogs_sbi_nf_fsm_fini(nf_instance);

    /* Gracefully shutdown the server by sending GOAWAY to each session. */
    ogs_sbi_server_graceful_shutdown_all();

    /* Starting holding timer */
    t_termination_holding = ogs_timer_add(ogs_app()->timer_mgr, NULL, NULL);
    ogs_assert(t_termination_holding);
#define TERMINATION_HOLDING_TIME ogs_time_from_msec(300)
    ogs_timer_start(t_termination_holding, TERMINATION_HOLDING_TIME);

    ogs_sbi_unlock();

    /* Sending termination event to the queue */
    amf_event_term();
}

void amf_terminate(void)
{
    if (!initialized) return;

    /* Daemon terminating */
    event_termination();
    ogs_thread_destroy(thread);
    ogs_timer_delete(t_termination_holding);

    /* shards send NGAP too: join them before the IO threads go */
    amf_workers_stop();

    /* main and the shards are joined, so nothing posts SEND/DRAIN
     * anymore: stop the IO threads before any socket teardown so no
     * send races a destroy */
    ngap_io_stop();

    ngap_close();
    ngap_rx_workers_stop();
    amf_sbi_close();

    /* no more producers of deferred frees or CONNREFUSED */
    ngap_free_stop();
    amf_event_ngap_connrefused_final();

    /* every confirming thread is joined: reap the close registry */
    ngap_sock_close_final();

    ogs_metrics_context_close(ogs_metrics_self());

    amf_context_final();
    /* UE timers of the shards are gone: free their timer managers */
    amf_workers_final();
    ogs_sbi_context_final();

    amf_metrics_final();

    /* per-thread pkbuf pools are destroyed in app_terminate() after
     * ogs_sctp_final(): pools must outlive every pkbuf */
}

static void amf_main(void *data)
{
    ogs_fsm_t amf_sm;
    int rv;
    bool backlog = false;

    /* sole consumer of ogs_app()->queue: must never block pushing to it */
    amf_event_mark_main_thread();
    ogs_sbi_lock_mark_poller();

    /* private pkbuf pool for the main loop (amf.pkbuf_thread_pool) */
    amf_pkbuf_thread_pool_attach();

    ogs_sbi_lock();
    ogs_fsm_init(&amf_sm, amf_state_initial, amf_state_final, 0);
    ogs_sbi_unlock();

    for ( ;; ) {
        ogs_time_t timeout = 0;

        /* events were left queued by the batch cap: do not sleep */
        if (!backlog) {
            ogs_sbi_lock();
            timeout = ogs_timer_mgr_next(ogs_app()->timer_mgr);
            ogs_sbi_unlock();
        }
        ogs_pollset_poll(ogs_app()->pollset, timeout);

        /*
         * After ogs_pollset_poll(), ogs_timer_mgr_expire() must be called.
         *
         * The reason is why ogs_timer_mgr_next() can get the current value
         * when ogs_timer_stop() is called internally in ogs_timer_mgr_expire().
         *
         * You should not use event-queue before ogs_timer_mgr_expire().
         * In this case, ogs_timer_mgr_expire() does not work
         * because 'if rv == OGS_DONE' statement is exiting and
         * not calling ogs_timer_mgr_expire().
         */
        ogs_sbi_lock();
        ogs_timer_mgr_expire(ogs_app()->timer_mgr);
        ogs_sbi_unlock();

        /*
         * Bound work per poll cycle: under a registration storm the
         * queue never empties, and draining it dry starves timers and
         * epoll.
         */
        {
            int batch = 0;
            const int batch_max = 128;

            backlog = false;
            for ( ;; ) {
                amf_event_t *e = NULL;

                /* CONNREFUSED first, then the app queue */
                rv = amf_event_ngap_connrefused_trypop(&e);
                if (rv == OGS_RETRY) {
                    rv = ogs_queue_trypop(ogs_app()->queue, (void**)&e);
                    ogs_assert(rv != OGS_ERROR);

                    if (rv == OGS_DONE)
                        goto done;

                    if (rv == OGS_RETRY)
                        break;
                } else {
                    ogs_assert(rv != OGS_ERROR);
                    if (rv == OGS_DONE)
                        goto done;
                }

                ogs_assert(e);
                if (!amf_workers_route(e)) {
                    amf_event_dispatch_begin();
                    ogs_sbi_lock();
                    do {
                        ogs_fsm_dispatch(&amf_sm, e);
                        ogs_event_free(e);
                    } while ((e = amf_event_local_pop()));
                    ogs_sbi_unlock();
                    amf_event_dispatch_end();
                }

                if (++batch >= batch_max) {
                    backlog = true;
                    break;
                }
            }
        }
    }
done:

    ogs_sbi_lock();
    ogs_fsm_fini(&amf_sm, 0);
    ogs_sbi_unlock();
}
