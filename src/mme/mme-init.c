/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
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
#include "ogs-gtp.h"

#include "mme-context.h"
#include "mme-sm.h"
#include "mme-event.h"
#include "mme-timer.h"

#include "mme-fd-path.h"
#include "s1ap-path.h"
#include "s1ap-rx.h"
#include "s1ap-tx.h"
#include "sgsap-path.h"
#include "mme-gtp-path.h"
#include "metrics.h"
#include "metrics/prometheus/json_pager.h"
#include "enb-info.h"
#include "ue-info.h"
#include "admin-api.h"
#ifdef OPEN5GS_ADMIN_WATCHER
#include "mme-admin-watcher.h"
#endif

static void mme_sighup_handler(void)
{
    mme_event_t *e = NULL;
    int rv;

    e = mme_event_new(MME_EVENT_CONFIG_RELOAD);
    ogs_assert(e);

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        mme_event_free(e);
        return;
    }

    ogs_pollset_notify(ogs_app()->pollset);
}

static ogs_thread_t *thread;
static void mme_main(void *data);

static int initialized = 0;

int mme_initialize(void)
{
    int rv;

#define APP_NAME "mme"
    rv = ogs_app_parse_local_conf(APP_NAME);
    if (rv != OGS_OK) return rv;

    mme_metrics_init();

    ogs_gtp_context_init(OGS_MAX_NUM_OF_GTPU_RESOURCE);
    mme_context_init();

    /* Operator can `kill -USR1 <mme-pid>` to dump live pool stats. */
    ogs_app_pool_dump_cb_set(mme_context_pool_dump);

    rv = ogs_gtp_xact_init();
    if (rv != OGS_OK) return rv;

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    rv = ogs_gtp_context_parse_config(APP_NAME, "sgwc");
    if (rv != OGS_OK) return rv;

    rv = ogs_metrics_context_parse_config(APP_NAME);
    if (rv != OGS_OK) return rv;

    rv = mme_context_parse_config();
    if (rv != OGS_OK) return rv;

    ogs_app_sighup_handler_set(mme_sighup_handler);

    ogs_metrics_context_open(ogs_metrics_self());

    /* dumpers /enb-info /ue-info */
    ogs_metrics_register_custom_ep(mme_dump_enb_info, "/enb-info");
    ogs_metrics_register_custom_ep(mme_dump_ue_info, "/ue-info");

    /*
     * Admin (mutating) endpoints. No internal ACL - the metrics
     * listener is expected to be firewalled at the host/network
     * level. Each admin call is logged with caller address; see
     * src/mme/admin-api.h for the endpoint surface.
     */
    mme_admin_api_register();

    rv = mme_fd_init();
    if (rv != OGS_OK) return OGS_ERROR;

    rv = mme_gtp_open();
    if (rv != OGS_OK) return OGS_ERROR;

    rv = sgsap_open();
    if (rv != OGS_OK) return OGS_ERROR;

    /* before s1ap_open(): eNB sockets are assigned at accept time */
    if (mme_self()->s1ap_rx_workers > 0) {
        rv = s1ap_rx_workers_start(mme_self()->s1ap_rx_workers);
        if (rv != OGS_OK) return OGS_ERROR;
    }

    /* TX encode workers do not own sockets; start before accept so the
     * first DownlinkNASTransport can already post (default 0 = off). */
    if (mme_self()->s1ap_tx_workers > 0) {
        rv = s1ap_tx_workers_start(mme_self()->s1ap_tx_workers);
        if (rv != OGS_OK) return OGS_ERROR;
    }

    rv = s1ap_open();
    if (rv != OGS_OK) return OGS_ERROR;

    thread = ogs_thread_create(mme_main, NULL);
    if (!thread) return OGS_ERROR;

#ifdef OPEN5GS_ADMIN_WATCHER
    (void)mme_admin_watcher_init();
#endif

    initialized = 1;

    return OGS_OK;
}

void mme_terminate(void)
{
    if (!initialized) return;

#ifdef OPEN5GS_ADMIN_WATCHER
    mme_admin_watcher_final();
#endif

    mme_event_term();

    /* Drain TX workers while main can still handle TX_READY (decrements
     * pending / frees pkbufs). Then join main and tear sockets down. */
    s1ap_tx_workers_stop();
    ogs_thread_destroy(thread);

    mme_gtp_close();
    sgsap_close();
    s1ap_close();
    s1ap_rx_workers_stop();

    ogs_metrics_context_close(ogs_metrics_self());

    mme_fd_final();

    mme_context_final();

    ogs_gtp_context_final();

    ogs_gtp_xact_final();

    mme_metrics_final();
}

static void mme_main(void *data)
{
    ogs_fsm_t mme_sm;
    int rv;

    ogs_fsm_init(&mme_sm, mme_state_initial, mme_state_final, 0);

    for ( ;; ) {
        ogs_pollset_poll(ogs_app()->pollset,
                ogs_timer_mgr_next(ogs_app()->timer_mgr));

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
        ogs_timer_mgr_expire(ogs_app()->timer_mgr);

        for ( ;; ) {
            mme_event_t *e = NULL;

            rv = ogs_queue_trypop(ogs_app()->queue, (void**)&e);
            ogs_assert(rv != OGS_ERROR);

            if (rv == OGS_DONE)
                goto done;

            if (rv == OGS_RETRY)
                break;

            ogs_assert(e);
            ogs_fsm_dispatch(&mme_sm, e);
            mme_event_free(e);
        }
    }
done:

    ogs_fsm_fini(&mme_sm, 0);
}
