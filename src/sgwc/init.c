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

#include "context.h"
#include "event.h"

#include "gtp-path.h"
#include "pfcp-path.h"
#include "ga-writer.h"
#include "metrics.h"
#include "ogs-metrics.h"
#include "metrics/prometheus/json_pager.h"
#include "admin-api.h"
#include "pdn-info.h"
#include "sgwc-workers.h"

#include "sgwc-reload-lists.h"

static ogs_thread_t *thread;
static void sgwc_main(void *data);

static void sgwc_sighup_handler(void)
{
    sgwc_event_t *e = NULL;
    int rv;

    e = sgwc_event_new(SGWC_EVT_CONFIG_RELOAD);
    ogs_assert(e);

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        sgwc_event_free(e);
        return;
    }

    ogs_pollset_notify(ogs_app()->pollset);
}

static int initialized = 0;

int sgwc_initialize(void)
{
    int rv;
    int want_workers;

#define APP_NAME "sgwc"
    rv = ogs_app_parse_local_conf(APP_NAME);
    if (rv != OGS_OK) return rv;

    rv = sgwc_workers_parse_config();
    if (rv != OGS_OK) return rv;
    want_workers = sgwc_workers_configured();

    sgwc_metrics_init();

    ogs_gtp_context_init(ogs_app()->pool.nf * OGS_MAX_NUM_OF_GTPU_RESOURCE);
    ogs_pfcp_context_init();

    /*
     * The SGW-C context is PROCESS-GLOBAL: one config, one UE list, one
     * set of pools and hashes, initialized exactly once here and shared
     * by the event-loop thread and every shard worker (all container
     * mutation goes through sgwc_ctx_lock, see context.c).
     */
    sgwc_context_init();
    sgwc_event_init();

    rv = ogs_gtp_xact_init();
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_xact_init();
    if (rv != OGS_OK) return rv;

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    rv = ogs_gtp_context_parse_config(APP_NAME, "sgwu");
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_context_parse_config(APP_NAME, "sgwu");
    if (rv != OGS_OK) return rv;

    rv = sgwc_context_parse_config();
    if (rv != OGS_OK) return rv;

    if (want_workers > 0 &&
            sgwc_self()->inbound_roam_teid_offset >=
                    (1u << (32 - OGS_WORKER_ID_BITS))) {
        ogs_error("inbound_roam teid_offset 0x%x too large for "
                "sgwc.workers (must be < 2^%d)",
                sgwc_self()->inbound_roam_teid_offset,
                32 - OGS_WORKER_ID_BITS);
        return OGS_ERROR;
    }

    rv = ogs_metrics_context_parse_config(APP_NAME);
    if (rv != OGS_OK) return rv;

    rv = sgwc_gtp_open();
    if (rv != OGS_OK) return rv;

    rv = sgwc_pfcp_open();
    if (rv != OGS_OK) return rv;

    rv = sgwc_ga_writer_open();
    if (rv != OGS_OK) return rv;

    ogs_metrics_context_open(ogs_metrics_self());

    sgwc_admin_api_register();

    ogs_metrics_register_custom_ep(sgwc_dump_pdn_info, "/pdn-info");

    ogs_app_sighup_handler_set(sgwc_sighup_handler);

    if (want_workers > 0) {
        rv = sgwc_workers_start();
        if (rv != OGS_OK) return rv;
    }

    thread = ogs_thread_create(sgwc_main, NULL);
    if (!thread) return OGS_ERROR;

    initialized = 1;

    return OGS_OK;
}

void sgwc_terminate(void)
{
    if (!initialized) return;

    /* Wake main first so it can exit; then tear down workers. Doing
     * workers_stop() first left main posting into dying queues and, under
     * load, ogs_thread_destroy() FATAL'd ("thread still running"). */
    sgwc_event_term();
    ogs_thread_destroy(thread);
    thread = NULL;

    sgwc_workers_stop();

    ogs_metrics_context_close(ogs_metrics_self());

    sgwc_ga_writer_close();

    /* context final BEFORE socket teardown: sess_remove sends PFCP
     * deletion/purge messages (sgwc_sess_purge_upf) and must not write
     * through a destroyed PFCP socket (TSAN: heap-use-after-free in
     * ogs_pfcp_sendto during sgwc_context_final). */
    sgwc_context_final();

    /* session timers on worker timer managers are gone; free them */
    sgwc_workers_final();

    sgwc_gtp_close();
    sgwc_pfcp_close();

    ogs_pfcp_context_final();
    ogs_gtp_context_final();

    ogs_pfcp_xact_final();
    ogs_gtp_xact_final();

    sgwc_metrics_final();

    sgwc_event_final();
}

static void sgwc_main(void *data)
{
    ogs_fsm_t sgwc_sm;
    int rv;

    /*
     * The SGW-C context is process-global and was fully initialized by
     * sgwc_initialize() (config parse, sockets, peers). This thread just
     * runs the event loop over that shared state. GTP/PFCP xacts are NOT
     * re-initialized: on non-worker threads they use the process-global
     * pool shared with initialize().
     */
    ogs_fsm_init(&sgwc_sm, sgwc_state_initial, sgwc_state_final, 0);

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
            sgwc_event_t *e = NULL;

            rv = ogs_queue_trypop(ogs_app()->queue, (void**)&e);
            ogs_assert(rv != OGS_ERROR);

            if (rv == OGS_DONE)
                goto done;

            if (rv == OGS_RETRY)
                break;

            ogs_assert(e);
            ogs_fsm_dispatch(&sgwc_sm, e);
            sgwc_event_free(e);
        }
    }
done:

    ogs_fsm_fini(&sgwc_sm, 0);
}
