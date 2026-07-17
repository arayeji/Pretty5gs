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
    int saved_max_ue = 0;
    int saved_sess = 0;
    int saved_bearer = 0;
    int saved_tunnel = 0;

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
     * The SGW-C context is per-thread (SMP). THIS thread only performs
     * initialization — config parse, socket setup, peer resolution — and
     * never owns UEs/sessions: those live on the event-loop thread
     * (sgwc_main, see below) or on shard workers. Always shrink the UE
     * pools for this thread's context instance so the real memory goes
     * to the threads that use it.
     */
    saved_max_ue = ogs_global_conf()->max.ue;
    saved_sess = ogs_app()->pool.sess;
    saved_bearer = ogs_app()->pool.bearer;
    saved_tunnel = ogs_app()->pool.tunnel;
    ogs_global_conf()->max.ue = 1;
    ogs_app()->pool.sess = 1;
    ogs_app()->pool.bearer = 4;
    ogs_app()->pool.tunnel = 4;

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

    /* Restore real pool sizes for the threads that own UEs/sessions. */
    ogs_global_conf()->max.ue = saved_max_ue;
    ogs_app()->pool.sess = saved_sess;
    ogs_app()->pool.bearer = saved_bearer;
    ogs_app()->pool.tunnel = saved_tunnel;

    if (want_workers > 0) {
        rv = sgwc_workers_start();
        if (rv != OGS_OK) return rv;

        /*
         * Workers have taken their per-shard pool sizes (workers_start
         * divides the globals). The event-loop thread owns no UEs in SMP
         * mode, so shrink the globals again before creating it; nothing
         * after this point reads the original values.
         */
        ogs_global_conf()->max.ue = 1;
        ogs_app()->pool.sess = 1;
        ogs_app()->pool.bearer = 4;
        ogs_app()->pool.tunnel = 4;
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

    sgwc_gtp_close();
    sgwc_pfcp_close();

    sgwc_ga_writer_close();

    sgwc_context_final();

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
     * This is NOT the thread that ran sgwc_initialize(): the SGW-C
     * context (pools, hashes, parsed config) is thread-local, so this
     * thread must build its own instance — same sequence as the shard
     * worker thread_init hook. Without it every self.* access here reads
     * a zeroed TLS struct: NULL hash asserts on the first S11 lookup
     * (workers: 0), echo answering with recovery counter 0, Gn disabled
     * in RX, etc. GTP/PFCP xacts are NOT re-initialized: on non-worker
     * threads they use the process-global pool shared with initialize().
     */
    sgwc_context_init();

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    ogs_assert(rv == OGS_OK);

    rv = sgwc_context_parse_config();
    ogs_assert(rv == OGS_OK);

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
