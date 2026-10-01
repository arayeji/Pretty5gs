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

#include "context.h"
#include "event.h"
#include "fd-path.h"
#include "gtp-path.h"
#include "pfcp-path.h"
#include "sbi-path.h"
#include "radius-path.h"
#include "ga-writer.h"
#include "metrics.h"
#include "ogs-metrics.h"
#include "metrics/prometheus/json_pager.h"
#include "pdu-info.h"
#include "admin-api.h"
#include "smf-reload-lists.h"
#include "smf-workers.h"
#include "sbi-relay.h"
#ifdef OPEN5GS_ADMIN_WATCHER
#include "smf-admin-watcher.h"
#endif

static ogs_thread_t *thread;
static void smf_main(void *data);

static void smf_sighup_handler(void)
{
    smf_event_push_main(smf_event_new(SMF_EVT_CONFIG_RELOAD));
}

static int initialized = 0;

int smf_initialize(void)
{
    int rv;

#define APP_NAME "smf"
    rv = ogs_app_parse_local_conf(APP_NAME);
    if (rv != OGS_OK) return rv;

    rv = smf_workers_parse_config();
    if (rv != OGS_OK) return rv;

    smf_metrics_init();

    ogs_gtp_context_init(ogs_app()->pool.nf * OGS_MAX_NUM_OF_GTPU_RESOURCE);
    ogs_pfcp_context_init();
    ogs_sbi_context_init(OpenAPI_nf_type_SMF);

    smf_context_init();

    rv = ogs_gtp_xact_init();
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_xact_init();
    if (rv != OGS_OK) return rv;

    /*
     * When the event queue lags, replies that arrived in time are still
     * waiting to be dispatched; defer GTP/PFCP retransmit give-ups so a
     * signaling storm does not turn into false "peer no response".
     */
    ogs_gtp_xact_set_lag_cb(smf_event_lag);
    ogs_pfcp_xact_set_lag_cb(smf_event_lag);

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    rv = ogs_gtp_context_parse_config(APP_NAME, "upf");
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_context_parse_config(APP_NAME, "upf");
    if (rv != OGS_OK) return rv;

    rv = ogs_sbi_context_parse_config(APP_NAME, "nrf", "scp");
    if (rv != OGS_OK) return rv;

    rv = ogs_metrics_context_parse_config(APP_NAME);
    if (rv != OGS_OK) return rv;

    rv = smf_context_parse_config();
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_ue_pool_generate();
    if (rv != OGS_OK) return rv;

    ogs_metrics_context_open(ogs_metrics_self());

    rv = smf_fd_init();
    if (rv != 0) return OGS_ERROR;

    rv = smf_gtp_open();
    if (rv != 0) return OGS_ERROR;

    rv = smf_pfcp_open();
    if (rv != 0) return OGS_ERROR;

    rv = smf_sbi_open();
    if (rv != 0) return OGS_ERROR;

    smf_radius_init();

    rv = smf_radius_pod_open();
    if (rv != 0) return OGS_ERROR;

    rv = smf_ga_writer_open();
    if (rv != 0) return OGS_ERROR;

    ogs_app_sighup_handler_set(smf_sighup_handler);

    smf_sbi_relay_init();

    rv = smf_workers_start();
    if (rv != OGS_OK) return rv;

    /* RX helpers after shards_enable (workers_start): not protocol shards */
    rv = smf_gtpc_rx_start();
    if (rv != OGS_OK) return rv;
    rv = smf_pfcp_rx_start();
    if (rv != OGS_OK) return rv;

    thread = ogs_thread_create_named(smf_main, NULL, "smf-main");
    if (!thread) return OGS_ERROR;

    /* dumper /pdu-info */
    ogs_metrics_register_custom_ep(smf_dump_pdu_info, "/pdu-info");

    smf_admin_api_register();

#ifdef OPEN5GS_ADMIN_WATCHER
    (void)smf_admin_watcher_init();
#endif

    initialized = 1;

    return OGS_OK;
}

static ogs_timer_t *t_termination_holding = NULL;

static void event_termination(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

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

    /* Sending termination event to the queue */
    ogs_queue_term(ogs_app()->queue);
    ogs_pollset_notify(ogs_app()->pollset);
}

void smf_terminate(void)
{
    if (!initialized) return;

#ifdef OPEN5GS_ADMIN_WATCHER
    smf_admin_watcher_final();
#endif

    /* Daemon terminating */
    event_termination();
    ogs_thread_destroy(thread);
    ogs_timer_delete(t_termination_holding);

    /*
     * RX helpers first: while alive they still recv/classify and can post
     * into dying worker queues. Then join shards (their timer managers
     * stay alive until smf_workers_final(), after context final).
     */
    smf_gtpc_rx_stop();
    smf_pfcp_rx_stop();
    smf_workers_stop();

    smf_ga_writer_close();
    smf_radius_pod_close();
    smf_gtp_close();
    smf_pfcp_close();
    smf_sbi_close();

    ogs_metrics_context_close(ogs_metrics_self());

    smf_fd_final();

    smf_context_final();
    smf_radius_servers_close();

    /* session timers on worker timer managers are gone; free them */
    smf_workers_final();
    smf_sbi_relay_final();

    ogs_pfcp_context_final();
    ogs_sbi_context_final();
    ogs_gtp_context_final();

    ogs_pfcp_xact_final();
    ogs_gtp_xact_final();

    smf_metrics_final();
}

static void smf_main(void *data)
{
    ogs_fsm_t smf_sm;
    int rv;

    ogs_fsm_init(&smf_sm, smf_state_initial, smf_state_final, 0);

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
            smf_event_t *e = NULL;

            rv = ogs_queue_trypop(ogs_app()->queue, (void**)&e);
            ogs_assert(rv != OGS_ERROR);

            if (rv == OGS_DONE)
                goto done;

            if (rv == OGS_RETRY)
                break;

            ogs_assert(e);
            smf_event_lag_observe(e);
            smf_event_trace_rx_restore(e);
            ogs_fsm_dispatch(&smf_sm, e);
            ogs_event_free(e);
        }
    }
done:
    /* workers blocked in smf_main_call() must not wait for us any more */
    smf_main_call_shutdown();

    ogs_fsm_fini(&smf_sm, 0);
    smf_radius_thread_final();
}
