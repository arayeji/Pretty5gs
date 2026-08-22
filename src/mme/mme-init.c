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
#include "mme-pgw-dns.h"

#include "mme-fd-path.h"
#include "s1ap-path.h"
#include "s1ap-free.h"
#include "s1ap-rx.h"
#include "s1ap-tx.h"
#include "s1ap-io.h"
#include "mme-workers.h"
#include "sgsap-path.h"
#include "sgsap-io.h"
#include "mme-gtp-path.h"
#include "metrics.h"
#include "metrics/prometheus/json_pager.h"
#include "enb-info.h"
#include "ue-info.h"
#include "admin-api.h"
#include "ogs-dbi.h"
#ifdef OPEN5GS_ADMIN_WATCHER
#include "mme-admin-watcher.h"
#endif

static void mme_sighup_handler(void)
{
    mme_event_t *e = NULL;
    int rv;

    e = mme_event_new(MME_EVENT_CONFIG_RELOAD);
    if (!e) {
        /* Under load the event pool can be empty; asserting here aborted
         * the whole MME on an otherwise recoverable SIGHUP. */
        ogs_error("SIGHUP: mme_event_new(CONFIG_RELOAD) failed - "
                "config reload skipped");
        return;
    }

    rv = mme_queue_push_main(e);
    if (rv != OGS_OK) {
        ogs_error("SIGHUP: config reload event dropped:%d", (int)rv);
        mme_event_free(e);
        return;
    }
}

static ogs_thread_t *thread;
static void mme_main(void *data);

static int initialized = 0;

int mme_initialize(void)
{
    int rv;

    /* Bootstrap / accept thread — distinct from mme-main event loop */
    ogs_thread_set_name("mme-boot");

#define APP_NAME "mme"
    rv = ogs_app_parse_local_conf(APP_NAME);
    if (rv != OGS_OK) return rv;

    mme_metrics_init();

    ogs_gtp_context_init(OGS_MAX_NUM_OF_GTPU_RESOURCE);
    mme_context_init();

    /* APN-FQDN DNS off the UE shards / mme-main (getaddrinfo / NAPTR). */
    mme_pgw_dns_workers_start();

    /* Operator can `kill -USR1 <mme-pid>` to dump live pool stats. */
    ogs_app_pool_dump_cb_set(mme_context_pool_dump);

    rv = ogs_gtp_xact_init();
    if (rv != OGS_OK) return rv;

    /*
     * Teach the GTP response timers the same lesson the NAS timers
     * already know: when the event queue lags, replies that arrived in
     * time are still waiting to be dispatched. Without this, an attach
     * storm turned S11 Create Session into false "SGW not responding"
     * (cause 100) -> Attach Reject #22 -> instant re-attach feedback loop.
     */
    ogs_gtp_xact_set_lag_cb(mme_event_lag);

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    rv = ogs_gtp_context_parse_config(APP_NAME, "sgwc");
    if (rv != OGS_OK) return rv;

    rv = ogs_metrics_context_parse_config(APP_NAME);
    if (rv != OGS_OK) return rv;

    /*
     * Optional MongoDB (same URI as HSS). Needed for provisioning_sms
     * IMSI→IMEI tracker (collection imei_tracker). Init before MME YAML
     * parse so rule load can see the collection.
     */
    if (ogs_app()->db_uri) {
        rv = ogs_dbi_init(ogs_app()->db_uri);
        if (rv != OGS_OK) {
            ogs_error("MME MongoDB init failed (db_uri) — "
                    "provisioning_sms IMEI tracker unavailable");
            /* Non-fatal: MME still runs without tracker */
        }
    }

    rv = mme_context_parse_config();
    if (rv != OGS_OK) return rv;

    /*
     * fake_csfb_lai=0 with fake_csfb=1 used to emit Combined Accept
     * without LAI (invalid NAS). That mode is rejected in emm-build:
     * Combined via fake_csfb always carries synthetic LAI/P-TMSI.
     */

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

    /* CONNREFUSED side-queue before any S1AP worker can post teardowns */
    mme_event_s1ap_connrefused_init();
    /* TX_READY side-queue before TX workers can complete encode jobs */
    mme_event_s1ap_tx_ready_init();

    /* close registry lock/hash before any thread can register/confirm */
    s1ap_sock_close_init();

    /*
     * UE-shard workers first: ogs_worker_shards_enable() must run
     * before ANY ogs_worker_create (including S1AP RX/TX/IO helpers).
     */
    if (mme_self()->workers > 0) {
        /*
         * With UE shards, S1AP output must go through the IO thread.
         * The legacy sync path (ogs_sctp_write_to_buffer) appends to
         * the per-eNB write_queue and arms POLLOUT on the MAIN
         * pollset — neither is thread-safe, so a shard worker sending
         * a NAS/release PDU would corrupt the queue and touch another
         * thread's pollset. Refuse the combination rather than crash
         * at random under load.
         */
        if (!mme_self()->s1ap_io_thread) {
            ogs_fatal("mme.workers requires mme.s1ap_io_thread: 1 "
                    "(S1AP TX from shard workers is only safe via the "
                    "IO thread). Set s1ap_io_thread: 1 or workers: 0.");
            return OGS_ERROR;
        }

        rv = mme_workers_start(mme_self()->workers);
        if (rv != OGS_OK) return OGS_ERROR;
    }

    /* Stage C needs UE shard workers to route to. */
    if (mme_self()->stage_c && mme_self()->workers <= 0) {
        ogs_warn("mme.stage_c requires mme.workers > 0; disabling stage_c");
        mme_self()->stage_c = 0;
    }

    /* Direct TX send needs both the encode workers and the IO thread. */
    if (mme_self()->s1ap_tx_direct &&
        (mme_self()->s1ap_tx_workers <= 0 ||
         mme_self()->s1ap_io_thread <= 0)) {
        ogs_warn("mme.s1ap_tx_direct requires s1ap_tx_workers > 0 and "
                "s1ap_io_thread >= 1; disabling s1ap_tx_direct");
        mme_self()->s1ap_tx_direct = 0;
    }

    /* before s1ap_open(): eNB sockets are assigned at accept time */
    if (mme_self()->s1ap_rx_workers > 0) {
        rv = s1ap_rx_workers_start(mme_self()->s1ap_rx_workers);
        if (rv != OGS_OK) return OGS_ERROR;
    }

    /* TX encode workers do not own sockets; start before accept so the
     * first DownlinkNASTransport can already post (default 0 = off). */
    if (mme_self()->s1ap_tx_workers > 0) {
        rv = s1ap_tx_workers_start(mme_self()->s1ap_tx_workers,
                mme_self()->s1ap_tx_direct ? true : false);
        if (rv != OGS_OK) return OGS_ERROR;
    }

    /* dedicated SCTP send thread(s): must exist before the first eNB
     * accept so every send since association start goes through it */
    if (mme_self()->s1ap_io_thread) {
        rv = s1ap_io_start(mme_self()->s1ap_io_thread);
        if (rv != OGS_OK) return OGS_ERROR;
    }

    /*
     * SGsAP TX from UE shards is the same hazard as S1AP TX from
     * shards: main owns the VLR socket lifecycle (CONNREFUSED close +
     * reconnect) while owner shards send CSFB/SMS PDUs. Auto-enable
     * the VLR send thread rather than run a known send-vs-destroy
     * race; one mostly-idle thread is the whole cost.
     */
    if (mme_self()->workers > 0 &&
        !ogs_list_empty(&mme_self()->vlr_list) &&
        !mme_self()->sgsap_io_thread) {
        ogs_warn("mme.workers with SGsAP/VLR configured requires "
                "mme.sgsap_io_thread: 1; enabling it");
        mme_self()->sgsap_io_thread = 1;
    }

    /* before mme-main starts: the first LU-Request must already route
     * through the IO thread */
    if (mme_self()->sgsap_io_thread) {
        rv = sgsap_io_start();
        if (rv != OGS_OK) return OGS_ERROR;
    }

    /* dedicated GTP-C RX thread (mme.gtpc_rx_thread, default off):
     * must come after mme_workers_start()/shards_enable(), and before
     * mme-main starts driving S11 transactions */
    rv = mme_gtpc_rx_start();
    if (rv != OGS_OK) return OGS_ERROR;

    /* ASN.1/pkbuf free offload: after shards_enable so the helper is a
     * normal ogs_worker; before accept so the first decoded PDU can defer */
    rv = s1ap_free_start();
    if (rv != OGS_OK) return OGS_ERROR;

    rv = s1ap_open();
    if (rv != OGS_OK) return OGS_ERROR;

    thread = ogs_thread_create_named(mme_main, NULL, "mme-main");
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

    /* After main joined nothing can post SEND/DRAIN jobs; stop the IO
     * thread BEFORE any socket teardown so no send races a destroy.
     * thread_fini frees everything still queued. */
    s1ap_io_stop();

    mme_gtp_close();
    sgsap_close();
    s1ap_close();
    s1ap_rx_workers_stop();

    /* UE shards after helpers: no more S11/EMM posts from sockets */
    mme_workers_stop();

    /* main + shards joined: nobody can post VLR sends anymore. Stop
     * BEFORE mme_context_final() frees the VLRs the queued jobs
     * reference (jobs re-validate under ctx lock, but the worker
     * itself must be gone before the pool is). */
    sgsap_io_stop();

    /* No more producers of deferred ASN.1 frees (main + RX + shards) */
    s1ap_free_stop();

    /* No more producers of CONNREFUSED / TX_READY */
    mme_event_s1ap_connrefused_final();
    mme_event_s1ap_tx_ready_final();

    /* every thread that could confirm is joined: reap sockets still
     * waiting in the close registry */
    s1ap_sock_close_final();

    ogs_metrics_context_close(ogs_metrics_self());

    mme_fd_final();

    mme_pgw_dns_workers_stop();

    mme_context_final();

    /* UE timers on worker timer managers are gone; now free them */
    mme_workers_final();

    ogs_gtp_context_final();

    ogs_gtp_xact_final();

    mme_metrics_final();

    if (ogs_mongoc()->initialized)
        ogs_dbi_final();

    /* Per-thread pkbuf pools are destroyed in app_terminate() AFTER
     * ogs_sctp_final(), not here: pools must outlive every pkbuf. */
}

static void mme_main(void *data)
{
    ogs_fsm_t mme_sm;
    int rv;

    /* Sole consumer of ogs_app()->queue: must never block pushing to it. */
    mme_event_mark_main_thread();

    /* private pkbuf pool for the main loop (mme.pkbuf_thread_pool) */
    mme_pkbuf_thread_pool_attach();

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

        /*
         * Bound work per poll cycle. Under attach storm the main queue
         * never empties; draining it to dry before re-polling starves
         * timers (orphan sweep / TX-hold watchdog) and epoll — lag climbs
         * while /admin/queues says "wedged". Cap so poll+timers run.
         */
        {
            int batch = 0;
            const int batch_max = 128;

            for ( ;; ) {
                mme_event_t *e = NULL;

                /* Prefer CONNREFUSED, then TX_READY, then the app queue. */
                rv = mme_event_s1ap_connrefused_trypop(&e);
                if (rv == OGS_RETRY)
                    rv = mme_event_s1ap_tx_ready_trypop(&e);
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
                mme_event_lag_observe(e);
                ogs_fsm_dispatch(&mme_sm, e);
                mme_event_free(e);

                if (++batch >= batch_max)
                    break;
            }
        }
    }
done:

    ogs_fsm_fini(&mme_sm, 0);
}
