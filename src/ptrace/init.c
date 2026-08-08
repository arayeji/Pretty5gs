/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "context.h"
#include "capture.h"
#include "capture-ring.h"
#include "decode.h"
#include "correlate.h"
#include "cache.h"
#include "rules.h"
#include "store.h"
#include "trace.h"
#include "api.h"
#include "ptrace-sm.h"

#include "ogs-s1ap.h"

static ogs_thread_t *main_thread;
static ogs_thread_t *worker_threads[PTRACE_MAX_WORKERS];
static int num_workers;
static bool started;
static bool workers_running;

static void process_packet(ptrace_packet_t *pkt)
{
    ptrace_event_t *evs[PTRACE_MAX_EVENTS_PER_PKT];
    int n = 0, i;
    ptrace_rule_t *rule;

    if (ptrace_decode_packet(pkt, evs, &n) != OGS_OK) {
        ptrace_packet_free(pkt);
        return;
    }

    for (i = 0; i < n; i++) {
        ptrace_correlate_event(evs[i]);
        ptrace_store_put(evs[i]);

        rule = ptrace_rules_match(evs[i]);
        if (rule && evs[i]->ue_id)
            ptrace_cache_pin_ue(evs[i]->ue_id, rule->expires);

        if (rule ||
                strstr(evs[i]->message, "Reject") ||
                strstr(evs[i]->message, "Detach") ||
                strstr(evs[i]->message, "Create Session") ||
                strstr(evs[i]->message, "Session Establishment"))
            ptrace_api_publish(evs[i]);

        ptrace_event_free(evs[i]);
    }

    ptrace_packet_free(pkt);
}

static void decode_worker(void *data)
{
    ptrace_context_t *ctx = ptrace_self();
    (void)data;

    while (workers_running) {
        ptrace_packet_t *pkt = NULL;
        int rv = ogs_queue_timedpop(ctx->pkt_queue, (void **)&pkt,
                ogs_time_from_msec(200));
        if (rv != OGS_OK || !pkt)
            continue;
        process_packet(pkt);
    }
}

static void expire_timer_cb(void *data)
{
    (void)data;
    ptrace_cache_expire();
    ptrace_rules_expire();
}

static void ptrace_main(void *data)
{
    (void)data;
    /* Avoid sharing ogs_app()->pollset with the signal thread.
     * Housekeeping runs on a simple sleep loop. */
    while (workers_running) {
        ogs_msleep(1000);
        expire_timer_cb(NULL);
    }
}

int ptrace_initialize(void)
{
    int rv, i;
    ptrace_context_t *ctx;

#define APP_NAME "ptrace"
    rv = ogs_app_parse_local_conf(APP_NAME);
    if (rv != OGS_OK)
        return rv;

    rv = ptrace_context_init();
    if (rv != OGS_OK)
        return rv;

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK)
        return rv;

    /* Required before any ogs_s1ap_decode() — otherwise decode-fail
     * logging aborts on an uninitialized S1AP log domain.
     * Keep at ERROR so incomplete SCTP chunks do not flood WARN. */
    ogs_log_install_domain(&__ogs_s1ap_domain, "s1ap", OGS_LOG_ERROR);
    ptrace_decode_s1ap_init();

    rv = ptrace_context_parse_config();
    if (rv != OGS_OK)
        return rv;

    ctx = ptrace_self();

    rv = ptrace_correlate_init();
    if (rv != OGS_OK)
        return rv;
    rv = ptrace_cache_init(ctx->cache_minutes);
    if (rv != OGS_OK)
        return rv;
    rv = ptrace_rules_init();
    if (rv != OGS_OK)
        return rv;
    rv = ptrace_store_init();
    if (rv != OGS_OK)
        return rv;
    rv = ptrace_trace_init();
    if (rv != OGS_OK)
        return rv;

    if (ctx->redis_enabled)
        ptrace_store_redis_init(ctx->redis_url);
    if (ctx->clickhouse_enabled)
        ptrace_store_clickhouse_init(ctx->clickhouse_url);

    rv = ptrace_ring_open(ctx->pcap_ring_path, ctx->pcap_ring_size_gb);
    if (rv != OGS_OK)
        ogs_warn("ptrace: PCAP ring unavailable (continuing without disk ring)");

    workers_running = true;
    num_workers = ctx->workers > 0 ? ctx->workers : 4;
    for (i = 0; i < num_workers; i++) {
        worker_threads[i] = ogs_thread_create(decode_worker, NULL);
        if (!worker_threads[i])
            return OGS_ERROR;
    }

    rv = ptrace_capture_open();
    if (rv != OGS_OK)
        return rv;

    rv = ptrace_api_open();
    if (rv != OGS_OK)
        return rv;

    main_thread = ogs_thread_create(ptrace_main, NULL);
    if (!main_thread)
        return OGS_ERROR;

    started = true;
    ogs_info("Pretty-Trace (ptrace) initialize...done");
    return OGS_OK;
}

void ptrace_terminate(void)
{
    int i;

    if (!started)
        return;

    workers_running = false;
    ptrace_capture_close();
    ptrace_api_close();

    if (main_thread) {
        ogs_thread_destroy(main_thread);
        main_thread = NULL;
    }

    for (i = 0; i < num_workers; i++) {
        if (worker_threads[i]) {
            ogs_thread_destroy(worker_threads[i]);
            worker_threads[i] = NULL;
        }
    }

    ptrace_ring_close();
    ptrace_store_redis_final();
    ptrace_store_clickhouse_final();
    ptrace_trace_final();
    ptrace_store_final();
    ptrace_rules_final();
    ptrace_cache_final();
    ptrace_correlate_final();
    ptrace_context_final();
    started = false;
    ogs_info("Pretty-Trace (ptrace) terminate...done");
}
