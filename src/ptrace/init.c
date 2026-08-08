/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "context.h"
#include "capture.h"
#include "capture-ring.h"
#include "decode.h"
#include "identity.h"
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

/* Optional: full S1AP ASN for a frame when the UE is already pinned/traced.
 * Uses the small pkt pool — never the default live path. */
static void enrich_asn_if_traced(ptrace_packet_t *pkt, uint64_t ue_id)
{
    ptrace_event_t *evs[PTRACE_MAX_EVENTS_PER_PKT];
    int n = 0, i;
    ptrace_context_t *ctx = ptrace_self();

    if (!pkt || !ue_id || !ptrace_cache_ue_is_pinned(ue_id))
        return;

    memset(evs, 0, sizeof(evs));
    if (ptrace_decode_packet(pkt, evs, &n) != OGS_OK)
        return;
    if (n > PTRACE_MAX_EVENTS_PER_PKT)
        n = PTRACE_MAX_EVENTS_PER_PKT;

    for (i = 0; i < n; i++) {
        if (!evs[i])
            continue;
        if (pkt->packet_ref[0] && !evs[i]->packet_ref[0])
            ogs_cpystrn(evs[i]->packet_ref, pkt->packet_ref,
                    sizeof(evs[i]->packet_ref));
        ptrace_correlate_event(evs[i]);
        ptrace_store_put(evs[i]);
        ptrace_event_free(evs[i]);
        ctx->asn_traced++;
    }
}

static void process_id_event(ptrace_id_event_t *id)
{
    ptrace_event_t *evt;
    ptrace_rule_t *rule;
    ptrace_context_t *ctx = ptrace_self();
    uint64_t eid;

    if (!id)
        return;

    evt = ptrace_event_alloc();
    if (!evt) {
        ptrace_id_event_free(id);
        return;
    }
    eid = evt->id;
    ptrace_identity_to_event(id, evt);
    evt->id = eid;

    ptrace_correlate_event(evt);
    ptrace_store_put(evt);

    rule = ptrace_rules_match(evt);
    if (rule && evt->ue_id)
        ptrace_cache_pin_ue(evt->ue_id, rule->expires);

    if (rule ||
            strstr(evt->message, "Reject") ||
            strstr(evt->message, "Detach") ||
            strstr(evt->message, "Create Session") ||
            strstr(evt->message, "Modify Bearer") ||
            strstr(evt->message, "Session Establishment") ||
            strstr(evt->message, "Attach") ||
            strstr(evt->message, "Initial UE") ||
            strstr(evt->message, "NAS ") ||
            !strcmp(evt->message, "AIR") ||
            !strcmp(evt->message, "AIA") ||
            !strcmp(evt->message, "ULR") ||
            !strcmp(evt->message, "ULA") ||
            evt->ids.imsi[0])
        ptrace_api_publish(evt);

    ctx->events_out++;
    ptrace_event_free(evt);
    ptrace_id_event_free(id);
}

static void process_packet_offline(ptrace_packet_t *pkt)
{
    ptrace_id_event_t id;
    char ref[PTRACE_MAX_REF_LEN];
    bool got_id = false;

    if (!pkt)
        return;

    memset(&id, 0, sizeof(id));
    ref[0] = '\0';
    if (pkt->packet_ref[0])
        ogs_cpystrn(ref, pkt->packet_ref, sizeof(ref));
    else
        ptrace_ring_write(pkt->data, pkt->len, pkt->ts, ref, sizeof(ref));

    got_id = ptrace_identity_extract(pkt->data, pkt->len, pkt->ts, pkt->role,
            ref[0] ? ref : pkt->packet_ref, &id);
    if (got_id) {
        ptrace_id_event_t *heap = ptrace_id_event_alloc();
        if (heap) {
            *heap = id;
            process_id_event(heap);
        } else {
            ptrace_event_t stack;
            uint64_t ue_id;
            memset(&stack, 0, sizeof(stack));
            ptrace_identity_to_event(&id, &stack);
            ue_id = ptrace_correlate_event(&stack);
            if (ue_id && ptrace_cache_ue_is_pinned(ue_id)) {
                if (ref[0])
                    ogs_cpystrn(pkt->packet_ref, ref, sizeof(pkt->packet_ref));
                enrich_asn_if_traced(pkt, ue_id);
            }
            ptrace_packet_free(pkt);
            return;
        }
    }

    if (got_id && id.ids.imsi[0]) {
        ptrace_ue_t *ue = ptrace_correlate_find(id.ids.imsi);
        if (ue && ptrace_cache_ue_is_pinned(ue->ue_id)) {
            if (ref[0])
                ogs_cpystrn(pkt->packet_ref, ref, sizeof(pkt->packet_ref));
            enrich_asn_if_traced(pkt, ue->ue_id);
        }
    }

    ptrace_packet_free(pkt);
}

static void index_worker(void *data)
{
    ptrace_context_t *ctx = ptrace_self();
    (void)data;

    while (workers_running) {
        ptrace_id_event_t *id = NULL;
        ptrace_packet_t *pkt = NULL;
        int rv;

        rv = ogs_queue_timedpop(ctx->id_queue, (void **)&id,
                ogs_time_from_msec(50));
        if (rv == OGS_OK && id)
            process_id_event(id);

        /* Offline pcap replay / rare ASN enrich still uses pkt_queue. */
        rv = ogs_queue_timedpop(ctx->pkt_queue, (void **)&pkt,
                ogs_time_from_msec(10));
        if (rv == OGS_OK && pkt)
            process_packet_offline(pkt);
    }
}

static void expire_timer_cb(void *data)
{
    (void)data;
    ptrace_cache_expire();
    ptrace_rules_expire();
    ptrace_correlate_expire();
    ptrace_rates_update();
}

static void ptrace_main(void *data)
{
    (void)data;
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

    if (ctx->pcap_ring_path[0])
        ptrace_ring_bootstrap(ctx->pcap_ring_path);

    rv = ptrace_ring_open(ctx->pcap_ring_path, ctx->pcap_ring_size_gb);
    if (rv != OGS_OK)
        ogs_warn("ptrace: PCAP ring unavailable (continuing without disk ring)");

    workers_running = true;
    num_workers = ctx->workers > 0 ? ctx->workers : 4;
    for (i = 0; i < num_workers; i++) {
        worker_threads[i] = ogs_thread_create(index_worker, NULL);
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
    ogs_info("Pretty-Trace (ptrace) initialize...done (target-only)");
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
