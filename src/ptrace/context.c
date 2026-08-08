/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "context.h"

int __ptrace_log_domain;

static ptrace_context_t self;
static bool initialized = false;

#define PTRACE_PKT_POOL_SIZE    65536
#define PTRACE_EVT_POOL_SIZE    65536

static OGS_POOL(pkt_pool, ptrace_packet_t);
static OGS_POOL(evt_pool, ptrace_event_t);
static ogs_thread_mutex_t pkt_lock;
static ogs_thread_mutex_t evt_lock;

ptrace_context_t *ptrace_self(void)
{
    return &self;
}

int ptrace_context_init(void)
{
    ogs_assert(!initialized);
    memset(&self, 0, sizeof(self));

    ogs_log_install_domain(&__ptrace_log_domain, "ptrace",
            ogs_core()->log.level);

    self.backend = PTRACE_BACKEND_PCAP;
    self.workers = 8;
    self.cache_minutes = 10;
    self.pcap_ring_size_gb = 2;
    ogs_cpystrn(self.pcap_ring_path,
            "/var/lib/open5gs/ptrace/ring", sizeof(self.pcap_ring_path));
    ogs_cpystrn(self.api_addr, "127.0.0.1", sizeof(self.api_addr));
    self.api_port = 8088;
    self.next_event_id = 1;
    self.next_ue_id = 1;

    ogs_pool_init(&pkt_pool, PTRACE_PKT_POOL_SIZE);
    ogs_pool_init(&evt_pool, PTRACE_EVT_POOL_SIZE);
    ogs_thread_mutex_init(&pkt_lock);
    ogs_thread_mutex_init(&evt_lock);

    self.pkt_queue = ogs_queue_create(PTRACE_PKT_POOL_SIZE);
    ogs_assert(self.pkt_queue);

    initialized = true;
    return OGS_OK;
}

void ptrace_context_final(void)
{
    if (!initialized)
        return;

    if (self.pkt_queue) {
        ogs_queue_term(self.pkt_queue);
        ogs_queue_destroy(self.pkt_queue);
        self.pkt_queue = NULL;
    }

    ogs_pool_final(&pkt_pool);
    ogs_pool_final(&evt_pool);
    ogs_thread_mutex_destroy(&pkt_lock);
    ogs_thread_mutex_destroy(&evt_lock);

    memset(&self, 0, sizeof(self));
    initialized = false;
}

static int parse_cache_minutes(int v)
{
    switch (v) {
    case 1: case 5: case 10: case 15: case 60:
        return v;
    default:
        ogs_warn("ptrace: invalid cache.duration_minutes=%d, using 10", v);
        return 10;
    }
}

int ptrace_context_parse_config(void)
{
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_app()->document;
    ogs_assert(document);

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "ptrace")) {
            ogs_yaml_iter_t ptrace_iter;
            ogs_yaml_iter_recurse(&root_iter, &ptrace_iter);
            while (ogs_yaml_iter_next(&ptrace_iter)) {
                const char *key = ogs_yaml_iter_key(&ptrace_iter);
                ogs_assert(key);

                if (!strcmp(key, "capture")) {
                    ogs_yaml_iter_t cap_iter;
                    ogs_yaml_iter_recurse(&ptrace_iter, &cap_iter);
                    while (ogs_yaml_iter_next(&cap_iter)) {
                        const char *ck = ogs_yaml_iter_key(&cap_iter);
                        if (!strcmp(ck, "backend")) {
                            const char *v = ogs_yaml_iter_value(&cap_iter);
                            if (v && !strcmp(v, "afpacket"))
                                self.backend = PTRACE_BACKEND_AFPACKET;
                            else if (v && !strcmp(v, "pfring"))
                                self.backend = PTRACE_BACKEND_PFRING;
                            else if (v && !strcmp(v, "dpdk"))
                                self.backend = PTRACE_BACKEND_DPDK;
                            else
                                self.backend = PTRACE_BACKEND_PCAP;
                        } else if (!strcmp(ck, "pcap_file")) {
                            const char *v = ogs_yaml_iter_value(&cap_iter);
                            if (v)
                                ogs_cpystrn(self.pcap_file, v,
                                        sizeof(self.pcap_file));
                        } else if (!strcmp(ck, "workers")) {
                            const char *v = ogs_yaml_iter_value(&cap_iter);
                            if (v) {
                                self.workers = atoi(v);
                                if (self.workers < 1)
                                    self.workers = 1;
                                if (self.workers > PTRACE_MAX_WORKERS)
                                    self.workers = PTRACE_MAX_WORKERS;
                            }
                        } else if (!strcmp(ck, "include_gtpu")) {
                            const char *v = ogs_yaml_iter_value(&cap_iter);
                            if (v && (!strcmp(v, "true") || !strcmp(v, "yes") ||
                                    !strcmp(v, "1")))
                                self.include_gtpu = true;
                        } else if (!strcmp(ck, "bpf")) {
                            const char *v = ogs_yaml_iter_value(&cap_iter);
                            if (v)
                                ogs_cpystrn(self.bpf, v, sizeof(self.bpf));
                        } else if (!strcmp(ck, "interface")) {
                            ogs_yaml_iter_t iface_array, iface_iter;
                            ogs_yaml_iter_recurse(&cap_iter, &iface_array);
                            while (ogs_yaml_iter_next(&iface_array) &&
                                    self.num_ifaces < PTRACE_MAX_IFACES) {
                                ptrace_iface_t *iface =
                                    &self.ifaces[self.num_ifaces];
                                ogs_yaml_iter_recurse(&iface_array,
                                        &iface_iter);
                                memset(iface, 0, sizeof(*iface));
                                while (ogs_yaml_iter_next(&iface_iter)) {
                                    const char *ik =
                                        ogs_yaml_iter_key(&iface_iter);
                                    const char *iv =
                                        ogs_yaml_iter_value(&iface_iter);
                                    if (!ik || !iv)
                                        continue;
                                    if (!strcmp(ik, "dev"))
                                        ogs_cpystrn(iface->dev, iv,
                                                sizeof(iface->dev));
                                    else if (!strcmp(ik, "role"))
                                        iface->role = ptrace_role_parse(iv);
                                }
                                if (iface->dev[0])
                                    self.num_ifaces++;
                            }
                        }
                    }
                } else if (!strcmp(key, "cache")) {
                    ogs_yaml_iter_t cache_iter;
                    ogs_yaml_iter_recurse(&ptrace_iter, &cache_iter);
                    while (ogs_yaml_iter_next(&cache_iter)) {
                        const char *ck = ogs_yaml_iter_key(&cache_iter);
                        const char *v = ogs_yaml_iter_value(&cache_iter);
                        if (!ck || !v)
                            continue;
                        if (!strcmp(ck, "duration_minutes"))
                            self.cache_minutes =
                                parse_cache_minutes(atoi(v));
                        else if (!strcmp(ck, "pcap_ring_path"))
                            ogs_cpystrn(self.pcap_ring_path, v,
                                    sizeof(self.pcap_ring_path));
                        else if (!strcmp(ck, "pcap_ring_size_gb"))
                            self.pcap_ring_size_gb = atoi(v);
                    }
                } else if (!strcmp(key, "redis")) {
                    ogs_yaml_iter_t r_iter;
                    ogs_yaml_iter_recurse(&ptrace_iter, &r_iter);
                    while (ogs_yaml_iter_next(&r_iter)) {
                        const char *rk = ogs_yaml_iter_key(&r_iter);
                        const char *v = ogs_yaml_iter_value(&r_iter);
                        if (!rk)
                            continue;
                        if (!strcmp(rk, "enabled") && v)
                            self.redis_enabled =
                                (!strcmp(v, "true") || !strcmp(v, "yes") ||
                                 !strcmp(v, "1"));
                        else if (!strcmp(rk, "url") && v)
                            ogs_cpystrn(self.redis_url, v,
                                    sizeof(self.redis_url));
                    }
                } else if (!strcmp(key, "clickhouse")) {
                    ogs_yaml_iter_t c_iter;
                    ogs_yaml_iter_recurse(&ptrace_iter, &c_iter);
                    while (ogs_yaml_iter_next(&c_iter)) {
                        const char *ck = ogs_yaml_iter_key(&c_iter);
                        const char *v = ogs_yaml_iter_value(&c_iter);
                        if (!ck)
                            continue;
                        if (!strcmp(ck, "enabled") && v)
                            self.clickhouse_enabled =
                                (!strcmp(v, "true") || !strcmp(v, "yes") ||
                                 !strcmp(v, "1"));
                        else if (!strcmp(ck, "url") && v)
                            ogs_cpystrn(self.clickhouse_url, v,
                                    sizeof(self.clickhouse_url));
                    }
                } else if (!strcmp(key, "api")) {
                    ogs_yaml_iter_t a_iter;
                    ogs_yaml_iter_recurse(&ptrace_iter, &a_iter);
                    while (ogs_yaml_iter_next(&a_iter)) {
                        const char *ak = ogs_yaml_iter_key(&a_iter);
                        const char *v = ogs_yaml_iter_value(&a_iter);
                        if (!ak || !v)
                            continue;
                        if (!strcmp(ak, "addr"))
                            ogs_cpystrn(self.api_addr, v,
                                    sizeof(self.api_addr));
                        else if (!strcmp(ak, "port"))
                            self.api_port = (uint16_t)atoi(v);
                    }
                }
            }
        }
    }

    return OGS_OK;
}

ptrace_packet_t *ptrace_packet_alloc(void)
{
    ptrace_packet_t *pkt = NULL;

    ogs_thread_mutex_lock(&pkt_lock);
    ogs_pool_alloc(&pkt_pool, &pkt);
    ogs_thread_mutex_unlock(&pkt_lock);
    if (!pkt)
        return NULL;
    memset(pkt, 0, sizeof(*pkt));
    return pkt;
}

void ptrace_packet_free(ptrace_packet_t *pkt)
{
    if (!pkt)
        return;
    ogs_thread_mutex_lock(&pkt_lock);
    ogs_pool_free(&pkt_pool, pkt);
    ogs_thread_mutex_unlock(&pkt_lock);
}

ptrace_event_t *ptrace_event_alloc(void)
{
    ptrace_event_t *evt = NULL;

    ogs_thread_mutex_lock(&evt_lock);
    ogs_pool_alloc(&evt_pool, &evt);
    if (evt) {
        memset(evt, 0, sizeof(*evt));
        evt->id = self.next_event_id++;
    }
    ogs_thread_mutex_unlock(&evt_lock);
    return evt;
}

void ptrace_event_free(ptrace_event_t *evt)
{
    if (!evt)
        return;
    ogs_thread_mutex_lock(&evt_lock);
    ogs_pool_free(&evt_pool, evt);
    ogs_thread_mutex_unlock(&evt_lock);
}
