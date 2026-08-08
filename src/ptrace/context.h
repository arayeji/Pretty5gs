/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_CONTEXT_H)
#define PTRACE_CONTEXT_H

#include "ptrace.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __ptrace_log_domain;
#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __ptrace_log_domain

typedef struct ptrace_rate_sample_s {
    ogs_time_t ts;
    uint64_t packets_in;
    uint64_t packets_drop;
    uint64_t filtered_noise;
    uint64_t identity_in;
    uint64_t events_out;
} ptrace_rate_sample_t;

typedef struct ptrace_context_s {
    ptrace_backend_e backend;
    char pcap_file[PTRACE_MAX_PATH_LEN];
    int workers;
    int num_ifaces;
    ptrace_iface_t ifaces[PTRACE_MAX_IFACES];
    bool include_gtpu;          /* capture GTP-U user plane (very heavy) */
    char bpf[256];              /* optional override; empty = auto */

    int cache_minutes;
    char pcap_ring_path[PTRACE_MAX_PATH_LEN];
    int pcap_ring_size_gb;

    bool redis_enabled;
    char redis_url[PTRACE_MAX_PATH_LEN];

    bool clickhouse_enabled;
    char clickhouse_url[PTRACE_MAX_PATH_LEN];

    char api_addr[PTRACE_MAX_ID_LEN];
    uint16_t api_port;

    /* Identity-first queue (default). Full pkt_queue kept for offline replay. */
    ogs_queue_t *id_queue;
    ogs_queue_t *pkt_queue;

    uint64_t next_event_id;
    uint64_t next_ue_id;
    uint64_t packets_in;
    uint64_t packets_drop;      /* failed to index identity (pool/queue full) */
    uint64_t packets_ring_drop; /* async PCAP ring queue full */
    uint64_t packets_filtered;  /* userspace non-signaling rejects */
    uint64_t filtered_noise;    /* signaling without subscriber identity */
    uint64_t identity_in;       /* compact identity events enqueued */
    uint64_t events_out;
    uint64_t s1ap_ok;
    uint64_t s1ap_fail;
    uint64_t s1ap_scan_hit;
    uint64_t s1ap_skip_pressure; /* ASN skipped (identity-first default) */
    uint64_t identity_inline;    /* legacy counter; same as identity_in path */
    uint64_t asn_traced;         /* optional ASN enrich for pinned/traced UEs */
    int capture_threads;

    /* Rolling 10s rate window (updated by /healthz or expire loop). */
    ptrace_rate_sample_t rate_prev;
    double drop_rate_10s;
    double identity_rate_10s;
    double filtered_noise_rate_10s;
    double packet_rate_10s;
} ptrace_context_t;

ptrace_context_t *ptrace_self(void);

int ptrace_initialize(void);
void ptrace_terminate(void);

int ptrace_context_init(void);
void ptrace_context_final(void);
int ptrace_context_parse_config(void);

ptrace_packet_t *ptrace_packet_alloc(void);
void ptrace_packet_free(ptrace_packet_t *pkt);
ptrace_id_event_t *ptrace_id_event_alloc(void);
void ptrace_id_event_free(ptrace_id_event_t *id);
ptrace_event_t *ptrace_event_alloc(void);
void ptrace_event_free(ptrace_event_t *evt);
int ptrace_packet_pool_avail(void);
int ptrace_id_pool_avail(void);
bool ptrace_under_pressure(void);
void ptrace_rates_update(void);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_CONTEXT_H */
