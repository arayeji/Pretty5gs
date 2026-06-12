/*
 * Copyright (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#if !defined(OGS_METRICS_INSIDE) && !defined(OGS_METRICS_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_METRICS_CONTEXT_H
#define OGS_METRICS_CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ogs_metrics_server_s ogs_metrics_server_t;

typedef enum ogs_metrics_metric_type_s  {
    OGS_METRICS_METRIC_TYPE_COUNTER,
    OGS_METRICS_METRIC_TYPE_GAUGE,
    OGS_METRICS_METRIC_TYPE_HISTOGRAM,
} ogs_metrics_metric_type_t;

typedef struct ogs_metrics_context_s {
    ogs_list_t  server_list;
    ogs_list_t  spec_list;

    uint16_t    metrics_port;

    /* custom endpoints */
    ogs_list_t custom_eps;
    /* admin endpoints (mutating) */
    ogs_list_t admin_eps;
} ogs_metrics_context_t;

typedef enum ogs_metrics_histogram_bucket_type_s  {
    OGS_METRICS_HISTOGRAM_BUCKET_TYPE_VARIABLE,
    OGS_METRICS_HISTOGRAM_BUCKET_TYPE_LINEAR,
    OGS_METRICS_HISTOGRAM_BUCKET_TYPE_EXPONENTIAL,
} ogs_metrics_histogram_bucket_type_t;

typedef struct ogs_metrics_histogram_bucket_params_s {
    ogs_metrics_histogram_bucket_type_t type;
    unsigned int count;
#define OGS_METRICS_HIST_VAR_BUCKETS_MAX 10
    union {
        struct {
            float start;
            float width;
        } lin;
        struct {
            float start;
            float factor;
        } exp;
        struct {
            float buckets[OGS_METRICS_HIST_VAR_BUCKETS_MAX];
        } var;
    };
} ogs_metrics_histogram_params_t;

typedef struct ogs_metrics_context_s ogs_metrics_context_t;
void ogs_metrics_context_init(void);
void ogs_metrics_context_open(ogs_metrics_context_t *ctx);
void ogs_metrics_context_close(ogs_metrics_context_t *ctx);
void ogs_metrics_context_final(void);
ogs_metrics_context_t *ogs_metrics_self(void);
int ogs_metrics_context_parse_config(const char *local);

void ogs_metrics_server_init(ogs_metrics_context_t *ctx);
void ogs_metrics_server_open(ogs_metrics_context_t *ctx);
void ogs_metrics_server_close(ogs_metrics_context_t *ctx);
void ogs_metrics_server_final(ogs_metrics_context_t *ctx);
ogs_metrics_server_t *ogs_metrics_server_add(
        ogs_sockaddr_t *addr, ogs_sockopt_t *option);
void ogs_metrics_server_remove(ogs_metrics_server_t *server);
void ogs_metrics_server_remove_all(void);

typedef struct ogs_metrics_spec_s ogs_metrics_spec_t;
void ogs_metrics_spec_init(ogs_metrics_context_t *ctx); 
void ogs_metrics_spec_final(ogs_metrics_context_t *ctx);
ogs_metrics_spec_t *ogs_metrics_spec_new(
        ogs_metrics_context_t *ctx, ogs_metrics_metric_type_t type,
        const char *name, const char *description,
        int initial_val, unsigned int num_labels, const char ** labels,
        ogs_metrics_histogram_params_t *histogram_params);
void ogs_metrics_spec_free(ogs_metrics_spec_t *spec);

typedef struct ogs_metrics_inst_s ogs_metrics_inst_t;
ogs_metrics_inst_t *ogs_metrics_inst_new(
        ogs_metrics_spec_t *spec,
        unsigned int num_labels, const char **label_values);
void ogs_metrics_inst_free(ogs_metrics_inst_t *inst);
void ogs_metrics_inst_set(ogs_metrics_inst_t *inst, int val);
void ogs_metrics_inst_reset(ogs_metrics_inst_t *inst);
void ogs_metrics_inst_add(ogs_metrics_inst_t *inst, int val);
static inline void ogs_metrics_inst_inc(ogs_metrics_inst_t *inst)
{
    ogs_metrics_inst_add(inst, 1);
}
static inline void ogs_metrics_inst_dec(ogs_metrics_inst_t *inst)
{
    ogs_metrics_inst_add(inst, -1);
}


/*
 * Optional query filter passed to JSON dumpers. The MHD access
 * handler populates this from HTTP query string parameters so each
 * dumper can implement simple server-side filtering without having
 * to know about MHD types. Pointer fields are NULL when the caller
 * did not pass the corresponding key. enb_id is wrapped in a
 * "presence" flag because 0 is a valid eNB id on some deployments.
 */
typedef struct ogs_metrics_query_s {
    const char *imsi;      /* ?imsi=15-digit          */
    const char *supi;      /* ?supi=imsi-15-digit     */
    const char *ue_ip;     /* ?ue_ip=10.x.y.z         */
    const char *ip;        /* ?ip= / ?enb_ip= / ?gnb_ip= (RAN user-plane IP) */
    uint32_t    enb_id;    /* ?enb_id=N (also reused for gnb_id) */
    int         has_enb_id;

    /*
     * ?force=1 (or true/yes) toggles "polite" vs "abrupt" semantics
     * on admin endpoints:
     *   - /admin/ue/detach:
     *       force=0 (default) -> standard MME-initiated explicit
     *                            detach: NAS Detach Request to UE,
     *                            S11 Delete Session, S1 release.
     *       force=1            -> implicit detach (UE not notified
     *                            over the air; clean SGW/SMF side).
     *   - /admin/enb/detach:
     *       force=0 (default) -> send S1AP Reset (s1_Interface) to
     *                            the eNB first, give it ~2s to act,
     *                            then release all UEs and close
     *                            SCTP.
     *       force=1            -> immediate SGW/SMF teardown and
     *                            SCTP close, no Reset PDU sent.
     */
    int         force;
} ogs_metrics_query_t;

typedef size_t (*ogs_metrics_custom_ep_hdlr_t)(
    char *buf, size_t buflen, size_t page, size_t page_size,
    const ogs_metrics_query_t *q);

typedef struct ogs_metrics_custom_ep_s {
    ogs_lnode_t lnode;

    char *endpoint;
    ogs_metrics_custom_ep_hdlr_t handler;
} ogs_metrics_custom_ep_t;


void ogs_metrics_register_custom_ep(ogs_metrics_custom_ep_hdlr_t handler,
        const char *endpoint);

/*
 * Admin endpoints (POST/GET). Restricted to loopback and private/local
 * client addresses (see prometheus/context.c); /metrics is not gated.
 * Returned int is the HTTP status to send; if `body` is left empty on
 * success the caller gets "OK\n".
 *
 * Methods bitmask uses MHD_HTTP_METHOD_GET / MHD_HTTP_METHOD_POST
 * style values via the OGS_METRICS_ADMIN_METHOD_* constants below.
 */
#define OGS_METRICS_ADMIN_METHOD_GET  0x1
#define OGS_METRICS_ADMIN_METHOD_POST 0x2

typedef int (*ogs_metrics_admin_ep_hdlr_t)(
    const ogs_metrics_query_t *q,
    char *body, size_t body_cap, size_t *body_len);

typedef struct ogs_metrics_admin_ep_s {
    ogs_lnode_t lnode;

    char *endpoint;
    unsigned int methods;       /* bitmask of OGS_METRICS_ADMIN_METHOD_* */
    ogs_metrics_admin_ep_hdlr_t handler;
} ogs_metrics_admin_ep_t;

void ogs_metrics_register_admin_ep(ogs_metrics_admin_ep_hdlr_t handler,
        const char *endpoint, unsigned int methods);

/*
 * Coarse mutex protecting NF state read by JSON custom endpoints
 * (/enb-info, /ue-info, etc). Since the metrics HTTP server now
 * runs on its own MHD thread, the NF main thread must take this
 * mutex around list mutations (add/remove) and dumpers must take
 * it during traversal. The /metrics endpoint itself uses atomic
 * prom counters and does NOT need the lock.
 *
 * Note: NF main thread MUST always use the _trylock variant when
 * holding any other lock to avoid priority inversion against the
 * MHD thread - though in practice the dumpers only hold this for
 * a single page of output (a few ms), so plain lock/unlock is
 * acceptable on the main thread too.
 */
void ogs_metrics_dump_lock_init(void);
void ogs_metrics_dump_lock_final(void);
void ogs_metrics_dump_lock(void);
void ogs_metrics_dump_unlock(void);

#ifdef __cplusplus
}
#endif

#endif /* OGS_METRICS_CONTEXT_H */
