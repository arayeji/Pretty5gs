/*
 * Copyright (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Copyright (C) 2023 by Sukchan Lee <acetcom@gmail.com>
 * Copyright (C) 2025 by Juraj Elias <juraj.elias@gmail.com>
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

 /*
 * Prometheus HTTP server (MicroHTTPD) with optional JSON endpoints:
 *   - /                (provide health check)
 *   - /metrics         (provide prometheus metrics metrics according to the relevant NF)
 *   - /pdu-info        (provided by NF registering ogs_metrics_pdu_info_dumper)
 *   - /gnb-info        (provided by NF registering ogs_metrics_gnb_info_dumper)
 *   - /enb-info        (provided by NF registering ogs_metrics_enb_info_dumper)
 *   - /ue-info         (provided by NF registering ogs_metrics_ue_info_dumper)
 */

#include "ogs-core.h"
#include "metrics/ogs-metrics.h"

#include <netdb.h> /* AI_PASSIVE */
#include <netinet/in.h>
#include <arpa/inet.h> /* inet_ntop for admin peer logging */
#include <stdlib.h> /* getenv, atoi */
#include "prom.h"
#include "microhttpd.h"
#include <string.h>
#include <strings.h> /* strcasecmp */


/* __ogs_metrics_domain is now declared extern in ogs-metrics.h. */
#define MAX_LABELS 8

#if MHD_VERSION >= 0x00096100
static void free_callback(void *cls) { ogs_free(cls); }
#endif

typedef struct ogs_metrics_server_s {
    ogs_socknode_t node;
    struct MHD_Daemon *mhd;
} ogs_metrics_server_t;

typedef struct ogs_metrics_spec_s {
    ogs_metrics_context_t       *ctx;  /* backpointer */ 
    ogs_list_t                  entry; /* included in ogs_metrics_context_t */
    ogs_metrics_metric_type_t   type;
    char                        *name;
    char                        *description;
    int                         initial_val;
    ogs_list_t                  inst_list; /* list of ogs_metrics_instance_t */
    unsigned int                num_labels;
    char                        *labels[MAX_LABELS];
    prom_metric_t               *prom;
} ogs_metrics_spec_t;

typedef struct ogs_metrics_inst_s {
    ogs_metrics_spec_t      *spec;  /* backpointer */
    ogs_list_t              entry; /* included in ogs_metrics_spec_t spec */
    unsigned int            num_labels;
    char                    *label_values[MAX_LABELS];
} ogs_metrics_inst_t;

static OGS_POOL(metrics_spec_pool, ogs_metrics_spec_t);
static OGS_POOL(metrics_server_pool, ogs_metrics_server_t);

/* Forward decls */
static int ogs_metrics_context_server_start(ogs_metrics_server_t *server);
static int ogs_metrics_context_server_stop(ogs_metrics_server_t *server);

static size_t get_query_size_t(struct MHD_Connection *connection,
                               const char *key, size_t default_val)
{
    const char *val = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, key);
    if (!val || !*val) return default_val;
    char *end = NULL;
    unsigned long long v = strtoull(val, &end, 10);
    if (end == val || *end != '\0') return default_val;
    return (size_t)v;
}

void ogs_metrics_server_init(ogs_metrics_context_t *ctx)
{
    ogs_list_init(&ctx->server_list);
    ogs_pool_init(&metrics_server_pool, ogs_app()->pool.nf);
}

void ogs_metrics_server_open(ogs_metrics_context_t *ctx)
{
    ogs_metrics_server_t *server = NULL;
    ogs_list_for_each(&ctx->server_list, server)
        ogs_metrics_context_server_start(server);
}

void ogs_metrics_server_close(ogs_metrics_context_t *ctx)
{
    ogs_metrics_server_t *server = NULL, *next = NULL;
    ogs_list_for_each_safe(&ctx->server_list, next, server)
        ogs_metrics_context_server_stop(server);
}

void ogs_metrics_server_final(ogs_metrics_context_t *ctx)
{
    ogs_metrics_server_t *server = NULL, *next = NULL;

    ogs_list_for_each_safe(&ctx->server_list, next, server)
        ogs_metrics_server_remove(server);

    ogs_pool_final(&metrics_server_pool);
}

ogs_metrics_server_t *ogs_metrics_server_add(ogs_sockaddr_t *addr, ogs_sockopt_t *option)
{
    ogs_metrics_server_t *server = NULL;

    ogs_assert(addr);
    ogs_pool_alloc(&metrics_server_pool, &server);
    ogs_assert(server);
    memset(server, 0, sizeof *server);

    ogs_assert(OGS_OK == ogs_copyaddrinfo(&server->node.addr, addr));
    if (option) server->node.option = ogs_memdup(option, sizeof *option);

    ogs_list_add(&ogs_metrics_self()->server_list, server);
    return server;
}

void ogs_metrics_server_remove(ogs_metrics_server_t *server)
{
    ogs_assert(server);

    ogs_list_remove(&ogs_metrics_self()->server_list, server);

    ogs_assert(server->node.addr);
    ogs_freeaddrinfo(server->node.addr);
    if (server->node.option) ogs_free(server->node.option);

    ogs_pool_free(&metrics_server_pool, server);
}

/*
 * Historically the MHD daemon was driven by the NF main event loop:
 * the listen fd plus every accepted connection fd was added to
 * ogs_app()->pollset, and MHD_run() was invoked from those pollset
 * callbacks. That model meant /metrics scrapes only made forward
 * progress when the NF main loop had time to spare. At MME scale
 * (thousands of eNBs producing constant S1AP traffic) the scraper
 * client would time out, drop the connection, and Prometheus would
 * see empty responses or RSTs.
 *
 * The new model uses MHD_USE_INTERNAL_POLLING_THREAD so MHD spins
 * up its own dedicated polling thread - completely independent of
 * the NF event loop. /metrics now responds in microseconds even
 * when the main thread is saturated. The previous
 * mhd_server_run / mhd_server_notify_connection helpers are no
 * longer needed.
 *
 * Side effect: custom JSON endpoints (/enb-info, /ue-info, etc)
 * now execute on the MHD thread and must not race the NF main
 * thread when it mutates state. ogs_metrics_dump_lock_*() below
 * exposes a coarse mutex the NF takes around list mutations and
 * the dumpers take during their traversal.
 */

#if MHD_VERSION >= 0x00097001
typedef enum MHD_Result _MHD_Result;
#else
typedef int _MHD_Result;
#endif

/*
 * Hard ceiling for the JSON response buffer. The dumpers grow the
 * output buffer until it fits or this cap is reached. 128 MB is
 * plenty for /enb-info with ~8k eNBs (~3 MB at ~400 bytes each) and
 * for /ue-info with hundreds of thousands of UEs at 100-500 bytes
 * each; it also caps memory usage so a malicious page_size=2^32
 * can not OOM the daemon.
 */
#define DUMPER_BUF_CAP_MAX (128u * 1024u * 1024u)

/* Small helper to serve JSON from a registered dumper */
static _MHD_Result serve_json_from_dumper(struct MHD_Connection *connection,
                                          ogs_metrics_custom_ep_hdlr_t handler,
                                          size_t page, size_t page_size,
                                          const ogs_metrics_query_t *q)
{
    ogs_assert(connection);
    ogs_assert(handler);

    size_t cap = 512 * 1024;
    char *bufjson = (char *)ogs_malloc(cap);
    if (!bufjson) {
        const char *msg = "Out of memory\n";
        struct MHD_Response *rsp = MHD_create_response_from_buffer(strlen(msg),
                                (void*)msg, MHD_RESPMEM_PERSISTENT);
        if (!rsp) return (_MHD_Result)MHD_NO;
        int ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, rsp);
        MHD_destroy_response(rsp);
        return (_MHD_Result)ret;
    }

    /*
     * Grow the buffer doubling each time the dumper fills it. A
     * dumper returning (cap-1) or more bytes means it ran out of
     * room mid-output; reallocate and try again. Bounded by
     * DUMPER_BUF_CAP_MAX so we never grow without limit.
     */
    size_t n = handler(bufjson, cap, page, page_size, q);
    while (n >= cap - 1 && cap < DUMPER_BUF_CAP_MAX) {
        size_t newcap = cap * 2;
        if (newcap > DUMPER_BUF_CAP_MAX) newcap = DUMPER_BUF_CAP_MAX;
        char *tmp = (char *)ogs_realloc(bufjson, newcap);
        if (!tmp) {
            ogs_free(bufjson);
            const char *msg = "Out of memory\n";
            struct MHD_Response *rsp = MHD_create_response_from_buffer(strlen(msg),
                                    (void*)msg, MHD_RESPMEM_PERSISTENT);
            if (!rsp) return (_MHD_Result)MHD_NO;
            int ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, rsp);
            MHD_destroy_response(rsp);
            return (_MHD_Result)ret;
        }
        bufjson = tmp; cap = newcap;
        n = handler(bufjson, cap, page, page_size, q);
    }
    if (n >= cap - 1) {
        /* Hit the hard ceiling; degrade gracefully to an empty list. */
        ogs_warn("metrics dumper output exceeded %zu bytes - truncating", cap);
        n = ogs_snprintf(bufjson, cap,
                "{\"items\":[],\"error\":\"output exceeds %u MB cap\"}",
                (unsigned)(DUMPER_BUF_CAP_MAX / (1024 * 1024)));
    }

    struct MHD_Response *rsp;
#if MHD_VERSION >= 0x00096100
    rsp = MHD_create_response_from_buffer_with_free_callback(n, (void*)bufjson, free_callback);
    bufjson = NULL; /* ownership moved to MHD */
#else
    rsp = MHD_create_response_from_buffer(n, (void*)bufjson, MHD_RESPMEM_MUST_COPY);
#endif
    if (!rsp) {
#if MHD_VERSION < 0x00096100
        ogs_free(bufjson);
#endif
        return (_MHD_Result)MHD_NO;
    }

    MHD_add_response_header(rsp, "Content-Type", "application/json");
    MHD_add_response_header(rsp, "Access-Control-Allow-Origin", "*");
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, rsp);
    MHD_destroy_response(rsp);
#if MHD_VERSION < 0x00096100
    ogs_free(bufjson);
#endif
    return (_MHD_Result)ret;
}

/*
 * Populate an ogs_metrics_query_t from MHD query parameters. The
 * lifetime of the returned strings is the connection's; the dumper
 * is invoked synchronously inside this handler so that is fine.
 */
static void fill_query_from_connection(struct MHD_Connection *connection,
                                       ogs_metrics_query_t *q)
{
    memset(q, 0, sizeof(*q));
    q->imsi  = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "imsi");
    q->supi  = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "supi");
    q->ue_ip = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "ue_ip");
    q->ip    = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "ip");

    const char *eid = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "enb_id");
    if (!eid) eid = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "gnb_id");
    if (eid && *eid) {
        char *end = NULL;
        unsigned long long v = strtoull(eid, &end, 0);
        if (end != eid && *end == '\0' && v <= 0xFFFFFFFFULL) {
            q->enb_id = (uint32_t)v;
            q->has_enb_id = 1;
        }
    }

    /*
     * Accept either ?force=1 or the textual forms operators tend to
     * type ("true", "yes", "on"). Anything else -> 0 (default graceful).
     */
    const char *fv = MHD_lookup_connection_value(connection,
            MHD_GET_ARGUMENT_KIND, "force");
    if (fv && *fv) {
        if (!strcasecmp(fv, "1") || !strcasecmp(fv, "true") ||
                !strcasecmp(fv, "yes") || !strcasecmp(fv, "on"))
            q->force = 1;
    }
}

/*
 * Format the client address for logging admin invocations. We log
 * every admin call so operators can audit who triggered detaches
 * after-the-fact; the metrics endpoint is expected to sit behind a
 * firewall / network ACL since it has no authentication of its own.
 */
static void format_client_addr(struct MHD_Connection *connection,
                               char *out, size_t cap)
{
    if (cap == 0) return;
    out[0] = '\0';

    const union MHD_ConnectionInfo *ci = MHD_get_connection_info(
            connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (!ci || !ci->client_addr) return;

    const struct sockaddr *sa = (const struct sockaddr *)ci->client_addr;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        char ip[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        ogs_snprintf(out, cap, "%s:%u", ip, (unsigned)ntohs(sin->sin_port));
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        char ip[INET6_ADDRSTRLEN] = "";
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        ogs_snprintf(out, cap, "[%s]:%u", ip, (unsigned)ntohs(sin6->sin6_port));
    }
}

static _MHD_Result reply_text(struct MHD_Connection *connection,
                              unsigned int status, const char *body)
{
    struct MHD_Response *rsp =
        MHD_create_response_from_buffer(strlen(body), (void *)body,
                MHD_RESPMEM_MUST_COPY);
    if (!rsp) return (_MHD_Result)MHD_NO;
    MHD_add_response_header(rsp, "Content-Type", "text/plain; charset=utf-8");
    int ret = MHD_queue_response(connection, status, rsp);
    MHD_destroy_response(rsp);
    return (_MHD_Result)ret;
}

/*
 * Paths under /admin/ are restricted to loopback and RFC1918 clients.
 * /metrics and JSON dumpers stay open to any reachable client.
 */
static bool metrics_client_is_local(struct MHD_Connection *connection)
{
    const union MHD_ConnectionInfo *ci = MHD_get_connection_info(
            connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    const struct sockaddr *sa = NULL;
    const uint8_t *b = NULL;

    if (!ci || !ci->client_addr)
        return false;

    sa = (const struct sockaddr *)ci->client_addr;

    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        uint32_t addr = ntohl(sin->sin_addr.s_addr);

        if ((addr & 0xff000000u) == 0x7f000000u) /* 127.0.0.0/8 */
            return true;
        if ((addr & 0xff000000u) == 0x0a000000u) /* 10.0.0.0/8 */
            return true;
        if ((addr & 0xfff00000u) == 0xac100000u) /* 172.16.0.0/12 */
            return true;
        if ((addr & 0xffff0000u) == 0xc0a80000u) /* 192.168.0.0/16 */
            return true;
        return false;
    }

    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;

        if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr))
            return true;

        /* Unique local (fc00::/7) and link-local (fe80::/10) */
        b = (const uint8_t *)&sin6->sin6_addr;
        if (b[0] == 0xfc || b[0] == 0xfd)
            return true;
        if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
            return true;
        return false;
    }

    return false;
}

static bool metrics_path_is_admin(const char *url)
{
    return url && strncmp(url, "/admin/", 7) == 0;
}

static _MHD_Result metrics_forbid_non_local_admin(
        struct MHD_Connection *connection, const char *url)
{
    char peer[128] = "";

    if (!metrics_path_is_admin(url))
        return (_MHD_Result)MHD_NO;

    if (metrics_client_is_local(connection))
        return (_MHD_Result)MHD_NO;

    format_client_addr(connection, peer, sizeof(peer));
    ogs_warn("admin: denied non-local client %s for %s",
            peer[0] ? peer : "unknown", url);
    return reply_text(connection, MHD_HTTP_FORBIDDEN, "Forbidden\n");
}

static _MHD_Result serve_admin(struct MHD_Connection *connection,
                               unsigned int method_bit,
                               const ogs_metrics_admin_ep_t *ep)
{
    if (!(ep->methods & method_bit))
        return reply_text(connection, MHD_HTTP_METHOD_NOT_ALLOWED,
                "Method Not Allowed\n");

    {
        _MHD_Result denied = metrics_forbid_non_local_admin(
                connection, ep->endpoint);
        if (denied)
            return denied;
    }

    ogs_metrics_query_t q;
    fill_query_from_connection(connection, &q);

    char peer[128] = "";
    format_client_addr(connection, peer, sizeof(peer));
    ogs_info("admin: %s from %s (force=%d)",
            ep->endpoint, peer[0] ? peer : "unknown", q.force);

    char body[1024];
    size_t body_len = 0;
    int status = ep->handler(&q, body, sizeof(body), &body_len);
    if (status <= 0) status = MHD_HTTP_INTERNAL_SERVER_ERROR;

    if (body_len == 0) {
        const char *def = (status >= 200 && status < 300) ? "OK\n" : "Error\n";
        return reply_text(connection, (unsigned int)status, def);
    }

    struct MHD_Response *rsp =
        MHD_create_response_from_buffer(body_len, body, MHD_RESPMEM_MUST_COPY);
    if (!rsp) return (_MHD_Result)MHD_NO;
    MHD_add_response_header(rsp, "Content-Type", "application/json");
    int ret = MHD_queue_response(connection, (unsigned int)status, rsp);
    MHD_destroy_response(rsp);
    return (_MHD_Result)ret;
}

static _MHD_Result
mhd_server_access_handler(void *cls, struct MHD_Connection *connection,
        const char *url, const char *method, const char *version,
        const char *upload_data, size_t *upload_data_size, void **con_cls)
{
    (void)cls; (void)version; (void)upload_data; (void)upload_data_size; (void)con_cls;

    const char *buf = NULL;
    struct MHD_Response *rsp = NULL;
    int ret = MHD_NO;

    const bool is_get  = (strcmp(method, "GET")  == 0);
    const bool is_post = (strcmp(method, "POST") == 0);

    /* Anything other than GET or POST is rejected outright. */
    if (!is_get && !is_post)
        return reply_text(connection, MHD_HTTP_METHOD_NOT_ALLOWED,
                "Method Not Allowed\n");

    /* Admin endpoints take precedence so they can handle POST. */
    {
        ogs_metrics_admin_ep_t *anode = NULL;
        ogs_list_for_each(&ogs_metrics_self()->admin_eps, anode) {
            if (!strcmp(anode->endpoint, url)) {
                unsigned int mbit = is_post
                        ? OGS_METRICS_ADMIN_METHOD_POST
                        : OGS_METRICS_ADMIN_METHOD_GET;
                return serve_admin(connection, mbit, anode);
            }
        }
    }

    /* The rest of the routes are GET only. */
    if (!is_get)
        return reply_text(connection, MHD_HTTP_METHOD_NOT_ALLOWED,
                "Method Not Allowed\n");

    /* Health */
    if (strcmp(url, "/") == 0) {
        buf = "OK\n";
        rsp = MHD_create_response_from_buffer(strlen(buf), (void *)buf, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(connection, MHD_HTTP_OK, rsp);
        MHD_destroy_response(rsp);
        return (_MHD_Result)ret;
    }

    /* Prometheus metrics plain-text */
    if (strcmp(url, "/metrics") == 0) {
        ogs_time_t t0 = ogs_time_now();

        /*
         * prom_collector_registry_bridge() can return NULL if an
         * internal allocation fails. Calling strlen(NULL) here would
         * crash the MHD worker thread and present client-side as
         * "connection reset" / "empty response" - exactly the
         * symptom we have been chasing. Guard it.
         */
        buf = prom_collector_registry_bridge(PROM_COLLECTOR_REGISTRY_DEFAULT);
        if (!buf) {
            ogs_error("/metrics: prom_collector_registry_bridge returned NULL");
            return reply_text(connection,
                    MHD_HTTP_INTERNAL_SERVER_ERROR,
                    "metrics bridge failed\n");
        }

        size_t len = strlen(buf);
        rsp = MHD_create_response_from_buffer(
                len, (void *)buf, MHD_RESPMEM_MUST_COPY);
        if (!rsp) {
            ogs_error("/metrics: MHD_create_response_from_buffer failed "
                    "(len=%zu)", len);
            prom_free((void *)buf);
            return (_MHD_Result)MHD_NO;
        }
        MHD_add_response_header(rsp, "Content-Type",
                "text/plain; version=0.0.4; charset=utf-8");
        ret = MHD_queue_response(connection, MHD_HTTP_OK, rsp);
        MHD_destroy_response(rsp);
        prom_free((void *)buf);

        ogs_time_t dt = ogs_time_now() - t0;
        if (dt > ogs_time_from_msec(500))
            ogs_warn("/metrics scrape took %lld ms (%zu bytes) "
                    "- consider increasing MHD thread pool",
                    (long long)(dt / 1000), len);
        else
            ogs_debug("/metrics scrape %lld ms (%zu bytes)",
                    (long long)(dt / 1000), len);

        return (_MHD_Result)ret;
    }

    size_t page = get_query_size_t(connection, "page", 0);
    /*
     * page_size default is 100 if not provided, but the upper bound
     * is no longer clamped here - the dumper is allowed to honour
     * any value (including SIZE_MAX) and serve_json_from_dumper()
     * grows its output buffer to fit, bounded by
     * DUMPER_BUF_CAP_MAX. Pass `page_size=0` or omit the key for
     * the default; pass an explicit big number to disable paging
     * effectively without going through page=-1.
     */
    size_t page_size = get_query_size_t(connection, "page_size", 100);

    ogs_metrics_query_t q;
    fill_query_from_connection(connection, &q);

    ogs_metrics_custom_ep_t *node = NULL;
    ogs_list_for_each(&ogs_metrics_self()->custom_eps, node) {
        if (!strcmp(node->endpoint, url)) {
            _MHD_Result denied = metrics_forbid_non_local_admin(
                    connection, url);
            if (denied)
                return denied;
            return serve_json_from_dumper(connection,
                    node->handler,
                    page, page_size, &q);
        }
    }

    /* No matching route */
    return reply_text(connection, MHD_HTTP_BAD_REQUEST, "Bad Request\n");
}

static int ogs_metrics_context_server_start(ogs_metrics_server_t *server)
{
    /*
     * Bumped from 8 to 16 to fit the new tuning options without
     * silently overrunning. MHD_OPTION_ARRAY scans until
     * MHD_OPTION_END so leaving spare slots is harmless.
     */
#define MAX_NUM_OF_MHD_OPTION_ITEM 16
    struct MHD_OptionItem mhd_ops[MAX_NUM_OF_MHD_OPTION_ITEM];
    int index = 0;
    char buf[OGS_ADDRSTRLEN];
    ogs_sockaddr_t *addr = NULL;
    char *hostname = NULL;

    ogs_assert(server);
    addr = server->node.addr;
    ogs_assert(addr);

#if MHD_VERSION >= 0x00095300
    unsigned int mhd_flags = MHD_USE_ERROR_LOG;
#else
    unsigned int mhd_flags = MHD_USE_DEBUG;
#endif

    /*
     * Drive MHD from its own polling thread instead of the NF main
     * event loop. Without this, /metrics scrapes only get serviced
     * when the NF main loop is idle - and on an MME running
     * thousands of eNBs the loop is almost never idle, producing
     * connection-reset / empty-response symptoms.
     *
     * MHD_USE_INTERNAL_POLLING_THREAD alone is the alias for
     * MHD_USE_SELECT_INTERNALLY: MHD polls its sockets with
     * select(2). select() is hard-capped by FD_SETSIZE (1024 on
     * Linux/glibc) and the cap is on the *numeric FD value*, not
     * on the number of monitored FDs. As soon as the daemon has
     * ~1000 SCTP/Diameter/GTP-C FDs already open the kernel hands
     * MHD an accept() FD > 1023, FD_SET() then writes out of
     * bounds and the scrape silently fails - presenting as
     * intermittent "empty body / connection reset" on /metrics
     * once the eNB fleet crosses ~1000. LimitNOFILE doesn't help;
     * only switching MHD off select() does.
     *
     * Backend selection is RUNTIME, not compile-time: in newer
     * libmicrohttpd the MHD_USE_* flags are enum members, not
     * macros, so `#if defined(MHD_USE_EPOLL)` is false even on a
     * library that fully supports epoll. We instead ask the
     * library directly via MHD_is_feature_supported() and try the
     * best available backend; if MHD_start_daemon() still refuses
     * (older library that doesn't honour the flag at runtime, or
     * built with that backend disabled) we fall back to the next.
     *
     * Preference order: epoll -> poll -> select.
     */
    if (addr->ogs_sa_family == AF_INET6)
        mhd_flags |= MHD_USE_IPv6;

    mhd_ops[index].option = MHD_OPTION_SOCK_ADDR;
    mhd_ops[index].value = 0;
    mhd_ops[index].ptr_value = (void *)&addr->sa; index++;

    /*
     * Tunables, with env-var overrides so operators can adjust at
     * runtime without recompiling. Defaults are sized for "MME
     * with thousands of eNBs and federation scraping every 15s".
     *
     *   OGS_METRICS_CONNECTION_LIMIT  (default 8192)
     *   OGS_METRICS_LISTEN_BACKLOG    (default 4096)
     *   OGS_METRICS_CONNECTION_TIMEOUT  seconds, default 30
     *   OGS_METRICS_THREAD_POOL_SIZE  (default 8)
     *
     * NOTE: listen backlog is silently capped by the kernel's
     * net.core.somaxconn. On older kernels that's 128 - tune it:
     *   sysctl -w net.core.somaxconn=4096
     * Also remember the daemon needs `ulimit -n` >= connection_limit
     * (systemd unit: LimitNOFILE=65536).
     */
    int conn_limit  = 8192;
    int backlog     = 4096;
    int conn_to_s   = 30;
    int pool_size   = 8;
    const char *env;
    if ((env = getenv("OGS_METRICS_CONNECTION_LIMIT")) && *env)
        conn_limit = atoi(env);
    if ((env = getenv("OGS_METRICS_LISTEN_BACKLOG")) && *env)
        backlog = atoi(env);
    if ((env = getenv("OGS_METRICS_CONNECTION_TIMEOUT")) && *env)
        conn_to_s = atoi(env);
    if ((env = getenv("OGS_METRICS_THREAD_POOL_SIZE")) && *env)
        pool_size = atoi(env);

#ifdef MHD_OPTION_CONNECTION_LIMIT
    mhd_ops[index].option = MHD_OPTION_CONNECTION_LIMIT;
    mhd_ops[index].value = conn_limit;
    mhd_ops[index].ptr_value = NULL; index++;
#endif
#ifdef MHD_OPTION_LISTEN_BACKLOG_SIZE
    mhd_ops[index].option = MHD_OPTION_LISTEN_BACKLOG_SIZE;
    mhd_ops[index].value = backlog;
    mhd_ops[index].ptr_value = NULL; index++;
#endif
#ifdef MHD_OPTION_CONNECTION_TIMEOUT
    mhd_ops[index].option = MHD_OPTION_CONNECTION_TIMEOUT;
    mhd_ops[index].value = conn_to_s;
    mhd_ops[index].ptr_value = NULL; index++;
#endif

    /*
     * Thread pool size. With THREAD_POOL_SIZE=N, MHD spawns N
     * worker daemons each with its own listen socket via
     * SO_REUSEPORT (on Linux). New connections are distributed
     * across them. /metrics under load is the bottleneck because
     * prom_collector_registry_bridge() holds the registry RW lock
     * during traversal - 8 threads give us enough parallel scrape
     * slots that the lock contention is the limit, not MHD itself.
     */
#ifdef MHD_OPTION_THREAD_POOL_SIZE
    mhd_ops[index].option = MHD_OPTION_THREAD_POOL_SIZE;
    mhd_ops[index].value = pool_size;
    mhd_ops[index].ptr_value = NULL; index++;
#endif

    mhd_ops[index].option = MHD_OPTION_END;
    mhd_ops[index].value = 0;
    mhd_ops[index].ptr_value = NULL; index++;

    if (server->mhd) {
        ogs_error("Prometheus HTTP server is already opened!");
        return OGS_ERROR;
    }

    /*
     * Backend attempts, best -> worst. We always combine the chosen
     * flag with MHD_USE_INTERNAL_POLLING_THREAD so MHD runs on its
     * own thread regardless of backend.
     *
     * Symbol availability:
     *   - MHD_VERSION:           macro, always usable in #if.
     *   - MHD_USE_POLL:          present since MHD 0.9.x (well below
     *                            our >=0.9.40 floor in meson.build).
     *   - MHD_USE_EPOLL:         macro name since MHD 0.9.50; before
     *                            that the flag was MHD_USE_EPOLL_LINUX_ONLY
     *                            (added in 0.9.16, value 0x100 in both).
     *   - MHD_FEATURE_*:         enum values, so #ifdef cannot detect
     *                            them. We gate on MHD_VERSION instead.
     *   - MHD_is_feature_supported(): MHD 0.9.42+.
     */
#if MHD_VERSION >= 0x00095000
#  define OGS_MHD_USE_EPOLL_FLAG MHD_USE_EPOLL
#elif MHD_VERSION >= 0x00091600
#  define OGS_MHD_USE_EPOLL_FLAG MHD_USE_EPOLL_LINUX_ONLY
#else
#  define OGS_MHD_USE_EPOLL_FLAG 0  /* no epoll support in headers */
#endif

    struct backend_attempt {
        const char *name;
        unsigned int extra_flag;    /* 0 = pure select */
        int feature_id;             /* MHD_FEATURE_* (enum), or -1 */
        int is_select;
    };

    struct backend_attempt attempts[] = {
#if MHD_VERSION >= 0x00094200
        { "epoll",  OGS_MHD_USE_EPOLL_FLAG, MHD_FEATURE_EPOLL, 0 },
        { "poll",   MHD_USE_POLL,           MHD_FEATURE_POLL,  0 },
#elif MHD_VERSION >= 0x00091600
        { "epoll",  OGS_MHD_USE_EPOLL_FLAG, -1, 0 },
        { "poll",   MHD_USE_POLL,           -1, 0 },
#else
        { "poll",   MHD_USE_POLL,           -1, 0 },
#endif
        { "select", 0,                      -1, 1 },
    };

    const char *chosen_backend = NULL;
    int chosen_is_select = 0;
    size_t a;
    for (a = 0; a < sizeof(attempts)/sizeof(attempts[0]); a++) {
        struct backend_attempt *at = &attempts[a];

        /*
         * Skip backends our header knows nothing about (epoll on
         * truly ancient MHD), so the loop doesn't waste a daemon
         * start with extra_flag = 0 before reaching "select".
         */
        if (!at->is_select && at->extra_flag == 0)
            continue;

#if MHD_VERSION >= 0x00094200
        /*
         * MHD_is_feature_supported() lets us skip backends the
         * library was built without, avoiding a noisy
         * MHD_start_daemon() error log on each fallback.
         */
        if (at->feature_id >= 0 &&
                MHD_is_feature_supported(
                    (enum MHD_FEATURE)at->feature_id) != MHD_YES) {
            ogs_debug("metrics_server: backend '%s' not supported "
                    "by libmicrohttpd, trying next", at->name);
            continue;
        }
#endif

        server->mhd = MHD_start_daemon(
                mhd_flags | at->extra_flag | MHD_USE_INTERNAL_POLLING_THREAD,
                0, NULL, NULL,
                mhd_server_access_handler, server,
                MHD_OPTION_ARRAY, mhd_ops,
                MHD_OPTION_END);
        if (server->mhd) {
            chosen_backend = at->name;
            chosen_is_select = at->is_select;
            break;
        }
        ogs_warn("metrics_server: MHD_start_daemon() with backend '%s' "
                "failed, trying next", at->name);
    }

    if (!server->mhd) {
        ogs_error("Cannot start Prometheus HTTP server "
                "(all backends failed: epoll, poll, select)");
        return OGS_ERROR;
    }

    ogs_info("metrics_server: pool=%d conn_limit=%d backlog=%d "
            "timeout=%ds backend=%s (override via OGS_METRICS_* env vars)",
            pool_size, conn_limit, backlog, conn_to_s, chosen_backend);

    if (chosen_is_select) {
        ogs_warn("metrics_server is using select() (FD_SETSIZE=1024 cap). "
                "Scrapes of /metrics will start failing with empty body / "
                "connection reset once the daemon has more than ~1000 "
                "open file descriptors (eNB SCTP associations + listen "
                "sockets + Diameter/GTP-C). Rebuild libmicrohttpd with "
                "--enable-poll or --enable-epoll to get a backend that "
                "isn't capped by FD_SETSIZE.");
    }

    /* No pollset wiring - MHD owns its own polling thread now. */
    server->node.poll = NULL;

    hostname = ogs_gethostname(addr);
    if (hostname)
        ogs_info("metrics_server() [http://%s]:%d (internal MHD thread)",
                 hostname, OGS_PORT(addr));
    else
        ogs_info("metrics_server() [http://%s]:%d (internal MHD thread)",
                 OGS_ADDR(addr, buf), OGS_PORT(addr));

    return OGS_OK;
}

static int ogs_metrics_context_server_stop(ogs_metrics_server_t *server)
{
    ogs_assert(server);

    /*
     * MHD_stop_daemon() blocks until the internal polling thread
     * (and any pool workers) has exited, so all in-flight scrapes
     * complete before we return - safe to free server state after.
     */
    if (server->mhd) {
        MHD_stop_daemon(server->mhd);
        server->mhd = NULL;
    }
    return OGS_OK;
}

/* ---- Metric spec/inst API (unchanged) ---------------------------------- */

void ogs_metrics_spec_init(ogs_metrics_context_t *ctx)
{
    ogs_list_init(&ctx->spec_list);
    ogs_pool_init(&metrics_spec_pool, ogs_app()->metrics.max_specs);
    prom_collector_registry_default_init();
}

void ogs_metrics_spec_final(ogs_metrics_context_t *ctx)
{
    ogs_metrics_spec_t *spec = NULL, *next = NULL;

    ogs_list_for_each_entry_safe(&ctx->spec_list, next, spec, entry)
        ogs_metrics_spec_free(spec);

    prom_collector_registry_destroy(PROM_COLLECTOR_REGISTRY_DEFAULT);
    ogs_pool_final(&metrics_spec_pool);
}

ogs_metrics_spec_t *ogs_metrics_spec_new(
        ogs_metrics_context_t *ctx, ogs_metrics_metric_type_t type,
        const char *name, const char *description,
        int initial_val, unsigned int num_labels, const char ** labels,
        ogs_metrics_histogram_params_t *histogram_params)
{
    ogs_metrics_spec_t *spec;
    unsigned int i;
    prom_histogram_buckets_t *buckets = NULL;
    double *upper_bounds;

    ogs_assert(name);
    ogs_assert(description);
    ogs_assert(num_labels <= MAX_LABELS);

    ogs_pool_alloc(&metrics_spec_pool, &spec);
    ogs_assert(spec);
    memset(spec, 0, sizeof *spec);
    spec->ctx = ctx;
    ogs_list_init(&spec->inst_list);
    spec->type = type;
    spec->name = ogs_strdup(name);
    spec->description = ogs_strdup(description);
    spec->initial_val = initial_val;
    spec->num_labels = num_labels;
    for (i = 0; i < num_labels; i++) {
        ogs_assert(labels[i]);
        spec->labels[i] = ogs_strdup(labels[i]);
    }

    switch (type) {
    case OGS_METRICS_METRIC_TYPE_COUNTER:
        spec->prom = prom_counter_new(spec->name, spec->description,
                                      spec->num_labels, (const char **)spec->labels);
        break;
    case OGS_METRICS_METRIC_TYPE_GAUGE:
        spec->prom = prom_gauge_new(spec->name, spec->description,
                                    spec->num_labels, (const char **)spec->labels);
        break;
    case OGS_METRICS_METRIC_TYPE_HISTOGRAM:
        ogs_assert(histogram_params);
        switch (histogram_params->type) {
        case OGS_METRICS_HISTOGRAM_BUCKET_TYPE_EXPONENTIAL:
            buckets = prom_histogram_buckets_exponential(histogram_params->exp.start,
                    histogram_params->exp.factor, histogram_params->count);
            ogs_assert(buckets);
            break;
        case OGS_METRICS_HISTOGRAM_BUCKET_TYPE_LINEAR:
            buckets = prom_histogram_buckets_linear(histogram_params->lin.start,
                    histogram_params->lin.width, histogram_params->count);
            ogs_assert(buckets);
            break;
        case OGS_METRICS_HISTOGRAM_BUCKET_TYPE_VARIABLE:
            buckets = (prom_histogram_buckets_t *)prom_malloc(sizeof(prom_histogram_buckets_t));
            ogs_assert(buckets);
            ogs_assert(histogram_params->count <= OGS_METRICS_HIST_VAR_BUCKETS_MAX);
            buckets->count = histogram_params->count;

            upper_bounds = (double *)prom_malloc(sizeof(double) * histogram_params->count);
            ogs_assert(upper_bounds);
            for (i = 0; i < histogram_params->count; i++) {
                upper_bounds[i] = histogram_params->var.buckets[i];
                if (i > 0) ogs_assert(upper_bounds[i] > upper_bounds[i - 1]);
            }
            buckets->upper_bounds = upper_bounds;
            break;
        default:
            ogs_assert_if_reached();
            break;
        }
        spec->prom = prom_histogram_new(spec->name, spec->description,
                buckets, spec->num_labels, (const char **)spec->labels);
        ogs_assert(spec->prom);
        break;
    default:
        ogs_assert_if_reached();
        break;
    }
    prom_collector_registry_must_register_metric(spec->prom);

    ogs_list_add(&ctx->spec_list, &spec->entry);
    return spec;
}

void ogs_metrics_spec_free(ogs_metrics_spec_t *spec)
{
    ogs_metrics_inst_t *inst = NULL, *next = NULL;
    unsigned int i;

    ogs_list_remove(&spec->ctx->spec_list, &spec->entry);

    ogs_list_for_each_entry_safe(&spec->inst_list, next, inst, entry)
        ogs_metrics_inst_free(inst);

    ogs_free(spec->name);
    ogs_free(spec->description);
    for (i = 0; i < spec->num_labels; i++)
        ogs_free(spec->labels[i]);

    ogs_pool_free(&metrics_spec_pool, spec);
}

ogs_metrics_inst_t *ogs_metrics_inst_new(
        ogs_metrics_spec_t *spec,
        unsigned int num_labels, const char **label_values)
{
    ogs_metrics_inst_t *inst;
    unsigned int i;

    ogs_assert(spec);
    ogs_assert(num_labels == spec->num_labels);

    inst = ogs_calloc(1, sizeof *inst);
    ogs_assert(inst);
    inst->spec = spec;
    inst->num_labels = num_labels;
    for (i = 0; i < num_labels; i++) {
        ogs_assert(label_values[i]);
        inst->label_values[i] = ogs_strdup(label_values[i]);
    }
    ogs_list_add(&spec->inst_list, &inst->entry);
    ogs_metrics_inst_reset(inst);
    return inst;
}

void ogs_metrics_inst_free(ogs_metrics_inst_t *inst)
{
    unsigned int i;

    ogs_list_remove(&inst->spec->inst_list, &inst->entry);

    for (i = 0; i < inst->num_labels; i++)
        ogs_free(inst->label_values[i]);

    ogs_free(inst);
}

void ogs_metrics_inst_set(ogs_metrics_inst_t *inst, int val)
{
    switch (inst->spec->type) {
    case OGS_METRICS_METRIC_TYPE_GAUGE:
        prom_gauge_set(inst->spec->prom, (double)val, (const char **)inst->label_values);
        break;
    default:
        ogs_assert_if_reached();
        break;
    }
}

void ogs_metrics_inst_reset(ogs_metrics_inst_t *inst)
{
    switch (inst->spec->type) {
    case OGS_METRICS_METRIC_TYPE_COUNTER:
        prom_counter_add(inst->spec->prom, 0.0, (const char **)inst->label_values);
        break;
    case OGS_METRICS_METRIC_TYPE_GAUGE:
        prom_gauge_set(inst->spec->prom, (double)inst->spec->initial_val, (const char **)inst->label_values);
        break;
    default:
        break;
    }
}

void ogs_metrics_inst_add(ogs_metrics_inst_t *inst, int val)
{
    switch (inst->spec->type) {
    case OGS_METRICS_METRIC_TYPE_COUNTER:
        ogs_assert(val >= 0);
        prom_counter_add(inst->spec->prom, (double)val, (const char **)inst->label_values);
        break;
    case OGS_METRICS_METRIC_TYPE_GAUGE:
        if (val >= 0)
            prom_gauge_add(inst->spec->prom, (double)val, (const char **)inst->label_values);
        else
            prom_gauge_sub(inst->spec->prom, (double)-1.0*(double)val, (const char **)inst->label_values);
        break;
    case OGS_METRICS_METRIC_TYPE_HISTOGRAM:
        ogs_assert(val >= 0);
        prom_histogram_observe(inst->spec->prom, (double)val, (const char **)inst->label_values);
        break;
    default:
        ogs_assert_if_reached();
        break;
    }
}

