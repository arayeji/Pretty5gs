/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * PrettyNMS REST + SSE live stream (libmicrohttpd).
 */

#include "api.h"
#include "context.h"
#include "correlate.h"
#include "rules.h"
#include "trace.h"
#include "capture-ring.h"

#include "microhttpd.h"

#include <stdio.h>
#include <ctype.h>

#if MHD_VERSION >= 0x00097001
typedef enum MHD_Result _MHD_Result;
#else
typedef int _MHD_Result;
#endif

#define LIVE_RING 256

static struct MHD_Daemon *daemon_ptr;
static char live_buf[LIVE_RING][1024];
static unsigned live_head;
static ogs_thread_mutex_t live_lock;

struct post_ctx {
    char data[8192];
    size_t len;
};

static void json_escape_copy(const char *in, char *out, size_t outlen)
{
    size_t o = 0;
    if (!in) {
        if (outlen) out[0] = '\0';
        return;
    }
    while (*in && o + 2 < outlen) {
        if (*in == '"' || *in == '\\') {
            out[o++] = '\\';
            out[o++] = *in++;
        } else {
            out[o++] = *in++;
        }
    }
    out[o] = '\0';
}

static const char *json_get_str(const char *json, const char *key,
        char *out, size_t outlen)
{
    char pat[64];
    const char *p, *q;
    size_t n;

    if (!json || !key || !out || !outlen)
        return NULL;
    out[0] = '\0';
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(json, pat);
    if (!p)
        return NULL;
    p = strchr(p + strlen(pat), ':');
    if (!p)
        return NULL;
    p++;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p != '"')
        return NULL;
    p++;
    q = strchr(p, '"');
    if (!q)
        return NULL;
    n = (size_t)(q - p);
    if (n >= outlen)
        n = outlen - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return out;
}

static int json_get_int(const char *json, const char *key, int def)
{
    char pat[64];
    const char *p;
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(json, pat);
    if (!p)
        return def;
    p = strchr(p + strlen(pat), ':');
    if (!p)
        return def;
    return atoi(p + 1);
}

static bool json_get_bool(const char *json, const char *key)
{
    char pat[64];
    const char *p;
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(json, pat);
    if (!p)
        return false;
    p = strchr(p + strlen(pat), ':');
    if (!p)
        return false;
    p++;
    while (*p && isspace((unsigned char)*p))
        p++;
    return !strncmp(p, "true", 4);
}

static _MHD_Result send_json(struct MHD_Connection *conn,
        int status, const char *json)
{
    struct MHD_Response *rsp;
    _MHD_Result ret;
    rsp = MHD_create_response_from_buffer(strlen(json),
            (void *)json, MHD_RESPMEM_MUST_COPY);
    if (!rsp)
        return MHD_NO;
    MHD_add_response_header(rsp, "Content-Type", "application/json");
    MHD_add_response_header(rsp, "Access-Control-Allow-Origin", "*");
    ret = MHD_queue_response(conn, status, rsp);
    MHD_destroy_response(rsp);
    return ret;
}

void ptrace_api_publish(const ptrace_event_t *evt)
{
    char line[1024];
    if (!evt)
        return;
    snprintf(line, sizeof(line),
            "{\"type\":\"event\",\"protocol\":\"%s\",\"message\":\"%s\","
            "\"imsi\":\"%s\",\"role\":\"%s\",\"cause\":\"%s\"}",
            ptrace_proto_str(evt->protocol), evt->message,
            evt->ids.imsi, ptrace_role_str(evt->role), evt->cause);
    ogs_thread_mutex_lock(&live_lock);
    ogs_cpystrn(live_buf[live_head % LIVE_RING], line, sizeof(live_buf[0]));
    live_head++;
    ogs_thread_mutex_unlock(&live_lock);
}

static _MHD_Result handle_trace_start(struct MHD_Connection *conn,
        const char *body)
{
    char imsi[PTRACE_MAX_ID_LEN];
    int duration;
    ptrace_trace_t *tr;
    char *resp;
    int n;

    json_get_str(body, "imsi", imsi, sizeof(imsi));
    if (!imsi[0]) {
        /* nested trace_request.imsi */
        const char *p = strstr(body ? body : "", "\"imsi\"");
        if (p)
            json_get_str(p - 1, "imsi", imsi, sizeof(imsi));
    }
    duration = json_get_int(body, "duration", 300);
    if (!imsi[0])
        return send_json(conn, MHD_HTTP_BAD_REQUEST,
                "{\"error\":\"imsi required\"}\n");

    tr = ptrace_trace_start(imsi, duration);
    if (!tr)
        return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                "{\"error\":\"trace start failed\"}\n");

    resp = ogs_malloc(PTRACE_MAX_JSON);
    if (!resp)
        return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                "{\"error\":\"oom\"}\n");
    n = ptrace_trace_timeline_json(tr, resp, PTRACE_MAX_JSON);
    if (n <= 0) {
        ogs_free(resp);
        return send_json(conn, MHD_HTTP_OK,
                "{\"status\":\"active\"}\n");
    }
    {
        _MHD_Result r = send_json(conn, MHD_HTTP_OK, resp);
        ogs_free(resp);
        return r;
    }
}

static _MHD_Result handle_rule(struct MHD_Connection *conn, const char *body)
{
    ptrace_rule_t in;
    ptrace_rule_t *r;
    char buf[512];

    memset(&in, 0, sizeof(in));
    json_get_str(body, "rule_id", in.id, sizeof(in.id));
    json_get_str(body, "imsi", in.imsi, sizeof(in.imsi));
    json_get_str(body, "msisdn", in.msisdn, sizeof(in.msisdn));
    json_get_str(body, "imei", in.imei, sizeof(in.imei));
    json_get_str(body, "ue_ip", in.ue_ip, sizeof(in.ue_ip));
    in.capture_full_packet = json_get_bool(body, "capture_full_packet");
    {
        int dur = json_get_int(body, "duration", 600);
        in.expires = ogs_time_now() + ogs_time_from_sec(dur);
    }
    /* nested match.imsi */
    if (!in.imsi[0] && body) {
        const char *m = strstr(body, "\"match\"");
        if (m)
            json_get_str(m, "imsi", in.imsi, sizeof(in.imsi));
    }

    r = ptrace_rules_add(&in);
    if (!r)
        return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                "{\"error\":\"rule add failed\"}\n");
    snprintf(buf, sizeof(buf),
            "{\"rule_id\":\"%s\",\"status\":\"active\"}\n", r->id);
    return send_json(conn, MHD_HTTP_OK, buf);
}

static _MHD_Result handle_sse(struct MHD_Connection *conn)
{
    char *body;
    size_t off = 0;
    unsigned i, start, end;
    struct MHD_Response *rsp;
    _MHD_Result ret;

    body = ogs_malloc(LIVE_RING * 1100);
    if (!body)
        return MHD_NO;

    ogs_thread_mutex_lock(&live_lock);
    end = live_head;
    start = end > LIVE_RING ? end - LIVE_RING : 0;
    for (i = start; i < end; i++) {
        int n = snprintf(body + off, LIVE_RING * 1100 - off,
                "data: %s\n\n", live_buf[i % LIVE_RING]);
        if (n < 0)
            break;
        off += (size_t)n;
    }
    ogs_thread_mutex_unlock(&live_lock);

    rsp = MHD_create_response_from_buffer(off, body, MHD_RESPMEM_MUST_FREE);
    if (!rsp) {
        ogs_free(body);
        return MHD_NO;
    }
    MHD_add_response_header(rsp, "Content-Type", "text/event-stream");
    MHD_add_response_header(rsp, "Cache-Control", "no-cache");
    MHD_add_response_header(rsp, "Access-Control-Allow-Origin", "*");
    ret = MHD_queue_response(conn, MHD_HTTP_OK, rsp);
    MHD_destroy_response(rsp);
    return ret;
}

static _MHD_Result access_handler(void *cls,
        struct MHD_Connection *conn, const char *url, const char *method,
        const char *version, const char *upload_data,
        size_t *upload_data_size, void **con_cls)
{
    struct post_ctx *post;
    ptrace_context_t *ctx = ptrace_self();
    (void)cls;
    (void)version;

    if (!con_cls)
        return MHD_NO;

    if (!*con_cls) {
        if (!strcmp(method, "POST")) {
            post = ogs_calloc(1, sizeof(*post));
            if (!post)
                return MHD_NO;
            *con_cls = post;
            return MHD_YES;
        }
        *con_cls = (void *)1;
    }

    if (!strcmp(method, "GET") && !strcmp(url, "/healthz")) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                "{\"status\":\"ok\",\"packets\":%llu,\"events\":%llu}\n",
                (unsigned long long)ctx->packets_in,
                (unsigned long long)ctx->events_out);
        return send_json(conn, MHD_HTTP_OK, buf);
    }

    if (!strcmp(method, "GET") &&
            (!strcmp(url, "/ws/events") || !strcmp(url, "/events/stream")))
        return handle_sse(conn);

    if (!strcmp(method, "GET") && !strncmp(url, "/ue/", 4)) {
        ptrace_ue_t *ue = ptrace_correlate_find(url + 4);
        char buf[4096];
        if (!ue)
            return send_json(conn, MHD_HTTP_NOT_FOUND,
                    "{\"error\":\"ue not found\"}\n");
        ptrace_correlate_ue_json(ue, buf, sizeof(buf));
        return send_json(conn, MHD_HTTP_OK, buf);
    }

    if (!strcmp(method, "GET") && !strncmp(url, "/trace/", 7)) {
        const char *rest = url + 7;
        const char *slash = strchr(rest, '/');
        char id[PTRACE_MAX_ID_LEN];
        ptrace_trace_t *tr;
        size_t idlen;

        if (slash && !strcmp(slash, "/pcap")) {
            idlen = (size_t)(slash - rest);
            if (idlen >= sizeof(id))
                idlen = sizeof(id) - 1;
            memcpy(id, rest, idlen);
            id[idlen] = '\0';
            tr = ptrace_trace_get(id);
            if (!tr)
                return send_json(conn, MHD_HTTP_NOT_FOUND,
                        "{\"error\":\"trace not found\"}\n");
            {
                char path[PTRACE_MAX_PATH_LEN];
                struct MHD_Response *rsp;
                FILE *fp;
                long sz;
                char *data;
                snprintf(path, sizeof(path),
                        "/tmp/ptrace-%s.pcap", id);
                if (ptrace_trace_export_pcap(tr, path) != OGS_OK)
                    return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "{\"error\":\"pcap export failed\"}\n");
                fp = fopen(path, "rb");
                if (!fp)
                    return send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                            "{\"error\":\"pcap open failed\"}\n");
                fseek(fp, 0, SEEK_END);
                sz = ftell(fp);
                fseek(fp, 0, SEEK_SET);
                data = ogs_malloc((size_t)sz);
                if (!data) {
                    fclose(fp);
                    return MHD_NO;
                }
                if (fread(data, 1, (size_t)sz, fp) != (size_t)sz) {
                    ogs_free(data);
                    fclose(fp);
                    return MHD_NO;
                }
                fclose(fp);
                rsp = MHD_create_response_from_buffer((size_t)sz, data,
                        MHD_RESPMEM_MUST_FREE);
                MHD_add_response_header(rsp, "Content-Type",
                        "application/vnd.tcpdump.pcap");
                {
                    _MHD_Result r = MHD_queue_response(
                            conn, MHD_HTTP_OK, rsp);
                    MHD_destroy_response(rsp);
                    return r;
                }
            }
        }

        ogs_cpystrn(id, rest, sizeof(id));
        tr = ptrace_trace_get(id);
        if (!tr)
            return send_json(conn, MHD_HTTP_NOT_FOUND,
                    "{\"error\":\"trace not found\"}\n");
        {
            char *resp = ogs_malloc(PTRACE_MAX_JSON);
            _MHD_Result r;
            if (!resp)
                return MHD_NO;
            ptrace_trace_timeline_json(tr, resp, PTRACE_MAX_JSON);
            r = send_json(conn, MHD_HTTP_OK, resp);
            ogs_free(resp);
            return r;
        }
    }

    if (!strcmp(method, "DELETE") && !strncmp(url, "/trace/", 7)) {
        if (ptrace_trace_stop(url + 7))
            return send_json(conn, MHD_HTTP_OK,
                    "{\"status\":\"stopped\"}\n");
        return send_json(conn, MHD_HTTP_NOT_FOUND,
                "{\"error\":\"trace not found\"}\n");
    }

    if (!strcmp(method, "GET") && !strcmp(url, "/rule")) {
        char *buf = ogs_malloc(8192);
        _MHD_Result r;
        if (!buf)
            return MHD_NO;
        ptrace_rules_json(buf, 8192);
        r = send_json(conn, MHD_HTTP_OK, buf);
        ogs_free(buf);
        return r;
    }

    if (!strcmp(method, "DELETE") && !strncmp(url, "/rule/", 6)) {
        if (ptrace_rules_delete(url + 6))
            return send_json(conn, MHD_HTTP_OK,
                    "{\"status\":\"deleted\"}\n");
        return send_json(conn, MHD_HTTP_NOT_FOUND,
                "{\"error\":\"rule not found\"}\n");
    }

    if (!strcmp(method, "POST")) {
        post = *con_cls;
        if (*upload_data_size > 0) {
            size_t room = sizeof(post->data) - post->len - 1;
            size_t copy = *upload_data_size < room ?
                *upload_data_size : room;
            memcpy(post->data + post->len, upload_data, copy);
            post->len += copy;
            post->data[post->len] = '\0';
            *upload_data_size = 0;
            return MHD_YES;
        }

        if (!strcmp(url, "/trace") || !strcmp(url, "/trace/start")) {
            _MHD_Result r = handle_trace_start(conn, post->data);
            ogs_free(post);
            *con_cls = NULL;
            return r;
        }
        if (!strcmp(url, "/rule")) {
            _MHD_Result r = handle_rule(conn, post->data);
            ogs_free(post);
            *con_cls = NULL;
            return r;
        }

        ogs_free(post);
        *con_cls = NULL;
        return send_json(conn, MHD_HTTP_NOT_FOUND,
                "{\"error\":\"not found\"}\n");
    }

    (void)json_escape_copy;
    return send_json(conn, MHD_HTTP_NOT_FOUND,
            "{\"error\":\"not found\"}\n");
}

int ptrace_api_open(void)
{
    ptrace_context_t *ctx = ptrace_self();

    ogs_thread_mutex_init(&live_lock);

    daemon_ptr = MHD_start_daemon(
            MHD_USE_INTERNAL_POLLING_THREAD,
            ctx->api_port, NULL, NULL,
            &access_handler, NULL,
            MHD_OPTION_END);
    if (!daemon_ptr) {
        ogs_error("ptrace API listen failed on %s:%u",
                ctx->api_addr, (unsigned)ctx->api_port);
        return OGS_ERROR;
    }

    ogs_info("ptrace API listening on :%u", (unsigned)ctx->api_port);
    return OGS_OK;
}

void ptrace_api_close(void)
{
    if (daemon_ptr) {
        MHD_stop_daemon(daemon_ptr);
        daemon_ptr = NULL;
    }
    ogs_thread_mutex_destroy(&live_lock);
}
