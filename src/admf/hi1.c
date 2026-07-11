/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * HI1 administrative HTTP API and internal /mdf/x2 ingestion (MDF2).
 */

#include "hi1.h"
#include "context.h"
#include "x1.h"
#include "mdf2.h"

#include "microhttpd.h"

#include <stdio.h>
#include <string.h>

#if MHD_VERSION >= 0x00097001
typedef enum MHD_Result _MHD_Result;
#else
typedef int _MHD_Result;
#endif

static struct MHD_Daemon *hi1_daemon = NULL;

struct admf_post_ctx {
    char data[OGS_LI_MAX_JSON];
    size_t len;
};

static const char *mhd_query(struct MHD_Connection *conn, const char *key)
{
    return MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, key);
}

static _MHD_Result admf_send_json(struct MHD_Connection *conn,
        int status, const char *json)
{
    struct MHD_Response *rsp;
    _MHD_Result ret;

    rsp = MHD_create_response_from_buffer(strlen(json),
            (void *)json, MHD_RESPMEM_PERSISTENT);
    if (!rsp)
        return MHD_NO;

    MHD_add_response_header(rsp, "Content-Type", "application/json");
    ret = MHD_queue_response(conn, status, rsp);
    MHD_destroy_response(rsp);
    return ret;
}

static int admf_targets_json(char *buf, size_t buflen)
{
    admf_context_t *ctx = admf_self();
    ogs_li_target_t *target = NULL;
    size_t off = 0;
    int n;

    n = snprintf(buf + off, buflen - off, "{\"targets\":[");
    if (n < 0)
        return 0;
    off += (size_t)n;

    ogs_list_for_each(&ctx->targets.list, target) {
        n = snprintf(buf + off, buflen - off,
                "%s{\"liid\":\"%s\",\"imsi\":\"%s\",\"msisdn\":\"%s\","
                "\"cin\":%u,\"active\":%s}",
                off > 14 ? "," : "",
                target->liid, target->imsi, target->msisdn,
                (unsigned)target->cin,
                target->active ? "true" : "false");
        if (n < 0 || (size_t)n >= buflen - off)
            break;
        off += (size_t)n;
    }

    n = snprintf(buf + off, buflen - off, "]}\n");
    if (n < 0)
        return 0;
    off += (size_t)n;
    return (int)off;
}

static _MHD_Result admf_handle_hi1(struct MHD_Connection *conn)
{
    admf_context_t *ctx = admf_self();
    const char *action = mhd_query(conn, "action");
    const char *liid = mhd_query(conn, "liid");
    const char *imsi = mhd_query(conn, "imsi");
    const char *msisdn = mhd_query(conn, "msisdn");
    char body[OGS_LI_MAX_JSON];
    ogs_li_target_t *target = NULL;

    if (!action || !strcmp(action, "list")) {
        admf_targets_json(body, sizeof(body));
        return admf_send_json(conn, MHD_HTTP_OK, body);
    }

    if (!strcmp(action, "add")) {
        if (!liid || !imsi) {
            return admf_send_json(conn, MHD_HTTP_BAD_REQUEST,
                    "{\"error\":\"liid and imsi required\"}\n");
        }

        target = ogs_li_target_add(&ctx->targets, liid, imsi, msisdn);
        if (!target) {
            return admf_send_json(conn, MHD_HTTP_SERVICE_UNAVAILABLE,
                    "{\"error\":\"target pool full\"}\n");
        }

        if (admf_x1_push_target_add(liid, imsi, msisdn) != OGS_OK) {
            ogs_warn("ADMF HI1: X1 push partially failed for [%s]", liid);
        }

        snprintf(body, sizeof(body),
                "{\"status\":\"active\",\"liid\":\"%s\",\"imsi\":\"%s\","
                "\"cin\":%u}\n",
                target->liid, target->imsi, (unsigned)target->cin);
        return admf_send_json(conn, MHD_HTTP_OK, body);
    }

    if (!strcmp(action, "remove")) {
        bool removed = false;

        if (liid)
            removed = ogs_li_target_remove_by_liid(&ctx->targets, liid);
        else if (imsi)
            removed = ogs_li_target_remove_by_imsi(&ctx->targets, imsi);

        if (!removed) {
            return admf_send_json(conn, MHD_HTTP_NOT_FOUND,
                    "{\"error\":\"target not found\"}\n");
        }

        admf_x1_push_target_remove(liid, imsi);
        return admf_send_json(conn, MHD_HTTP_OK,
                "{\"status\":\"removed\"}\n");
    }

    return admf_send_json(conn, MHD_HTTP_BAD_REQUEST,
            "{\"error\":\"unknown action\"}\n");
}

static _MHD_Result admf_access_handler(void *cls,
        struct MHD_Connection *conn, const char *url, const char *method,
        const char *version, const char *upload_data,
        size_t *upload_data_size, void **con_cls)
{
    struct admf_post_ctx *post = NULL;
    (void)cls;
    (void)version;

    if (!con_cls)
        return MHD_NO;

    if (!*con_cls) {
        if (!strcmp(method, "POST") && !strcmp(url, "/mdf/x2")) {
            post = ogs_calloc(1, sizeof(*post));
            ogs_assert(post);
            *con_cls = post;
            return MHD_YES;
        }

        *con_cls = (void *)1;
    }

    if (!strcmp(url, "/hi1/intercepts") &&
            (!strcmp(method, "GET") || !strcmp(method, "POST"))) {
        return admf_handle_hi1(conn);
    }

    if (!strcmp(url, "/mdf/x2") && !strcmp(method, "POST")) {
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

        if (post->len == 0) {
            admf_send_json(conn, MHD_HTTP_BAD_REQUEST,
                    "{\"error\":\"empty x2 body\"}\n");
        } else if (admf_mdf2_handle_x2(post->data) != OGS_OK) {
            admf_send_json(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                    "{\"error\":\"mdf2 failed\"}\n");
        } else {
            admf_send_json(conn, MHD_HTTP_OK,
                    "{\"status\":\"hi2-delivered\"}\n");
        }

        ogs_free(post);
        *con_cls = NULL;
        return MHD_YES;
    }

    return admf_send_json(conn, MHD_HTTP_NOT_FOUND,
            "{\"error\":\"not found\"}\n");
}

int admf_hi1_open(void)
{
    admf_context_t *ctx = admf_self();
    uint16_t port = ctx->hi1_port;

    hi1_daemon = MHD_start_daemon(
            MHD_USE_INTERNAL_POLLING_THREAD,
            port, NULL, NULL,
            &admf_access_handler, NULL,
            MHD_OPTION_END);
    if (!hi1_daemon) {
        ogs_error("ADMF HI1 HTTP start failed (port %u)",
                (unsigned)port);
        return OGS_ERROR;
    }

    ogs_info("ADMF HI1/MDF2 HTTP listening on :%u", (unsigned)port);
    return OGS_OK;
}

void admf_hi1_close(void)
{
    if (hi1_daemon) {
        MHD_stop_daemon(hi1_daemon);
        hi1_daemon = NULL;
    }
}
