/*
 * Copyright (C) 2026 by Open5GS contributors
 *
 * MME /admin/trace/imsi ?sync=sgwc,smf propagation to peer NF metrics ports.
 */

#include "mme-trace-sync.h"

#include "ogs-core.h"
#include "ogs-app.h"
#include "ogs-metrics.h"

#include <string.h>
#include <strings.h>

typedef struct {
    const char *name;
    const char *host;
    uint16_t port;
} mme_trace_sync_peer_t;

/* Default loopback metrics ports from configs/open5gs yaml templates */
static const mme_trace_sync_peer_t default_peers[] = {
    { "sgwc", "127.0.0.3", 9090 },
    { "smf",  "127.0.0.4", 9090 },
};

static bool sync_token_requested(const char *sync, const char *name)
{
    char pattern[32];
    const char *p, *end;

    if (!sync || !sync[0] || !name || !name[0])
        return false;

    /* sync=all → every known peer */
    if (!strcasecmp(sync, "all"))
        return true;

    ogs_snprintf(pattern, sizeof(pattern), "%s", name);
    p = sync;
    while (*p) {
        while (*p == ',' || *p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        end = strchr(p, ',');
        if (!end)
            end = p + strlen(p);
        if ((size_t)(end - p) == 3 && strncasecmp(p, "all", 3) == 0)
            return true;
        if ((size_t)(end - p) == strlen(pattern) &&
                strncasecmp(p, pattern, end - p) == 0)
            return true;
        p = end;
    }
    return false;
}

static void trace_build_peer_path(const ogs_metrics_query_t *q,
        char *path, size_t pathlen)
{
    bool exact = q->match && strcasecmp(q->match, "exact") == 0;

    ogs_assert(path);
    path[0] = '\0';

    if (q->force) {
        ogs_snprintf(path, pathlen, "/admin/trace/imsi?force=1");
        return;
    }
    if (q->imsi && strcmp(q->imsi, "list") == 0) {
        ogs_snprintf(path, pathlen, "/admin/trace/imsi?imsi=list");
        return;
    }
    if (!q->imsi || !q->imsi[0]) {
        ogs_snprintf(path, pathlen, "/admin/trace/imsi?imsi=list");
        return;
    }

    ogs_snprintf(path, pathlen,
            "/admin/trace/imsi?imsi=%s%s%s%s",
            q->imsi,
            q->remove ? "&remove=1" : "",
            q->replace ? "&replace=1" : "",
            exact ? "&match=exact" : "");
}

static int trace_http_get(const char *host, uint16_t port,
        const char *path, char *body, size_t body_cap, size_t *body_len)
{
    ogs_sockaddr_t addr;
    ogs_sock_t *sock = NULL;
    char req[OGS_HUGE_LEN];
    char *resp = NULL;
    ssize_t n;
    int req_len, total = 0;
    bool headers_done = false;
    size_t body_off = 0;

    if (!host || !path || !body || body_cap == 0 || !body_len)
        return OGS_ERROR;

    memset(&addr, 0, sizeof(addr));
    addr.ogs_sa_family = AF_INET;
    addr.sin.sin_family = AF_INET;
    addr.sin.sin_port = htobe16(port);
    if (ogs_inet_pton(AF_INET, host, &addr.sin.sin_addr) != OGS_OK)
        return OGS_ERROR;

    sock = ogs_tcp_client(&addr, NULL);
    if (!sock)
        return OGS_ERROR;

    req_len = ogs_snprintf(req, sizeof(req),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, host);
    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        ogs_sock_destroy(sock);
        return OGS_ERROR;
    }

    n = ogs_send(sock->fd, req, (size_t)req_len, 0);
    if (n != req_len) {
        ogs_sock_destroy(sock);
        return OGS_ERROR;
    }

    resp = ogs_calloc(1, OGS_HUGE_LEN);
    if (!resp) {
        ogs_sock_destroy(sock);
        return OGS_ERROR;
    }

    while ((n = ogs_recv(sock->fd, resp + total,
                    OGS_HUGE_LEN - 1 - (size_t)total, 0)) > 0) {
        total += (int)n;
        if (total >= (int)OGS_HUGE_LEN - 1)
            break;
    }
    ogs_sock_destroy(sock);

    if (total <= 0) {
        ogs_free(resp);
        return OGS_ERROR;
    }
    resp[total] = '\0';

    {
        char *body_start = strstr(resp, "\r\n\r\n");

        if (!body_start) {
            ogs_free(resp);
            return OGS_ERROR;
        }
        body_start += 4;
        headers_done = true;
        body_off = (size_t)(body_start - resp);
    }

    if (!headers_done) {
        ogs_free(resp);
        return OGS_ERROR;
    }

    *body_len = ogs_min(body_cap - 1, (size_t)total - body_off);
    memcpy(body, resp + body_off, *body_len);
    body[*body_len] = '\0';
    ogs_free(resp);
    return OGS_OK;
}

size_t mme_trace_sync_append(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t body_len)
{
    size_t off = body_len;
    char path[512];
    char peer_body[4096];
    size_t peer_len = 0;
    unsigned int i;

    if (!q || !q->sync || !q->sync[0] || !body || body_cap == 0)
        return body_len;

    if (off > 0 && body[off - 1] == '\n')
        off--;

    if (off > 0 && body[off - 1] == '}')
        off--;

    trace_build_peer_path(q, path, sizeof(path));

    for (i = 0; i < OGS_ARRAY_SIZE(default_peers); i++) {
        const mme_trace_sync_peer_t *peer = &default_peers[i];

        if (!sync_token_requested(q->sync, peer->name))
            continue;

        peer_len = 0;
        peer_body[0] = '\0';
        if (trace_http_get(peer->host, peer->port, path,
                peer_body, sizeof(peer_body), &peer_len) != OGS_OK) {
            off += (size_t)snprintf(body + off, body_cap - off,
                    ",\"%s\":{\"ok\":false,\"detail\":\"peer unreachable\"}",
                    peer->name);
            continue;
        }

        off += (size_t)snprintf(body + off, body_cap - off,
                ",\"%s\":", peer->name);
        if (peer_len > 0 && peer_body[peer_len - 1] == '\n')
            peer_body[--peer_len] = '\0';
        off += (size_t)snprintf(body + off, body_cap - off, "%s",
                peer_body[0] ? peer_body : "{\"ok\":false}");
    }

    if (off < body_cap)
        off += (size_t)snprintf(body + off, body_cap - off, "}\n");

    return off;
}
