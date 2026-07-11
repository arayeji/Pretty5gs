/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Minimal blocking HTTP/1.1 client for X2 delivery to ADMF/MDF2.
 */

#include "ogs-li.h"

#include <stdio.h>
#include <string.h>

static int ogs_li_http_request(const ogs_li_mdf_peer_t *peer,
        const char *method, const char *path,
        const char *json_body, int timeout_ms)
{
    ogs_sock_t *sock = NULL;
    ogs_sockaddr_t *addr = NULL;
    char req[OGS_LI_MAX_JSON + 512];
    char resp[512];
    int n, rv = OGS_ERROR;
    int body_len = 0;

    (void)timeout_ms;

    ogs_assert(peer);
    ogs_assert(method && method[0]);
    ogs_assert(path && path[0]);

    if (!peer->addr) {
        ogs_error("LI HTTP peer address not configured");
        return OGS_ERROR;
    }

    addr = peer->addr;

    sock = ogs_sock_socket(addr->ogs_sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (!sock)
        return OGS_ERROR;

    if (ogs_sock_connect(sock, addr) != OGS_OK) {
        ogs_error("LI HTTP connect failed [%s:%u]",
                peer->host, (unsigned)peer->port);
        ogs_sock_destroy(sock);
        return OGS_ERROR;
    }

    if (json_body && json_body[0])
        body_len = (int)strlen(json_body);

    if (body_len > 0) {
        n = snprintf(req, sizeof(req),
                "%s %s HTTP/1.1\r\n"
                "Host: %s:%u\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %d\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%s",
                method, path,
                peer->host[0] ? peer->host : "127.0.0.1",
                (unsigned)peer->port,
                body_len,
                json_body);
    } else {
        n = snprintf(req, sizeof(req),
                "%s %s HTTP/1.1\r\n"
                "Host: %s:%u\r\n"
                "Connection: close\r\n"
                "\r\n",
                method, path,
                peer->host[0] ? peer->host : "127.0.0.1",
                (unsigned)peer->port);
    }

    if (n <= 0 || (size_t)n >= sizeof(req))
        goto done;

    if (ogs_write(sock->fd, req, (size_t)n) != (ssize_t)n)
        goto done;

    n = (int)ogs_read(sock->fd, resp, sizeof(resp) - 1);
    if (n > 0) {
        resp[n] = '\0';
        if (strstr(resp, "HTTP/1.") && strstr(resp, " 2"))
            rv = OGS_OK;
    }

done:
    ogs_sock_destroy(sock);
    return rv;
}

int ogs_li_http_post_json(const ogs_li_mdf_peer_t *peer,
        const char *path, const char *json_body, int timeout_ms)
{
    return ogs_li_http_request(peer, "POST", path, json_body, timeout_ms);
}

int ogs_li_http_get(const ogs_li_mdf_peer_t *peer,
        const char *path, int timeout_ms)
{
    return ogs_li_http_request(peer, "GET", path, NULL, timeout_ms);
}
