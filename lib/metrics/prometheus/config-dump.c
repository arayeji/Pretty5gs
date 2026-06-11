/*
 * Copyright (C) 2026 by Open5GS contributors
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "ogs-app.h"
#include "ogs-metrics.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

static size_t json_append_bytes(char *dst, size_t cap, size_t off,
        const char *src, size_t len)
{
    size_t i;

    for (i = 0; i < len && off + 1 < cap; i++) {
        unsigned char c = (unsigned char)src[i];

        if (c == '"' || c == '\\') {
            if (off + 2 >= cap)
                break;
            dst[off++] = '\\';
            dst[off++] = (char)c;
        } else if (c == '\n') {
            if (off + 2 >= cap)
                break;
            dst[off++] = '\\';
            dst[off++] = 'n';
        } else if (c == '\r') {
            if (off + 2 >= cap)
                break;
            dst[off++] = '\\';
            dst[off++] = 'r';
        } else if (c == '\t') {
            if (off + 2 >= cap)
                break;
            dst[off++] = '\\';
            dst[off++] = 't';
        } else if (c < 0x20) {
            int n;
            if (off + 6 >= cap)
                break;
            n = snprintf(dst + off, cap - off, "\\u%04x", c);
            if (n < 0)
                break;
            off += (size_t)n;
        } else {
            dst[off++] = (char)c;
        }
    }

    if (off < cap)
        dst[off] = '\0';
    return off;
}

size_t ogs_metrics_config_file_dump(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    const char *path = NULL;
    FILE *fp = NULL;
    char *filebuf = NULL;
    long fsize = 0;
    size_t nread = 0;
    size_t off = 0;
    int n;
    int64_t mtime = 0;
#if HAVE_SYS_STAT_H
    struct stat st;
#endif

    (void)q;

    if (!buf || buflen == 0)
        return 0;

    path = ogs_app()->file;
    if (!path || !path[0]) {
        n = snprintf(buf, buflen,
                "{\"error\":\"no config file path\"}\n");
        return n > 0 ? (size_t)n : 0;
    }

#if HAVE_SYS_STAT_H
    if (stat(path, &st) == 0)
        mtime = (int64_t)st.st_mtime;
#endif

    fp = fopen(path, "rb");
    if (!fp) {
        n = snprintf(buf, buflen,
                "{\"path\":\"%s\",\"error\":\"cannot open file\"}\n", path);
        return n > 0 ? (size_t)n : 0;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        n = snprintf(buf, buflen,
                "{\"path\":\"%s\",\"error\":\"cannot seek file\"}\n", path);
        return n > 0 ? (size_t)n : 0;
    }

    fsize = ftell(fp);
    if (fsize < 0) {
        fclose(fp);
        n = snprintf(buf, buflen,
                "{\"path\":\"%s\",\"error\":\"cannot stat file size\"}\n",
                path);
        return n > 0 ? (size_t)n : 0;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        n = snprintf(buf, buflen,
                "{\"path\":\"%s\",\"error\":\"cannot rewind file\"}\n", path);
        return n > 0 ? (size_t)n : 0;
    }

    filebuf = ogs_calloc(1, (size_t)fsize + 1);
    if (!filebuf) {
        fclose(fp);
        n = snprintf(buf, buflen,
                "{\"path\":\"%s\",\"error\":\"out of memory\"}\n", path);
        return n > 0 ? (size_t)n : 0;
    }

    nread = fread(filebuf, 1, (size_t)fsize, fp);
    fclose(fp);

    n = snprintf(buf, buflen,
            "{\"path\":\"%s\",\"size\":%ld,\"mtime\":%lld,"
            "\"note\":\"on-disk YAML (same file SIGHUP reload reads); "
            "effective runtime state may differ for add-only keys\","
            "\"content\":\"",
            path, (long)fsize, (long long)mtime);
    if (n < 0) {
        ogs_free(filebuf);
        return 0;
    }
    off = (size_t)n;
    if (off >= buflen) {
        ogs_free(filebuf);
        return buflen - 1;
    }

    off = json_append_bytes(buf, buflen, off, filebuf, nread);
    ogs_free(filebuf);

    if (off + 4 < buflen) {
        buf[off++] = '"';
        buf[off++] = '}';
        buf[off++] = '\n';
        buf[off] = '\0';
    }

    (void)page;
    (void)page_size;
    return off;
}
