/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Push LI_X1-style target tasking to MME/SMF admin endpoints.
 */

#include "x1.h"

#include <stdio.h>
#include <string.h>

static int admf_x1_push_query(const char *path)
{
    admf_context_t *ctx = admf_self();
    int i, ok = 0;

    for (i = 0; i < ctx->num_x1_peers; i++) {
        if (ogs_li_http_get(&ctx->x1_peers[i].peer, path, 3000)
                == OGS_OK) {
            ok++;
            ogs_info("ADMF X1 [%s] ok [%s]",
                    ctx->x1_peers[i].name, path);
        } else {
            ogs_warn("ADMF X1 [%s] failed [%s]",
                    ctx->x1_peers[i].name, path);
        }
    }

    return ok > 0 ? OGS_OK : OGS_ERROR;
}

int admf_x1_push_target_add(const char *liid, const char *imsi,
        const char *msisdn)
{
    char path[512];

    ogs_assert(liid && liid[0]);
    ogs_assert(imsi && imsi[0]);

    snprintf(path, sizeof(path),
            "/admin/li/target?action=add&liid=%s&imsi=%s%s%s",
            liid, imsi,
            msisdn && msisdn[0] ? "&msisdn=" : "",
            msisdn && msisdn[0] ? msisdn : "");

    return admf_x1_push_query(path);
}

int admf_x1_push_target_remove(const char *liid, const char *imsi)
{
    char path[512];

    if (liid && liid[0]) {
        snprintf(path, sizeof(path),
                "/admin/li/target?action=remove&liid=%s", liid);
    } else if (imsi && imsi[0]) {
        snprintf(path, sizeof(path),
                "/admin/li/target?action=remove&imsi=%s", imsi);
    } else {
        return OGS_ERROR;
    }

    return admf_x1_push_query(path);
}
