/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * MDF2: accept xIRI (X2) from POIs, emit HI2 records for LEMF.
 */

#include "mdf2.h"
#include "context.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

int admf_mdf2_handle_x2(const char *x2_json)
{
    admf_context_t *ctx = admf_self();
    char hi2[OGS_LI_MAX_JSON];
    time_t now;
    struct tm tm_buf;
    char ts[32];
    int n;

    ogs_assert(x2_json && x2_json[0]);

    now = time(NULL);
    ogs_localtime(now, &tm_buf);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    n = snprintf(hi2, sizeof(hi2),
            "{"
            "\"pdu\":\"hi2\","
            "\"interface\":\"HI2\","
            "\"timestamp\":\"%s\","
            "\"x2\":%s"
            "}",
            ts, x2_json);
    if (n <= 0 || (size_t)n >= sizeof(hi2)) {
        ogs_error("ADMF MDF2 HI2 encode overflow");
        return OGS_ERROR;
    }

    if (ogs_li_hi2_write_spool(ctx->hi2_spool_dir, hi2) != OGS_OK)
        return OGS_ERROR;

    ogs_info("ADMF MDF2 HI2 delivered (spool)");
    return OGS_OK;
}
