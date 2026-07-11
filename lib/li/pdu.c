/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "ogs-li.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *ogs_li_event_name(ogs_li_event_e event)
{
    switch (event) {
    case OGS_LI_EVENT_EPS_ATTACH:
        return "eps-attach";
    case OGS_LI_EVENT_EPS_DETACH:
        return "eps-detach";
    case OGS_LI_EVENT_EPS_TAU:
        return "eps-tau";
    case OGS_LI_EVENT_EPS_BEARER_ACTIVATE:
        return "eps-bearer-activate";
    case OGS_LI_EVENT_EPS_BEARER_DEACTIVATE:
        return "eps-bearer-deactivate";
    case OGS_LI_EVENT_PDN_SESSION_ESTABLISH:
        return "pdn-session-establish";
    case OGS_LI_EVENT_PDN_SESSION_RELEASE:
        return "pdn-session-release";
    case OGS_LI_EVENT_PDN_SESSION_MODIFY:
        return "pdn-session-modify";
    default:
        return "unknown";
    }
}

static const char *ogs_li_poi_name(ogs_li_poi_e poi)
{
    switch (poi) {
    case OGS_LI_POI_MME:
        return "MME";
    case OGS_LI_POI_SMF:
        return "SMF";
    case OGS_LI_POI_SGW:
        return "SGW";
    case OGS_LI_POI_UPF:
        return "UPF";
    default:
        return "UNKNOWN";
    }
}

int ogs_li_x2_encode_json(char *buf, size_t buflen,
        ogs_li_poi_e poi, ogs_li_event_e event,
        const char *liid, uint32_t cin, const char *imsi,
        const char *msisdn, const char *detail)
{
    time_t now;
    struct tm tm_buf;
    char ts[32];

    ogs_assert(buf);
    ogs_assert(liid && liid[0]);
    ogs_assert(imsi && imsi[0]);

    now = time(NULL);
    ogs_localtime(now, &tm_buf);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    return snprintf(buf, buflen,
            "{"
            "\"pdu\":\"x2\","
            "\"poi\":\"%s\","
            "\"event\":\"%s\","
            "\"liid\":\"%s\","
            "\"cin\":%u,"
            "\"imsi\":\"%s\","
            "\"msisdn\":\"%s\","
            "\"timestamp\":\"%s\","
            "\"detail\":\"%s\""
            "}",
            ogs_li_poi_name(poi),
            ogs_li_event_name(event),
            liid,
            (unsigned)cin,
            imsi,
            msisdn ? msisdn : "",
            ts,
            detail ? detail : "");
}

int ogs_li_hi2_write_spool(const char *spool_dir, const char *hi2_json)
{
    FILE *fp = NULL;
    char path[OGS_LI_MAX_SPOOL_PATH + 64];
    time_t now;
    struct tm tm_buf;
    char ts[32];
    int n;

    ogs_assert(spool_dir && spool_dir[0]);
    ogs_assert(hi2_json && hi2_json[0]);

    now = time(NULL);
    ogs_localtime(now, &tm_buf);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%S", &tm_buf);

    n = snprintf(path, sizeof(path), "%s/hi2-%s-%ld.json",
            spool_dir, ts, (long)now);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return OGS_ERROR;

    fp = fopen(path, "w");
    if (!fp) {
        ogs_error("LI HI2 spool open failed [%s] errno=%d",
                path, errno);
        return OGS_ERROR;
    }

    fputs(hi2_json, fp);
    fputc('\n', fp);
    fclose(fp);

    ogs_debug("LI HI2 spooled [%s]", path);
    return OGS_OK;
}
