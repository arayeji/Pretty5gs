/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Optional ClickHouse insert via HTTP (libcurl). Query stub for MVP.
 */

#include "store.h"

#if defined(HAVE_LIBCURL)
#include <curl/curl.h>
static char ch_url[PTRACE_MAX_PATH_LEN];
static bool ch_ready;
#endif

int ptrace_store_clickhouse_init(const char *url)
{
#if defined(HAVE_LIBCURL)
    if (!url || !url[0])
        return OGS_OK;
    ogs_cpystrn(ch_url, url, sizeof(ch_url));
    curl_global_init(CURL_GLOBAL_DEFAULT);
    ch_ready = true;
    ogs_info("ptrace ClickHouse HTTP sink enabled");
    return OGS_OK;
#else
    (void)url;
    ogs_warn("ptrace: ClickHouse requested but libcurl not built in");
    return OGS_OK;
#endif
}

void ptrace_store_clickhouse_final(void)
{
#if defined(HAVE_LIBCURL)
    if (ch_ready) {
        curl_global_cleanup();
        ch_ready = false;
    }
#endif
}

void ptrace_store_clickhouse_put(ptrace_event_t *evt)
{
#if defined(HAVE_LIBCURL)
    CURL *curl;
    char body[1024];
    if (!ch_ready || !evt)
        return;
    snprintf(body, sizeof(body),
            "{\"ts\":%lld,\"proto\":\"%s\",\"msg\":\"%s\","
            "\"imsi\":\"%s\",\"teid\":%u,\"seid\":%llu,\"cause\":%u}\n",
            (long long)evt->ts, ptrace_proto_str(evt->protocol),
            evt->message, evt->ids.imsi,
            evt->ids.has_teid ? evt->ids.teid : 0,
            (unsigned long long)evt->ids.seid, evt->cause_code);
    curl = curl_easy_init();
    if (!curl)
        return;
    curl_easy_setopt(curl, CURLOPT_URL, ch_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
#else
    (void)evt;
#endif
}
