/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "trace.h"
#include "cache.h"
#include "capture-ring.h"
#include "correlate.h"

static ogs_list_t traces;
static ogs_thread_mutex_t lock;
static bool ready;
static uint32_t next_id = 1;

int ptrace_trace_init(void)
{
    ogs_list_init(&traces);
    ogs_thread_mutex_init(&lock);
    ready = true;
    return OGS_OK;
}

void ptrace_trace_final(void)
{
    ptrace_trace_t *t, *n;
    if (!ready)
        return;
    ogs_thread_mutex_lock(&lock);
    for (t = ogs_list_first(&traces); t; t = n) {
        n = ogs_list_next(t);
        ogs_list_remove(&traces, t);
        ogs_free(t);
    }
    ogs_thread_mutex_unlock(&lock);
    ogs_thread_mutex_destroy(&lock);
    ready = false;
}

ptrace_trace_t *ptrace_trace_start(const char *imsi, int duration_sec)
{
    ptrace_trace_t *tr;
    ptrace_ue_t *ue;

    if (!ready || !imsi || !imsi[0])
        return NULL;
    if (duration_sec <= 0)
        duration_sec = 300;

    ue = ptrace_correlate_find(imsi);
    tr = ogs_calloc(1, sizeof(*tr));
    if (!tr)
        return NULL;
    snprintf(tr->id, sizeof(tr->id), "t-%u", next_id++);
    ogs_cpystrn(tr->imsi, imsi, sizeof(tr->imsi));
    tr->ue_id = ue ? ue->ue_id : 0;
    tr->created = ogs_time_now();
    tr->until = tr->created + ogs_time_from_sec(duration_sec);
    ogs_cpystrn(tr->status, "active", sizeof(tr->status));

    if (tr->ue_id)
        ptrace_cache_pin_ue(tr->ue_id, tr->until);

    ogs_thread_mutex_lock(&lock);
    ogs_list_add(&traces, tr);
    ogs_thread_mutex_unlock(&lock);
    return tr;
}

ptrace_trace_t *ptrace_trace_get(const char *id)
{
    ptrace_trace_t *t;
    if (!id || !ready)
        return NULL;
    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&traces, t) {
        if (!strcmp(t->id, id)) {
            ogs_thread_mutex_unlock(&lock);
            return t;
        }
    }
    ogs_thread_mutex_unlock(&lock);
    return NULL;
}

bool ptrace_trace_stop(const char *id)
{
    ptrace_trace_t *t;
    if (!id || !ready)
        return false;
    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&traces, t) {
        if (!strcmp(t->id, id)) {
            ogs_cpystrn(t->status, "stopped", sizeof(t->status));
            t->until = ogs_time_now();
            ogs_thread_mutex_unlock(&lock);
            return true;
        }
    }
    ogs_thread_mutex_unlock(&lock);
    return false;
}

static void fmt_ts(ogs_time_t ts, char *buf, size_t buflen)
{
    time_t sec = (time_t)ogs_time_sec(ts);
    struct tm tm;
    gmtime_r(&sec, &tm);
    strftime(buf, buflen, "%H:%M:%S", &tm);
}

int ptrace_trace_timeline_json(ptrace_trace_t *tr, char *buf, size_t buflen)
{
    ptrace_event_t *evs[PTRACE_MAX_TIMELINE];
    int n, i, first = 1;
    size_t off = 0;
    int w;
    ptrace_ue_t *ue;
    char uejson[2048];

    if (!tr || !buf || !buflen)
        return 0;

    ue = ptrace_correlate_find(tr->imsi);
    uejson[0] = '\0';
    if (ue)
        ptrace_correlate_ue_json(ue, uejson, sizeof(uejson));

    n = ptrace_cache_query_ue(tr->ue_id, 0, 0, evs, PTRACE_MAX_TIMELINE);
    /* Also match by IMSI if ue_id unknown */
    if (!tr->ue_id && tr->imsi[0]) {
        ptrace_event_t *all[PTRACE_MAX_TIMELINE];
        int m = ptrace_cache_query_ue(0, 0, 0, all, PTRACE_MAX_TIMELINE);
        n = 0;
        for (i = 0; i < m; i++) {
            if (!strcmp(all[i]->ids.imsi, tr->imsi))
                evs[n++] = all[i];
        }
    }

    w = snprintf(buf + off, buflen - off,
            "{\"id\":\"%s\",\"status\":\"%s\",\"imsi\":\"%s\","
            "\"ue\":%s,\"timeline\":[",
            tr->id, tr->status, tr->imsi,
            uejson[0] ? uejson : "null");
    /* uejson ends with }\n — strip newline */
    if (w < 0)
        return 0;
    /* Fix null vs object: if uejson present it includes trailing }\n */
    if (uejson[0]) {
        /* rebuild more carefully */
        off = 0;
        w = snprintf(buf + off, buflen - off,
                "{\"id\":\"%s\",\"status\":\"%s\",\"imsi\":\"%s\",\"ue\":",
                tr->id, tr->status, tr->imsi);
        off += (size_t)w;
        /* copy uejson without trailing newline */
        {
            size_t ulen = strlen(uejson);
            while (ulen && (uejson[ulen - 1] == '\n' ||
                    uejson[ulen - 1] == '\r'))
                ulen--;
            if (off + ulen < buflen) {
                memcpy(buf + off, uejson, ulen);
                off += ulen;
            }
        }
        w = snprintf(buf + off, buflen - off, ",\"timeline\":[");
        if (w > 0) off += (size_t)w;
    } else {
        off = (size_t)w;
    }

    for (i = 0; i < n && off < buflen; i++) {
        char tbuf[16];
        fmt_ts(evs[i]->ts, tbuf, sizeof(tbuf));
        w = snprintf(buf + off, buflen - off,
                "%s{\"timestamp\":\"%s\",\"interface\":\"%s\","
                "\"protocol\":\"%s\",\"message\":\"%s\","
                "\"cause\":\"%s\",\"packet_ref\":\"%s\","
                "\"fields\":\"%s\"}",
                first ? "" : ",",
                tbuf, ptrace_role_str(evs[i]->role),
                ptrace_proto_str(evs[i]->protocol),
                evs[i]->message, evs[i]->cause,
                evs[i]->packet_ref, evs[i]->fields);
        if (w < 0 || (size_t)w >= buflen - off)
            break;
        off += (size_t)w;
        first = 0;
    }

    w = snprintf(buf + off, buflen - off,
            "],\"pcap_url\":\"/trace/%s/pcap\"}\n", tr->id);
    if (w > 0) off += (size_t)w;
    return (int)off;
}

int ptrace_trace_export_pcap(ptrace_trace_t *tr, const char *path)
{
    ptrace_event_t *evs[PTRACE_MAX_TIMELINE];
    const char *refs[PTRACE_MAX_TIMELINE];
    int n, i, nref = 0;

    if (!tr || !path)
        return OGS_ERROR;

    n = ptrace_cache_query_ue(tr->ue_id, 0, 0, evs, PTRACE_MAX_TIMELINE);
    if (!tr->ue_id && tr->imsi[0]) {
        ptrace_event_t *all[PTRACE_MAX_TIMELINE];
        int m = ptrace_cache_query_ue(0, 0, 0, all, PTRACE_MAX_TIMELINE);
        n = 0;
        for (i = 0; i < m; i++)
            if (!strcmp(all[i]->ids.imsi, tr->imsi))
                evs[n++] = all[i];
    }

    for (i = 0; i < n; i++) {
        if (evs[i]->packet_ref[0])
            refs[nref++] = evs[i]->packet_ref;
    }
    return ptrace_ring_export(refs, nref, path);
}
