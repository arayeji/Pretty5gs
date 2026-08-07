/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "rules.h"
#include "cache.h"

static ogs_list_t rules;
static ogs_thread_mutex_t lock;
static bool ready;
static uint32_t next_id = 1;

int ptrace_rules_init(void)
{
    ogs_list_init(&rules);
    ogs_thread_mutex_init(&lock);
    ready = true;
    return OGS_OK;
}

void ptrace_rules_final(void)
{
    ptrace_rule_t *r, *n;
    if (!ready)
        return;
    ogs_thread_mutex_lock(&lock);
    for (r = ogs_list_first(&rules); r; r = n) {
        n = ogs_list_next(r);
        ogs_list_remove(&rules, r);
        ogs_free(r);
    }
    ogs_thread_mutex_unlock(&lock);
    ogs_thread_mutex_destroy(&lock);
    ready = false;
}

ptrace_rule_t *ptrace_rules_add(ptrace_rule_t *in)
{
    ptrace_rule_t *r;
    if (!in || !ready)
        return NULL;
    r = ogs_calloc(1, sizeof(*r));
    if (!r)
        return NULL;
    *r = *in;
    if (!r->id[0])
        snprintf(r->id, sizeof(r->id), "%u", next_id++);
    if (!r->expires)
        r->expires = ogs_time_now() + ogs_time_from_sec(600);

    ogs_thread_mutex_lock(&lock);
    ogs_list_add(&rules, r);
    ogs_thread_mutex_unlock(&lock);
    return r;
}

bool ptrace_rules_delete(const char *id)
{
    ptrace_rule_t *r;
    if (!id || !ready)
        return false;
    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&rules, r) {
        if (!strcmp(r->id, id)) {
            ogs_list_remove(&rules, r);
            ogs_free(r);
            ogs_thread_mutex_unlock(&lock);
            return true;
        }
    }
    ogs_thread_mutex_unlock(&lock);
    return false;
}

ptrace_rule_t *ptrace_rules_get(const char *id)
{
    ptrace_rule_t *r;
    if (!id || !ready)
        return NULL;
    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&rules, r) {
        if (!strcmp(r->id, id)) {
            ogs_thread_mutex_unlock(&lock);
            return r;
        }
    }
    ogs_thread_mutex_unlock(&lock);
    return NULL;
}

ptrace_rule_t *ptrace_rules_match(const ptrace_event_t *evt)
{
    ptrace_rule_t *r;
    ogs_time_t now;
    if (!evt || !ready)
        return NULL;
    now = ogs_time_now();
    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&rules, r) {
        if (r->expires && r->expires < now)
            continue;
        if (r->imsi[0] && strcmp(r->imsi, evt->ids.imsi))
            continue;
        if (r->msisdn[0] && strcmp(r->msisdn, evt->ids.msisdn))
            continue;
        if (r->imei[0] && strcmp(r->imei, evt->ids.imei))
            continue;
        if (r->ue_ip[0] && strcmp(r->ue_ip, evt->ids.ue_ip))
            continue;
        if (r->has_teid && (!evt->ids.has_teid || r->teid != evt->ids.teid))
            continue;
        if (r->has_seid && (!evt->ids.has_seid || r->seid != evt->ids.seid))
            continue;
        if (r->has_tac && (!evt->ids.has_tac || r->tac != evt->ids.tac))
            continue;
        if (r->has_cell && (!evt->ids.has_cell_id ||
                r->cell_id != evt->ids.cell_id))
            continue;
        /* empty match fields => skip (must have at least one criterion) */
        if (!r->imsi[0] && !r->msisdn[0] && !r->imei[0] && !r->ue_ip[0] &&
                !r->has_teid && !r->has_seid && !r->has_tac && !r->has_cell)
            continue;
        ogs_thread_mutex_unlock(&lock);
        return r;
    }
    ogs_thread_mutex_unlock(&lock);
    return NULL;
}

void ptrace_rules_expire(void)
{
    ptrace_rule_t *r, *n;
    ogs_time_t now;
    if (!ready)
        return;
    now = ogs_time_now();
    ogs_thread_mutex_lock(&lock);
    for (r = ogs_list_first(&rules); r; r = n) {
        n = ogs_list_next(r);
        if (r->expires && r->expires < now) {
            ogs_list_remove(&rules, r);
            ogs_free(r);
        }
    }
    ogs_thread_mutex_unlock(&lock);
}

int ptrace_rules_json(char *buf, size_t buflen)
{
    ptrace_rule_t *r;
    size_t off = 0;
    int n, first = 1;
    if (!buf || !buflen)
        return 0;
    n = snprintf(buf, buflen, "{\"rules\":[");
    if (n < 0) return 0;
    off = (size_t)n;
    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&rules, r) {
        n = snprintf(buf + off, buflen - off,
                "%s{\"rule_id\":\"%s\",\"imsi\":\"%s\",\"duration\":%lld,"
                "\"capture_full_packet\":%s}",
                first ? "" : ",", r->id, r->imsi,
                (long long)((r->expires - ogs_time_now()) / OGS_USEC_PER_SEC),
                r->capture_full_packet ? "true" : "false");
        if (n < 0 || (size_t)n >= buflen - off)
            break;
        off += (size_t)n;
        first = 0;
    }
    ogs_thread_mutex_unlock(&lock);
    n = snprintf(buf + off, buflen - off, "]}\n");
    if (n > 0) off += (size_t)n;
    return (int)off;
}
