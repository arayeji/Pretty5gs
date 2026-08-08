/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "target.h"
#include "context.h"
#include "cache.h"

#include <ctype.h>

static ogs_list_t targets;
static ogs_thread_mutex_t lock;
static bool ready;
static uint64_t next_id = 1;
static volatile int active_count;

static void digits_only(const char *in, char *out, size_t outlen)
{
    size_t o = 0;
    int i;
    if (!out || !outlen)
        return;
    out[0] = '\0';
    if (!in)
        return;
    for (i = 0; in[i] && o + 1 < outlen; i++) {
        if (in[i] >= '0' && in[i] <= '9')
            out[o++] = in[i];
    }
    out[o] = '\0';
}

static void sync_ue_view(ptrace_target_t *t)
{
    ptrace_ue_t *ue;
    int i;

    if (!t)
        return;
    ue = &t->ue;
    memset(ue, 0, sizeof(*ue));
    ue->ue_id = t->id;
    ogs_cpystrn(ue->imsi, t->imsi, sizeof(ue->imsi));
    ogs_cpystrn(ue->msisdn, t->msisdn, sizeof(ue->msisdn));
    ogs_cpystrn(ue->imei, t->imei, sizeof(ue->imei));
    ogs_cpystrn(ue->guti, t->guti, sizeof(ue->guti));
    ogs_cpystrn(ue->m_tmsi, t->m_tmsi, sizeof(ue->m_tmsi));
    ue->num_ue_ips = t->num_ue_ips;
    for (i = 0; i < t->num_ue_ips; i++)
        ogs_cpystrn(ue->ue_ips[i], t->ue_ips[i], sizeof(ue->ue_ips[i]));
    ue->num_teids = t->num_teids < PTRACE_MAX_UE_TEIDS ?
            t->num_teids : PTRACE_MAX_UE_TEIDS;
    for (i = 0; i < ue->num_teids; i++)
        ue->teids[i] = t->teids[i];
    ue->num_seids = t->num_seids < PTRACE_MAX_UE_SEIDS ?
            t->num_seids : PTRACE_MAX_UE_SEIDS;
    for (i = 0; i < ue->num_seids; i++)
        ue->seids[i] = t->seids[i];
    ue->num_sessions = t->num_sessions < PTRACE_MAX_UE_SESSIONS ?
            t->num_sessions : PTRACE_MAX_UE_SESSIONS;
    for (i = 0; i < ue->num_sessions; i++)
        ogs_cpystrn(ue->sessions[i], t->sessions[i],
                sizeof(ue->sessions[i]));
    ue->last_seen = t->last_seen;
}

static bool key_matches_target(ptrace_target_t *t, const char *key,
        const char *digits)
{
    if (!t || !t->active)
        return false;
    if (key && key[0]) {
        if (t->imsi[0] && !strcmp(t->imsi, key))
            return true;
        if (t->msisdn[0] && !strcmp(t->msisdn, key))
            return true;
        if (t->imei[0] && !strcmp(t->imei, key))
            return true;
        if (t->guti[0] && !strcmp(t->guti, key))
            return true;
        if (t->m_tmsi[0] && !strcmp(t->m_tmsi, key))
            return true;
    }
    if (digits && digits[0]) {
        if (t->imsi[0] && !strcmp(t->imsi, digits))
            return true;
        if (t->msisdn[0] && !strcmp(t->msisdn, digits))
            return true;
        if (t->imei[0] && !strcmp(t->imei, digits))
            return true;
    }
    return false;
}

static void add_teid(ptrace_target_t *t, uint32_t teid)
{
    int i;
    if (!teid)
        return;
    for (i = 0; i < t->num_teids; i++)
        if (t->teids[i] == teid)
            return;
    if (t->num_teids < PTRACE_TARGET_MAX_TEIDS)
        t->teids[t->num_teids++] = teid;
}

static void add_seid(ptrace_target_t *t, uint64_t seid)
{
    int i;
    if (!seid)
        return;
    for (i = 0; i < t->num_seids; i++)
        if (t->seids[i] == seid)
            return;
    if (t->num_seids < PTRACE_TARGET_MAX_SEIDS)
        t->seids[t->num_seids++] = seid;
}

static void add_hbh(ptrace_target_t *t, uint32_t hbh)
{
    int i;
    if (!hbh)
        return;
    for (i = 0; i < t->num_hbhs; i++)
        if (t->hbhs[i] == hbh)
            return;
    if (t->num_hbhs < PTRACE_TARGET_MAX_HBH)
        t->hbhs[t->num_hbhs++] = hbh;
}

static void add_str(char (*arr)[PTRACE_MAX_ID_LEN], int *n, int max,
        const char *s)
{
    int i;
    if (!s || !s[0] || !n)
        return;
    for (i = 0; i < *n; i++)
        if (!strcmp(arr[i], s))
            return;
    if (*n < max) {
        ogs_cpystrn(arr[*n], s, PTRACE_MAX_ID_LEN);
        (*n)++;
    }
}

static void add_session(ptrace_target_t *t, const char *s)
{
    int i;
    if (!s || !s[0])
        return;
    for (i = 0; i < t->num_sessions; i++)
        if (!strcmp(t->sessions[i], s))
            return;
    if (t->num_sessions < PTRACE_TARGET_MAX_SESS) {
        ogs_cpystrn(t->sessions[t->num_sessions], s,
                sizeof(t->sessions[0]));
        t->num_sessions++;
    }
}

static void learn(ptrace_target_t *t, const ptrace_ids_t *ids)
{
    int i;

    if (!t || !ids)
        return;
    if (ids->imsi[0] && !t->imsi[0])
        ogs_cpystrn(t->imsi, ids->imsi, sizeof(t->imsi));
    if (ids->msisdn[0])
        ogs_cpystrn(t->msisdn, ids->msisdn, sizeof(t->msisdn));
    if (ids->imei[0])
        ogs_cpystrn(t->imei, ids->imei, sizeof(t->imei));
    if (ids->guti[0])
        ogs_cpystrn(t->guti, ids->guti, sizeof(t->guti));
    if (ids->m_tmsi[0])
        ogs_cpystrn(t->m_tmsi, ids->m_tmsi, sizeof(t->m_tmsi));
    if (ids->ue_ip[0])
        add_str(t->ue_ips, &t->num_ue_ips, PTRACE_MAX_UE_IPS, ids->ue_ip);
    if (ids->session_id[0])
        add_session(t, ids->session_id);
    if (ids->has_teid)
        add_teid(t, ids->teid);
    for (i = 0; i < ids->num_teids; i++)
        add_teid(t, ids->teids[i]);
    if (ids->has_seid)
        add_seid(t, ids->seid);
    if (ids->has_diam_hbh)
        add_hbh(t, ids->diam_hbh);
    sync_ue_view(t);
}

static bool ids_match_target(ptrace_target_t *t, const ptrace_ids_t *ids)
{
    int i, j;

    if (!t || !t->active || !ids)
        return false;

    if (ids->imsi[0] && t->imsi[0] && !strcmp(ids->imsi, t->imsi))
        return true;
    if (ids->msisdn[0] && t->msisdn[0] && !strcmp(ids->msisdn, t->msisdn))
        return true;
    if (ids->imei[0] && t->imei[0] && !strcmp(ids->imei, t->imei))
        return true;
    if (ids->guti[0] && t->guti[0] && !strcmp(ids->guti, t->guti))
        return true;
    if (ids->m_tmsi[0] && t->m_tmsi[0] && !strcmp(ids->m_tmsi, t->m_tmsi))
        return true;
    if (ids->session_id[0]) {
        for (i = 0; i < t->num_sessions; i++)
            if (!strcmp(ids->session_id, t->sessions[i]))
                return true;
    }
    if (ids->ue_ip[0]) {
        for (i = 0; i < t->num_ue_ips; i++)
            if (!strcmp(ids->ue_ip, t->ue_ips[i]))
                return true;
    }
    if (ids->num_teids > 0) {
        for (j = 0; j < ids->num_teids; j++) {
            for (i = 0; i < t->num_teids; i++)
                if (ids->teids[j] && ids->teids[j] == t->teids[i])
                    return true;
        }
    } else if (ids->has_teid && ids->teid) {
        for (i = 0; i < t->num_teids; i++)
            if (ids->teid == t->teids[i])
                return true;
    }
    if (ids->has_seid) {
        for (i = 0; i < t->num_seids; i++)
            if (ids->seid == t->seids[i])
                return true;
    }
    if (ids->has_diam_hbh) {
        for (i = 0; i < t->num_hbhs; i++)
            if (ids->diam_hbh == t->hbhs[i])
                return true;
    }
    return false;
}

int ptrace_target_init(void)
{
    ogs_list_init(&targets);
    ogs_thread_mutex_init(&lock);
    active_count = 0;
    ready = true;
    return OGS_OK;
}

void ptrace_target_final(void)
{
    ptrace_target_t *t, *n;
    if (!ready)
        return;
    ogs_thread_mutex_lock(&lock);
    for (t = ogs_list_first(&targets); t; t = n) {
        n = ogs_list_next(t);
        ogs_list_remove(&targets, t);
        ogs_free(t);
    }
    active_count = 0;
    ogs_thread_mutex_unlock(&lock);
    ogs_thread_mutex_destroy(&lock);
    ready = false;
}

bool ptrace_target_any_active(void)
{
    return ready && active_count > 0;
}

int ptrace_target_count(void)
{
    return ready ? active_count : 0;
}

ptrace_target_t *ptrace_target_find(const char *key)
{
    ptrace_target_t *t;
    char digits[PTRACE_MAX_ID_LEN];

    if (!ready || !key || !key[0])
        return NULL;
    digits_only(key, digits, sizeof(digits));

    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&targets, t) {
        if (key_matches_target(t, key, digits)) {
            ogs_thread_mutex_unlock(&lock);
            return t;
        }
    }
    ogs_thread_mutex_unlock(&lock);
    return NULL;
}

ptrace_target_t *ptrace_target_activate(const char *key, int duration_sec)
{
    ptrace_target_t *t;
    char digits[PTRACE_MAX_ID_LEN];
    ogs_time_t now, until;

    if (!ready || !key || !key[0])
        return NULL;
    if (duration_sec <= 0)
        duration_sec = PTRACE_TARGET_DEFAULT_SEC;

    digits_only(key, digits, sizeof(digits));
    if (!digits[0])
        ogs_cpystrn(digits, key, sizeof(digits));

    now = ogs_time_now();
    until = now + ogs_time_from_sec(duration_sec);

    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&targets, t) {
        if (key_matches_target(t, key, digits) ||
                (t->imsi[0] && !strcmp(t->imsi, digits))) {
            if (!t->active) {
                t->active = true;
                active_count++;
            }
            if (until > t->until)
                t->until = until;
            t->last_seen = now;
            /* NMS activates by IMSI (or MSISDN digits); store as IMSI key. */
            if (!t->imsi[0])
                ogs_cpystrn(t->imsi, digits, sizeof(t->imsi));
            sync_ue_view(t);
            ptrace_cache_pin_ue(t->id, t->until);
            ogs_thread_mutex_unlock(&lock);
            return t;
        }
    }

    if (ogs_list_count(&targets) >= PTRACE_MAX_TARGETS) {
        ogs_thread_mutex_unlock(&lock);
        ogs_warn("ptrace: target table full (%d)", PTRACE_MAX_TARGETS);
        return NULL;
    }

    t = ogs_calloc(1, sizeof(*t));
    if (!t) {
        ogs_thread_mutex_unlock(&lock);
        return NULL;
    }
    t->id = next_id++;
    t->created = now;
    t->until = until;
    t->last_seen = now;
    t->active = true;
    ogs_cpystrn(t->imsi, digits, sizeof(t->imsi));
    sync_ue_view(t);
    ogs_list_add(&targets, t);
    active_count++;
    ptrace_cache_pin_ue(t->id, t->until);
    ogs_thread_mutex_unlock(&lock);

    ogs_info("ptrace: target activated imsi=%s msisdn=%s imei=%s until+%ds",
            t->imsi, t->msisdn, t->imei, duration_sec);
    return t;
}

bool ptrace_target_deactivate(const char *key)
{
    ptrace_target_t *t;
    char digits[PTRACE_MAX_ID_LEN];

    if (!ready || !key || !key[0])
        return false;
    digits_only(key, digits, sizeof(digits));

    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&targets, t) {
        if (key_matches_target(t, key, digits)) {
            if (t->active) {
                t->active = false;
                t->until = ogs_time_now();
                active_count--;
                if (active_count < 0)
                    active_count = 0;
            }
            ogs_thread_mutex_unlock(&lock);
            return true;
        }
    }
    ogs_thread_mutex_unlock(&lock);
    return false;
}

uint64_t ptrace_target_match_learn(ptrace_ids_t *ids, ogs_time_t ts)
{
    ptrace_target_t *t;
    uint64_t id = 0;

    if (!ready || !ids || active_count <= 0)
        return 0;

    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&targets, t) {
        if (!t->active)
            continue;
        if (!ids_match_target(t, ids))
            continue;
        learn(t, ids);
        t->last_seen = ts ? ts : ogs_time_now();
        if (ids->imsi[0] == '\0' && t->imsi[0])
            ogs_cpystrn(ids->imsi, t->imsi, sizeof(ids->imsi));
        if (ids->msisdn[0] == '\0' && t->msisdn[0])
            ogs_cpystrn(ids->msisdn, t->msisdn, sizeof(ids->msisdn));
        if (ids->imei[0] == '\0' && t->imei[0])
            ogs_cpystrn(ids->imei, t->imei, sizeof(ids->imei));
        id = t->id;
        break;
    }
    ogs_thread_mutex_unlock(&lock);
    return id;
}

int ptrace_target_expire(void)
{
    ptrace_target_t *t, *n;
    ogs_time_t now;
    int removed = 0;

    if (!ready)
        return 0;
    now = ogs_time_now();

    ogs_thread_mutex_lock(&lock);
    for (t = ogs_list_first(&targets); t; t = n) {
        n = ogs_list_next(t);
        if (t->active && t->until && t->until < now) {
            t->active = false;
            active_count--;
            if (active_count < 0)
                active_count = 0;
            removed++;
            ogs_info("ptrace: target expired imsi=%s", t->imsi);
        }
        /* Drop inactive targets older than idle window to free slots. */
        if (!t->active && t->last_seen +
                ogs_time_from_sec(PTRACE_UE_IDLE_SEC) < now) {
            ogs_list_remove(&targets, t);
            ogs_free(t);
        }
    }
    ogs_thread_mutex_unlock(&lock);
    return removed;
}

ptrace_ue_t *ptrace_target_ue(ptrace_target_t *t)
{
    if (!t || !t->active)
        return NULL;
    sync_ue_view(t);
    return &t->ue;
}

int ptrace_target_ue_json(ptrace_target_t *t, char *buf, size_t buflen)
{
    ptrace_ue_t *ue = ptrace_target_ue(t);
    if (!ue)
        return 0;
    return ptrace_correlate_ue_json(ue, buf, buflen);
}
