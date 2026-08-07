/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "correlate.h"
#include "context.h"

static ogs_list_t ue_list;
static ogs_hash_t *by_imsi;
static ogs_hash_t *by_msisdn;
static ogs_hash_t *by_imei;
static ogs_hash_t *by_guti;
static ogs_hash_t *by_mtmsi;
static ogs_hash_t *by_ueip;
static ogs_hash_t *by_teid;
static ogs_hash_t *by_seid;
static ogs_hash_t *by_enb;
static ogs_hash_t *by_mme;
static ogs_thread_mutex_t lock;
static bool ready;

static void index_str(ogs_hash_t *h, const char *key, ptrace_ue_t *ue)
{
    if (!key || !key[0])
        return;
    ogs_hash_set(h, ogs_strdup(key), OGS_HASH_KEY_STRING, ue);
}

static void index_u32(ogs_hash_t *h, uint32_t key, ptrace_ue_t *ue)
{
    uint32_t *k = ogs_malloc(sizeof(*k));
    *k = key;
    ogs_hash_set(h, k, sizeof(*k), ue);
}

static void index_u64(ogs_hash_t *h, uint64_t key, ptrace_ue_t *ue)
{
    uint64_t *k = ogs_malloc(sizeof(*k));
    *k = key;
    ogs_hash_set(h, k, sizeof(*k), ue);
}

static ptrace_ue_t *lookup_str(ogs_hash_t *h, const char *key)
{
    if (!key || !key[0])
        return NULL;
    return ogs_hash_get(h, key, OGS_HASH_KEY_STRING);
}

static ptrace_ue_t *lookup_u32(ogs_hash_t *h, uint32_t key)
{
    return ogs_hash_get(h, &key, sizeof(key));
}

static ptrace_ue_t *lookup_u64(ogs_hash_t *h, uint64_t key)
{
    return ogs_hash_get(h, &key, sizeof(key));
}

static ptrace_ue_t *ue_new(void)
{
    ptrace_context_t *ctx = ptrace_self();
    ptrace_ue_t *ue = ogs_calloc(1, sizeof(*ue));
    if (!ue)
        return NULL;
    ue->ue_id = ctx->next_ue_id++;
    ue->last_seen = ogs_time_now();
    ogs_list_add(&ue_list, ue);
    return ue;
}

static void ue_merge_ids(ptrace_ue_t *ue, const ptrace_ids_t *ids)
{
    int i;
    if (ids->imsi[0] && !ue->imsi[0])
        ogs_cpystrn(ue->imsi, ids->imsi, sizeof(ue->imsi));
    if (ids->msisdn[0] && !ue->msisdn[0])
        ogs_cpystrn(ue->msisdn, ids->msisdn, sizeof(ue->msisdn));
    if (ids->imei[0] && !ue->imei[0])
        ogs_cpystrn(ue->imei, ids->imei, sizeof(ue->imei));
    if (ids->guti[0])
        ogs_cpystrn(ue->guti, ids->guti, sizeof(ue->guti));
    if (ids->m_tmsi[0])
        ogs_cpystrn(ue->m_tmsi, ids->m_tmsi, sizeof(ue->m_tmsi));
    if (ids->apn[0])
        ogs_cpystrn(ue->apn, ids->apn, sizeof(ue->apn));
    if (ids->ue_ip[0]) {
        for (i = 0; i < ue->num_ue_ips; i++)
            if (!strcmp(ue->ue_ips[i], ids->ue_ip))
                break;
        if (i == ue->num_ue_ips && ue->num_ue_ips < PTRACE_MAX_UE_IPS)
            ogs_cpystrn(ue->ue_ips[ue->num_ue_ips++], ids->ue_ip,
                    sizeof(ue->ue_ips[0]));
    }
    if (ids->has_teid) {
        for (i = 0; i < ue->num_teids; i++)
            if (ue->teids[i] == ids->teid)
                break;
        if (i == ue->num_teids && ue->num_teids < PTRACE_MAX_UE_TEIDS)
            ue->teids[ue->num_teids++] = ids->teid;
    }
    if (ids->has_seid) {
        for (i = 0; i < ue->num_seids; i++)
            if (ue->seids[i] == ids->seid)
                break;
        if (i == ue->num_seids && ue->num_seids < PTRACE_MAX_UE_SEIDS)
            ue->seids[ue->num_seids++] = ids->seid;
    }
    if (ids->has_enb_ue_s1ap_id && ue->num_enb < 4) {
        for (i = 0; i < ue->num_enb; i++)
            if (ue->enb_ue_s1ap_ids[i] == ids->enb_ue_s1ap_id)
                break;
        if (i == ue->num_enb)
            ue->enb_ue_s1ap_ids[ue->num_enb++] = ids->enb_ue_s1ap_id;
    }
    if (ids->has_mme_ue_s1ap_id && ue->num_mme < 4) {
        for (i = 0; i < ue->num_mme; i++)
            if (ue->mme_ue_s1ap_ids[i] == ids->mme_ue_s1ap_id)
                break;
        if (i == ue->num_mme)
            ue->mme_ue_s1ap_ids[ue->num_mme++] = ids->mme_ue_s1ap_id;
    }
    if (ids->has_tac && ue->num_tac < 4) {
        for (i = 0; i < ue->num_tac; i++)
            if (ue->tacs[i] == ids->tac)
                break;
        if (i == ue->num_tac)
            ue->tacs[ue->num_tac++] = ids->tac;
    }
    ue->last_seen = ogs_time_now();
}

static void ue_reindex(ptrace_ue_t *ue)
{
    int i;
    if (ue->imsi[0]) index_str(by_imsi, ue->imsi, ue);
    if (ue->msisdn[0]) index_str(by_msisdn, ue->msisdn, ue);
    if (ue->imei[0]) index_str(by_imei, ue->imei, ue);
    if (ue->guti[0]) index_str(by_guti, ue->guti, ue);
    if (ue->m_tmsi[0]) index_str(by_mtmsi, ue->m_tmsi, ue);
    for (i = 0; i < ue->num_ue_ips; i++)
        index_str(by_ueip, ue->ue_ips[i], ue);
    for (i = 0; i < ue->num_teids; i++)
        index_u32(by_teid, ue->teids[i], ue);
    for (i = 0; i < ue->num_seids; i++)
        index_u64(by_seid, ue->seids[i], ue);
    for (i = 0; i < ue->num_enb; i++)
        index_u32(by_enb, ue->enb_ue_s1ap_ids[i], ue);
    for (i = 0; i < ue->num_mme; i++)
        index_u32(by_mme, ue->mme_ue_s1ap_ids[i], ue);
}

int ptrace_correlate_init(void)
{
    ogs_list_init(&ue_list);
    by_imsi = ogs_hash_make();
    by_msisdn = ogs_hash_make();
    by_imei = ogs_hash_make();
    by_guti = ogs_hash_make();
    by_mtmsi = ogs_hash_make();
    by_ueip = ogs_hash_make();
    by_teid = ogs_hash_make();
    by_seid = ogs_hash_make();
    by_enb = ogs_hash_make();
    by_mme = ogs_hash_make();
    ogs_thread_mutex_init(&lock);
    ready = true;
    return OGS_OK;
}

void ptrace_correlate_final(void)
{
    ptrace_ue_t *ue, *next;
    if (!ready)
        return;
    ogs_thread_mutex_lock(&lock);
    for (ue = ogs_list_first(&ue_list); ue; ue = next) {
        next = ogs_list_next(ue);
        ogs_list_remove(&ue_list, ue);
        ogs_free(ue);
    }
    ogs_hash_destroy(by_imsi);
    ogs_hash_destroy(by_msisdn);
    ogs_hash_destroy(by_imei);
    ogs_hash_destroy(by_guti);
    ogs_hash_destroy(by_mtmsi);
    ogs_hash_destroy(by_ueip);
    ogs_hash_destroy(by_teid);
    ogs_hash_destroy(by_seid);
    ogs_hash_destroy(by_enb);
    ogs_hash_destroy(by_mme);
    ogs_thread_mutex_unlock(&lock);
    ogs_thread_mutex_destroy(&lock);
    ready = false;
}

uint64_t ptrace_correlate_event(ptrace_event_t *evt)
{
    ptrace_ue_t *ue = NULL;
    ptrace_ids_t *ids;

    if (!evt || !ready)
        return 0;
    ids = &evt->ids;

    ogs_thread_mutex_lock(&lock);

    if (ids->imsi[0])
        ue = lookup_str(by_imsi, ids->imsi);
    if (!ue && ids->msisdn[0])
        ue = lookup_str(by_msisdn, ids->msisdn);
    if (!ue && ids->imei[0])
        ue = lookup_str(by_imei, ids->imei);
    if (!ue && ids->guti[0])
        ue = lookup_str(by_guti, ids->guti);
    if (!ue && ids->m_tmsi[0])
        ue = lookup_str(by_mtmsi, ids->m_tmsi);
    if (!ue && ids->ue_ip[0])
        ue = lookup_str(by_ueip, ids->ue_ip);
    if (!ue && ids->has_teid)
        ue = lookup_u32(by_teid, ids->teid);
    if (!ue && ids->has_seid)
        ue = lookup_u64(by_seid, ids->seid);
    if (!ue && ids->has_enb_ue_s1ap_id)
        ue = lookup_u32(by_enb, ids->enb_ue_s1ap_id);
    if (!ue && ids->has_mme_ue_s1ap_id)
        ue = lookup_u32(by_mme, ids->mme_ue_s1ap_id);

    if (!ue) {
        /* Only create a UE when we have at least one strong identifier */
        if (ids->imsi[0] || ids->msisdn[0] || ids->guti[0] ||
                ids->ue_ip[0] || ids->has_teid || ids->has_seid ||
                ids->has_enb_ue_s1ap_id || ids->has_mme_ue_s1ap_id)
            ue = ue_new();
    }

    if (ue) {
        ue_merge_ids(ue, ids);
        ue_reindex(ue);
        evt->ue_id = ue->ue_id;
    }

    ogs_thread_mutex_unlock(&lock);
    return evt->ue_id;
}

ptrace_ue_t *ptrace_correlate_find(const char *key)
{
    ptrace_ue_t *ue = NULL;
    uint32_t u32;
    uint64_t u64;

    if (!key || !key[0] || !ready)
        return NULL;

    ogs_thread_mutex_lock(&lock);
    ue = lookup_str(by_imsi, key);
    if (!ue) ue = lookup_str(by_msisdn, key);
    if (!ue) ue = lookup_str(by_imei, key);
    if (!ue) ue = lookup_str(by_guti, key);
    if (!ue) ue = lookup_str(by_mtmsi, key);
    if (!ue) ue = lookup_str(by_ueip, key);
    if (!ue && sscanf(key, "%u", &u32) == 1) {
        ue = lookup_u32(by_teid, u32);
        if (!ue) ue = lookup_u32(by_enb, u32);
        if (!ue) ue = lookup_u32(by_mme, u32);
    }
    if (!ue && sscanf(key, "%llu", (unsigned long long *)&u64) == 1)
        ue = lookup_u64(by_seid, u64);
    ogs_thread_mutex_unlock(&lock);
    return ue;
}

int ptrace_correlate_ue_json(ptrace_ue_t *ue, char *buf, size_t buflen)
{
    int n, i;
    size_t off = 0;
    if (!ue || !buf || !buflen)
        return 0;

    n = snprintf(buf + off, buflen - off,
            "{\"ue_id\":%llu,\"imsi\":\"%s\",\"msisdn\":\"%s\","
            "\"imei\":\"%s\",\"guti\":\"%s\",\"m_tmsi\":\"%s\",\"apn\":\"%s\","
            "\"ue_ips\":[",
            (unsigned long long)ue->ue_id, ue->imsi, ue->msisdn, ue->imei,
            ue->guti, ue->m_tmsi, ue->apn);
    if (n < 0) return 0;
    off += (size_t)n;
    for (i = 0; i < ue->num_ue_ips && off < buflen; i++) {
        n = snprintf(buf + off, buflen - off, "%s\"%s\"",
                i ? "," : "", ue->ue_ips[i]);
        if (n < 0) break;
        off += (size_t)n;
    }
    n = snprintf(buf + off, buflen - off, "],\"teids\":[");
    if (n > 0) off += (size_t)n;
    for (i = 0; i < ue->num_teids && off < buflen; i++) {
        n = snprintf(buf + off, buflen - off, "%s%u",
                i ? "," : "", ue->teids[i]);
        if (n < 0) break;
        off += (size_t)n;
    }
    n = snprintf(buf + off, buflen - off, "],\"seids\":[");
    if (n > 0) off += (size_t)n;
    for (i = 0; i < ue->num_seids && off < buflen; i++) {
        n = snprintf(buf + off, buflen - off, "%s%llu",
                i ? "," : "", (unsigned long long)ue->seids[i]);
        if (n < 0) break;
        off += (size_t)n;
    }
    n = snprintf(buf + off, buflen - off, "]}\n");
    if (n > 0) off += (size_t)n;
    return (int)off;
}
