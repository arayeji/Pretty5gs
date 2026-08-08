/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "correlate.h"
#include "context.h"
#include "cache.h"

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
static ogs_hash_t *by_session;
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
    int i, t;
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
    /* Prefer full TEID set from the message; fall back to scalar. */
    if (ids->num_teids > 0) {
        for (t = 0; t < ids->num_teids; t++) {
            uint32_t teid = ids->teids[t];
            for (i = 0; i < ue->num_teids; i++)
                if (ue->teids[i] == teid)
                    break;
            if (i == ue->num_teids && ue->num_teids < PTRACE_MAX_UE_TEIDS)
                ue->teids[ue->num_teids++] = teid;
        }
    } else if (ids->has_teid) {
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
    if (ids->session_id[0]) {
        for (i = 0; i < ue->num_sessions; i++)
            if (!strcmp(ue->sessions[i], ids->session_id))
                break;
        if (i == ue->num_sessions &&
                ue->num_sessions < PTRACE_MAX_UE_SESSIONS)
            ogs_cpystrn(ue->sessions[ue->num_sessions++], ids->session_id,
                    sizeof(ue->sessions[0]));
    }
    ue->last_seen = ogs_time_now();
}

/* Fold drop into keep so S1AP-only and GTP/Diameter roots become one UE. */
static void ue_absorb(ptrace_ue_t *keep, ptrace_ue_t *drop)
{
    ptrace_ids_t ids;
    int i;

    if (!keep || !drop || keep == drop)
        return;

    memset(&ids, 0, sizeof(ids));
    ogs_cpystrn(ids.imsi, drop->imsi, sizeof(ids.imsi));
    ogs_cpystrn(ids.msisdn, drop->msisdn, sizeof(ids.msisdn));
    ogs_cpystrn(ids.imei, drop->imei, sizeof(ids.imei));
    ogs_cpystrn(ids.guti, drop->guti, sizeof(ids.guti));
    ogs_cpystrn(ids.m_tmsi, drop->m_tmsi, sizeof(ids.m_tmsi));
    ogs_cpystrn(ids.apn, drop->apn, sizeof(ids.apn));
    if (drop->num_ue_ips > 0)
        ogs_cpystrn(ids.ue_ip, drop->ue_ips[0], sizeof(ids.ue_ip));
    for (i = 0; i < drop->num_teids && i < PTRACE_MAX_UE_TEIDS; i++)
        ids.teids[ids.num_teids++] = drop->teids[i];
    if (ids.num_teids > 0) {
        ids.teid = ids.teids[0];
        ids.has_teid = true;
    }
    for (i = 0; i < drop->num_seids && i < 1; i++) {
        ids.seid = drop->seids[i];
        ids.has_seid = true;
    }
    if (drop->num_enb > 0) {
        ids.enb_ue_s1ap_id = drop->enb_ue_s1ap_ids[0];
        ids.has_enb_ue_s1ap_id = true;
    }
    if (drop->num_mme > 0) {
        ids.mme_ue_s1ap_id = drop->mme_ue_s1ap_ids[0];
        ids.has_mme_ue_s1ap_id = true;
    }
    if (drop->num_tac > 0) {
        ids.tac = drop->tacs[0];
        ids.has_tac = true;
    }
    ue_merge_ids(keep, &ids);
    /* Remaining TEIDs / S1AP IDs / IPs beyond the first */
    for (i = 1; i < drop->num_ue_ips; i++) {
        ptrace_ids_t one;
        memset(&one, 0, sizeof(one));
        ogs_cpystrn(one.ue_ip, drop->ue_ips[i], sizeof(one.ue_ip));
        ue_merge_ids(keep, &one);
    }
    for (i = 1; i < drop->num_enb; i++) {
        ptrace_ids_t one;
        memset(&one, 0, sizeof(one));
        one.enb_ue_s1ap_id = drop->enb_ue_s1ap_ids[i];
        one.has_enb_ue_s1ap_id = true;
        ue_merge_ids(keep, &one);
    }
    for (i = 1; i < drop->num_mme; i++) {
        ptrace_ids_t one;
        memset(&one, 0, sizeof(one));
        one.mme_ue_s1ap_id = drop->mme_ue_s1ap_ids[i];
        one.has_mme_ue_s1ap_id = true;
        ue_merge_ids(keep, &one);
    }
    for (i = 1; i < drop->num_seids; i++) {
        ptrace_ids_t one;
        memset(&one, 0, sizeof(one));
        one.seid = drop->seids[i];
        one.has_seid = true;
        ue_merge_ids(keep, &one);
    }
    for (i = 0; i < drop->num_sessions; i++) {
        ptrace_ids_t one;
        memset(&one, 0, sizeof(one));
        ogs_cpystrn(one.session_id, drop->sessions[i], sizeof(one.session_id));
        ue_merge_ids(keep, &one);
    }

    /* Cached events still carry the absorbed ue_id — retarget them. */
    ptrace_cache_remap_ue(drop->ue_id, keep->ue_id);

    ogs_list_remove(&ue_list, drop);
    ogs_free(drop);
}

static void consider_ue(ptrace_ue_t **cands, int *nc, ptrace_ue_t *ue)
{
    int i;
    if (!ue || *nc >= 8)
        return;
    for (i = 0; i < *nc; i++) {
        if (cands[i] == ue)
            return;
    }
    cands[(*nc)++] = ue;
}

static ptrace_ue_t *prefer_ue(ptrace_ue_t **cands, int nc)
{
    int i;
    ptrace_ue_t *best = NULL;
    if (nc <= 0)
        return NULL;
    best = cands[0];
    for (i = 1; i < nc; i++) {
        if (cands[i]->imsi[0] && !best->imsi[0])
            best = cands[i];
        else if (cands[i]->imsi[0] && best->imsi[0] &&
                cands[i]->ue_id < best->ue_id)
            best = cands[i];
        else if (!best->imsi[0] && cands[i]->ue_id < best->ue_id)
            best = cands[i];
    }
    return best;
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
    for (i = 0; i < ue->num_sessions; i++)
        index_str(by_session, ue->sessions[i], ue);
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
    by_session = ogs_hash_make();
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
    ogs_hash_destroy(by_session);
    ogs_thread_mutex_unlock(&lock);
    ogs_thread_mutex_destroy(&lock);
    ready = false;
}

uint64_t ptrace_correlate_event(ptrace_event_t *evt)
{
    ptrace_ue_t *ue = NULL;
    ptrace_ue_t *cands[8];
    ptrace_ids_t *ids;
    int nc = 0;
    int i;

    if (!evt || !ready)
        return 0;
    ids = &evt->ids;

    ogs_thread_mutex_lock(&lock);

    /* Collect every UE that already owns any identity on this message,
     * then absorb duplicates so attach S1AP + GTP-C + Diameter share one root. */
    consider_ue(cands, &nc, lookup_str(by_imsi, ids->imsi));
    consider_ue(cands, &nc, lookup_str(by_msisdn, ids->msisdn));
    consider_ue(cands, &nc, lookup_str(by_imei, ids->imei));
    consider_ue(cands, &nc, lookup_str(by_guti, ids->guti));
    consider_ue(cands, &nc, lookup_str(by_mtmsi, ids->m_tmsi));
    consider_ue(cands, &nc, lookup_str(by_ueip, ids->ue_ip));
    if (ids->num_teids > 0) {
        for (i = 0; i < ids->num_teids; i++)
            consider_ue(cands, &nc, lookup_u32(by_teid, ids->teids[i]));
    } else if (ids->has_teid) {
        consider_ue(cands, &nc, lookup_u32(by_teid, ids->teid));
    }
    if (ids->has_seid)
        consider_ue(cands, &nc, lookup_u64(by_seid, ids->seid));
    if (ids->has_enb_ue_s1ap_id)
        consider_ue(cands, &nc, lookup_u32(by_enb, ids->enb_ue_s1ap_id));
    if (ids->has_mme_ue_s1ap_id)
        consider_ue(cands, &nc, lookup_u32(by_mme, ids->mme_ue_s1ap_id));
    consider_ue(cands, &nc, lookup_str(by_session, ids->session_id));

    ue = prefer_ue(cands, nc);
    if (ue && nc > 1) {
        for (i = 0; i < nc; i++) {
            if (cands[i] != ue)
                ue_absorb(ue, cands[i]);
        }
    }

    if (!ue) {
        /* Create on subscriber / tunnel / S1AP keys. Session-Id alone
         * only looks up (so AIA/ULA attach to the AIR/ULR UE). */
        if (ids->imsi[0] || ids->msisdn[0] || ids->guti[0] ||
                ids->ue_ip[0] || ids->has_teid || ids->has_seid ||
                ids->has_enb_ue_s1ap_id || ids->has_mme_ue_s1ap_id)
            ue = ue_new();
    }

    if (ue) {
        ue_merge_ids(ue, ids);
        ue_reindex(ue);
        evt->ue_id = ue->ue_id;
        /* Stamp subscriber IDs onto the event so export/timeline
         * still match after the packet itself omitted them (AIA/ULA). */
        if (ue->imsi[0] && !ids->imsi[0])
            ogs_cpystrn(ids->imsi, ue->imsi, sizeof(ids->imsi));
        if (ue->msisdn[0] && !ids->msisdn[0])
            ogs_cpystrn(ids->msisdn, ue->msisdn, sizeof(ids->msisdn));
        if (ue->imei[0] && !ids->imei[0])
            ogs_cpystrn(ids->imei, ue->imei, sizeof(ids->imei));
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
    n = snprintf(buf + off, buflen - off, "],\"enb_ue_s1ap_ids\":[");
    if (n > 0) off += (size_t)n;
    for (i = 0; i < ue->num_enb && off < buflen; i++) {
        n = snprintf(buf + off, buflen - off, "%s%u",
                i ? "," : "", ue->enb_ue_s1ap_ids[i]);
        if (n < 0) break;
        off += (size_t)n;
    }
    n = snprintf(buf + off, buflen - off, "],\"mme_ue_s1ap_ids\":[");
    if (n > 0) off += (size_t)n;
    for (i = 0; i < ue->num_mme && off < buflen; i++) {
        n = snprintf(buf + off, buflen - off, "%s%u",
                i ? "," : "", ue->mme_ue_s1ap_ids[i]);
        if (n < 0) break;
        off += (size_t)n;
    }
    n = snprintf(buf + off, buflen - off, "],\"sessions\":[");
    if (n > 0) off += (size_t)n;
    for (i = 0; i < ue->num_sessions && off < buflen; i++) {
        n = snprintf(buf + off, buflen - off, "%s\"%s\"",
                i ? "," : "", ue->sessions[i]);
        if (n < 0) break;
        off += (size_t)n;
    }
    n = snprintf(buf + off, buflen - off, "]}\n");
    if (n > 0) off += (size_t)n;
    return (int)off;
}

bool ptrace_correlate_event_matches_ue(const ptrace_event_t *evt,
        const ptrace_ue_t *ue)
{
    int i, j;
    const ptrace_ids_t *ids;

    if (!evt || !ue)
        return false;
    ids = &evt->ids;

    if (evt->ue_id && evt->ue_id == ue->ue_id)
        return true;
    if (ids->imsi[0] && ue->imsi[0] && !strcmp(ids->imsi, ue->imsi))
        return true;
    if (ids->msisdn[0] && ue->msisdn[0] && !strcmp(ids->msisdn, ue->msisdn))
        return true;
    if (ids->imei[0] && ue->imei[0] && !strcmp(ids->imei, ue->imei))
        return true;
    if (ids->guti[0] && ue->guti[0] && !strcmp(ids->guti, ue->guti))
        return true;
    if (ids->m_tmsi[0] && ue->m_tmsi[0] && !strcmp(ids->m_tmsi, ue->m_tmsi))
        return true;
    if (ids->ue_ip[0]) {
        for (i = 0; i < ue->num_ue_ips; i++)
            if (!strcmp(ids->ue_ip, ue->ue_ips[i]))
                return true;
    }
    if (ids->session_id[0]) {
        for (i = 0; i < ue->num_sessions; i++)
            if (!strcmp(ids->session_id, ue->sessions[i]))
                return true;
    }
    if (ids->num_teids > 0) {
        for (j = 0; j < ids->num_teids; j++) {
            for (i = 0; i < ue->num_teids; i++)
                if (ids->teids[j] && ids->teids[j] == ue->teids[i])
                    return true;
        }
    } else if (ids->has_teid && ids->teid) {
        for (i = 0; i < ue->num_teids; i++)
            if (ids->teid == ue->teids[i])
                return true;
    }
    if (ids->has_seid) {
        for (i = 0; i < ue->num_seids; i++)
            if (ids->seid == ue->seids[i])
                return true;
    }
    if (ids->has_enb_ue_s1ap_id) {
        for (i = 0; i < ue->num_enb; i++)
            if (ids->enb_ue_s1ap_id == ue->enb_ue_s1ap_ids[i])
                return true;
    }
    if (ids->has_mme_ue_s1ap_id) {
        for (i = 0; i < ue->num_mme; i++)
            if (ids->mme_ue_s1ap_id == ue->mme_ue_s1ap_ids[i])
                return true;
    }
    return false;
}
