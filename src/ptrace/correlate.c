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
static ogs_hash_t *by_hbh;
static ogs_thread_mutex_t lock;
static bool ready;
static uint64_t next_pdn_id = 1;

static ptrace_ue_t *ue_resolve(ptrace_ue_t *ue)
{
    int guard = 0;
    while (ue && ue->canonical && guard++ < 8)
        ue = ue->canonical;
    return ue;
}

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
    return ue_resolve(ogs_hash_get(h, key, OGS_HASH_KEY_STRING));
}

static ptrace_ue_t *lookup_u32(ogs_hash_t *h, uint32_t key)
{
    return ue_resolve(ogs_hash_get(h, &key, sizeof(key)));
}

static ptrace_ue_t *lookup_u64(ogs_hash_t *h, uint64_t key)
{
    return ue_resolve(ogs_hash_get(h, &key, sizeof(key)));
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
    if (ids->has_enb_ue_s1ap_id && ue->num_enb < 8) {
        for (i = 0; i < ue->num_enb; i++)
            if (ue->enb_ue_s1ap_ids[i] == ids->enb_ue_s1ap_id)
                break;
        if (i == ue->num_enb)
            ue->enb_ue_s1ap_ids[ue->num_enb++] = ids->enb_ue_s1ap_id;
        /* Newest S1AP ID first — reattach must win over stale IDs. */
        if (ue->enb_ue_s1ap_ids[0] != ids->enb_ue_s1ap_id) {
            for (i = 0; i < ue->num_enb; i++) {
                if (ue->enb_ue_s1ap_ids[i] == ids->enb_ue_s1ap_id) {
                    uint32_t tmp = ue->enb_ue_s1ap_ids[0];
                    ue->enb_ue_s1ap_ids[0] = ids->enb_ue_s1ap_id;
                    ue->enb_ue_s1ap_ids[i] = tmp;
                    break;
                }
            }
        }
    }
    if (ids->has_mme_ue_s1ap_id && ue->num_mme < 8) {
        for (i = 0; i < ue->num_mme; i++)
            if (ue->mme_ue_s1ap_ids[i] == ids->mme_ue_s1ap_id)
                break;
        if (i == ue->num_mme)
            ue->mme_ue_s1ap_ids[ue->num_mme++] = ids->mme_ue_s1ap_id;
        if (ue->mme_ue_s1ap_ids[0] != ids->mme_ue_s1ap_id) {
            for (i = 0; i < ue->num_mme; i++) {
                if (ue->mme_ue_s1ap_ids[i] == ids->mme_ue_s1ap_id) {
                    uint32_t tmp = ue->mme_ue_s1ap_ids[0];
                    ue->mme_ue_s1ap_ids[0] = ids->mme_ue_s1ap_id;
                    ue->mme_ue_s1ap_ids[i] = tmp;
                    break;
                }
            }
        }
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

static const char *sess_state_str(ptrace_sess_state_e s)
{
    switch (s) {
    case PTRACE_SESS_ACTIVE: return "active";
    case PTRACE_SESS_STALE: return "stale";
    default: return "released";
    }
}

static void pdn_add_teid(ptrace_pdn_sess_t *s, uint32_t teid)
{
    int i;
    if (!s || !teid)
        return;
    for (i = 0; i < s->num_teids; i++)
        if (s->teids[i] == teid)
            return;
    if (s->num_teids < 8)
        s->teids[s->num_teids++] = teid;
}

static void pdn_add_seid(ptrace_pdn_sess_t *s, uint64_t seid)
{
    int i;
    if (!s || !seid)
        return;
    for (i = 0; i < s->num_seids; i++)
        if (s->seids[i] == seid)
            return;
    if (s->num_seids < 4)
        s->seids[s->num_seids++] = seid;
}

static void ue_expire_pdn(ptrace_ue_t *ue)
{
    int i;
    ogs_time_t now = ogs_time_now();
    for (i = 0; i < ue->num_pdn; i++) {
        if (ue->pdn[i].state == PTRACE_SESS_STALE &&
                ue->pdn[i].stale_until && ue->pdn[i].stale_until < now)
            ue->pdn[i].state = PTRACE_SESS_RELEASED;
    }
}

static void ue_stale_active(ptrace_ue_t *ue)
{
    int i;
    ogs_time_t until = ogs_time_now() +
            ogs_time_from_sec(PTRACE_SESS_STALE_SEC);
    for (i = 0; i < ue->num_pdn; i++) {
        if (ue->pdn[i].state == PTRACE_SESS_ACTIVE) {
            ue->pdn[i].state = PTRACE_SESS_STALE;
            ue->pdn[i].stale_until = until;
        }
    }
}

static ptrace_pdn_sess_t *ue_new_pdn(ptrace_ue_t *ue)
{
    ptrace_pdn_sess_t *s;
    if (ue->num_pdn >= PTRACE_MAX_PDN_SESSIONS) {
        /* Drop oldest released, else oldest stale */
        int i, victim = 0;
        for (i = 0; i < ue->num_pdn; i++) {
            if (ue->pdn[i].state == PTRACE_SESS_RELEASED) {
                victim = i;
                break;
            }
            if (ue->pdn[i].state == PTRACE_SESS_STALE &&
                    ue->pdn[victim].state != PTRACE_SESS_STALE)
                victim = i;
            else if (ue->pdn[i].created < ue->pdn[victim].created)
                victim = i;
        }
        memmove(&ue->pdn[victim], &ue->pdn[victim + 1],
                (size_t)(ue->num_pdn - victim - 1) * sizeof(ue->pdn[0]));
        ue->num_pdn--;
    }
    s = &ue->pdn[ue->num_pdn++];
    memset(s, 0, sizeof(*s));
    s->id = next_pdn_id++;
    s->state = PTRACE_SESS_ACTIVE;
    s->created = s->last_seen = ogs_time_now();
    return s;
}

/* Pick / create PDN session: new eNB S1AP ID => re-attach (stale old).
 * Same APN active session is reused; new APN gets another active session. */
static void ue_touch_pdn(ptrace_ue_t *ue, const ptrace_ids_t *ids)
{
    ptrace_pdn_sess_t *s = NULL;
    int i, t;
    bool new_s1 = false;

    ue_expire_pdn(ue);

    if (ids->has_enb_ue_s1ap_id) {
        for (i = 0; i < ue->num_pdn; i++) {
            if (ue->pdn[i].state == PTRACE_SESS_ACTIVE &&
                    ue->pdn[i].has_enb &&
                    ue->pdn[i].enb_ue_s1ap_id == ids->enb_ue_s1ap_id) {
                s = &ue->pdn[i];
                break;
            }
        }
        if (!s) {
            /* Unknown eNB-UE-S1AP-ID on an attach-like message */
            new_s1 = true;
            for (i = 0; i < ue->num_pdn; i++) {
                if (ue->pdn[i].state == PTRACE_SESS_ACTIVE &&
                        ue->pdn[i].has_enb &&
                        ue->pdn[i].enb_ue_s1ap_id != ids->enb_ue_s1ap_id)
                    new_s1 = true;
            }
        }
    }

    if (!s && ids->apn[0]) {
        for (i = 0; i < ue->num_pdn; i++) {
            if (ue->pdn[i].state == PTRACE_SESS_ACTIVE &&
                    ue->pdn[i].apn[0] && !strcmp(ue->pdn[i].apn, ids->apn)) {
                s = &ue->pdn[i];
                break;
            }
        }
    }

    if (!s && !new_s1) {
        for (i = 0; i < ue->num_pdn; i++) {
            if (ue->pdn[i].state == PTRACE_SESS_ACTIVE) {
                s = &ue->pdn[i];
                break;
            }
        }
    }

    if (new_s1 && ids->has_enb_ue_s1ap_id) {
        ue_stale_active(ue);
        s = NULL;
    }

    if (!s && (ids->has_enb_ue_s1ap_id || ids->apn[0] ||
            ids->ue_ip[0] || ids->num_teids > 0 || ids->has_seid))
        s = ue_new_pdn(ue);

    if (!s)
        return;

    s->last_seen = ogs_time_now();
    if (ids->apn[0])
        ogs_cpystrn(s->apn, ids->apn, sizeof(s->apn));
    if (ids->ue_ip[0])
        ogs_cpystrn(s->ue_ip, ids->ue_ip, sizeof(s->ue_ip));
    if (ids->has_enb_ue_s1ap_id) {
        s->enb_ue_s1ap_id = ids->enb_ue_s1ap_id;
        s->has_enb = true;
    }
    if (ids->has_mme_ue_s1ap_id) {
        s->mme_ue_s1ap_id = ids->mme_ue_s1ap_id;
        s->has_mme = true;
    }
    if (ids->num_teids > 0) {
        for (t = 0; t < ids->num_teids; t++)
            pdn_add_teid(s, ids->teids[t]);
    } else if (ids->has_teid && ids->teid) {
        pdn_add_teid(s, ids->teid);
    }
    if (ids->has_seid)
        pdn_add_seid(s, ids->seid);
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
    /* Move PDN sessions from drop into keep (mark drop's as stale). */
    for (i = 0; i < drop->num_pdn && keep->num_pdn < PTRACE_MAX_PDN_SESSIONS;
            i++) {
        keep->pdn[keep->num_pdn] = drop->pdn[i];
        if (keep->pdn[keep->num_pdn].state == PTRACE_SESS_ACTIVE) {
            keep->pdn[keep->num_pdn].state = PTRACE_SESS_STALE;
            keep->pdn[keep->num_pdn].stale_until = ogs_time_now() +
                    ogs_time_from_sec(PTRACE_SESS_STALE_SEC);
        }
        keep->num_pdn++;
    }

    /* Cached events still carry the absorbed ue_id — retarget them. */
    ptrace_cache_remap_ue(drop->ue_id, keep->ue_id);

    /* Do not free drop: other threads may hold the pointer from find().
     * Leave it in the list as an alias that resolves to keep. */
    drop->canonical = keep;
}

static void consider_ue(ptrace_ue_t **cands, int *nc, ptrace_ue_t *ue)
{
    int i;
    ue = ue_resolve(ue);
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
    by_hbh = ogs_hash_make();
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
    ogs_hash_destroy(by_hbh);
    ogs_thread_mutex_unlock(&lock);
    ogs_thread_mutex_destroy(&lock);
    ready = false;
}

uint64_t ptrace_correlate_event(ptrace_event_t *evt)
{
    ptrace_ue_t *ue = NULL;
    ptrace_ue_t *imsi_ue = NULL;
    ptrace_ue_t *cands[8];
    ptrace_ids_t *ids;
    int nc = 0;
    int i;

    if (!evt || !ready)
        return 0;
    ids = &evt->ids;

    ogs_thread_mutex_lock(&lock);

    /* IMSI is authoritative — eNB/MME S1AP IDs are recycled and must not
     * glue a new subscriber onto an old UE that already has another IMSI. */
    if (ids->imsi[0])
        imsi_ue = ue_resolve(lookup_str(by_imsi, ids->imsi));

    consider_ue(cands, &nc, imsi_ue);
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
    if (ids->has_diam_hbh)
        consider_ue(cands, &nc, lookup_u32(by_hbh, ids->diam_hbh));

    /* Drop candidates whose IMSI conflicts with this message. */
    if (ids->imsi[0] && nc > 0) {
        int w = 0;
        for (i = 0; i < nc; i++) {
            if (cands[i]->imsi[0] && strcmp(cands[i]->imsi, ids->imsi))
                continue;
            cands[w++] = cands[i];
        }
        nc = w;
    }

    if (imsi_ue)
        ue = imsi_ue;
    else
        ue = prefer_ue(cands, nc);

    /* S1AP-only hit on a UE that already has a *different* IMSI → new root. */
    if (ids->imsi[0] && ue && ue->imsi[0] && strcmp(ue->imsi, ids->imsi))
        ue = NULL;

    if (ue && nc > 1) {
        for (i = 0; i < nc; i++) {
            if (cands[i] == ue)
                continue;
            /* Never absorb a UE that already has a conflicting IMSI. */
            if (ue->imsi[0] && cands[i]->imsi[0] &&
                    strcmp(ue->imsi, cands[i]->imsi))
                continue;
            if (ids->imsi[0] && cands[i]->imsi[0] &&
                    strcmp(ids->imsi, cands[i]->imsi))
                continue;
            ue_absorb(ue, cands[i]);
        }
    }

    if (!ue) {
        /* Create only on subscriber identity. Tunnel IDs alone recycled
         * and exploded ue_count under S1 storms. */
        if (ids->imsi[0] || ids->msisdn[0] || ids->guti[0] || ids->imei[0] ||
                ids->session_id[0])
            ue = ue_new();
    }

    if (ue) {
        ue_merge_ids(ue, ids);
        /* Always bind this message's IMSI if present (new root or empty). */
        if (ids->imsi[0] && !ue->imsi[0])
            ogs_cpystrn(ue->imsi, ids->imsi, sizeof(ue->imsi));
        ue->last_seen = ogs_time_now();
        ue_touch_pdn(ue, ids);
        if (ids->has_diam_hbh)
            index_u32(by_hbh, ids->diam_hbh, ue);
        ue_reindex(ue);
        evt->ue_id = ue->ue_id;
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
    char digits[PTRACE_MAX_ID_LEN];
    int i, o = 0;

    if (!key || !key[0] || !ready)
        return NULL;

    /* Normalize IMSI/MSISDN-like keys to digits (NMS may send spaces). */
    for (i = 0; key[i] && o + 1 < (int)sizeof(digits); i++) {
        if (key[i] >= '0' && key[i] <= '9')
            digits[o++] = key[i];
    }
    digits[o] = '\0';

    ogs_thread_mutex_lock(&lock);
    if (digits[0])
        ue = lookup_str(by_imsi, digits);
    if (!ue) ue = lookup_str(by_imsi, key);
    if (!ue) ue = lookup_str(by_msisdn, digits[0] ? digits : key);
    if (!ue) ue = lookup_str(by_imei, digits[0] ? digits : key);
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
    ue = ue_resolve(ue);
    ogs_thread_mutex_unlock(&lock);
    return ue;
}

int ptrace_correlate_ue_count(void)
{
    ptrace_ue_t *ue;
    int n = 0;
    if (!ready)
        return 0;
    ogs_thread_mutex_lock(&lock);
    ogs_list_for_each(&ue_list, ue) {
        if (!ue->canonical)
            n++;
    }
    ogs_thread_mutex_unlock(&lock);
    return n;
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
    n = snprintf(buf + off, buflen - off, "],\"pdn_sessions\":[");
    if (n > 0) off += (size_t)n;
    {
        int first = 1, j;
        for (i = 0; i < ue->num_pdn && off < buflen; i++) {
            ptrace_pdn_sess_t *s = &ue->pdn[i];
            if (s->state == PTRACE_SESS_RELEASED)
                continue;
            n = snprintf(buf + off, buflen - off,
                    "%s{\"id\":%llu,\"state\":\"%s\",\"apn\":\"%s\","
                    "\"ue_ip\":\"%s\",\"enb_ue_s1ap_id\":%u,"
                    "\"mme_ue_s1ap_id\":%u,\"teids\":[",
                    first ? "" : ",",
                    (unsigned long long)s->id, sess_state_str(s->state),
                    s->apn, s->ue_ip,
                    s->has_enb ? s->enb_ue_s1ap_id : 0,
                    s->has_mme ? s->mme_ue_s1ap_id : 0);
            if (n < 0) break;
            off += (size_t)n;
            for (j = 0; j < s->num_teids && off < buflen; j++) {
                n = snprintf(buf + off, buflen - off, "%s%u",
                        j ? "," : "", s->teids[j]);
                if (n < 0) break;
                off += (size_t)n;
            }
            n = snprintf(buf + off, buflen - off, "],\"seids\":[");
            if (n > 0) off += (size_t)n;
            for (j = 0; j < s->num_seids && off < buflen; j++) {
                n = snprintf(buf + off, buflen - off, "%s%llu",
                        j ? "," : "", (unsigned long long)s->seids[j]);
                if (n < 0) break;
                off += (size_t)n;
            }
            n = snprintf(buf + off, buflen - off, "]}");
            if (n > 0) off += (size_t)n;
            first = 0;
        }
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

static void unindex_str(ogs_hash_t *h, const char *key)
{
    if (!key || !key[0])
        return;
    ogs_hash_set(h, key, OGS_HASH_KEY_STRING, NULL);
}

static void unindex_u32(ogs_hash_t *h, uint32_t key)
{
    ogs_hash_set(h, &key, sizeof(key), NULL);
}

static void unindex_u64(ogs_hash_t *h, uint64_t key)
{
    ogs_hash_set(h, &key, sizeof(key), NULL);
}

static void ue_unindex(ptrace_ue_t *ue)
{
    int i;
    if (!ue)
        return;
    unindex_str(by_imsi, ue->imsi);
    unindex_str(by_msisdn, ue->msisdn);
    unindex_str(by_imei, ue->imei);
    unindex_str(by_guti, ue->guti);
    unindex_str(by_mtmsi, ue->m_tmsi);
    for (i = 0; i < ue->num_ue_ips; i++)
        unindex_str(by_ueip, ue->ue_ips[i]);
    for (i = 0; i < ue->num_teids; i++)
        unindex_u32(by_teid, ue->teids[i]);
    for (i = 0; i < ue->num_seids; i++)
        unindex_u64(by_seid, ue->seids[i]);
    for (i = 0; i < ue->num_enb; i++)
        unindex_u32(by_enb, ue->enb_ue_s1ap_ids[i]);
    for (i = 0; i < ue->num_mme; i++)
        unindex_u32(by_mme, ue->mme_ue_s1ap_ids[i]);
    for (i = 0; i < ue->num_sessions; i++)
        unindex_str(by_session, ue->sessions[i]);
}

int ptrace_correlate_expire(void)
{
    ptrace_ue_t *ue, *next;
    ogs_time_t now;
    ogs_time_t no_imsi_cut;
    ogs_time_t idle_cut;
    int removed = 0;

    if (!ready)
        return 0;

    now = ogs_time_now();
    no_imsi_cut = now - ogs_time_from_sec(PTRACE_UE_NO_IMSI_IDLE_SEC);
    idle_cut = now - ogs_time_from_sec(PTRACE_UE_IDLE_SEC);

    ogs_thread_mutex_lock(&lock);
    for (ue = ogs_list_first(&ue_list); ue; ue = next) {
        next = ogs_list_next(ue);
        if (ue->canonical)
            continue;
        /* Skip pinned without taking cache lock under correlate lock —
         * collect candidates first would be safer; short pin check is OK
         * if cache never takes correlate lock (it does not). */
        if (!ue->imsi[0] && ue->last_seen < no_imsi_cut) {
            if (ptrace_cache_ue_is_pinned(ue->ue_id))
                continue;
            ue_unindex(ue);
            ogs_list_remove(&ue_list, ue);
            ogs_free(ue);
            removed++;
            continue;
        }
        if (ue->imsi[0] && ue->last_seen < idle_cut) {
            if (ptrace_cache_ue_is_pinned(ue->ue_id))
                continue;
            ue_unindex(ue);
            ogs_list_remove(&ue_list, ue);
            ogs_free(ue);
            removed++;
        }
    }
    ogs_thread_mutex_unlock(&lock);
    return removed;
}
