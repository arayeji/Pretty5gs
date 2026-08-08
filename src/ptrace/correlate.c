/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Thin facade over active trace targets (no global UE hash table).
 */

#include "correlate.h"
#include "target.h"
#include "context.h"

int ptrace_correlate_init(void)
{
    return ptrace_target_init();
}

void ptrace_correlate_final(void)
{
    ptrace_target_final();
}

uint64_t ptrace_correlate_event(ptrace_event_t *evt)
{
    uint64_t id;

    if (!evt)
        return 0;
    id = ptrace_target_match_learn(&evt->ids, evt->ts);
    evt->ue_id = id;
    return id;
}

ptrace_ue_t *ptrace_correlate_find(const char *key)
{
    ptrace_target_t *t = ptrace_target_find(key);
    return ptrace_target_ue(t);
}

int ptrace_correlate_ue_count(void)
{
    return ptrace_target_count();
}

int ptrace_correlate_expire(void)
{
    return ptrace_target_expire();
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
            "\"target\":true,\"ue_ips\":[",
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
