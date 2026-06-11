/*
 * Copyright (C) 2026 by Open5GS Contributors
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "collision-replace.h"

#include "gtp-path.h"
#include "pfcp-path.h"
#include "smf-sm.h"
#include "smf-trace.h"

static void smf_ue_collision_clear(smf_ue_t *smf_ue)
{
    ogs_assert(smf_ue);

    if (smf_ue->collision_replace.pkbuf) {
        ogs_pkbuf_free(smf_ue->collision_replace.pkbuf);
        smf_ue->collision_replace.pkbuf = NULL;
    }

    memset(&smf_ue->collision_replace, 0, sizeof(smf_ue->collision_replace));
}

bool smf_sess_upf_established(smf_sess_t *sess)
{
    ogs_assert(sess);

    if (!sess->pfcp_node)
        return false;

    return sess->upf_n4_seid != 0;
}

smf_sess_t *smf_sess_find_collision_for_gtp2(ogs_gtp2_message_t *message)
{
    smf_ue_t *smf_ue = NULL;
    smf_sess_t *sess = NULL;
    char apn[OGS_MAX_APN_LEN+1];
    char *full_apn = NULL;

    ogs_gtp2_create_session_request_t *req = NULL;

    ogs_assert(message);
    req = &message->create_session_request;

    if (req->imsi.presence == 0 ||
            req->access_point_name.presence == 0 ||
            req->rat_type.presence == 0)
        return NULL;

    if (!smf_gtp_apn_parse(apn, &full_apn, req->access_point_name.data,
                req->access_point_name.len)) {
        ogs_free(full_apn);
        return NULL;
    }
    ogs_free(full_apn);

    smf_ue = smf_ue_find_by_imsi(req->imsi.data, req->imsi.len);
    if (!smf_ue)
        return NULL;

    sess = smf_sess_find_by_apn(smf_ue, apn, req->rat_type.u8);
    return sess;
}

smf_sess_t *smf_sess_find_collision_for_gtp1(ogs_gtp1_message_t *message)
{
    smf_ue_t *smf_ue = NULL;
    smf_sess_t *sess = NULL;
    char apn[OGS_MAX_APN_LEN+1];
    char *full_apn = NULL;

    ogs_gtp1_create_pdp_context_request_t *req = NULL;

    ogs_assert(message);
    req = &message->create_pdp_context_request;

    if (req->imsi.presence == 0 ||
            req->access_point_name.presence == 0 ||
            req->rat_type.presence == 0)
        return NULL;

    if (!smf_gtp_apn_parse(apn, &full_apn, req->access_point_name.data,
                req->access_point_name.len)) {
        ogs_free(full_apn);
        return NULL;
    }
    ogs_free(full_apn);

    smf_ue = smf_ue_find_by_imsi(req->imsi.data, req->imsi.len);
    if (!smf_ue)
        return NULL;

    sess = smf_sess_find_by_apn(smf_ue, apn, req->rat_type.u8);
    return sess;
}

static bool smf_sess_collision_replace_begin(
        smf_sess_t *old_sess, smf_ue_t *smf_ue, smf_event_t *e,
        bool gtp2, ogs_gtp2_sender_f_teid_t *sender_f_teid)
{
    ogs_pkbuf_t *pkbuf_copy = NULL;

    ogs_assert(old_sess);
    ogs_assert(smf_ue);
    ogs_assert(e);
    ogs_assert(e->pkbuf);

    if (smf_ue->collision_replace.pending) {
        ogs_gtp_xact_t *gtp_xact = NULL;

        ogs_error("[%s] Create while collision replace already pending",
                smf_ue->imsi_bcd);
        gtp_xact = ogs_gtp_xact_find_by_id(e->gtp_xact_id);
        if (gtp_xact) {
            if (gtp2) {
                ogs_gtp2_send_error_message(gtp_xact,
                        sender_f_teid && sender_f_teid->teid_presence ?
                            sender_f_teid->teid : 0,
                        OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
                        OGS_GTP2_CAUSE_SYSTEM_FAILURE);
            } else {
                ogs_gtp1_send_error_message(gtp_xact, 0,
                        OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE,
                        OGS_GTP1_CAUSE_SYSTEM_FAILURE);
            }
        }
        return true;
    }

    pkbuf_copy = ogs_pkbuf_copy(e->pkbuf);
    if (!pkbuf_copy) {
        ogs_error("[%s] ogs_pkbuf_copy() failed for collision replace",
                smf_ue->imsi_bcd);
        return false;
    }

    smf_ue->collision_replace.pending = true;
    smf_ue->collision_replace.gtp2 = gtp2;
    smf_ue->collision_replace.pkbuf = pkbuf_copy;
    smf_ue->collision_replace.gtp_xact_id = e->gtp_xact_id;
    smf_ue->collision_replace.gtp_node = e->gnode ? e->gnode->gnode : NULL;
    smf_ue->collision_replace.peer_teid_presence = false;
    smf_ue->collision_replace.peer_teid = 0;

    if (gtp2 && sender_f_teid &&
            sender_f_teid->teid_presence == true) {
        smf_ue->collision_replace.peer_teid_presence = true;
        smf_ue->collision_replace.peer_teid = sender_f_teid->teid;
    }

    old_sess->collision_replace = true;

    char buf4[OGS_ADDRSTRLEN];

    ogs_info("[%s] OLD Session collision replace DNN:%s IPv4:%s "
            "(UPF SEID=0x%llx): best-effort PFCP delete, proceeding",
            smf_ue->imsi_bcd,
            old_sess->session.name ? old_sess->session.name : "-",
            old_sess->ipv4 ?
                OGS_INET_NTOP(&old_sess->ipv4->addr, buf4) : "-",
            (unsigned long long)old_sess->upf_n4_seid);

    smf_epc_pfcp_send_session_deletion_best_effort(old_sess);
    smf_sess_collision_replace_complete(old_sess);

    return true;
}

bool smf_sess_collision_replace_begin_gtp2(
        smf_sess_t *old_sess, smf_event_t *e,
        ogs_gtp2_sender_f_teid_t *sender_f_teid)
{
    smf_ue_t *smf_ue = NULL;

    old_sess = smf_sess_find_active_by_id(old_sess ? old_sess->id :
            OGS_INVALID_POOL_ID);
    if (!old_sess)
        return false;

    smf_ue = smf_ue_find_active(old_sess->smf_ue_id);
    if (!smf_ue)
        return false;

    if (!smf_sess_upf_established(old_sess))
        return false;

    return smf_sess_collision_replace_begin(
            old_sess, smf_ue, e, true, sender_f_teid);
}

bool smf_sess_collision_replace_begin_gtp1(
        smf_sess_t *old_sess, smf_event_t *e)
{
    smf_ue_t *smf_ue = NULL;

    old_sess = smf_sess_find_active_by_id(old_sess ? old_sess->id :
            OGS_INVALID_POOL_ID);
    if (!old_sess)
        return false;

    smf_ue = smf_ue_find_active(old_sess->smf_ue_id);
    if (!smf_ue)
        return false;

    if (!smf_sess_upf_established(old_sess))
        return false;

    return smf_sess_collision_replace_begin(
            old_sess, smf_ue, e, false, NULL);
}

static void smf_ue_collision_replace_fail(smf_ue_t *smf_ue)
{
    ogs_gtp_xact_t *gtp_xact = NULL;

    ogs_assert(smf_ue);
    ogs_assert(smf_ue->collision_replace.pending);

    gtp_xact = ogs_gtp_xact_find_by_id(smf_ue->collision_replace.gtp_xact_id);
    if (gtp_xact) {
        if (smf_ue->collision_replace.gtp2) {
            ogs_gtp2_send_error_message(gtp_xact,
                    smf_ue->collision_replace.peer_teid_presence ?
                        smf_ue->collision_replace.peer_teid : 0,
                    OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE,
                    OGS_GTP2_CAUSE_SYSTEM_FAILURE);
        } else {
            ogs_gtp1_send_error_message(gtp_xact, 0,
                    OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE,
                    OGS_GTP1_CAUSE_SYSTEM_FAILURE);
        }
    }

    smf_ue_collision_clear(smf_ue);
}

void smf_ue_collision_abort(smf_ue_t *smf_ue)
{
    if (!smf_ue || !smf_ue->collision_replace.pending)
        return;

    smf_ue_collision_replace_fail(smf_ue);
}

void smf_sess_collision_replace_complete(smf_sess_t *old_sess)
{
    smf_ue_t *smf_ue = NULL;
    smf_sess_t *new_sess = NULL;
    smf_event_t ev;
    ogs_gtp2_message_t gtp2_message;
    ogs_gtp1_message_t gtp1_message;
    ogs_pkbuf_t *pkbuf = NULL;
    int rv;
    ogs_pool_id_t old_sess_id;

    if (!old_sess)
        return;

    old_sess_id = old_sess->id;
    old_sess = smf_sess_find_active_by_id(old_sess_id);
    if (!old_sess) {
        ogs_warn("collision replace complete on removed session "
                "(sess_id=%d)", (int)old_sess_id);
        return;
    }

    smf_ue = smf_ue_find_active(old_sess->smf_ue_id);
    if (!smf_ue || !smf_ue->collision_replace.pending) {
        ogs_warn("collision replace complete without pending context "
                "(sess_id=%d)", (int)old_sess->id);
        old_sess->collision_replace = false;
        smf_sess_remove(old_sess);
        return;
    }

    pkbuf = smf_ue->collision_replace.pkbuf;

    old_sess->collision_replace = false;
    smf_sess_remove(old_sess);

    if (smf_ue->collision_replace.gtp2) {
        rv = ogs_gtp2_parse_msg(&gtp2_message, pkbuf);
        if (rv != OGS_OK) {
            ogs_error("[%s] collision replace: GTPv2 parse failed",
                    smf_ue->imsi_bcd);
            smf_ue_collision_replace_fail(smf_ue);
            return;
        }

        new_sess = smf_sess_add_by_gtp2_message(&gtp2_message);
        if (!new_sess) {
            ogs_error("[%s] collision replace: session add failed",
                    smf_ue->imsi_bcd);
            smf_ue_collision_replace_fail(smf_ue);
            return;
        }

        if (smf_ue->collision_replace.gtp_node)
            OGS_SETUP_GTP_NODE(new_sess, smf_ue->collision_replace.gtp_node);

        if (smf_ue->collision_replace.peer_teid_presence)
            new_sess->sgw_s5c_teid = smf_ue->collision_replace.peer_teid;

        ogs_smf_trace_set(smf_ue, new_sess, "create-session");
        OGS_TLOG_INFO("Create Session Request (after UPF collision replace)");

        memset(&ev, 0, sizeof(ev));
        ev.sess_id = new_sess->id;
        ev.gtp_xact_id = smf_ue->collision_replace.gtp_xact_id;
        ev.gtp2_message = &gtp2_message;
        ev.pkbuf = pkbuf;
        ev.gnode = NULL;

        ogs_fsm_dispatch(&new_sess->sm, &ev);
        smf_ue_collision_clear(smf_ue);
        return;
    }

    rv = ogs_gtp1_parse_msg(&gtp1_message, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("[%s] collision replace: GTPv1 parse failed",
                smf_ue->imsi_bcd);
        smf_ue_collision_replace_fail(smf_ue);
        return;
    }

    new_sess = smf_sess_add_by_gtp1_message(&gtp1_message);
    if (!new_sess) {
        ogs_error("[%s] collision replace: PDP context add failed",
                smf_ue->imsi_bcd);
        smf_ue_collision_replace_fail(smf_ue);
        return;
    }

    if (smf_ue->collision_replace.gtp_node)
        OGS_SETUP_GTP_NODE(new_sess, smf_ue->collision_replace.gtp_node);

    memset(&ev, 0, sizeof(ev));
    ev.sess_id = new_sess->id;
    ev.gtp_xact_id = smf_ue->collision_replace.gtp_xact_id;
    ev.gtp1_message = &gtp1_message;
    ev.pkbuf = pkbuf;
    ev.gnode = NULL;

    ogs_fsm_dispatch(&new_sess->sm, &ev);
    smf_ue_collision_clear(smf_ue);
}

void smf_sess_collision_on_pfcp_delete_timeout(smf_sess_t *sess)
{
    smf_ue_t *smf_ue = NULL;
    ogs_pool_id_t sess_id;

    if (!sess)
        return;

    if (!sess->collision_replace)
        return;

    sess_id = sess->id;
    sess = smf_sess_find_active_by_id(sess_id);
    if (!sess) {
        ogs_warn("collision replace timeout on removed session "
                "(sess_id=%d)", (int)sess_id);
        return;
    }

    smf_ue = smf_ue_find_active(sess->smf_ue_id);
    ogs_warn("[%s] collision replace: PFCP delete timeout, "
            "continuing with new session",
            smf_ue && smf_ue->imsi_bcd[0] ? smf_ue->imsi_bcd : "-");

    smf_sess_collision_replace_complete(sess);
}
