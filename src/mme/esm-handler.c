/*
 * Copyright (C) 2019-2026 by Sukchan Lee <acetcom@gmail.com>
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

#include "mme-context.h"
#include "nas-path.h"
#include "sgsap-path.h"
#include "mme-gtp-path.h"
#include "mme-path.h"
#include "mme-trace.h"
#include "mme-inbound-roam-apn.h"
#include "mme-apn-policy.h"
#include "metrics.h"

#include "esm-build.h"
#include "esm-handler.h"

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __esm_log_domain

/*
 * Resolve the PDN type to use on the Create Session Request: the UE
 * request intersected with the subscription, then corrected or clamped
 * by mme.apn_correction. Returns OGS_ERROR when the request cannot be
 * satisfied and the caller must reject with ESM #28.
 */
static int esm_resolve_pdn_type(mme_ue_t *mme_ue, mme_sess_t *sess)
{
    uint8_t derived;

    ogs_assert(sess);
    ogs_assert(sess->session);

    if (sess->session->session_type != OGS_PDU_SESSION_TYPE_IPV4 &&
        sess->session->session_type != OGS_PDU_SESSION_TYPE_IPV6 &&
        sess->session->session_type != OGS_PDU_SESSION_TYPE_IPV4V6) {
        ogs_error("[%s] Invalid PDN_TYPE[%d] in subscription for APN[%s]",
                mme_ue->imsi_bcd, sess->session->session_type,
                sess->session->name ? sess->session->name : "-");
        return OGS_ERROR;
    }

    derived = mme_apn_policy_pdn_type(
            mme_ue, sess->session, sess->ue_request_type.type);
    if (derived == 0) {
        ogs_error("[%s] Cannot derive PDN Type [UE:%d,HSS:%d]",
                mme_ue->imsi_bcd, sess->ue_request_type.type,
                sess->session->session_type);
        return OGS_ERROR;
    }

    sess->policy_pdn_type = derived;
    return OGS_OK;
}

int esm_handle_pdn_connectivity_request(
        enb_ue_t *enb_ue, mme_bearer_t *bearer,
        ogs_nas_eps_pdn_connectivity_request_t *req,
        int create_action)
{
    int r;
    mme_ue_t *mme_ue = NULL;
    mme_sess_t *sess = NULL;
    uint8_t security_protected_required = 0;
    uint8_t no_apn_cause = OGS_NAS_ESM_CAUSE_MISSING_OR_UNKNOWN_APN;
    const char *emergency_dnn = mme_self()->emergency.dnn;
    bool emergency;

    ogs_assert(req);

    if (!bearer) {
        ogs_error("No bearer context");
        return OGS_NOTFOUND;
    }
    sess = mme_sess_find_by_id(bearer->sess_id);
    if (!sess) {
        ogs_warn("Session context has already been removed");
        return OGS_NOTFOUND;
    }
    mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
    if (!mme_ue) {
        ogs_warn("UE(mme-ue) context has already been removed");
        return OGS_NOTFOUND;
    }

    ogs_assert(MME_UE_HAVE_IMSI(mme_ue));

    mme_metrics_pdn_connectivity_attempt(mme_ue);

    if (mme_self()->maintenance_mode) {
        ogs_warn("[%s] PDN connectivity rejected: MME maintenance mode",
                mme_ue->imsi_bcd);
        r = nas_eps_send_pdn_connectivity_reject(
                sess, OGS_NAS_ESM_CAUSE_INSUFFICIENT_RESOURCES,
                create_action);
        ogs_expect(r == OGS_OK);
        return OGS_ERROR;
    }

    if (!SECURITY_CONTEXT_IS_VALID(mme_ue)) {
        ogs_error("No Security Context : IMSI[%s]", mme_ue->imsi_bcd);
        r = nas_eps_send_pdn_connectivity_reject(
                sess, OGS_NAS_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                create_action);
        ogs_expect(r == OGS_OK);
        return OGS_ERROR;
    }

    if (req->request_type.type == OGS_NAS_EPS_PDN_TYPE_IPV4 ||
        req->request_type.type == OGS_NAS_EPS_PDN_TYPE_IPV6 ||
        req->request_type.type == OGS_NAS_EPS_PDN_TYPE_IPV4V6) {
        /* OK */
    } else {
        /* NOT-allowed PDN Type */
        r = nas_eps_send_pdn_connectivity_reject(
                sess, OGS_NAS_ESM_CAUSE_UNKNOWN_PDN_TYPE,
                create_action);
        ogs_expect(r == OGS_OK);
        return OGS_ERROR;
    }

    memcpy(&sess->ue_request_type,
            &req->request_type, sizeof(sess->ue_request_type));
    sess->policy_pdn_type = 0;

    security_protected_required = 0;
    if (req->presencemask &
        OGS_NAS_EPS_PDN_CONNECTIVITY_REQUEST_ESM_INFORMATION_TRANSFER_FLAG_PRESENT) {
        ogs_nas_esm_information_transfer_flag_t *esm_information_transfer_flag =
            &req->esm_information_transfer_flag;
        security_protected_required = 
                esm_information_transfer_flag->security_protected_required;
        ogs_debug("    EIT(ESM information transfer)[%d]",
                security_protected_required);
    }

    emergency = (req->request_type.value == OGS_NAS_EPS_REQUEST_TYPE_EMERGENCY);
    if (emergency && !emergency_dnn) {
        /* Emergency call, but no emergency APN defined */
        r = nas_eps_send_pdn_connectivity_reject(
                sess, OGS_NAS_ESM_CAUSE_REQUEST_REJECTED_UNSPECIFIED, create_action);
        ogs_expect(r == OGS_OK);
        ogs_warn("[%s] Emergency call, but no emergency APN defined",
                mme_ue->imsi_bcd);
        return OGS_ERROR;
    }
    /*
     * TS 23.401 / 24.301: APN IE absent or empty → select the default APN
     * from the S6a subscription (mme_default_session). inbound_roam
     * allowed_apn is enforced only on the RESOLVED APN (after subscription
     * match / apn_correction), so SMACTCTRL can rewrite a disallowed
     * request before the allow-list runs.
     */
    sess->ue_provided_apn = false;
    if (emergency) {
        const char *apn = emergency_dnn;
        sess->ue_request_type.value = 1;
        sess->ue_provided_apn = true;
        mme_ue_info(mme_ue, NULL, "esm", apn,
                "PDN connectivity request APN[%s] (emergency)", apn);
        sess->session = mme_session_find_by_apn(mme_ue, apn);
        if (!sess->session) {
            r = nas_eps_send_pdn_connectivity_reject(
                    sess, OGS_NAS_ESM_CAUSE_MISSING_OR_UNKNOWN_APN,
                    create_action);
            ogs_expect(r == OGS_OK);
            mme_ue_warn(mme_ue, NULL, "esm",
                    apn, "Invalid emergency APN[%s]", apn);
            return OGS_ERROR;
        }
    } else if ((req->presencemask &
            OGS_NAS_EPS_PDN_CONNECTIVITY_REQUEST_ACCESS_POINT_NAME_PRESENT) &&
            req->access_point_name.length > 0 &&
            req->access_point_name.apn[0] != '\0') {
        const char *apn = req->access_point_name.apn;

        /* inbound_roam allow/deny is applied only after APN resolution
         * (subscription match or apn_correction) below — not on the raw
         * UE-requested string, so SMACTCTRL can rewrite first. */
        sess->ue_provided_apn = true;
        mme_ue_info(mme_ue, NULL, "esm", apn,
                "PDN connectivity request APN[%s]", apn);
        sess->session = mme_session_find_by_apn(mme_ue, apn);
        if (!sess->session) {
            uint8_t esm_cause = OGS_NAS_ESM_CAUSE_MISSING_OR_UNKNOWN_APN;

            sess->session = mme_apn_policy_correct_apn(
                    mme_ue, apn, &esm_cause);
            if (!sess->session) {
                r = nas_eps_send_pdn_connectivity_reject(
                        sess, esm_cause, create_action);
                ogs_expect(r == OGS_OK);
                mme_ue_warn(mme_ue, NULL, "esm",
                        apn, "Invalid APN requested[%s]", apn);
                return OGS_ERROR;
            }
        }

        if (esm_resolve_pdn_type(mme_ue, sess) != OGS_OK) {
            r = nas_eps_send_pdn_connectivity_reject(
                    sess, OGS_NAS_ESM_CAUSE_UNKNOWN_PDN_TYPE, create_action);
            ogs_expect(r == OGS_OK);
            return OGS_ERROR;
        }
    }

    if (req->presencemask &
        OGS_NAS_EPS_PDN_CONNECTIVITY_REQUEST_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_PRESENT) {
        ogs_nas_extended_protocol_configuration_options_t
            *extended_protocol_configuration_options =
            &req->extended_protocol_configuration_options;

        OGS_NAS_STORE_DATA(&sess->ue_epco,
            extended_protocol_configuration_options);
    } else if (req->presencemask &
        OGS_NAS_EPS_PDN_CONNECTIVITY_REQUEST_PROTOCOL_CONFIGURATION_OPTIONS_PRESENT) {
        ogs_nas_protocol_configuration_options_t
            *protocol_configuration_options =
            &req->protocol_configuration_options;

        OGS_NAS_STORE_DATA(&sess->ue_pco, protocol_configuration_options);
    }

    if (security_protected_required) {
        CLEAR_BEARER_TIMER(bearer->t3489);
        r = nas_eps_send_esm_information_request(bearer);
        ogs_expect(r == OGS_OK);

        return OGS_OK;
    }

    if (!sess->session) {
        /* Default APN from S6a (UE omitted or sent empty APN IE) */
        sess->session = mme_default_session(mme_ue);
        if (sess->session && sess->session->name)
            mme_ue_info(mme_ue, NULL, "esm", sess->session->name,
                    "PDN connectivity: using S6a default APN[%s] "
                    "(UE APN absent/empty)", sess->session->name);
    }
    if (!sess->session) {
        /* No default Context-Identifier: apn_correction may still pick one */
        sess->session = mme_apn_policy_correct_apn(
                mme_ue, NULL, &no_apn_cause);
    }

    if (sess->session) {
        ogs_assert(sess->session->name);
        ogs_debug("    APN[%s]", sess->session->name);

        /* Enforce allow-list on the resolved APN (UE-provided OR the
         * S6a default) so disallowed APNs never reach the SGW */
        {
            uint8_t roam_cause = mme_inbound_roam_apn_esm_cause(
                    mme_ue, sess->session->name);

            if (roam_cause != MME_INBOUND_ROAM_APN_ESM_ACCEPT) {
                ogs_warn("[%s] inbound roam APN policy: reject PDN APN[%s]%s "
                        "esm_cause=%u",
                        mme_ue->imsi_bcd, sess->session->name,
                        sess->ue_provided_apn ? "" : " (S6a default)",
                        roam_cause);
                r = nas_eps_send_pdn_connectivity_reject(
                        sess, roam_cause, create_action);
                ogs_expect(r == OGS_OK);
                return OGS_ERROR;
            }
        }

        /*
         * Duplicate-PDN guard on the RESOLVED APN. The earlier check in
         * mme_bearer_find_or_add_by_message compares the raw UE-requested
         * string, which misses requests that subscription matching or
         * apn_correction rewrite to an APN that is already active: one UE
         * stacked 11 PDNs to the same APN this way until EBI 5-15 was
         * exhausted (2026-07-31). TS 24.301 cause #55. The rejected sess
         * has no PGW TEID, so incomplete-session reclaim frees its EBI.
         */
        if (create_action != OGS_GTP_CREATE_IN_ATTACH_REQUEST) {
            mme_sess_t *dup = mme_sess_find_by_apn(
                    mme_ue, sess->session->name);
            if (dup && dup != sess) {
                ogs_warn("[%s] PDN connectivity: resolved APN[%s] already "
                        "active%s; rejecting duplicate PDN (cause #55)",
                        mme_ue->imsi_bcd, sess->session->name,
                        sess->ue_provided_apn ? "" : " (S6a default)");
                r = nas_eps_send_pdn_connectivity_reject(sess,
                        OGS_NAS_ESM_CAUSE_MULTIPLE_PDN_CONNECTIONS_FOR_A_GIVEN_APN_NOT_ALLOWED,
                        create_action);
                ogs_expect(r == OGS_OK);
                return OGS_ERROR;
            }
        }

        /* Not yet done when the APN came from the S6a default */
        if (!sess->policy_pdn_type &&
                esm_resolve_pdn_type(mme_ue, sess) != OGS_OK) {
            r = nas_eps_send_pdn_connectivity_reject(
                    sess, OGS_NAS_ESM_CAUSE_UNKNOWN_PDN_TYPE, create_action);
            ogs_expect(r == OGS_OK);
            return OGS_ERROR;
        }

        mme_bearer_t *default_bearer = NULL;
        mme_bearer_t *dedicated_bearer = NULL, *next_dedicated_bearer = NULL;

        ogs_assert(sess->session->name);
        ogs_debug("    APN[%s]", sess->session->name);

        default_bearer = mme_default_bearer_in_sess(sess);
        if (default_bearer) {
            dedicated_bearer = mme_bearer_next(default_bearer);
            while (dedicated_bearer) {
                next_dedicated_bearer = mme_bearer_next(dedicated_bearer);

                ogs_warn("Dedicated-Bearer[%d] removed forcely",
                        dedicated_bearer->ebi);
                mme_bearer_remove(dedicated_bearer);

                dedicated_bearer = next_dedicated_bearer;
            }
        }

        r = mme_gtp_send_create_session_request(enb_ue, sess, create_action);
        if (r != OGS_OK) {
            ogs_warn("[%s] Create Session Request failed", mme_ue->imsi_bcd);
            r = nas_eps_send_pdn_connectivity_reject(
                    sess, OGS_NAS_ESM_CAUSE_INSUFFICIENT_RESOURCES,
                    create_action);
            ogs_expect(r == OGS_OK);
            return OGS_ERROR;
        }
    } else {
        ogs_error("[%s] No APN: UE omitted/empty APN and S6a has no "
                "default Context-Identifier", mme_ue->imsi_bcd);
        r = nas_eps_send_pdn_connectivity_reject(
                sess, no_apn_cause, create_action);
        ogs_expect(r == OGS_OK);
        return OGS_ERROR;
    }

    return OGS_OK;
}

int esm_handle_information_response(
        enb_ue_t *enb_ue, mme_sess_t *sess,
        ogs_nas_eps_esm_information_response_t *rsp)
{
    int r;
    mme_ue_t *mme_ue = NULL;
    uint8_t no_apn_cause = OGS_NAS_ESM_CAUSE_MISSING_OR_UNKNOWN_APN;

    ogs_assert(rsp);

    if (!sess) {
        ogs_warn("Session context has already been removed");
        return OGS_NOTFOUND;
    }
    mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
    if (!mme_ue) {
        ogs_warn("UE(mme-ue) context has already been removed");
        return OGS_NOTFOUND;
    }

    /*
     * Non-empty UE APN → subscription match, then apn_correction.
     * Absent/empty APN → S6a default (TS 23.401). inbound_roam allow/deny
     * runs only on the resolved APN below either way.
     */
    if ((rsp->presencemask &
            OGS_NAS_EPS_ESM_INFORMATION_RESPONSE_ACCESS_POINT_NAME_PRESENT) &&
            rsp->access_point_name.length > 0 &&
            rsp->access_point_name.apn[0] != '\0') {
        sess->ue_provided_apn = true;

        sess->session = mme_session_find_by_apn(
                            mme_ue, rsp->access_point_name.apn);
        if (!sess->session)
            sess->session = mme_apn_policy_correct_apn(
                    mme_ue, rsp->access_point_name.apn, &no_apn_cause);
    } else {
        sess->ue_provided_apn = false;
        if (!sess->session) {
            sess->session = mme_default_session(mme_ue);
            if (sess->session && sess->session->name)
                ogs_info("[%s] ESM Information Response: using S6a "
                        "default APN[%s] (UE APN absent/empty)",
                        mme_ue->imsi_bcd, sess->session->name);
        }
        if (!sess->session)
            sess->session = mme_apn_policy_correct_apn(
                    mme_ue, NULL, &no_apn_cause);
    }

    if (rsp->presencemask &
        OGS_NAS_EPS_ESM_INFORMATION_RESPONSE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_PRESENT) {
        ogs_nas_extended_protocol_configuration_options_t
            *extended_protocol_configuration_options =
            &rsp->extended_protocol_configuration_options;

        OGS_NAS_STORE_DATA(&sess->ue_epco,
            extended_protocol_configuration_options);
    } else if (rsp->presencemask &
        OGS_NAS_EPS_ESM_INFORMATION_RESPONSE_PROTOCOL_CONFIGURATION_OPTIONS_PRESENT) {
        ogs_nas_protocol_configuration_options_t
            *protocol_configuration_options =
                &rsp->protocol_configuration_options;
        OGS_NAS_STORE_DATA(&sess->ue_pco, protocol_configuration_options);
    }

    if (sess->session) {
        ogs_assert(sess->session->name);
        ogs_debug("    APN[%s]", sess->session->name);

        /* Enforce allow-list on the resolved APN (UE-provided OR the
         * S6a default) so disallowed APNs never reach the SGW */
        {
            uint8_t roam_cause = mme_inbound_roam_apn_esm_cause(
                    mme_ue, sess->session->name);

            if (roam_cause != MME_INBOUND_ROAM_APN_ESM_ACCEPT) {
                ogs_warn("[%s] inbound roam APN policy: reject attach "
                        "APN[%s]%s esm_cause=%u",
                        mme_ue->imsi_bcd, sess->session->name,
                        sess->ue_provided_apn ? "" : " (S6a default)",
                        roam_cause);
                r = nas_eps_send_pdn_connectivity_reject(
                        sess, roam_cause, OGS_GTP_CREATE_IN_ATTACH_REQUEST);
                ogs_expect(r == OGS_OK);
                return OGS_ERROR;
            }
        }

        if (esm_resolve_pdn_type(mme_ue, sess) != OGS_OK) {
            r = nas_eps_send_pdn_connectivity_reject(
                    sess, OGS_NAS_ESM_CAUSE_UNKNOWN_PDN_TYPE,
                    OGS_GTP_CREATE_IN_ATTACH_REQUEST);
            ogs_expect(r == OGS_OK);
            return OGS_ERROR;
        }

        if (SESSION_CONTEXT_IS_AVAILABLE(mme_ue)) {
            mme_csmap_t *csmap = mme_csmap_find_for_ue(mme_ue);
            mme_ue->csmap = csmap;

            if (!csmap ||
                ogs_global_conf()->parameter.ignore_sgs == true ||
                mme_ue->network_access_mode ==
                    OGS_NETWORK_ACCESS_MODE_ONLY_PACKET ||
                mme_ue->nas_eps.attach.value ==
                    OGS_NAS_ATTACH_TYPE_EPS_ATTACH) {
                r = nas_eps_send_attach_accept(mme_ue);
                if (r != OGS_OK)
                    mme_send_delete_session_after_attach_accept_fail(
                            enb_ue, mme_ue);
                ogs_expect(r == OGS_OK);
            } else {
                mme_ue_progress(mme_ue, "attach_accept_deferred_sgs");
                if (OGS_OK != sgsap_send_location_update_request(mme_ue)) {
                    ogs_error("[%s] sgsap_send_location_update_request() failed",
                            mme_ue->imsi_bcd);
                    return OGS_ERROR;
                }
            }
        } else {
            if (mme_self()->maintenance_mode) {
                ogs_warn("[%s] Attach PDN rejected: MME maintenance mode",
                        mme_ue->imsi_bcd);
                r = nas_eps_send_pdn_connectivity_reject(
                        sess, OGS_NAS_ESM_CAUSE_INSUFFICIENT_RESOURCES,
                        OGS_GTP_CREATE_IN_ATTACH_REQUEST);
                ogs_expect(r == OGS_OK);
                return OGS_ERROR;
            }

            r = mme_gtp_send_create_session_request(
                    enb_ue, sess, OGS_GTP_CREATE_IN_ATTACH_REQUEST);
            if (r != OGS_OK) {
                ogs_warn("[%s] Create Session Request failed",
                        mme_ue->imsi_bcd);
                r = nas_eps_send_pdn_connectivity_reject(
                        sess, OGS_NAS_ESM_CAUSE_INSUFFICIENT_RESOURCES,
                        OGS_GTP_CREATE_IN_ATTACH_REQUEST);
                ogs_expect(r == OGS_OK);
                return OGS_ERROR;
            }
        }
    } else {
        if (sess->ue_provided_apn && rsp->access_point_name.length)
            ogs_warn("[%s] Invalid APN[%s] (not in S6a subscription)",
                    mme_ue->imsi_bcd, rsp->access_point_name.apn);
        else
            ogs_warn("[%s] No APN: UE omitted APN and S6a has no "
                    "default Context-Identifier", mme_ue->imsi_bcd);

        r = nas_eps_send_pdn_connectivity_reject(
                sess, no_apn_cause, OGS_GTP_CREATE_IN_ATTACH_REQUEST);
        ogs_expect(r == OGS_OK);
        return OGS_ERROR;
    }

    return OGS_OK;
}

int esm_handle_bearer_resource_allocation_request(
        enb_ue_t *enb_ue, mme_bearer_t *bearer, ogs_nas_eps_message_t *message)
{
    int r;
    mme_ue_t *mme_ue = NULL;
    mme_sess_t *sess = NULL;

    if (!bearer) {
        ogs_error("No bearer context");
        return OGS_NOTFOUND;
    }
    sess = mme_sess_find_by_id(bearer->sess_id);
    if (!sess) {
        ogs_warn("Session context has already been removed");
        return OGS_NOTFOUND;
    }
    mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
    if (!mme_ue) {
        ogs_warn("UE(mme-ue) context has already been removed");
        return OGS_NOTFOUND;
    }

    r = nas_eps_send_bearer_resource_allocation_reject(
            mme_ue, sess->pti, OGS_NAS_ESM_CAUSE_NETWORK_FAILURE);
    ogs_expect(r == OGS_OK);

    return OGS_OK;
}

int esm_handle_bearer_resource_modification_request(
        enb_ue_t *enb_ue, mme_bearer_t *bearer, ogs_nas_eps_message_t *message)
{
    mme_ue_t *mme_ue = NULL;

    if (!bearer) {
        ogs_error("No bearer context");
        return OGS_NOTFOUND;
    }
    mme_ue = mme_ue_find_by_id(bearer->mme_ue_id);
    if (!mme_ue) {
        ogs_warn("UE(mme-ue) context has already been removed");
        return OGS_NOTFOUND;
    }

    if (mme_gtp_send_bearer_resource_command(bearer, message) != OGS_OK) {
        ogs_error("[%s] Bearer Resource Command failed EBI[%d]",
                mme_ue->imsi_bcd, bearer->ebi);
        return OGS_ERROR;
    }

    return OGS_OK;
}
