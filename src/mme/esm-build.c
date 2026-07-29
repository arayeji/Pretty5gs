/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
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

#include "nas-security.h"
#include "esm-build.h"
#include "mme-sm.h"
#include "mme-ambr.h"
#include "mme-context.h"
#include "mme-trace.h"

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __esm_log_domain

static bool esm_pdn_connectivity_reject_t3396_allowed(uint8_t esm_cause)
{
    switch (esm_cause) {
    case OGS_NAS_ESM_CAUSE_OPERATOR_DETERMINED_BARRING:
    case OGS_NAS_ESM_CAUSE_INSUFFICIENT_RESOURCES:
    case OGS_NAS_ESM_CAUSE_NETWORK_FAILURE:
        return true;
    default:
        return false;
    }
}

static bool mme_esm_include_pdn_type_cause(
        mme_sess_t *sess, uint8_t esm_cause)
{
    mme_context_t *ctx = mme_self();

    if (!ctx->attach_accept.esm_cause_pdn_type_mismatch)
        return false;

    if (ctx->inbound_roam_suppress_pdn_type_esm_cause)
        return false;

    if (ctx->inbound_roam_force_ipv4_pdn_on_home_pgw &&
            esm_cause == OGS_NAS_ESM_CAUSE_PDN_TYPE_IPV4_ONLY_ALLOWED &&
            sess->ue_request_type.type == OGS_NAS_EPS_PDN_TYPE_IPV4V6 &&
            sess->paa.session_type == OGS_PDU_SESSION_TYPE_IPV4)
        return false;

    return true;
}

static void mme_esm_set_pdn_type_cause(
        ogs_nas_eps_activate_default_eps_bearer_context_request_t *req,
        mme_sess_t *sess, uint8_t esm_cause)
{
    if (!mme_esm_include_pdn_type_cause(sess, esm_cause))
        return;

    req->esm_cause = esm_cause;
    req->presencemask |=
        OGS_NAS_EPS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_ESM_CAUSE_PRESENT;
}

static void mme_esm_add_legacy_gprs_qos(
        ogs_nas_eps_activate_default_eps_bearer_context_request_t *req)
{
    static const uint8_t negotiated_qos[] = {
        0x23, 0x93, 0x1F, 0x91, 0x96, 0xFE, 0xFE, 0x74,
        0x4B, 0xFF, 0xFF, 0x00, 0xCA, 0x00, 0xFA, 0x00, 0x32
    };

    ogs_assert(req);

    req->negotiated_qos.length = sizeof(negotiated_qos);
    memcpy(req->negotiated_qos.buffer, negotiated_qos,
            sizeof(negotiated_qos));
    req->presencemask |=
        OGS_NAS_EPS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_NEGOTIATED_QOS_PRESENT;

    req->negotiated_llc_sapi = 0x03;
    req->presencemask |=
        OGS_NAS_EPS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_NEGOTIATED_LLC_SAPI_PRESENT;

    req->radio_priority.spare = 0;
    req->radio_priority.value = 2;
    req->presencemask |=
        OGS_NAS_EPS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_RADIO_PRIORITY_PRESENT;

    req->packet_flow_identifier.length = 1;
    req->packet_flow_identifier.spare = 0;
    req->packet_flow_identifier.value = 8;
    req->presencemask |=
        OGS_NAS_EPS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_PACKET_FLOW_IDENTIFIER_PRESENT;
}

ogs_pkbuf_t *esm_build_pdn_connectivity_reject(
        mme_sess_t *sess, ogs_nas_esm_cause_t esm_cause, int create_action)
{
    mme_ue_t *mme_ue = NULL;
    ogs_nas_eps_message_t message;
    ogs_nas_eps_pdn_connectivity_reject_t *pdn_connectivity_reject =
            &message.esm.pdn_connectivity_reject;

    ogs_assert(sess);
    mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
    ogs_assert(mme_ue);

    mme_ue_warn(mme_ue, NULL, "esm", NULL,
            "PDN connectivity reject PTI=%d Cause=%d",
            sess->pti, esm_cause);

    memset(&message, 0, sizeof(message));
    if (create_action == OGS_GTP_CREATE_IN_ATTACH_REQUEST) {
        /* Nothing */
    } else {
        message.h.security_header_type =
           OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
        message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    }
    message.esm.h.eps_bearer_identity = 0;
    message.esm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_ESM;
    message.esm.h.procedure_transaction_identity = sess->pti;
    message.esm.h.message_type = OGS_NAS_EPS_PDN_CONNECTIVITY_REJECT;

    pdn_connectivity_reject->esm_cause = esm_cause;

    if (mme_self()->time.t3396.value &&
        esm_pdn_connectivity_reject_t3396_allowed(esm_cause)) {
        int rv;
        ogs_nas_gprs_timer_t gprs_timer;

        rv = ogs_nas_gprs_timer_3_from_sec(
                &gprs_timer, mme_self()->time.t3396.value);
        ogs_assert(rv == OGS_OK);

        pdn_connectivity_reject->presencemask |=
            OGS_NAS_EPS_PDN_CONNECTIVITY_REJECT_BACK_OFF_TIMER_VALUE_PRESENT;
        pdn_connectivity_reject->back_off_timer_value.length = 1;
        pdn_connectivity_reject->back_off_timer_value.t = gprs_timer;
    }

    if (create_action == OGS_GTP_CREATE_IN_ATTACH_REQUEST)
        return ogs_nas_eps_plain_encode(&message);
    else
        return nas_eps_security_encode(mme_ue, &message);
}

ogs_pkbuf_t *esm_build_information_request(mme_bearer_t *bearer)
{
    ogs_nas_eps_message_t message;
    mme_ue_t *mme_ue = NULL;
    mme_sess_t *sess = NULL;

    ogs_assert(bearer);
    sess = mme_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    mme_ue = mme_ue_find_by_id(bearer->mme_ue_id);
    ogs_assert(mme_ue);

    ogs_debug("ESM information request");
    ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
            mme_ue->imsi_bcd, sess->pti, bearer->ebi);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
       OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;

    message.esm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_ESM;
    message.esm.h.procedure_transaction_identity = sess->pti;
    message.esm.h.message_type = OGS_NAS_EPS_ESM_INFORMATION_REQUEST;

    return nas_eps_security_encode(mme_ue, &message);
}

ogs_pkbuf_t *esm_build_activate_default_bearer_context_request(
        mme_sess_t *sess, int create_action)
{
    ogs_nas_eps_message_t message;
    ogs_nas_eps_activate_default_eps_bearer_context_request_t 
        *activate_default_eps_bearer_context_request =
            &message.esm.activate_default_eps_bearer_context_request;
    ogs_nas_eps_quality_of_service_t *eps_qos =
        &activate_default_eps_bearer_context_request->eps_qos;
    ogs_nas_access_point_name_t *access_point_name =
        &activate_default_eps_bearer_context_request->access_point_name;
    ogs_nas_pdn_address_t *pdn_address =
        &activate_default_eps_bearer_context_request->pdn_address;
    ogs_nas_apn_aggregate_maximum_bit_rate_t *apn_ambr =
        &activate_default_eps_bearer_context_request->apn_ambr;
    ogs_nas_protocol_configuration_options_t *protocol_configuration_options =
        &activate_default_eps_bearer_context_request
            ->protocol_configuration_options;
    ogs_nas_extended_protocol_configuration_options_t
        *extended_protocol_configuration_options =
            &activate_default_eps_bearer_context_request
                ->extended_protocol_configuration_options;
    
    mme_ue_t *mme_ue = NULL;
    mme_bearer_t *bearer = NULL;
    ogs_session_t *session = NULL;

    ogs_assert(sess);
    mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
    ogs_assert(mme_ue);
    session = sess->session;
    ogs_assert(session);
    ogs_assert(session->name);
    bearer = mme_default_bearer_in_sess(sess);
    ogs_assert(bearer);

    ogs_debug("Activate default bearer context request");
    ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
            mme_ue->imsi_bcd, sess->pti, bearer->ebi);

    memset(&message, 0, sizeof(message));
    if (create_action == OGS_GTP_CREATE_IN_ATTACH_REQUEST) {
        /* Nothing */
    } else {
        message.h.security_header_type =
           OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
        message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    }
    message.esm.h.eps_bearer_identity = bearer->ebi;
    message.esm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_ESM;
    message.esm.h.procedure_transaction_identity = sess->pti;
    message.esm.h.message_type =
        OGS_NAS_EPS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST;

    memcpy(&bearer->qos, &session->qos, sizeof(ogs_qos_t));
    mme_qos_fill_bearer_bitrates(mme_ue, session, &bearer->qos);
    mme_bearer_qos_for_s1ap(&bearer->qos);

    eps_qos_build(eps_qos, bearer->qos.index,
            bearer->qos.mbr.downlink, bearer->qos.mbr.uplink,
            bearer->qos.gbr.downlink, bearer->qos.gbr.uplink);

    access_point_name->length = strlen(session->name);
    ogs_cpystrn(access_point_name->apn, session->name,
            ogs_min(access_point_name->length, OGS_MAX_APN_LEN) + 1);
    ogs_debug("    APN[%s]", session->name);

    /*
     * In TS24.301 V15.6.0
     * 6.5.1.3 UE requested PDN connectivity procedure accepted by the network
     *
     * If connectivity with the requested PDN is accepted,
     * but with a restriction of IP version (i.e. both an IPv4 address and
     * an IPv6 prefix is requested, but only one particular IP version, or
     * only single IP version bearers are supported/allowed by the network),
     * ESM cause #50 "PDN type IPv4 only allowed",
     * #51 "PDN type IPv6 only allowed", or
     * #52 "single address bearers only allowed", respectively, shall be
     * included in the ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST message.
     */

    pdn_address->pdn_type = sess->paa.session_type;
    if (sess->ue_request_type.type == OGS_NAS_EPS_PDN_TYPE_IPV4V6) {
        if (sess->paa.session_type == OGS_PDU_SESSION_TYPE_IPV4) {
            pdn_address->pdn_type = OGS_PDU_SESSION_TYPE_IPV4;
            mme_esm_set_pdn_type_cause(activate_default_eps_bearer_context_request,
                    sess, OGS_NAS_ESM_CAUSE_PDN_TYPE_IPV4_ONLY_ALLOWED);
        } else if (sess->paa.session_type == OGS_PDU_SESSION_TYPE_IPV6) {
            pdn_address->pdn_type = OGS_PDU_SESSION_TYPE_IPV6;
            mme_esm_set_pdn_type_cause(activate_default_eps_bearer_context_request,
                    sess, OGS_NAS_ESM_CAUSE_PDN_TYPE_IPV6_ONLY_ALLOWED);
        }
    } else if (sess->ue_request_type.type == OGS_PDU_SESSION_TYPE_IPV4) {
        if (sess->paa.session_type == OGS_PDU_SESSION_TYPE_IPV6) {
            pdn_address->pdn_type = OGS_PDU_SESSION_TYPE_IPV6;
            mme_esm_set_pdn_type_cause(activate_default_eps_bearer_context_request,
                    sess, OGS_NAS_ESM_CAUSE_PDN_TYPE_IPV6_ONLY_ALLOWED);
        }
    } else if (sess->ue_request_type.type == OGS_PDU_SESSION_TYPE_IPV6) {
        if (sess->paa.session_type == OGS_PDU_SESSION_TYPE_IPV4) {
            pdn_address->pdn_type = OGS_PDU_SESSION_TYPE_IPV4;
            mme_esm_set_pdn_type_cause(activate_default_eps_bearer_context_request,
                    sess, OGS_NAS_ESM_CAUSE_PDN_TYPE_IPV4_ONLY_ALLOWED);
        }
    }

    if (pdn_address->pdn_type == OGS_PDU_SESSION_TYPE_IPV4) {
        pdn_address->addr = sess->paa.addr;
        pdn_address->length = OGS_NAS_PDU_ADDRESS_IPV4_LEN;
        ogs_debug("    IPv4");
    } else if (pdn_address->pdn_type == OGS_PDU_SESSION_TYPE_IPV6) {
        memcpy(pdn_address->addr6,
                sess->paa.addr6+(OGS_IPV6_LEN>>1), OGS_IPV6_LEN>>1);
        pdn_address->length = OGS_NAS_PDU_ADDRESS_IPV6_LEN;
        ogs_debug("    IPv6");
    } else if (pdn_address->pdn_type == OGS_PDU_SESSION_TYPE_IPV4V6) {
        pdn_address->both.addr = sess->paa.both.addr;
        memcpy(pdn_address->both.addr6,
                sess->paa.both.addr6+(OGS_IPV6_LEN>>1), OGS_IPV6_LEN>>1);
        pdn_address->length = OGS_NAS_PDU_ADDRESS_IPV4V6_LEN;
        ogs_debug("    IPv4v6");
    } else {
        ogs_fatal("Unexpected PDN Type %u", pdn_address->pdn_type);
        ogs_assert_if_reached();
    }

    {
        ogs_bitrate_t sess_ambr = mme_sess_ambr_for_pdn(mme_ue, session);

        mme_ambr_apply_config(&sess_ambr);
        mme_ambr_complete_directions(&sess_ambr);
        if (!sess_ambr.uplink && !sess_ambr.downlink &&
                mme_self()->ambr_limit.enabled) {
            sess_ambr.uplink = mme_self()->ambr_limit.uplink_bps;
            sess_ambr.downlink = mme_self()->ambr_limit.downlink_bps;
        }
        if (sess_ambr.uplink && sess_ambr.downlink) {
            activate_default_eps_bearer_context_request->presencemask |=
                OGS_NAS_EPS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_APN_AMBR_PRESENT;
            apn_ambr_build(apn_ambr, sess_ambr.downlink, sess_ambr.uplink);
        }
    }

    if (sess->pgw_epco.presence && sess->pgw_epco.len && sess->pgw_epco.data) {
        activate_default_eps_bearer_context_request->presencemask |=
            OGS_NAS_EPS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_PRESENT;
        extended_protocol_configuration_options->length =
            sess->pgw_epco.len;
        extended_protocol_configuration_options->buffer =
            sess->pgw_epco.data;
    } else if (sess->pgw_pco.presence && sess->pgw_pco.len &&
            sess->pgw_pco.data) {
        activate_default_eps_bearer_context_request->presencemask |=
            OGS_NAS_EPS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_PROTOCOL_CONFIGURATION_OPTIONS_PRESENT;
        protocol_configuration_options->length = sess->pgw_pco.len;
        memcpy(protocol_configuration_options->buffer,
                sess->pgw_pco.data, protocol_configuration_options->length);
    }

    if (mme_self()->attach_accept.legacy_gprs_qos)
        mme_esm_add_legacy_gprs_qos(activate_default_eps_bearer_context_request);

    if (create_action == OGS_GTP_CREATE_IN_ATTACH_REQUEST)
        return ogs_nas_eps_plain_encode(&message);
    else
        return nas_eps_security_encode(mme_ue, &message);
}

ogs_pkbuf_t *esm_build_activate_dedicated_bearer_context_request(
        mme_bearer_t *bearer)
{
    mme_ue_t *mme_ue = NULL;
    mme_sess_t *sess = NULL;
    mme_bearer_t *linked_bearer = NULL;

    ogs_nas_eps_message_t message;
    ogs_nas_eps_activate_dedicated_eps_bearer_context_request_t 
        *activate_dedicated_eps_bearer_context_request =
            &message.esm.activate_dedicated_eps_bearer_context_request;
    ogs_nas_linked_eps_bearer_identity_t *linked_ebi =
        &activate_dedicated_eps_bearer_context_request->
            linked_eps_bearer_identity;
    ogs_nas_eps_quality_of_service_t *eps_qos =
        &activate_dedicated_eps_bearer_context_request->eps_qos;
    ogs_nas_traffic_flow_template_t *tft =
        &activate_dedicated_eps_bearer_context_request->tft;
    
    ogs_assert(bearer);
    sess = mme_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    mme_ue = mme_ue_find_by_id(bearer->mme_ue_id);
    ogs_assert(mme_ue);
    linked_bearer = mme_linked_bearer(bearer); 
    ogs_assert(linked_bearer);

    ogs_debug("Activate dedicated bearer context request");
    ogs_debug("    IMSI[%s] EBI[%d] Linked-EBI[%d]",
            mme_ue->imsi_bcd, bearer->ebi, linked_bearer->ebi);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
       OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.esm.h.eps_bearer_identity = bearer->ebi;
    message.esm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_ESM;

    /*
     * Issue #3072
     *
     * PTI 0 is set here to prevent a InitialContextSetupRequest message
     * with a PTI of 0 from being created when the Create Bearer Request occurs
     * and InitialContextSetupRequest occurs.
     *
     * If you implement the creation of a dedicated bearer
     * in the ESM procedure reqeusted by the UE,
     * you will need to refactor the part that sets the PTI.
     */
    message.esm.h.procedure_transaction_identity =
        sess->pti = OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED;

    message.esm.h.message_type =
        OGS_NAS_EPS_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST;

    linked_ebi->eps_bearer_identity = linked_bearer->ebi;
    eps_qos_build(eps_qos, bearer->qos.index,
            bearer->qos.mbr.downlink, bearer->qos.mbr.uplink,
            bearer->qos.gbr.downlink, bearer->qos.gbr.uplink);

    tft->length = bearer->tft.len;
    ogs_assert(tft->length);
    ogs_assert(bearer->tft.data);
    memcpy(tft->buffer, bearer->tft.data, tft->length);

    return nas_eps_security_encode(mme_ue, &message);
}

ogs_pkbuf_t *esm_build_modify_bearer_context_request(
        mme_bearer_t *bearer, int qos_presence, int tft_presence)
{
    mme_ue_t *mme_ue = NULL;
    mme_sess_t *sess = NULL;

    ogs_nas_eps_message_t message;
    ogs_nas_eps_modify_eps_bearer_context_request_t 
        *modify_eps_bearer_context_request =
            &message.esm.modify_eps_bearer_context_request;
    ogs_nas_eps_quality_of_service_t *new_eps_qos =
        &modify_eps_bearer_context_request->new_eps_qos;
    ogs_nas_traffic_flow_template_t *tft =
        &modify_eps_bearer_context_request->tft;

    ogs_assert(bearer);
    sess = mme_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    mme_ue = mme_ue_find_by_id(bearer->mme_ue_id);
    ogs_assert(mme_ue);

    ogs_debug("Modify bearer context request");
    ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
            mme_ue->imsi_bcd, sess->pti, bearer->ebi);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
       OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.esm.h.eps_bearer_identity = bearer->ebi;
    message.esm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_ESM;
    message.esm.h.procedure_transaction_identity = sess->pti;
    message.esm.h.message_type = OGS_NAS_EPS_MODIFY_EPS_BEARER_CONTEXT_REQUEST;

    if (qos_presence == 1) {
        modify_eps_bearer_context_request->presencemask |=
            OGS_NAS_EPS_MODIFY_EPS_BEARER_CONTEXT_REQUEST_NEW_EPS_QOS_PRESENT;
        eps_qos_build(new_eps_qos, bearer->qos.index,
                bearer->qos.mbr.downlink, bearer->qos.mbr.uplink,
                bearer->qos.gbr.downlink, bearer->qos.gbr.uplink);
    }

    if (tft_presence == 1) {
        modify_eps_bearer_context_request->presencemask |=
            OGS_NAS_EPS_MODIFY_EPS_BEARER_CONTEXT_REQUEST_TFT_PRESENT;
        tft->length = bearer->tft.len;
        ogs_assert(tft->length);
        ogs_assert(bearer->tft.data);
        memcpy(tft->buffer, bearer->tft.data, tft->length);
    }

    return nas_eps_security_encode(mme_ue, &message);
}

ogs_pkbuf_t *esm_build_deactivate_bearer_context_request(
        mme_bearer_t *bearer, ogs_nas_esm_cause_t esm_cause)
{
    mme_ue_t *mme_ue = NULL;
    mme_sess_t *sess = NULL;

    ogs_nas_eps_message_t message;
    ogs_nas_eps_deactivate_eps_bearer_context_request_t 
        *deactivate_eps_bearer_context_request =
            &message.esm.deactivate_eps_bearer_context_request;
    
    ogs_assert(bearer);
    sess = mme_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    mme_ue = mme_ue_find_by_id(bearer->mme_ue_id);
    ogs_assert(mme_ue);

    ogs_debug("Deactivate bearer context request");
    ogs_debug("    IMSI[%s] PTI[%d] EBI[%d]",
            mme_ue->imsi_bcd, sess->pti, bearer->ebi);
    ogs_debug("    Cause[%d]", esm_cause);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
       OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    message.esm.h.eps_bearer_identity = bearer->ebi;
    message.esm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_ESM;
    message.esm.h.procedure_transaction_identity = sess->pti;
    message.esm.h.message_type =
        OGS_NAS_EPS_DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST;

    deactivate_eps_bearer_context_request->esm_cause = esm_cause;

    return nas_eps_security_encode(mme_ue, &message);
}

ogs_pkbuf_t *esm_build_bearer_resource_allocation_reject(
        mme_ue_t *mme_ue, uint8_t pti, ogs_nas_esm_cause_t esm_cause)
{
    ogs_nas_eps_message_t message;
    ogs_nas_eps_bearer_resource_allocation_reject_t
        *bearer_resource_allocation_reject =
            &message.esm.bearer_resource_allocation_reject;

    ogs_assert(mme_ue);
    if (pti == OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED) {
        ogs_error("[%s] Bearer resource allocation reject: PTI unassigned",
                mme_ue->imsi_bcd);
        return NULL;
    }

    ogs_debug("Bearer resource allocation reject");
    ogs_debug("    IMSI[%s] PTI[%d] Cause[%d]",
            mme_ue->imsi_bcd, pti, esm_cause);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
       OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;

    message.esm.h.eps_bearer_identity = 0;
    message.esm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_ESM;
    message.esm.h.procedure_transaction_identity = pti;
    message.esm.h.message_type = OGS_NAS_EPS_BEARER_RESOURCE_ALLOCATION_REJECT;

    bearer_resource_allocation_reject->esm_cause = esm_cause;

    return nas_eps_security_encode(mme_ue, &message);
}

ogs_pkbuf_t *esm_build_bearer_resource_modification_reject(
        mme_ue_t *mme_ue, uint8_t pti, ogs_nas_esm_cause_t esm_cause)
{
    ogs_nas_eps_message_t message;
    ogs_nas_eps_bearer_resource_modification_reject_t
        *bearer_resource_modification_reject =
            &message.esm.bearer_resource_modification_reject;

    ogs_assert(mme_ue);
    if (pti == OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED) {
        ogs_error("[%s] Bearer resource modification reject: PTI unassigned",
                mme_ue->imsi_bcd);
        return NULL;
    }

    ogs_debug("Bearer resource modification reject");
    ogs_debug("    IMSI[%s] PTI[%d] Cause[%d]",
            mme_ue->imsi_bcd, pti, esm_cause);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
       OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    message.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;

    message.esm.h.eps_bearer_identity = 0;
    message.esm.h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_ESM;
    message.esm.h.procedure_transaction_identity = pti;
    message.esm.h.message_type =
        OGS_NAS_EPS_BEARER_RESOURCE_MODIFICATION_REJECT;

    bearer_resource_modification_reject->esm_cause = esm_cause;

    return nas_eps_security_encode(mme_ue, &message);
}
