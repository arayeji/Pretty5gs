/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

/*
 * Collapsed SAEGW-C phase 2: S8 relay (SGW-C role) for home-routed roamers.
 *
 * When the MME sends an S11 Create Session Request whose "PGW S5/S8 Address
 * for Control Plane" is NOT one of our own GTP-C addresses, the session is
 * home-routed: the SMF relays GTPv2-C between the MME (S11) and the home
 * PGW (S5/S8) and programs the UPF as a pure GTP-U forwarder between the
 * eNB (S1-U) and the home PGW (S5/S8-U). No UE IP anchoring, no Gx/Gy.
 *
 * Message flow (mirrors src/sgwc):
 *   S11 CSR -> PFCP Session Establishment (UPF chooses both F-TEIDs)
 *           -> S5 CSR to home PGW (rewritten in place)
 *           -> S5 CSR rsp: learn PGW-S5U, PFCP modify (UL FAR -> FORW+OHC)
 *           -> S11 CSR rsp to MME (rewritten in place)
 *   Modify Bearer / Release Access Bearers / DDN reuse the sess->s11 paths.
 *   S11 DSR -> S5 DSR -> S5 DSR rsp -> PFCP deletion -> S11 DSR rsp.
 *   PGW-initiated Update/Delete Bearer are relayed 1:1 both directions.
 */

#ifndef SMF_S11_RELAY_H
#define SMF_S11_RELAY_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

/* S11 CSR for a remote PGW: prepare the relay session (PGW node, UPF,
 * forwarding PDR/FARs) and send the PFCP Session Establishment Request.
 * The session has already been created by the generic CSR path. */
void smf_s11_relay_handle_create_session_request(
        smf_sess_t *sess, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message);

/* PFCP Session Establishment Response for a relay session: map the
 * UPF-chosen F-TEIDs, rewrite the buffered S11 CSR and send it to the
 * home PGW as an S5 Create Session Request. */
void smf_s11_relay_pfcp_establishment_response(
        smf_sess_t *sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_gtp2_message_t *recv_message,
        ogs_pfcp_session_establishment_response_t *rsp);

/* S5 Create Session Response from the home PGW: learn the PGW C/U TEIDs,
 * activate the UL FAR towards the PGW; the PFCP Session Modification
 * Response then triggers smf_s11_relay_forward_create_session_response(). */
void smf_s11_relay_handle_create_session_response(
        smf_sess_t *sess, ogs_gtp_xact_t *s5c_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message);

/* Rewrite the buffered S5 Create Session Response and forward it to the
 * MME over S11 (called from the PFCP modification-response handler). */
void smf_s11_relay_forward_create_session_response(
        smf_sess_t *sess, ogs_gtp_xact_t *s11_xact,
        ogs_gtp2_message_t *recv_message);

/* S11 Delete Session Request: relay it to the home PGW. */
void smf_s11_relay_handle_delete_session_request(
        smf_sess_t *sess, ogs_gtp_xact_t *s11_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message);

/* S5 Delete Session Response from the home PGW: delete the PFCP session;
 * the deletion response then triggers the S11 relay + session removal. */
void smf_s11_relay_handle_delete_session_response(
        smf_sess_t *sess, ogs_gtp_xact_t *s5c_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp2_message_t *message);

/* PFCP Session Deletion Response for a relay session: forward the buffered
 * S5 Delete Session Response to the MME and remove the session. */
void smf_s11_relay_pfcp_deletion_response(
        smf_sess_t *sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_gtp2_message_t *recv_message);

/* PGW-initiated Update/Delete Bearer Request: relay 1:1 to the MME. */
void smf_s11_relay_bearer_request_to_mme(
        smf_sess_t *sess, ogs_gtp_xact_t *s5c_xact,
        ogs_gtp2_message_t *message);

/* MME's Update/Delete Bearer Response: relay 1:1 back to the home PGW.
 * A Delete Bearer Response for the default bearer (Linked EBI present)
 * additionally tears down the PFCP session and removes the session. */
void smf_s11_relay_bearer_response_to_pgw(
        smf_sess_t *sess, ogs_gtp_xact_t *s11_xact,
        ogs_gtp2_message_t *message);

#ifdef __cplusplus
}
#endif

#endif /* SMF_S11_RELAY_H */
