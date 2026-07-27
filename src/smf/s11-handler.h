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
 * Collapsed SAEGW-C: S11 server role of the SMF.
 *
 * When smf.collapsed is enabled the MME talks S11 directly to the SMF
 * (no SGW-C in the path) and the UPF terminates S1-U from the eNB.
 * This module holds the S11-only procedures (classification, Release
 * Access Bearers, Downlink Data Notification); Create Session / Modify
 * Bearer / Delete Session reuse the S5C handlers with sess->s11 branches.
 */

#ifndef SMF_S11_HANDLER_H
#define SMF_S11_HANDLER_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

/* True if the Create Session Request came from an MME over S11
 * (sender F-TEID interface type == S11 MME GTP-C). */
bool smf_s11_csr_is_s11(ogs_gtp2_create_session_request_t *req);

/* True if the "PGW S5/S8 Address for Control Plane" chosen by the MME is
 * one of our own GTP-C addresses (or the IE is absent), i.e. the session
 * is anchored locally and we serve as collapsed SGW-C+PGW-C.
 * False means home-routed roaming (S8 relay), which is not supported yet. */
bool smf_s11_csr_pgw_is_local(ogs_gtp2_create_session_request_t *req);

/* Find the UE session owning EPS Bearer ID `ebi` (S11 TEIDs are UE-scoped
 * at the MME, so any of the UE's session TEIDs may appear in the header). */
smf_sess_t *smf_s11_sess_find_by_ebi(smf_sess_t *any_sess, uint8_t ebi);

/* TAU / path-switch with SGW relocation: if the S11 Create Session Request
 * carries a PGW S5/S8 F-TEID matching an existing session (locally
 * anchored, or an S8 relay towards that PGW when pgw_is_remote), return
 * that session so it can be adopted instead of duplicated. */
smf_sess_t *smf_s11_csr_find_reanchor_sess(
        ogs_gtp2_create_session_request_t *req, bool pgw_is_remote);

/* Adopt an existing session for a re-anchoring Create Session Request:
 * update the MME endpoint, point the DL FAR at the new eNB F-TEID
 * (path-switch) or buffer (idle TAU), then answer with a Create Session
 * Response built from the existing session state. */
void smf_s11_handle_reanchor_csr(
        smf_sess_t *sess, ogs_gtp_xact_t *xact, ogs_pkbuf_t *gtpbuf,
        ogs_gtp2_create_session_request_t *req);

void smf_s11_handle_release_access_bearers_request(
        smf_sess_t *sess, ogs_gtp_xact_t *xact, ogs_pkbuf_t *gtpbuf,
        ogs_gtp2_release_access_bearers_request_t *req);

void smf_s11_handle_downlink_data_notification_ack(
        smf_sess_t *sess, ogs_gtp_xact_t *xact,
        ogs_gtp2_downlink_data_notification_acknowledge_t *ack);

/* Send Downlink Data Notification to the MME for `bearer`
 * (triggered by a PFCP Session Report / Downlink Data Report). */
int smf_s11_send_downlink_data_notification(
        uint8_t cause_value, smf_bearer_t *bearer);

#ifdef __cplusplus
}
#endif

#endif /* SMF_S11_HANDLER_H */
