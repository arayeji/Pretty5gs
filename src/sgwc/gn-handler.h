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

#ifndef SGWC_GN_HANDLER_H
#define SGWC_GN_HANDLER_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

void sgwc_gn_handle_echo_request(
        ogs_gtp_xact_t *xact, ogs_gtp1_echo_request_t *req);

bool sgwc_gn_handle_known_request(
        ogs_gtp_node_t *gnode, ogs_pkbuf_t *recvbuf);

void sgwc_gn_handle_create_pdp_context_request(
        sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *gn_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp1_message_t *message);

void sgwc_gn_handle_delete_pdp_context_request(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess, ogs_gtp_xact_t *gn_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp1_message_t *message);

void sgwc_gn_handle_update_pdp_context_request(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess, ogs_gtp_xact_t *gn_xact,
        ogs_pkbuf_t *gtpbuf, ogs_gtp1_message_t *message);

void sgwc_gn_csr_replace_continue(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *old_sess, bool proceed);

void sgwc_gn_send_create_reject(
        sgwc_sess_t *sess, sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *gn_xact,
        uint8_t gtp2_cause);

void sgwc_gtp_create_reject(
        sgwc_sess_t *sess, sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *xact,
        uint8_t gtp2_cause);

void sgwc_create_session_reject_and_cleanup(
        sgwc_sess_t *sess, sgwc_ue_t *sgwc_ue, ogs_gtp_xact_t *s11_xact,
        uint8_t gtp2_cause);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_GN_HANDLER_H */
