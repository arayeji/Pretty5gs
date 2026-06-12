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

#ifndef SGWC_GTP_PATH_H
#define SGWC_GTP_PATH_H

#include "s11-build.h"

#ifdef __cplusplus
extern "C" {
#endif

int sgwc_gtp_open(void);
void sgwc_gtp_close(void);

void sgwc_gtp_send_mme_echo(ogs_gtp_node_t *gnode);
void sgwc_timer_mme_echo(void *data);
void sgwc_mme_peer_setup(ogs_gtp_node_t *gnode);

void sgwc_gtp_send_sgsn_echo(ogs_gtp_node_t *gnode);
void sgwc_timer_sgsn_echo(void *data);
void sgwc_sgsn_peer_start_echo(ogs_gtp_node_t *gnode);

void sgwc_gtp_send_pgw_echo(ogs_gtp_node_t *gnode);
void sgwc_timer_pgw_echo(void *data);
void sgwc_pgw_peer_setup(ogs_gtp_node_t *gnode);
int sgwc_gtp_send_network_delete_session(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess);
int sgwc_gtp_send_s5c_delete_session_request(sgwc_sess_t *sess);

bool sgwc_gtpc_roam_port_enabled(void);
int sgwc_gtp_connect_peer(sgwc_sess_t *sess, ogs_gtp_node_t *gnode);
void sgwc_gtpc_f_teid_addr(
        sgwc_sess_t *sess,
        ogs_sockaddr_t **addr, ogs_sockaddr_t **addr6);

int sgwc_gtp_send_create_session_response(
    sgwc_sess_t *sess, ogs_gtp_xact_t *xact);

int sgwc_gtp_send_create_pdp_context_response(
        sgwc_sess_t *sess, ogs_gtp_xact_t *gn_xact,
        ogs_gtp2_create_session_response_t *s5_rsp);
int sgwc_gtp_send_delete_pdp_context_response(
        sgwc_sess_t *sess, ogs_gtp_xact_t *gn_xact, uint8_t gtp1_cause);
int sgwc_gtp_send_update_pdp_context_response(
        ogs_gtp_xact_t *gn_xact, uint32_t sgsn_teid, ogs_pkbuf_t *pkbuf);

int sgwc_gtp_send_downlink_data_notification(
    uint8_t cause_value, sgwc_bearer_t *bearer);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_GTP_PATH_H */
