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

#ifndef SGWC_GN_BUILD_H
#define SGWC_GN_BUILD_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

uint8_t sgwc_gtp2_to_gtp1_cause(uint8_t gtp2_cause);

ogs_pkbuf_t *sgwc_gn_build_create_session_request_pkbuf(
        sgwc_sess_t *sess, sgwc_ue_t *sgwc_ue,
        ogs_gtp1_create_pdp_context_request_t *req);

ogs_pkbuf_t *sgwc_gn_build_create_pdp_context_response(
        uint8_t type, sgwc_sess_t *sess,
        ogs_gtp2_create_session_response_t *s5_rsp);

ogs_pkbuf_t *sgwc_gn_build_delete_pdp_context_response(
        uint8_t type, sgwc_sess_t *sess, uint8_t cause);

ogs_pkbuf_t *sgwc_gn_build_update_pdp_context_response(
        uint8_t type, sgwc_sess_t *sess, uint8_t cause);

ogs_pkbuf_t *sgwc_gn_build_modify_bearer_request_pkbuf(
        sgwc_sess_t *sess, ogs_gtp1_update_pdp_context_request_t *req);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_GN_BUILD_H */
