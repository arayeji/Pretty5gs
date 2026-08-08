/*
 * Copyright (C) 2025 Open5GS contributors
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

#ifndef SMF_TRACE_H
#define SMF_TRACE_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

void ogs_smf_trace_set(
        smf_ue_t *smf_ue, smf_sess_t *sess,
        const char *proc);

void ogs_smf_trace_set_from_gtp2_create_session_request(
        ogs_gtp2_create_session_request_t *req, const char *proc);

void smf_trace_bind_gtp(ogs_gtp_xact_t *xact, smf_ue_t *smf_ue);
void smf_trace_bind_pfcp(ogs_pfcp_xact_t *xact, smf_sess_t *sess);
void smf_trace_pfcp_rx(ogs_pfcp_xact_t *xact, smf_sess_t *sess,
        const void *data, size_t len);

/*
 * Enriched per-UE log: full ogs_trace_format_prefix on one line.
 * DEBUG is emitted when logger level is debug or trace_imsi matches.
 */
void smf_ue_log(
        smf_ue_t *smf_ue, smf_sess_t *sess,
        const char *proc, int level,
        const char *fmt, ...) OGS_GNUC_PRINTF(5, 6);

#define smf_ue_info(ue, sess, proc, ...) \
    smf_ue_log(ue, sess, proc, OGS_LOG_INFO, __VA_ARGS__)
#define smf_ue_warn(ue, sess, proc, ...) \
    smf_ue_log(ue, sess, proc, OGS_LOG_WARN, __VA_ARGS__)
#define smf_ue_error(ue, sess, proc, ...) \
    smf_ue_log(ue, sess, proc, OGS_LOG_ERROR, __VA_ARGS__)
#define smf_ue_debug(ue, sess, proc, ...) \
    smf_ue_log(ue, sess, proc, OGS_LOG_DEBUG, __VA_ARGS__)

const char *smf_log_id(smf_ue_t *smf_ue);
void smf_log_sgw_peer(char *buf, size_t buflen, smf_sess_t *sess);
void smf_log_upf_peer(char *buf, size_t buflen, smf_sess_t *sess);

#ifdef __cplusplus
}
#endif

#endif /* SMF_TRACE_H */
