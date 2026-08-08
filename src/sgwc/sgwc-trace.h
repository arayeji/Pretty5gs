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

#ifndef SGWC_TRACE_H
#define SGWC_TRACE_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

void ogs_sgwc_trace_set(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess,
        const char *apn, const char *proc);

/* Bind IMSI onto GTP/PFCP xacts for PACKET dumps (not thread-local). */
void sgwc_trace_bind_gtp(ogs_gtp_xact_t *xact, sgwc_ue_t *sgwc_ue);
void sgwc_trace_bind_pfcp(ogs_pfcp_xact_t *xact, sgwc_sess_t *sess);
void sgwc_trace_pfcp_rx(ogs_pfcp_xact_t *xact, sgwc_sess_t *sess,
        const void *data, size_t len);

/*
 * Enriched per-UE log: full ogs_trace_format_prefix (IMSI, APN, PROC, TEIDs,
 * UE IP) on one line.  DEBUG is emitted when logger level is debug or
 * trace_imsi matches this subscriber.
 */
void sgwc_ue_log(
        sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess,
        const char *proc, const char *apn, int level,
        const char *fmt, ...) OGS_GNUC_PRINTF(6, 7);

/*
 * WARN with enriched prefix when no SGWC-UE context exists (IMSI shows as "-").
 * sgw_s11_teid from the GTP header is included when non-zero.
 */
void sgwc_ue_warn_no_ctx(
        const char *proc, uint32_t sgw_s11_teid,
        const char *fmt, ...) OGS_GNUC_PRINTF(3, 4);

#define sgwc_ue_info(ue, sess, proc, apn, ...) \
    sgwc_ue_log(ue, sess, proc, apn, OGS_LOG_INFO, __VA_ARGS__)
#define sgwc_ue_warn(ue, sess, proc, apn, ...) \
    sgwc_ue_log(ue, sess, proc, apn, OGS_LOG_WARN, __VA_ARGS__)
#define sgwc_ue_error(ue, sess, proc, apn, ...) \
    sgwc_ue_log(ue, sess, proc, apn, OGS_LOG_ERROR, __VA_ARGS__)
#define sgwc_ue_debug(ue, sess, proc, apn, ...) \
    sgwc_ue_log(ue, sess, proc, apn, OGS_LOG_DEBUG, __VA_ARGS__)

const char *sgwc_log_imsi(sgwc_ue_t *sgwc_ue);
void sgwc_log_mme_peer(char *buf, size_t buflen, sgwc_ue_t *sgwc_ue);
void sgwc_log_pgw_peer(char *buf, size_t buflen, sgwc_sess_t *sess);
void sgwc_log_sgwu_peer(char *buf, size_t buflen, sgwc_sess_t *sess);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_TRACE_H */
