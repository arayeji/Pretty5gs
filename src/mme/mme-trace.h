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

#ifndef MME_TRACE_H
#define MME_TRACE_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

void ogs_mme_trace_set(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue,
        const char *apn, const char *proc);
void ogs_mme_trace_from_ids(
        ogs_pool_id_t enb_ue_id, ogs_pool_id_t mme_ue_id,
        const char *apn, const char *proc);

/* Move TLS-bound S1AP RX copy onto enb_ue for dump after IMSI is known. */
void mme_enb_ue_s1ap_trace_take_bound(enb_ue_t *enb_ue);
void mme_enb_ue_s1ap_trace_dump(enb_ue_t *enb_ue, const char *imsi_bcd);
void mme_enb_ue_s1ap_trace_clear(enb_ue_t *enb_ue);

/* Attach/SGW pipeline breadcrumbs (INFO; ERROR for *_fail / attach_reject /
 * attach_accept_no_s1 / attach_accept_fail / sgsap_lu_reject) */
void mme_ue_progress(mme_ue_t *mme_ue, const char *step);

/* Service-request logs with full trace prefix (IMSI, TEIDs, S1AP IDs) */
void mme_ue_service_progress(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue, const char *step);
void mme_ue_service_info(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue, const char *fmt, ...)
    OGS_GNUC_PRINTF(3, 4);
void mme_ue_service_error(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue, const char *fmt, ...)
    OGS_GNUC_PRINTF(3, 4);

/*
 * Enriched per-UE log: full ogs_trace_format_prefix (IMSI, ENB, S1AP, EBI,
 * APN, PROC, TEIDs) on one line.  DEBUG is emitted when logger level is
 * debug or mme.trace_imsi matches this subscriber.
 */
void mme_ue_log(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue,
        const char *proc, const char *apn, int level,
        const char *fmt, ...) OGS_GNUC_PRINTF(6, 7);

#define mme_ue_info(ue, enb, proc, apn, ...) \
    mme_ue_log(ue, enb, proc, apn, OGS_LOG_INFO, __VA_ARGS__)
#define mme_ue_warn(ue, enb, proc, apn, ...) \
    mme_ue_log(ue, enb, proc, apn, OGS_LOG_WARN, __VA_ARGS__)
#define mme_ue_error(ue, enb, proc, apn, ...) \
    mme_ue_log(ue, enb, proc, apn, OGS_LOG_ERROR, __VA_ARGS__)
#define mme_ue_debug(ue, enb, proc, apn, ...) \
    mme_ue_log(ue, enb, proc, apn, OGS_LOG_DEBUG, __VA_ARGS__)

/*
 * Per-UE log when mme_ue/enb_ue is available; eNB-only trace when only enb is
 * known; plain ogs_error otherwise.
 */
void mme_ran_error(
        mme_enb_t *enb, enb_ue_t *enb_ue, mme_ue_t *mme_ue,
        const char *proc, const char *apn, const char *fmt, ...)
    OGS_GNUC_PRINTF(6, 7);
void mme_ran_warn(
        mme_enb_t *enb, enb_ue_t *enb_ue, mme_ue_t *mme_ue,
        const char *proc, const char *apn, const char *fmt, ...)
    OGS_GNUC_PRINTF(6, 7);

void mme_sess_removed_log(mme_ue_t *mme_ue, const char *apn);
void mme_bearer_added_log(mme_ue_t *mme_ue, mme_bearer_t *bearer);
void mme_bearer_removed_log(mme_ue_t *mme_ue, mme_bearer_t *bearer);

/* Serialize freeDiameter msg → PACKET: proto=diameter (filter-gated). */
struct msg;
void mme_trace_diameter(
        const char *imsi_bcd, const char *dir, struct msg *msg);

/* Context strings for ogs_error/ogs_warn (IMSI, peers, radio) */
const char *mme_log_imsi(mme_ue_t *mme_ue);
void mme_log_gtp_peer(char *buf, size_t buflen, ogs_gtp_node_t *gnode);
void mme_log_pgw_peer(char *buf, size_t buflen, mme_sess_t *sess);
void mme_log_radio(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue,
        uint16_t *tac, uint32_t *cell_id, uint32_t *enb_id);

#ifdef __cplusplus
}
#endif

#endif /* MME_TRACE_H */
