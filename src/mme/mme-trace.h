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

/* DEBUG for one UE when IMSI is on ogs_trace_filter list (no restart) */
void mme_ue_debug(mme_ue_t *mme_ue, const char *fmt, ...)
    OGS_GNUC_PRINTF(2, 3);

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
