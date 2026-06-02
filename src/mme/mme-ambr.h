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

#ifndef MME_AMBR_H
#define MME_AMBR_H

#include "ogs-proto.h"
#include "ogs-gtp.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mme_ue_s;
struct mme_sess_s;
typedef struct mme_ue_s mme_ue_t;
typedef struct mme_sess_s mme_sess_t;

#define MME_AMBR_UNLIMITED_BPS UINT32_MAX
/* Some HSS profiles use 2^30 bps instead of 0xFFFFFFFF for "unlimited". */
#define MME_AMBR_HSS_LARGE_BPS 1073741824u

bool mme_ambr_bps_meaningful(uint32_t bps);
void mme_ambr_sanitize_bitrate(ogs_bitrate_t *ambr);
void mme_ambr_complete_directions(ogs_bitrate_t *ambr);

/* PDN type for CSR from HSS session type and UE request (home-PGW roam tweak). */
uint8_t mme_gtp2_pdn_type_for_sess(
        ogs_session_t *session, uint8_t ue_request_type);

void mme_ambr_apply_config(ogs_bitrate_t *ambr);

/*
 * PDN AMBR for GTP/NAS: per-APN AMBR from HSS when present, otherwise
 * subscribed UE-AMBR (TS 23.401 default bearer / PDN connectivity).
 * HSS sentinel 0xFFFFFFFF is treated as unset (unlimited / not specified).
 */
ogs_bitrate_t mme_sess_ambr_for_pdn(mme_ue_t *mme_ue, ogs_session_t *session);

bool mme_epc_qci_is_gbr(uint8_t qci);

/*
 * Bearer QoS MBR/GBR: use qos->mbr/gbr when already set (e.g. PCRF later);
 * for GBR QCIs, set MBR/GBR from effective PDN AMBR when unset.
 * Non-GBR (e.g. QCI 9) leaves MBR/GBR at zero on GTP/NAS (AMBR IE carries rates).
 */
void mme_qos_fill_bearer_bitrates(
        mme_ue_t *mme_ue, ogs_session_t *session, ogs_qos_t *qos);

void mme_gtp2_bearer_qos_from_session(
        ogs_gtp2_bearer_qos_t *bearer_qos,
        mme_ue_t *mme_ue, ogs_session_t *session);

/* TS 29.274 Selection Mode for CSR from UE request vs HSS Service-Selection */
uint8_t mme_gtp2_selection_mode_for_sess(
        mme_ue_t *mme_ue, mme_sess_t *sess, ogs_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* MME_AMBR_H */
