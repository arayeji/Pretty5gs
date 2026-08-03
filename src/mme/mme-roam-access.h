/*
 * Copyright (C) 2026 by Open5GS Contributors
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

#ifndef MME_ROAM_ACCESS_H
#define MME_ROAM_ACCESS_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mme_ue_s mme_ue_t;
typedef struct enb_ue_s enb_ue_t;
typedef struct mme_access_control_s mme_access_control_t;

void mme_access_control_free_all(void);
bool mme_access_control_tac_add(mme_access_control_t *ac, uint16_t tac);
bool mme_access_control_enb_add(mme_access_control_t *ac, uint32_t enb_id);

/*
 * Inbound roam only: IMSI prefix / PLMN whitelist plus optional TAC / eNB-ID
 * allow-lists on access_control entries.
 * Returns OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED when allowed or not applicable.
 */
uint8_t mme_inbound_roam_access_emm_cause(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue);

/*
 * When attach_accept.equivalent_plmn_access_control_tac is enabled, call this
 * before including the EPLMN IE. Uses the UE's matched access_control entry
 * and that entry's TAC allow-list (see mme_access_control_eplmn_tac_allowed_for).
 */
bool mme_access_control_eplmn_tac_allowed(mme_ue_t *mme_ue);

#ifdef __cplusplus
}
#endif

#endif /* MME_ROAM_ACCESS_H */
