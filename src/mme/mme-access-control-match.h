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

#ifndef MME_ACCESS_CONTROL_MATCH_H
#define MME_ACCESS_CONTROL_MATCH_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mme_access_control_s {
    int reject_cause;
    ogs_plmn_id_t plmn_id;
    bool plmn_id_configured;
    char imsi_prefix[OGS_MAX_IMSI_BCD_LEN + 1];
    int selection_order;
    ogs_hash_t *tac_hash;
    ogs_hash_t *enb_id_hash;
} mme_access_control_t;

/*
 * Longest IMSI-prefix match, else PLMN match — same rules as inbound roam
 * access_control selection.
 */
mme_access_control_t *mme_access_control_find_for_imsi(
        mme_access_control_t *acs, int num, const char *imsi_bcd);

/*
 * EPLMN TAC gate (option 1):
 *  - no matching access_control entry → false
 *  - match with no tac list → true
 *  - match with tac list → true iff tac is listed
 */
bool mme_access_control_eplmn_tac_allowed_for(
        mme_access_control_t *acs, int num,
        const char *imsi_bcd, uint16_t tac);

#ifdef __cplusplus
}
#endif

#endif /* MME_ACCESS_CONTROL_MATCH_H */
