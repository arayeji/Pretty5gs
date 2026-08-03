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

#include "mme-access-control-match.h"

#include <limits.h>
#include <string.h>

#include "ogs-core.h"

mme_access_control_t *mme_access_control_find_for_imsi(
        mme_access_control_t *acs, int num, const char *imsi_bcd)
{
    int i, best = -1, best_prefix_len = -1, best_order = INT_MAX;

    ogs_assert(imsi_bcd);
    if (!acs || num <= 0)
        return NULL;

    for (i = 0; i < num; i++) {
        mme_access_control_t *ac = &acs[i];
        size_t prefix_len;

        if (ac->imsi_prefix[0]) {
            prefix_len = strlen(ac->imsi_prefix);
            if (prefix_len == 0)
                continue;
            if (strncmp(imsi_bcd, ac->imsi_prefix, prefix_len) != 0)
                continue;
            if ((int)prefix_len > best_prefix_len ||
                    ((int)prefix_len == best_prefix_len &&
                     ac->selection_order < best_order)) {
                best_prefix_len = (int)prefix_len;
                best_order = ac->selection_order;
                best = i;
            }
            continue;
        }

        if (ac->plmn_id_configured &&
                ogs_plmn_id_imsi_prefix_match(imsi_bcd, &ac->plmn_id)) {
            if (best_prefix_len < 5 ||
                    (best_prefix_len == 5 &&
                     ac->selection_order < best_order)) {
                if (best_prefix_len < 5)
                    best_prefix_len = 5;
                best_order = ac->selection_order;
                best = i;
            }
        }
    }

    if (best < 0)
        return NULL;

    return &acs[best];
}

bool mme_access_control_eplmn_tac_allowed_for(
        mme_access_control_t *acs, int num,
        const char *imsi_bcd, uint16_t tac)
{
    mme_access_control_t *ac;

    if (!imsi_bcd || !imsi_bcd[0])
        return false;

    ac = mme_access_control_find_for_imsi(acs, num, imsi_bcd);
    if (!ac)
        return false;

    if (!ac->tac_hash)
        return true;

    return ogs_hash_get(ac->tac_hash, &tac, sizeof(tac)) != NULL;
}
