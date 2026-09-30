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

#include "mme-gtpc-select-match.h"

#include <string.h>

#include "ogs-core.h"

bool mme_gtpc_sel_keys_are_empty(const mme_gtpc_sel_keys_t *keys)
{
    ogs_assert(keys);

    return keys->num_of_apn == 0 &&
            keys->num_of_tac == 0 &&
            keys->num_of_e_cell_id == 0 &&
            !keys->imsi_plmn_present &&
            !keys->serving_plmn_present &&
            !(keys->imsi_prefix && keys->imsi_prefix[0]);
}

/* OR over the values of the apn key */
static bool apn_key_match(
        const mme_gtpc_sel_keys_t *keys, const mme_gtpc_sel_facts_t *facts)
{
    int i;

    /*
     * APN not known yet. Skip the entry — "APN unknown" is not a hit,
     * or an apn: entry would steal every UE that has no APN yet.
     */
    if (!facts->apn)
        return false;

    for (i = 0; i < keys->num_of_apn; i++)
        if (keys->apn[i] && !ogs_strcasecmp(keys->apn[i], facts->apn))
            return true;

    return false;
}

static bool tac_key_match(
        const mme_gtpc_sel_keys_t *keys, const mme_gtpc_sel_facts_t *facts)
{
    int i;

    if (!facts->tac_known)
        return false;

    for (i = 0; i < keys->num_of_tac; i++)
        if (keys->tac[i] == facts->tac)
            return true;

    return false;
}

static bool e_cell_id_key_match(
        const mme_gtpc_sel_keys_t *keys, const mme_gtpc_sel_facts_t *facts)
{
    int i;

    if (!facts->e_cell_id_known)
        return false;

    for (i = 0; i < keys->num_of_e_cell_id; i++)
        if (keys->e_cell_id[i] == facts->e_cell_id)
            return true;

    return false;
}

bool mme_gtpc_sel_match(const mme_gtpc_sel_keys_t *keys,
        const mme_gtpc_sel_facts_t *facts)
{
    ogs_assert(keys);
    ogs_assert(facts);

    /* The default entry is fallback only, never a match. */
    if (mme_gtpc_sel_keys_are_empty(keys))
        return false;

    /* Every key present on the entry must match (AND). */

    if (keys->num_of_apn > 0 && !apn_key_match(keys, facts))
        return false;

    if (keys->num_of_tac > 0 && !tac_key_match(keys, facts))
        return false;

    if (keys->num_of_e_cell_id > 0 && !e_cell_id_key_match(keys, facts))
        return false;

    if (keys->imsi_plmn_present) {
        if (!facts->imsi_known || !facts->imsi_bcd)
            return false;
        if (!ogs_plmn_id_imsi_prefix_match(
                    facts->imsi_bcd, &keys->imsi_plmn_id))
            return false;
    }

    if (keys->imsi_prefix && keys->imsi_prefix[0]) {
        size_t len = strlen(keys->imsi_prefix);

        if (!facts->imsi_known || !facts->imsi_bcd)
            return false;
        if (strncmp(facts->imsi_bcd, keys->imsi_prefix, len) != 0)
            return false;
    }

    if (keys->serving_plmn_present) {
        /* Shared RAN: the TAI PLMN is not this UE's home network. */
        if (facts->inbound_roam)
            return false;
        if (!facts->serving_plmn_known)
            return false;
        if (memcmp(&keys->serving_plmn_id, &facts->serving_plmn_id,
                    OGS_PLMN_ID_LEN) != 0)
            return false;
    }

    return true;
}

int mme_gtpc_sel_pick(const mme_gtpc_sel_keys_t *const *keys,
        const int *order, int num, const mme_gtpc_sel_facts_t *facts)
{
    int i, best = -1;

    ogs_assert(facts);
    if (num <= 0)
        return -1;
    ogs_assert(keys);
    ogs_assert(order);

    for (i = 0; i < num; i++) {
        if (!keys[i] || !mme_gtpc_sel_match(keys[i], facts))
            continue;
        if (best < 0 || order[i] < order[best])
            best = i;
    }

    return best;
}

mme_pdn_sgw_place_e mme_gtpc_pdn_sgw_place(bool wanted_is_primary,
        bool primary_unused, bool wanted_is_extra)
{
    /*
     * Extra first: after a primary reselect both contexts can point at
     * the same SGW, and the extra one already holds the S11 TEID there.
     */
    if (wanted_is_extra)
        return MME_PDN_SGW_EXTRA;
    if (wanted_is_primary)
        return MME_PDN_SGW_PRIMARY;
    if (primary_unused)
        return MME_PDN_SGW_RETARGET_PRIMARY;
    return MME_PDN_SGW_NEW_EXTRA;
}

int mme_gtpc_sgw_relocation_plan(int n, const int *cur, const int *want,
        int nctx, const int *ctx_sgw, const bool *ctx_ready,
        int *join, int *group)
{
    int i, j, c, moving = 0;

    for (i = 0; i < n; i++) {
        join[i] = -1;
        group[i] = -1;
        if (want[i] >= 0 && cur[i] >= 0 && cur[i] < nctx &&
                want[i] != ctx_sgw[cur[i]])
            group[i] = want[i];
    }

    for (i = 0; i < n; i++) {
        if (group[i] < 0)
            continue;
        moving++;

        for (c = 0; c < nctx; c++) {
            bool keeps = false;

            if (ctx_sgw[c] != want[i] || !ctx_ready[c])
                continue;
            for (j = 0; j < n && !keeps; j++)
                keeps = cur[j] == c && group[j] < 0 && join[j] < 0;
            if (keeps)
                break;
        }
        if (c < nctx) {
            join[i] = c;
            group[i] = -1;
        }
    }

    return moving;
}
