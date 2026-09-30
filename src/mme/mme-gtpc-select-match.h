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

#ifndef MME_GTPC_SELECT_MATCH_H
#define MME_GTPC_SELECT_MATCH_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Match keys of one gtpc.client.smf / gtpc.client.sgwc YAML entry.
 *
 *   - keys present on the SAME entry are ANDed
 *     (apn + plmn_id = that APN for that IMSI PLMN only)
 *   - values of ONE key are ORed (apn: [ims, volte], tac: [1, 2])
 *
 * An entry with no key at all is the "default" entry: it never matches
 * here, the caller uses it as fallback when nothing matched.
 */
typedef struct mme_gtpc_sel_keys_s {
    const char          **apn;
    int                 num_of_apn;

    const uint16_t      *tac;
    int                 num_of_tac;

    const uint32_t      *e_cell_id;
    int                 num_of_e_cell_id;

    /* IMSI home PLMN (YAML imsi_plmn_id, or plmn_id in imsi-plmn mode) */
    bool                imsi_plmn_present;
    ogs_plmn_id_t       imsi_plmn_id;

    /* TAI PLMN (YAML serving_plmn_id) */
    bool                serving_plmn_present;
    ogs_plmn_id_t       serving_plmn_id;

    /* NULL or "" when the entry has no imsi_prefix */
    const char          *imsi_prefix;
} mme_gtpc_sel_keys_t;

/*
 * What the MME knows about the UE / session at selection time.
 *
 * A key whose fact is not known yet never matches, so an entry listing
 * that key is skipped instead of being treated as a hit. In particular
 * apn == NULL (APN not known yet) skips every entry carrying apn:.
 */
typedef struct mme_gtpc_sel_facts_s {
    /* Session APN, or NULL when it is not known yet */
    const char          *apn;

    bool                tac_known;
    uint16_t            tac;

    bool                e_cell_id_known;
    uint32_t            e_cell_id;

    /* imsi_bcd is valid only when imsi_known */
    bool                imsi_known;
    const char          *imsi_bcd;

    bool                serving_plmn_known;
    ogs_plmn_id_t       serving_plmn_id;

    /*
     * The UE is roaming in on this TAI. serving_plmn_id is then the TAI
     * PLMN of a shared RAN, so the serving_plmn_id key does not apply.
     */
    bool                inbound_roam;
} mme_gtpc_sel_facts_t;

/* true when the entry carries no match key at all (the default entry) */
bool mme_gtpc_sel_keys_are_empty(const mme_gtpc_sel_keys_t *keys);

/*
 * true only when EVERY key present on the entry matches. Always false
 * for an empty (default) key set.
 */
bool mme_gtpc_sel_match(const mme_gtpc_sel_keys_t *keys,
        const mme_gtpc_sel_facts_t *facts);

/*
 * Index of the lowest-order entry whose keys all match, -1 when none
 * does. Empty (default) entries never win here. Ties keep the first.
 */
int mme_gtpc_sel_pick(const mme_gtpc_sel_keys_t *const *keys,
        const int *order, int num, const mme_gtpc_sel_facts_t *facts);

/*
 * mme.sgwc_selection: per_pdn places each PDN on one of at most two S11
 * contexts per UE: the UE's SGW (primary) or one extra SGW.
 */
typedef enum {
    MME_PDN_SGW_PRIMARY = 0,
    MME_PDN_SGW_EXTRA,          /* reuse the existing extra context */
    MME_PDN_SGW_NEW_EXTRA,      /* create the extra context */
    MME_PDN_SGW_PRIMARY_LIMIT,  /* wanted a third SGW: stays on primary */
} mme_pdn_sgw_place_e;

/*
 * rule_hit:           an apn: entry matched this PDN
 * wanted_is_primary:  the wanted SGW has the primary context's address
 * have_extra:         the UE already holds the extra context
 * wanted_is_extra:    the wanted SGW has the extra context's address
 *
 * Without a rule hit the wanted SGW is the primary one.
 */
mme_pdn_sgw_place_e mme_gtpc_pdn_sgw_place(bool rule_hit,
        bool wanted_is_primary, bool have_extra, bool wanted_is_extra);

#ifdef __cplusplus
}
#endif

#endif /* MME_GTPC_SELECT_MATCH_H */
