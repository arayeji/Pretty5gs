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

#include "ogs-core.h"
#include "core/abts.h"

#include "mme-access-control-match.h"

static void ac_add_tac(mme_access_control_t *ac, uint16_t tac)
{
    uint16_t *key;

    if (!ac->tac_hash)
        ac->tac_hash = ogs_hash_make();
    key = ogs_calloc(1, sizeof(*key));
    ogs_assert(key);
    *key = tac;
    ogs_hash_set(ac->tac_hash, key, sizeof(*key), (void *)(intptr_t)1);
}

static void ac_free_tac_hash(mme_access_control_t *ac)
{
    ogs_hash_index_t *hi;

    if (!ac->tac_hash)
        return;
    for (hi = ogs_hash_first(ac->tac_hash); hi; hi = ogs_hash_next(hi)) {
        void *key;

        ogs_hash_this(hi, (const void **)&key, NULL, NULL);
        ogs_free(key);
    }
    ogs_hash_destroy(ac->tac_hash);
    ac->tac_hash = NULL;
}

static void access_control_eplmn_tac_test(abts_case *tc, void *data)
{
    mme_access_control_t ac[2];

    memset(ac, 0, sizeof(ac));
    ogs_cpystrn(ac[0].imsi_prefix, "43235", sizeof(ac[0].imsi_prefix));
    ac[0].selection_order = 0;
    ac_add_tac(&ac[0], 1234);
    ac_add_tac(&ac[0], 1235);

    /* Match + TAC hit */
    ABTS_TRUE(tc, mme_access_control_eplmn_tac_allowed_for(
                ac, 1, "432351234567890", 1234));
    /* Match + TAC miss */
    ABTS_TRUE(tc, !mme_access_control_eplmn_tac_allowed_for(
                ac, 1, "432351234567890", 9999));
    /* No IMSI match */
    ABTS_TRUE(tc, !mme_access_control_eplmn_tac_allowed_for(
                ac, 1, "432111234567890", 1234));

    ac_free_tac_hash(&ac[0]);

    /* Match with no tac list → allowed on any TAC */
    ABTS_TRUE(tc, mme_access_control_eplmn_tac_allowed_for(
                ac, 1, "432351234567890", 1));
    ABTS_TRUE(tc, mme_access_control_eplmn_tac_allowed_for(
                ac, 1, "432351234567890", 65535));

    /* Empty access_control */
    ABTS_TRUE(tc, !mme_access_control_eplmn_tac_allowed_for(
                NULL, 0, "432351234567890", 1234));
}

abts_suite *test_access_control_eplmn(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, access_control_eplmn_tac_test, NULL);

    return suite;
}
