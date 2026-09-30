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
#include "ogs-app.h"
#include "core/abts.h"

#include "../../src/mme/mme-gtpc-select-match.h"

#define IMSI_HOME       "432120123456789"
#define IMSI_OTHER      "432110123456789"

static ogs_plmn_id_t plmn_home;     /* 432-12, matches IMSI_HOME */
static ogs_plmn_id_t plmn_other;    /* 432-11, matches IMSI_OTHER */

static void plmn_init(void)
{
    ogs_plmn_id_build(&plmn_home, 432, 12, 2);
    ogs_plmn_id_build(&plmn_other, 432, 11, 2);
}

/* Facts as the MME knows them when it picks an SMF for one session. */
static void sess_facts(mme_gtpc_sel_facts_t *facts,
        const char *apn, const char *imsi_bcd, uint16_t tac)
{
    memset(facts, 0, sizeof(*facts));

    facts->apn = apn;
    facts->imsi_known = imsi_bcd ? true : false;
    facts->imsi_bcd = imsi_bcd;
    facts->tac_known = true;
    facts->tac = tac;
    facts->e_cell_id_known = true;
    facts->e_cell_id = 0x1234501;
    facts->serving_plmn_known = true;
    facts->serving_plmn_id = plmn_home;
}

/*
 * One smf entry, apn: [ims] + plmn_id: 432-12 — that APN for that IMSI
 * PLMN only, not either of them.
 */
static void gtpc_select_and_test(abts_case *tc, void *data)
{
    mme_gtpc_sel_keys_t keys;
    mme_gtpc_sel_facts_t facts;
    const char *apn[OGS_MAX_NUM_OF_APN];

    plmn_init();

    memset(&keys, 0, sizeof(keys));
    apn[0] = "ims";
    keys.apn = apn;
    keys.num_of_apn = 1;
    keys.imsi_plmn_present = true;
    keys.imsi_plmn_id = plmn_home;

    /* An entry carrying keys is never the default entry. */
    ABTS_TRUE(tc, mme_gtpc_sel_keys_are_empty(&keys) == false);

    /* ims + 432-12 -> hit */
    sess_facts(&facts, "ims", IMSI_HOME, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == true);

    /* same PLMN but the internet APN -> AND fails, must NOT hit */
    sess_facts(&facts, "internet", IMSI_HOME, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == false);

    /* right APN, other IMSI PLMN -> must NOT hit */
    sess_facts(&facts, "ims", IMSI_OTHER, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == false);

    /* right APN, IMSI not known yet -> must NOT hit */
    sess_facts(&facts, "ims", NULL, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == false);

    /* APN not known yet -> must NOT hit */
    sess_facts(&facts, NULL, IMSI_HOME, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == false);
}

/* Values of ONE key are ORed; the keys themselves are still ANDed. */
static void gtpc_select_or_within_key_test(abts_case *tc, void *data)
{
    mme_gtpc_sel_keys_t keys;
    mme_gtpc_sel_facts_t facts;
    const char *apn[OGS_MAX_NUM_OF_APN];
    uint16_t tac[2] = { 1, 2 };

    plmn_init();

    /* apn: [ims, volte] + tac: [1, 2] */
    memset(&keys, 0, sizeof(keys));
    apn[0] = "ims";
    apn[1] = "volte";
    keys.apn = apn;
    keys.num_of_apn = 2;
    keys.tac = tac;
    keys.num_of_tac = 2;

    sess_facts(&facts, "volte", IMSI_HOME, 2);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == true);

    sess_facts(&facts, "ims", IMSI_HOME, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == true);

    /* APN listed, TAC not -> AND fails */
    sess_facts(&facts, "ims", IMSI_HOME, 3);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == false);

    /* TAC listed, APN not -> AND fails */
    sess_facts(&facts, "internet", IMSI_HOME, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == false);

    /* APN comparison stays case-insensitive */
    sess_facts(&facts, "IMS", IMSI_HOME, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == true);
}

/*
 * Before any APN exists (UE creation, IMSI known) an apn-keyed entry
 * must not match, and a PLMN/TAC entry must win instead.
 */
static void gtpc_select_sgw_apn_never_wins_test(abts_case *tc, void *data)
{
    mme_gtpc_sel_keys_t apn_only, plmn_entry, tac_entry;
    mme_gtpc_sel_facts_t facts;
    const char *apn[OGS_MAX_NUM_OF_APN];
    uint16_t tac[1] = { 7 };

    plmn_init();

    memset(&apn_only, 0, sizeof(apn_only));
    apn[0] = "ims";
    apn_only.apn = apn;
    apn_only.num_of_apn = 1;

    memset(&plmn_entry, 0, sizeof(plmn_entry));
    plmn_entry.imsi_plmn_present = true;
    plmn_entry.imsi_plmn_id = plmn_home;

    memset(&tac_entry, 0, sizeof(tac_entry));
    tac_entry.tac = tac;
    tac_entry.num_of_tac = 1;

    /* An apn-only entry is a filtered entry, so it is not the default. */
    ABTS_TRUE(tc, mme_gtpc_sel_keys_are_empty(&apn_only) == false);

    /* IMSI known, no APN: the SGW reselect after authentication. */
    sess_facts(&facts, NULL, IMSI_HOME, 7);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&apn_only, &facts) == false);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&plmn_entry, &facts) == true);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&tac_entry, &facts) == true);

    /* Attach before the IMSI is known: the TAC entry still picks it. */
    sess_facts(&facts, NULL, NULL, 7);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&apn_only, &facts) == false);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&plmn_entry, &facts) == false);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&tac_entry, &facts) == true);

}

/*
 * The deployed sgwc shape:
 *
 *   - address: A   apn: ims   plmn_id: 432-12   order: 0
 *   - address: B              plmn_id: 432-12   order: 1
 *   - address: C              plmn_id: 999-12   order: 2
 *   - address: D                                order: 3   <- default
 *
 * An ims session of a 432-12 sub must take A on order 0; any other APN
 * of the same sub must take B; a roamer must fall through to C / D.
 */
static void gtpc_select_sgw_apn_plmn_order_test(abts_case *tc, void *data)
{
    mme_gtpc_sel_keys_t A, B, C, D;
    mme_gtpc_sel_facts_t facts;
    const char *apn[OGS_MAX_NUM_OF_APN];
    struct { const char *name; mme_gtpc_sel_keys_t *k; int order; } list[4];
    const char *winner;
    int i, best;

    plmn_init();

    memset(&A, 0, sizeof(A));
    apn[0] = "ims";
    A.apn = apn;
    A.num_of_apn = 1;
    A.imsi_plmn_present = true;
    A.imsi_plmn_id = plmn_home;

    memset(&B, 0, sizeof(B));
    B.imsi_plmn_present = true;
    B.imsi_plmn_id = plmn_home;

    memset(&C, 0, sizeof(C));
    C.imsi_plmn_present = true;
    C.imsi_plmn_id = plmn_other;

    memset(&D, 0, sizeof(D));   /* no keys -> the default entry */

    list[0].name = "A"; list[0].k = &A; list[0].order = 0;
    list[1].name = "B"; list[1].k = &B; list[1].order = 1;
    list[2].name = "C"; list[2].k = &C; list[2].order = 2;
    list[3].name = "D"; list[3].k = &D; list[3].order = 3;

    /* order is not a match key: the keyless entry is still the default */
    ABTS_TRUE(tc, mme_gtpc_sel_keys_are_empty(&D) == true);

/* lowest order among matching entries wins, else the default */
#define PICK(fp) do {                                                   winner = "D"; best = 0x7fffffff;                                    for (i = 0; i < 4; i++) {                                               if (mme_gtpc_sel_keys_are_empty(list[i].k))                             continue;                                                       if (!mme_gtpc_sel_match(list[i].k, (fp)))                               continue;                                                       if (list[i].order < best) {                                             best = list[i].order; winner = list[i].name;                    }                                                               }                                                               } while (0)

    /* ims session of a 432-12 sub -> A wins on order 0 */
    sess_facts(&facts, "ims", IMSI_HOME, 1);
    PICK(&facts);
    ABTS_STR_EQUAL(tc, "A", winner);

    /* hiweb session of the same sub -> B; A must not steal it */
    sess_facts(&facts, "hiweb", IMSI_HOME, 1);
    PICK(&facts);
    ABTS_STR_EQUAL(tc, "B", winner);

    /* no APN yet (UE creation / IMSI known) -> B, never A */
    sess_facts(&facts, NULL, IMSI_HOME, 1);
    PICK(&facts);
    ABTS_STR_EQUAL(tc, "B", winner);

    /* other-PLMN sub -> C */
    sess_facts(&facts, "mcinet", IMSI_OTHER, 1);
    PICK(&facts);
    ABTS_STR_EQUAL(tc, "C", winner);

    /* nothing matches -> the keyless default */
    sess_facts(&facts, "mtnirancell", "432350123456789", 1);
    PICK(&facts);
    ABTS_STR_EQUAL(tc, "D", winner);
#undef PICK
}

static void gtpc_select_default_test(abts_case *tc, void *data)
{
    mme_gtpc_sel_keys_t keys;
    mme_gtpc_sel_facts_t facts;

    plmn_init();

    /* No apn, tac, e_cell_id, plmn or prefix -> the default entry. */
    memset(&keys, 0, sizeof(keys));
    keys.imsi_prefix = "";
    ABTS_TRUE(tc, mme_gtpc_sel_keys_are_empty(&keys) == true);

    /* The default never matches; the caller uses it as fallback. */
    sess_facts(&facts, "internet", IMSI_HOME, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == false);
}

/* serving_plmn_id is the TAI PLMN, and does not apply to an inbound roamer. */
static void gtpc_select_serving_plmn_test(abts_case *tc, void *data)
{
    mme_gtpc_sel_keys_t keys;
    mme_gtpc_sel_facts_t facts;

    plmn_init();

    memset(&keys, 0, sizeof(keys));
    keys.serving_plmn_present = true;
    keys.serving_plmn_id = plmn_home;

    sess_facts(&facts, "internet", IMSI_HOME, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == true);

    facts.inbound_roam = true;
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == false);

    sess_facts(&facts, "internet", IMSI_HOME, 1);
    facts.serving_plmn_id = plmn_other;
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == false);
}

/* apn: [ims] + imsi_prefix: 43212 */
static void gtpc_select_imsi_prefix_test(abts_case *tc, void *data)
{
    mme_gtpc_sel_keys_t keys;
    mme_gtpc_sel_facts_t facts;
    const char *apn[OGS_MAX_NUM_OF_APN];

    plmn_init();

    memset(&keys, 0, sizeof(keys));
    apn[0] = "ims";
    keys.apn = apn;
    keys.num_of_apn = 1;
    keys.imsi_prefix = "43212";

    sess_facts(&facts, "ims", IMSI_HOME, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == true);

    sess_facts(&facts, "ims", IMSI_OTHER, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == false);

    sess_facts(&facts, "internet", IMSI_HOME, 1);
    ABTS_TRUE(tc, mme_gtpc_sel_match(&keys, &facts) == false);
}

/*
 * sgwc_selection: per_pdn rules (every one carries apn:)
 *
 *   [0] apn: ims                      order: 5
 *   [1] apn: ims    plmn_id: 432-12   order: 1
 *   [2] apn: [ims, volte]             order: 5   (ties [0], [0] listed first)
 */
static void gtpc_select_pick_test(abts_case *tc, void *data)
{
    mme_gtpc_sel_keys_t r0, r1, r2, empty;
    const mme_gtpc_sel_keys_t *kp[4];
    int order[4];
    mme_gtpc_sel_facts_t facts;
    const char *apn_ims[OGS_MAX_NUM_OF_APN];
    const char *apn_both[OGS_MAX_NUM_OF_APN];

    plmn_init();

    memset(&r0, 0, sizeof(r0));
    apn_ims[0] = "ims";
    r0.apn = apn_ims;
    r0.num_of_apn = 1;

    r1 = r0;
    r1.imsi_plmn_present = true;
    r1.imsi_plmn_id = plmn_home;

    memset(&r2, 0, sizeof(r2));
    apn_both[0] = "ims";
    apn_both[1] = "volte";
    r2.apn = apn_both;
    r2.num_of_apn = 2;

    kp[0] = &r0; order[0] = 5;
    kp[1] = &r1; order[1] = 1;
    kp[2] = &r2; order[2] = 5;

    /* home sub: the AND rule has the lowest order */
    sess_facts(&facts, "ims", IMSI_HOME, 1);
    ABTS_INT_EQUAL(tc, 1, mme_gtpc_sel_pick(kp, order, 3, &facts));

    /* roamer: [1] fails the PLMN key, [0] and [2] tie -> first listed */
    sess_facts(&facts, "ims", IMSI_OTHER, 1);
    ABTS_INT_EQUAL(tc, 0, mme_gtpc_sel_pick(kp, order, 3, &facts));

    /* only [2] lists volte */
    sess_facts(&facts, "volte", IMSI_HOME, 1);
    ABTS_INT_EQUAL(tc, 2, mme_gtpc_sel_pick(kp, order, 3, &facts));

    /* no rule for internet -> -1, the PDN stays on the UE's SGW */
    sess_facts(&facts, "internet", IMSI_HOME, 1);
    ABTS_INT_EQUAL(tc, -1, mme_gtpc_sel_pick(kp, order, 3, &facts));

    /* APN unknown -> nothing */
    sess_facts(&facts, NULL, IMSI_HOME, 1);
    ABTS_INT_EQUAL(tc, -1, mme_gtpc_sel_pick(kp, order, 3, &facts));

    /* a keyless entry never wins, even on the lowest order */
    memset(&empty, 0, sizeof(empty));
    kp[3] = &empty; order[3] = 0;
    sess_facts(&facts, "internet", IMSI_HOME, 1);
    ABTS_INT_EQUAL(tc, -1, mme_gtpc_sel_pick(kp, order, 4, &facts));
    sess_facts(&facts, "ims", IMSI_HOME, 1);
    ABTS_INT_EQUAL(tc, 1, mme_gtpc_sel_pick(kp, order, 4, &facts));

    /* empty list */
    ABTS_INT_EQUAL(tc, -1, mme_gtpc_sel_pick(kp, order, 0, &facts));
}

static void gtpc_select_pdn_place_test(abts_case *tc, void *data)
{
    /* no rule hit: always the UE's SGW, whatever the extra state */
    ABTS_INT_EQUAL(tc, MME_PDN_SGW_PRIMARY,
            mme_gtpc_pdn_sgw_place(false, true, false, false));
    ABTS_INT_EQUAL(tc, MME_PDN_SGW_PRIMARY,
            mme_gtpc_pdn_sgw_place(false, true, true, false));

    /* rule points at the UE's own SGW: no extra context */
    ABTS_INT_EQUAL(tc, MME_PDN_SGW_PRIMARY,
            mme_gtpc_pdn_sgw_place(true, true, false, false));
    ABTS_INT_EQUAL(tc, MME_PDN_SGW_PRIMARY,
            mme_gtpc_pdn_sgw_place(true, true, true, false));

    /* rule points elsewhere, first time: open the extra context */
    ABTS_INT_EQUAL(tc, MME_PDN_SGW_NEW_EXTRA,
            mme_gtpc_pdn_sgw_place(true, false, false, false));

    /* second PDN for the same other SGW: share the extra context */
    ABTS_INT_EQUAL(tc, MME_PDN_SGW_EXTRA,
            mme_gtpc_pdn_sgw_place(true, false, true, true));

    /* would be a third SGW: stay on the UE's SGW */
    ABTS_INT_EQUAL(tc, MME_PDN_SGW_PRIMARY_LIMIT,
            mme_gtpc_pdn_sgw_place(true, false, true, false));
}

abts_suite *test_gtpc_select(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, gtpc_select_and_test, NULL);
    abts_run_test(suite, gtpc_select_or_within_key_test, NULL);
    abts_run_test(suite, gtpc_select_sgw_apn_never_wins_test, NULL);
    abts_run_test(suite, gtpc_select_sgw_apn_plmn_order_test, NULL);
    abts_run_test(suite, gtpc_select_default_test, NULL);
    abts_run_test(suite, gtpc_select_serving_plmn_test, NULL);
    abts_run_test(suite, gtpc_select_imsi_prefix_test, NULL);
    abts_run_test(suite, gtpc_select_pick_test, NULL);
    abts_run_test(suite, gtpc_select_pdn_place_test, NULL);

    return suite;
}
