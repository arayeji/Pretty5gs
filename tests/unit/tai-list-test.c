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

#include "ogs-core.h"
#include "ogs-nas-eps.h"
#include "core/abts.h"

static void tai_list_serving_only_test(abts_case *tc, void *data)
{
    ogs_nas_tracking_area_identity_list_t tai_list;
    ogs_eps_tai_t serving;
    ogs_pkbuf_t *pkbuf = NULL;
    uint8_t *encoded = NULL;
    int size;
    /*
     * TS 24.301 9.9.3.33 partial TAI list header, octet 1:
     *   bit 8    spare
     *   bits 7-6 type of list
     *   bits 5-1 number of elements - 1
     * One TAI of type 2 (TAIs belonging to different PLMNs) is
     * (2 << 5) | 0 = 0x40, followed by PLMN 432-12 (34 f2 21) and
     * TAC 16003 (3e 83).
     */
    uint8_t expected[] = { 0x40, 0x34, 0xf2, 0x21, 0x3e, 0x83 };

    ogs_plmn_id_build(&serving.plmn_id, 432, 12, 2);
    serving.tac = 16003;

    ABTS_INT_EQUAL(tc, OGS_OK,
            ogs_nas_tai_list_build_serving_only(&tai_list, &serving));
    ABTS_INT_EQUAL(tc, 6, tai_list.length);
    ABTS_TRUE(tc, memcmp(tai_list.buffer, expected, sizeof(expected)) == 0);

    pkbuf = ogs_pkbuf_alloc(NULL, 256);
    ogs_assert(pkbuf);
    ogs_pkbuf_put(pkbuf, 256);

    /*
     * The encoders pull pkbuf->data forward and write at the old
     * position, so the encoded bytes live at the pointer taken *before*
     * the call - reading pkbuf->data afterwards lands past them.
     */
    encoded = pkbuf->data;
    size = ogs_nas_eps_encode_tracking_area_identity_list(pkbuf, &tai_list);
    ABTS_INT_EQUAL(tc, 7, size);
    ABTS_INT_EQUAL(tc, 6, encoded[0]);      /* length octet */
    ABTS_TRUE(tc, memcmp(encoded + 1, expected, sizeof(expected)) == 0);

    ogs_pkbuf_free(pkbuf);
}

static void tai_list_truncation_fallback_test(abts_case *tc, void *data)
{
    ogs_nas_tracking_area_identity_list_t tai_list;
    ogs_eps_tai0_list_t *list0 = NULL;
    ogs_eps_tai_t serving;
    int i, j, tac;

    list0 = ogs_calloc(1, sizeof(ogs_eps_tai0_list_t));
    ABTS_PTR_NOTNULL(tc, list0);

    ogs_plmn_id_build(&serving.plmn_id, 432, 12, 2);
    serving.tac = 16003;

    /*
     * Fill type-0 partial lists until the 96-octet NAS cap is exceeded.
     * Without fallback this would leave length==0 (malformed).
     */
    for (i = 0; i < OGS_MAX_NUM_OF_EPS_TAI0_PARTIAL_LIST; i++) {
        list0->tai[i].type = OGS_TAI0_TYPE;
        list0->tai[i].num = OGS_MAX_NUM_OF_TAI;
        ogs_plmn_id_build(&list0->tai[i].plmn_id, 432, 12, 2);
        for (j = 0; j < OGS_MAX_NUM_OF_TAI; j++)
            list0->tai[i].tac[j] = 10000 + (i * OGS_MAX_NUM_OF_TAI) + j;
    }

    ABTS_INT_EQUAL(tc, OGS_OK,
            ogs_nas_tai_list_build(&tai_list, list0, NULL, NULL, &serving));

    /*
     * ogs_nas_tai_list_build() prioritizes the serving TAI but does not
     * trim to it - that is ogs_nas_tai_list_build_serving_only(). The
     * result is therefore the full list capped at the 96-octet NAS
     * maximum, not a single 6-octet entry.
     */
    ABTS_INT_EQUAL(tc, OGS_NAS_EPS_MAX_TAI_LIST_LEN, tai_list.length);
    /* type of list is bits 7-6; the source lists are type 0 */
    ABTS_INT_EQUAL(tc, OGS_TAI0_TYPE, (tai_list.buffer[0] >> 5) & 0x03);
    /* serving TAC must have been prioritized to the front */
    tac = be16toh(*(uint16_t *)(tai_list.buffer + 4));
    ABTS_INT_EQUAL(tc, 16003, tac);

    ogs_free(list0);
}

abts_suite *test_tai_list(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, tai_list_serving_only_test, NULL);
    abts_run_test(suite, tai_list_truncation_fallback_test, NULL);

    return suite;
}
