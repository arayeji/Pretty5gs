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
#include "ogs-app.h"
#include "ogs-nas-eps.h"
#include "core/abts.h"

#include "../../src/mme/eplmn-config.h"

static int parse_equivalent_plmn_yaml(const char *yaml,
        int *num_of_eplmn, ogs_plmn_id_t *eplmn)
{
    yaml_parser_t parser;
    yaml_document_t document;
    ogs_yaml_iter_t root_iter, mme_iter;
    int rv = OGS_OK;

    ogs_assert(yaml);
    ogs_assert(num_of_eplmn);
    ogs_assert(eplmn);

    *num_of_eplmn = 0;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser,
            (const unsigned char *)yaml, strlen(yaml));
    if (!yaml_parser_load(&parser, &document)) {
        yaml_parser_delete(&parser);
        return OGS_ERROR;
    }

    ogs_yaml_iter_init(&root_iter, &document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        if (!root_key || strcmp(root_key, "mme"))
            continue;

        ogs_yaml_iter_recurse(&root_iter, &mme_iter);
        while (ogs_yaml_iter_next(&mme_iter)) {
            const char *mme_key = ogs_yaml_iter_key(&mme_iter);
            if (!mme_key || strcmp(mme_key, "equivalent_plmn"))
                continue;

            rv = mme_eplmn_parse_config(&mme_iter, num_of_eplmn, eplmn);
            break;
        }
    }

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

    return rv;
}

static void eplmn_config_count_test(abts_case *tc, void *data)
{
    ogs_plmn_id_t eplmn[OGS_NAS_MAX_PLMN];
    int num_of_eplmn = 0;
    int rv;
    char yaml[4096];
    int i;

    rv = parse_equivalent_plmn_yaml("mme:\n  equivalent_plmn: []\n",
            &num_of_eplmn, eplmn);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 0, num_of_eplmn);

    rv = parse_equivalent_plmn_yaml(
            "mme:\n  equivalent_plmn:\n    - { mcc: 999, mnc: 71 }\n",
            &num_of_eplmn, eplmn);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 1, num_of_eplmn);
    ABTS_INT_EQUAL(tc, 432, ogs_plmn_id_mcc(&eplmn[0]));
    ABTS_INT_EQUAL(tc, 11, ogs_plmn_id_mnc(&eplmn[0]));

    snprintf(yaml, sizeof(yaml), "mme:\n  equivalent_plmn:\n");
    for (i = 0; i < 8; i++)
        snprintf(yaml + strlen(yaml), sizeof(yaml) - strlen(yaml),
                "    - { mcc: 999, mnc: %d }\n", 10 + i);
    num_of_eplmn = 0;
    rv = parse_equivalent_plmn_yaml(yaml, &num_of_eplmn, eplmn);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 8, num_of_eplmn);

    snprintf(yaml, sizeof(yaml), "mme:\n  equivalent_plmn:\n");
    for (i = 0; i < 15; i++)
        snprintf(yaml + strlen(yaml), sizeof(yaml) - strlen(yaml),
                "    - { mcc: 999, mnc: %d }\n", 10 + i);
    num_of_eplmn = 0;
    rv = parse_equivalent_plmn_yaml(yaml, &num_of_eplmn, eplmn);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 15, num_of_eplmn);

    snprintf(yaml, sizeof(yaml), "mme:\n  equivalent_plmn:\n");
    for (i = 0; i < 16; i++)
        snprintf(yaml + strlen(yaml), sizeof(yaml) - strlen(yaml),
                "    - { mcc: 999, mnc: %d }\n", 10 + i);
    num_of_eplmn = 0;
    rv = parse_equivalent_plmn_yaml(yaml, &num_of_eplmn, eplmn);
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);

    num_of_eplmn = 0;
    rv = parse_equivalent_plmn_yaml(
            "mme:\n  equivalent_plmn:\n    - { mcc: 999 }\n",
            &num_of_eplmn, eplmn);
    ABTS_INT_EQUAL(tc, OGS_ERROR, rv);
}

static void eplmn_nas_encoding_test(abts_case *tc, void *data)
{
    ogs_plmn_id_t plmn_id;
    ogs_nas_plmn_list_t nas_list;
    ogs_nas_plmn_id_t *nas_plmn;
    ogs_pkbuf_t *pkbuf = NULL;
    uint8_t expected[3];
    int rv;

    ogs_plmn_id_build(&plmn_id, 432, 12, 2);
    rv = mme_eplmn_build_nas_list(&nas_list, 1, &plmn_id);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 3, nas_list.length);

    nas_plmn = &nas_list.nas_plmn_id[0];
    expected[0] = (plmn_id.mcc2 << 4) | plmn_id.mcc1;
    expected[1] = (plmn_id.mnc1 << 4) | plmn_id.mcc3;
    expected[2] = (plmn_id.mnc3 << 4) | plmn_id.mnc2;
    ABTS_INT_EQUAL(tc, expected[0], *((uint8_t *)nas_plmn));
    ABTS_INT_EQUAL(tc, expected[1], *((uint8_t *)nas_plmn + 1));
    ABTS_INT_EQUAL(tc, expected[2], *((uint8_t *)nas_plmn + 2));
    ABTS_INT_EQUAL(tc, 0x34, *((uint8_t *)nas_plmn));
    ABTS_INT_EQUAL(tc, 0xf2, *((uint8_t *)nas_plmn + 1));
    ABTS_INT_EQUAL(tc, 0x21, *((uint8_t *)nas_plmn + 2));

    ogs_plmn_id_build(&plmn_id, 310, 260, 3);
    rv = mme_eplmn_build_nas_list(&nas_list, 1, &plmn_id);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    nas_plmn = &nas_list.nas_plmn_id[0];
    expected[0] = (plmn_id.mcc2 << 4) | plmn_id.mcc1;
    expected[1] = (plmn_id.mnc1 << 4) | plmn_id.mcc3;
    expected[2] = (plmn_id.mnc3 << 4) | plmn_id.mnc2;
    ABTS_INT_EQUAL(tc, expected[0], *((uint8_t *)nas_plmn));
    ABTS_INT_EQUAL(tc, expected[1], *((uint8_t *)nas_plmn + 1));
    ABTS_INT_EQUAL(tc, expected[2], *((uint8_t *)nas_plmn + 2));

    memset(&nas_list, 0, sizeof(nas_list));
    ogs_plmn_id_build(&plmn_id, 432, 12, 2);
    mme_eplmn_build_nas_list(&nas_list, 1, &plmn_id);

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);

    ABTS_INT_EQUAL(tc, 4, ogs_nas_eps_encode_plmn_list(pkbuf, &nas_list));
    ABTS_INT_EQUAL(tc, 3, pkbuf->data[0]);
    ABTS_INT_EQUAL(tc, 0x34, pkbuf->data[1]);
    ABTS_INT_EQUAL(tc, 0xf2, pkbuf->data[2]);
    ABTS_INT_EQUAL(tc, 0x21, pkbuf->data[3]);

    ogs_pkbuf_free(pkbuf);
}

static void eplmn_serving_only_test(abts_case *tc, void *data)
{
    ogs_plmn_id_t eplmn[OGS_NAS_MAX_PLMN];
    ogs_plmn_id_t serving;
    ogs_nas_plmn_list_t nas_list;
    int rv;

    ogs_plmn_id_build(&eplmn[0], 432, 12, 2);
    ogs_plmn_id_build(&eplmn[1], 432, 11, 2);
    ogs_plmn_id_build(&eplmn[2], 432, 35, 2);
    ogs_plmn_id_build(&serving, 432, 11, 2);

    ABTS_INT_EQUAL(tc, 1, mme_eplmn_count_for_serving(
                &serving, true, 3, eplmn));
    rv = mme_eplmn_build_nas_list_for_serving(
            &nas_list, &serving, true, 3, eplmn);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 3, nas_list.length);
    {
        ogs_nas_plmn_list_t expected;
        rv = mme_eplmn_build_nas_list(&expected, 1, &eplmn[1]);
        ABTS_INT_EQUAL(tc, OGS_OK, rv);
        ABTS_INT_EQUAL(tc, expected.length, nas_list.length);
        ABTS_TRUE(tc, memcmp(&expected, &nas_list, sizeof(nas_list)) == 0);
    }

    ogs_plmn_id_build(&serving, 432, 99, 2);
    ABTS_INT_EQUAL(tc, 3, mme_eplmn_count_for_serving(
                &serving, true, 3, eplmn));
    rv = mme_eplmn_build_nas_list_for_serving(
            &nas_list, &serving, true, 3, eplmn);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 9, nas_list.length);

    ogs_plmn_id_build(&serving, 432, 11, 2);
    ABTS_INT_EQUAL(tc, 3, mme_eplmn_count_for_serving(
                &serving, false, 3, eplmn));
    rv = mme_eplmn_build_nas_list_for_serving(
            &nas_list, &serving, false, 3, eplmn);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, 9, nas_list.length);
}

abts_suite *test_eplmn(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, eplmn_config_count_test, NULL);
    abts_run_test(suite, eplmn_nas_encoding_test, NULL);
    abts_run_test(suite, eplmn_serving_only_test, NULL);

    return suite;
}
