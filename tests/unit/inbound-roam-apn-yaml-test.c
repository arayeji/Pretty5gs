/*
 * Copyright (C) 2026 by Open5GS Contributors
 *
 * This file is part of Open5GS.
 *
 * Regression: ogs_yaml sequence iteration must next() only in the loop
 * body. An extra next() in the while condition skips every other item —
 * the bug that dropped inbound_roam.apn_rule[1] (e.g. 43235 deny ims).
 */

#include "ogs-core.h"
#include "ogs-app.h"
#include "core/abts.h"

static int count_sequence_maps_correct(const char *yaml)
{
    yaml_parser_t parser;
    yaml_document_t document;
    ogs_yaml_iter_t root_iter, mme_iter, roam_iter, rule_array, rule_iter;
    int count = 0;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser,
            (const unsigned char *)yaml, strlen(yaml));
    if (!yaml_parser_load(&parser, &document)) {
        yaml_parser_delete(&parser);
        return -1;
    }

    ogs_yaml_iter_init(&root_iter, &document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        if (!root_key || strcmp(root_key, "mme"))
            continue;
        ogs_yaml_iter_recurse(&root_iter, &mme_iter);
        while (ogs_yaml_iter_next(&mme_iter)) {
            const char *mme_key = ogs_yaml_iter_key(&mme_iter);
            if (!mme_key || strcmp(mme_key, "inbound_roam"))
                continue;
            ogs_yaml_iter_recurse(&mme_iter, &roam_iter);
            while (ogs_yaml_iter_next(&roam_iter)) {
                const char *rk = ogs_yaml_iter_key(&roam_iter);
                if (!rk || strcmp(rk, "apn_rule"))
                    continue;
                ogs_yaml_iter_recurse(&roam_iter, &rule_array);
                do {
                    if (ogs_yaml_iter_type(&rule_array) ==
                            YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&rule_array))
                            break;
                        ogs_yaml_iter_recurse(&rule_array, &rule_iter);
                        count++;
                    } else {
                        break;
                    }
                } while (ogs_yaml_iter_type(&rule_array) ==
                        YAML_SEQUENCE_NODE);
            }
        }
    }

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);
    return count;
}

static int count_sequence_maps_buggy_double_next(const char *yaml)
{
    yaml_parser_t parser;
    yaml_document_t document;
    ogs_yaml_iter_t root_iter, mme_iter, roam_iter, rule_array, rule_iter;
    int count = 0;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser,
            (const unsigned char *)yaml, strlen(yaml));
    if (!yaml_parser_load(&parser, &document)) {
        yaml_parser_delete(&parser);
        return -1;
    }

    ogs_yaml_iter_init(&root_iter, &document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        if (!root_key || strcmp(root_key, "mme"))
            continue;
        ogs_yaml_iter_recurse(&root_iter, &mme_iter);
        while (ogs_yaml_iter_next(&mme_iter)) {
            const char *mme_key = ogs_yaml_iter_key(&mme_iter);
            if (!mme_key || strcmp(mme_key, "inbound_roam"))
                continue;
            ogs_yaml_iter_recurse(&mme_iter, &roam_iter);
            while (ogs_yaml_iter_next(&roam_iter)) {
                const char *rk = ogs_yaml_iter_key(&roam_iter);
                if (!rk || strcmp(rk, "apn_rule"))
                    continue;
                ogs_yaml_iter_recurse(&roam_iter, &rule_array);
                do {
                    if (ogs_yaml_iter_type(&rule_array) ==
                            YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&rule_array))
                            break;
                        ogs_yaml_iter_recurse(&rule_array, &rule_iter);
                        count++;
                    } else {
                        break;
                    }
                } while (ogs_yaml_iter_type(&rule_array) ==
                        YAML_SEQUENCE_NODE &&
                        ogs_yaml_iter_next(&rule_array));
            }
        }
    }

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);
    return count;
}

static void inbound_roam_apn_rule_yaml_count_test(abts_case *tc, void *data)
{
    static const char *yaml =
        "mme:\n"
        "  inbound_roam:\n"
        "    apn_rule:\n"
        "      - plmn_id: { mcc: 432, mnc: 11 }\n"
        "        allowed_apn: [mcinet]\n"
        "      - plmn_id: { mcc: \"432\", mnc: \"35\" }\n"
        "        denied_apn: [ims]\n";

    ABTS_INT_EQUAL(tc, 2, count_sequence_maps_correct(yaml));
    ABTS_INT_EQUAL(tc, 1, count_sequence_maps_buggy_double_next(yaml));
}

abts_suite *test_inbound_roam_apn_yaml(abts_suite *suite)
{
    suite = ADD_SUITE(suite);

    abts_run_test(suite, inbound_roam_apn_rule_yaml_count_test, NULL);

    return suite;
}
