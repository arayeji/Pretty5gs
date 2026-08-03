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

#include "eplmn-config.h"

int mme_eplmn_parse_config(ogs_yaml_iter_t *parent,
        int *num_of_eplmn, ogs_plmn_id_t *eplmn)
{
    ogs_yaml_iter_t eplmn_array, eplmn_iter;

    ogs_assert(parent);
    ogs_assert(num_of_eplmn);
    ogs_assert(eplmn);

    ogs_yaml_iter_recurse(parent, &eplmn_array);
    do {
        const char *mcc = NULL, *mnc = NULL;

        if (ogs_yaml_iter_type(&eplmn_array) == YAML_MAPPING_NODE) {
            memcpy(&eplmn_iter, &eplmn_array, sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(&eplmn_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&eplmn_array))
                break;
            ogs_yaml_iter_recurse(&eplmn_array, &eplmn_iter);
        } else if (ogs_yaml_iter_type(&eplmn_array) == YAML_SCALAR_NODE) {
            break;
        } else
            ogs_assert_if_reached();

        while (ogs_yaml_iter_next(&eplmn_iter)) {
            const char *eplmn_key = ogs_yaml_iter_key(&eplmn_iter);
            ogs_assert(eplmn_key);
            if (!strcmp(eplmn_key, "mcc")) {
                mcc = ogs_yaml_iter_value(&eplmn_iter);
            } else if (!strcmp(eplmn_key, "mnc")) {
                mnc = ogs_yaml_iter_value(&eplmn_iter);
            } else
                ogs_warn("unknown key `%s`", eplmn_key);
        }

        if (!mcc || !mnc) {
            ogs_error("equivalent_plmn entry missing mcc or mnc");
            return OGS_ERROR;
        }

        if (*num_of_eplmn >= OGS_NAS_MAX_PLMN) {
            ogs_error("Too many equivalent_plmn entries (max %d)",
                    OGS_NAS_MAX_PLMN);
            return OGS_ERROR;
        }

        ogs_plmn_id_build(&eplmn[*num_of_eplmn],
                atoi(mcc), atoi(mnc), strlen(mnc));
        (*num_of_eplmn)++;

    } while (ogs_yaml_iter_type(&eplmn_array) == YAML_SEQUENCE_NODE);

    return OGS_OK;
}

int mme_eplmn_add_if_new(int *num_of_eplmn, ogs_plmn_id_t *eplmn,
        const ogs_plmn_id_t *candidate)
{
    int i;

    ogs_assert(num_of_eplmn);
    ogs_assert(eplmn);
    ogs_assert(candidate);

    for (i = 0; i < *num_of_eplmn; i++) {
        if (memcmp(&eplmn[i], candidate, OGS_PLMN_ID_LEN) == 0)
            return 0;
    }

    if (*num_of_eplmn >= OGS_NAS_MAX_PLMN) {
        ogs_warn("equivalent_plmn list full (max %d)", OGS_NAS_MAX_PLMN);
        return 0;
    }

    eplmn[*num_of_eplmn] = *candidate;
    (*num_of_eplmn)++;
    return 1;
}

int mme_eplmn_validate(int num_of_eplmn)
{
    if (num_of_eplmn < 0 || num_of_eplmn > OGS_NAS_MAX_PLMN) {
        ogs_error("Invalid equivalent_plmn count [%d] (max %d)",
                num_of_eplmn, OGS_NAS_MAX_PLMN);
        return OGS_ERROR;
    }

    return OGS_OK;
}

void mme_eplmn_log_config(int num_of_eplmn, ogs_plmn_id_t *eplmn)
{
    int i;

    ogs_assert(eplmn);

    ogs_info("Equivalent PLMNs configured: %d", num_of_eplmn);
    for (i = 0; i < num_of_eplmn; i++) {
        ogs_info("  EPLMN[%d]: MCC=%03d MNC=%0*d", i,
                ogs_plmn_id_mcc(&eplmn[i]),
                ogs_plmn_id_mnc_len(&eplmn[i]),
                ogs_plmn_id_mnc(&eplmn[i]));
    }
}

void mme_eplmn_log_serving_only(bool serving_only)
{
    ogs_info("Equivalent PLMN serving_only: %s",
            serving_only ? "enabled" : "disabled");
}

int mme_eplmn_build_nas_list(ogs_nas_plmn_list_t *nas_list,
        int num_of_eplmn, ogs_plmn_id_t *eplmn)
{
    int i;

    ogs_assert(nas_list);
    ogs_assert(eplmn);

    if (num_of_eplmn <= 0)
        return OGS_OK;

    if (num_of_eplmn > OGS_NAS_MAX_PLMN) {
        ogs_error("Too many equivalent PLMNs [%d]", num_of_eplmn);
        return OGS_ERROR;
    }

    memset(nas_list, 0, sizeof(*nas_list));
    nas_list->length = num_of_eplmn * OGS_PLMN_ID_LEN;
    for (i = 0; i < num_of_eplmn; i++)
        ogs_nas_from_plmn_id(&nas_list->nas_plmn_id[i], &eplmn[i]);

    return OGS_OK;
}

/*
 * Longest IMSI-prefix match against configured EPLMNs (so 432-11 wins
 * over a hypothetical 432 when both are listed). Returns index or -1.
 */
static int mme_eplmn_index_for_imsi(const char *imsi_bcd,
        int num_of_eplmn, ogs_plmn_id_t *eplmn)
{
    int i, best = -1, best_digits = -1;

    if (!imsi_bcd || !imsi_bcd[0] || num_of_eplmn <= 0)
        return -1;

    for (i = 0; i < num_of_eplmn; i++) {
        char plmn_str[OGS_PLMNIDSTRLEN];
        int digits;

        if (!ogs_plmn_id_imsi_prefix_match(imsi_bcd, &eplmn[i]))
            continue;

        ogs_plmn_id_to_string(&eplmn[i], plmn_str);
        digits = (int)strlen(plmn_str);
        if (digits > best_digits) {
            best_digits = digits;
            best = i;
        }
    }

    return best;
}

int mme_eplmn_count_for_imsi(const char *imsi_bcd, bool imsi_plmn_only,
        int num_of_eplmn, ogs_plmn_id_t *eplmn)
{
    ogs_assert(eplmn);

    if (num_of_eplmn <= 0)
        return 0;

    if (imsi_plmn_only &&
            mme_eplmn_index_for_imsi(imsi_bcd, num_of_eplmn, eplmn) >= 0)
        return 1;

    return num_of_eplmn;
}

int mme_eplmn_build_nas_list_for_imsi(ogs_nas_plmn_list_t *nas_list,
        const char *imsi_bcd, bool imsi_plmn_only,
        int num_of_eplmn, ogs_plmn_id_t *eplmn)
{
    int idx;

    ogs_assert(nas_list);
    ogs_assert(eplmn);

    if (num_of_eplmn <= 0)
        return OGS_OK;

    if (imsi_plmn_only) {
        idx = mme_eplmn_index_for_imsi(imsi_bcd, num_of_eplmn, eplmn);
        if (idx >= 0)
            return mme_eplmn_build_nas_list(nas_list, 1, &eplmn[idx]);
    }

    return mme_eplmn_build_nas_list(nas_list, num_of_eplmn, eplmn);
}

int mme_eplmn_count_for_serving(const ogs_plmn_id_t *serving_plmn,
        bool serving_only, int num_of_eplmn, ogs_plmn_id_t *eplmn)
{
    int i;

    ogs_assert(eplmn);

    if (num_of_eplmn <= 0)
        return 0;

    if (serving_only && serving_plmn) {
        for (i = 0; i < num_of_eplmn; i++) {
            if (memcmp(&eplmn[i], serving_plmn, OGS_PLMN_ID_LEN) == 0)
                return 1;
        }
    }

    return num_of_eplmn;
}

int mme_eplmn_build_nas_list_for_serving(ogs_nas_plmn_list_t *nas_list,
        const ogs_plmn_id_t *serving_plmn, bool serving_only,
        int num_of_eplmn, ogs_plmn_id_t *eplmn)
{
    int i;

    ogs_assert(nas_list);
    ogs_assert(eplmn);

    if (num_of_eplmn <= 0)
        return OGS_OK;

    if (serving_only && serving_plmn) {
        for (i = 0; i < num_of_eplmn; i++) {
            if (memcmp(&eplmn[i], serving_plmn, OGS_PLMN_ID_LEN) == 0)
                return mme_eplmn_build_nas_list(nas_list, 1, &eplmn[i]);
        }
    }

    return mme_eplmn_build_nas_list(nas_list, num_of_eplmn, eplmn);
}
