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

#include "mme-inbound-roam-apn.h"

#include "mme-apn.h"
#include "mme-context.h"

#include <string.h>

static void mme_inbound_roam_apn_policy_clear(mme_context_t *self)
{
    ogs_assert(self);

    self->num_of_inbound_roam_allowed_apn = 0;
    self->num_of_inbound_roam_denied_apn = 0;
    self->num_of_inbound_roam_apn_rule = 0;
    memset(self->inbound_roam_allowed_apn, 0,
            sizeof(self->inbound_roam_allowed_apn));
    memset(self->inbound_roam_denied_apn, 0,
            sizeof(self->inbound_roam_denied_apn));
    memset(self->inbound_roam_apn_rule, 0,
            sizeof(self->inbound_roam_apn_rule));
}

static void mme_apn_normalize_ni(
        char *apn_ni, size_t buflen, const char *apn)
{
    char *oi = NULL;

    ogs_assert(apn_ni);
    ogs_assert(apn);

    ogs_cpystrn(apn_ni, apn, buflen);
    oi = ogs_dnn_oi_from_fqdn(apn_ni);
    if (oi && oi > apn_ni && oi[-1] == '.')
        oi[-1] = '\0';
}

static bool mme_apn_in_list(const char *apn_ni,
        int count, const char list[][OGS_MAX_APN_LEN + 1])
{
    int i;

    if (!apn_ni || !apn_ni[0] || count <= 0)
        return false;

    for (i = 0; i < count; i++) {
        if (list[i][0] && ogs_strcasecmp(apn_ni, list[i]) == 0)
            return true;
    }

    return false;
}

static int mme_inbound_roam_apn_yaml_list(ogs_yaml_iter_t *iter,
        char list[][OGS_MAX_APN_LEN + 1], int max_count, int *out_count)
{
    ogs_yaml_iter_t list_array, list_iter;
    int count = 0;

    ogs_assert(iter);
    ogs_assert(list);
    ogs_assert(out_count);

    *out_count = 0;

    ogs_yaml_iter_recurse(iter, &list_array);
    do {
        if (ogs_yaml_iter_type(&list_array) == YAML_MAPPING_NODE)
            break;
        if (ogs_yaml_iter_type(&list_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&list_array))
                break;
            ogs_yaml_iter_recurse(&list_array, &list_iter);
        } else if (ogs_yaml_iter_type(&list_array) == YAML_SCALAR_NODE) {
            const char *v = ogs_yaml_iter_value(&list_array);
            if (!v || !v[0])
                return OGS_OK;
            if (count >= max_count) {
                ogs_warn("inbound_roam APN list full (max %d)", max_count);
                return OGS_ERROR;
            }
            ogs_cpystrn(list[count], v, OGS_MAX_APN_LEN + 1);
            count++;
            *out_count = count;
            return OGS_OK;
        } else {
            ogs_warn("unexpected YAML node in inbound_roam APN list");
            return OGS_ERROR;
        }

        while (ogs_yaml_iter_next(&list_iter)) {
            const char *v = ogs_yaml_iter_value(&list_iter);

            if (!v || !v[0])
                continue;
            if (count >= max_count) {
                ogs_warn("inbound_roam APN list full (max %d)", max_count);
                break;
            }
            ogs_cpystrn(list[count], v, OGS_MAX_APN_LEN + 1);
            count++;
        }
    } while (ogs_yaml_iter_type(&list_array) == YAML_SEQUENCE_NODE &&
            ogs_yaml_iter_next(&list_array));

    *out_count = count;
    return OGS_OK;
}

static int mme_inbound_roam_apn_parse_plmn_id(ogs_yaml_iter_t *parent_iter,
        ogs_plmn_id_t *plmn_id, bool *configured)
{
    ogs_yaml_iter_t plmn_iter;
    const char *mnc = NULL, *mcc = NULL;

    ogs_assert(parent_iter);
    ogs_assert(plmn_id);
    ogs_assert(configured);

    *configured = false;
    ogs_yaml_iter_recurse(parent_iter, &plmn_iter);
    while (ogs_yaml_iter_next(&plmn_iter)) {
        const char *plmn_key = ogs_yaml_iter_key(&plmn_iter);
        ogs_assert(plmn_key);
        if (!strcmp(plmn_key, "mcc"))
            mcc = ogs_yaml_iter_value(&plmn_iter);
        else if (!strcmp(plmn_key, "mnc"))
            mnc = ogs_yaml_iter_value(&plmn_iter);
    }

    if (!mcc || !mnc)
        return OGS_ERROR;

    ogs_plmn_id_build(plmn_id, atoi(mcc), atoi(mnc), strlen(mnc));
    *configured = true;
    return OGS_OK;
}

static void mme_inbound_roam_apn_parse_rule(mme_context_t *self,
        ogs_yaml_iter_t *rule_iter)
{
    mme_inbound_roam_apn_rule_t *rule = NULL;

    ogs_assert(self);
    ogs_assert(rule_iter);

    if (self->num_of_inbound_roam_apn_rule >= MME_MAX_INBOUND_ROAM_APN_RULE) {
        ogs_warn("inbound_roam apn_rule list full (max %d)",
                MME_MAX_INBOUND_ROAM_APN_RULE);
        return;
    }

    rule = &self->inbound_roam_apn_rule[self->num_of_inbound_roam_apn_rule];
    memset(rule, 0, sizeof(*rule));

    while (ogs_yaml_iter_next(rule_iter)) {
        const char *rule_key = ogs_yaml_iter_key(rule_iter);
        ogs_assert(rule_key);

        if (!strcmp(rule_key, "plmn_id")) {
            if (mme_inbound_roam_apn_parse_plmn_id(rule_iter,
                        &rule->plmn_id, &rule->plmn_id_configured) != OGS_OK)
                ogs_warn("inbound_roam apn_rule missing plmn_id");
        } else if (!strcmp(rule_key, "allowed_apn") ||
                !strcmp(rule_key, "allow_apn")) {
            mme_inbound_roam_apn_yaml_list(rule_iter,
                    rule->allowed_apn, MME_MAX_INBOUND_ROAM_APN,
                    &rule->num_of_allowed_apn);
        } else if (!strcmp(rule_key, "denied_apn") ||
                !strcmp(rule_key, "deny_apn")) {
            mme_inbound_roam_apn_yaml_list(rule_iter,
                    rule->denied_apn, MME_MAX_INBOUND_ROAM_APN,
                    &rule->num_of_denied_apn);
        } else {
            ogs_warn("unknown key `%s` in mme.inbound_roam.apn_rule", rule_key);
        }
    }

    if (!rule->plmn_id_configured) {
        ogs_warn("inbound_roam apn_rule ignored (no plmn_id)");
        return;
    }

    self->num_of_inbound_roam_apn_rule++;
}

static void mme_inbound_roam_apn_parse_rules(mme_context_t *self,
        ogs_yaml_iter_t *iter)
{
    ogs_yaml_iter_t rule_array, rule_iter;

    ogs_assert(self);
    ogs_assert(iter);

    ogs_yaml_iter_recurse(iter, &rule_array);
    do {
        if (ogs_yaml_iter_type(&rule_array) == YAML_MAPPING_NODE) {
            memcpy(&rule_iter, &rule_array, sizeof(ogs_yaml_iter_t));
            mme_inbound_roam_apn_parse_rule(self, &rule_iter);
            break;
        }
        if (ogs_yaml_iter_type(&rule_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&rule_array))
                break;
            ogs_yaml_iter_recurse(&rule_array, &rule_iter);
        } else {
            ogs_warn("unexpected YAML node in inbound_roam apn_rule");
            break;
        }

        while (ogs_yaml_iter_next(&rule_iter))
            mme_inbound_roam_apn_parse_rule(self, &rule_iter);
    } while (ogs_yaml_iter_type(&rule_array) == YAML_SEQUENCE_NODE &&
            ogs_yaml_iter_next(&rule_array));
}

static void mme_inbound_roam_config_parse_key(mme_context_t *self,
        ogs_yaml_iter_t *roam_iter)
{
    const char *rk = ogs_yaml_iter_key(roam_iter);

    ogs_assert(self);
    ogs_assert(rk);

    if (!strcmp(rk, "gtp_apn_format") || !strcmp(rk, "apn_format")) {
        const char *rv = ogs_yaml_iter_value(roam_iter);

        if (rv && (!strcmp(rv, "received") || !strcmp(rv, "exact") ||
                    !strcmp(rv, "as_received"))) {
            self->inbound_roam_gtp_apn_format =
                MME_INBOUND_ROAM_GTP_APN_RECEIVED;
        } else if (rv && (!strcmp(rv, "fqdn") || !strcmp(rv, "full"))) {
            self->inbound_roam_gtp_apn_format =
                MME_INBOUND_ROAM_GTP_APN_FQDN;
        } else
            ogs_warn("unknown mme.inbound_roam.gtp_apn_format `%s` "
                    "(use received|fqdn)", rv);
    } else if (!strcmp(rk, "gtp_apn_lowercase") ||
            !strcmp(rk, "apn_lowercase") || !strcmp(rk, "lowercase")) {
        self->inbound_roam_gtp_apn_lowercase =
            ogs_yaml_iter_bool(roam_iter);
    } else if (!strcmp(rk, "strip_pap_from_gtp_pco") ||
            !strcmp(rk, "strip_pap_from_pco")) {
        self->inbound_roam_strip_pap_from_gtp_pco =
            ogs_yaml_iter_bool(roam_iter);
    } else if (!strcmp(rk, "omit_indication_on_gtp_csr") ||
            !strcmp(rk, "omit_gtp_indication")) {
        self->omit_indication_on_gtp_csr =
            ogs_yaml_iter_bool(roam_iter);
        ogs_warn("mme.inbound_roam.omit_indication_on_gtp_csr is deprecated; "
                "use mme.omit_indication_on_gtp_csr");
    } else if (!strcmp(rk, "force_ipv4_pdn_on_home_pgw") ||
            !strcmp(rk, "force_ipv4_pdn")) {
        self->inbound_roam_force_ipv4_pdn_on_home_pgw =
            ogs_yaml_iter_bool(roam_iter);
    } else if (!strcmp(rk, "zero_bearer_mbr_for_non_gbr") ||
            !strcmp(rk, "non_gbr_zero_bearer_mbr")) {
        self->inbound_roam_zero_bearer_mbr_for_non_gbr =
            ogs_yaml_iter_bool(roam_iter);
    } else if (!strcmp(rk, "gtpc_plmn_id_is_imsi_plmn") ||
            !strcmp(rk, "plmn_id_is_imsi_plmn")) {
        self->inbound_roam_gtpc_plmn_id_is_imsi_plmn =
            ogs_yaml_iter_bool(roam_iter);
    } else if (!strcmp(rk, "allowed_apn") || !strcmp(rk, "allow_apn")) {
        mme_inbound_roam_apn_yaml_list(roam_iter,
                self->inbound_roam_allowed_apn, MME_MAX_INBOUND_ROAM_APN,
                &self->num_of_inbound_roam_allowed_apn);
    } else if (!strcmp(rk, "denied_apn") || !strcmp(rk, "deny_apn")) {
        mme_inbound_roam_apn_yaml_list(roam_iter,
                self->inbound_roam_denied_apn, MME_MAX_INBOUND_ROAM_APN,
                &self->num_of_inbound_roam_denied_apn);
    } else if (!strcmp(rk, "apn_reject_cause") ||
            !strcmp(rk, "reject_cause")) {
        const char *rv = ogs_yaml_iter_value(roam_iter);

        if (rv)
            self->inbound_roam_apn_reject_cause = (uint8_t)atoi(rv);
    } else if (!strcmp(rk, "apn_rule") || !strcmp(rk, "apn_policy")) {
        mme_inbound_roam_apn_parse_rules(self, roam_iter);
    } else {
        ogs_warn("unknown key `%s` in mme.inbound_roam", rk);
    }
}

static void mme_inbound_roam_config_log(mme_context_t *self)
{
    int i;

    ogs_assert(self);

    ogs_info("Inbound roam: apn=%s lowercase=%s sanitize_pco=%s "
            "force_ipv4_pdn=%s non_gbr_zero_mbr=%s "
            "gtpc_plmn_id_is_imsi_plmn=%s "
            "allowed_apn=%d denied_apn=%d apn_rule=%d reject_cause=%u",
            self->inbound_roam_gtp_apn_format ==
            MME_INBOUND_ROAM_GTP_APN_FQDN ? "fqdn" : "received",
            self->inbound_roam_gtp_apn_lowercase ? "true" : "false",
            self->inbound_roam_strip_pap_from_gtp_pco ? "true" : "false",
            self->inbound_roam_force_ipv4_pdn_on_home_pgw ? "true" : "false",
            self->inbound_roam_zero_bearer_mbr_for_non_gbr ? "true" : "false",
            self->inbound_roam_gtpc_plmn_id_is_imsi_plmn ? "true" : "false",
            self->num_of_inbound_roam_allowed_apn,
            self->num_of_inbound_roam_denied_apn,
            self->num_of_inbound_roam_apn_rule,
            self->inbound_roam_apn_reject_cause);

    for (i = 0; i < self->num_of_inbound_roam_allowed_apn; i++)
        ogs_info("  inbound_roam allowed_apn[%d]=%s",
                i, self->inbound_roam_allowed_apn[i]);
    for (i = 0; i < self->num_of_inbound_roam_denied_apn; i++)
        ogs_info("  inbound_roam denied_apn[%d]=%s",
                i, self->inbound_roam_denied_apn[i]);
}

void mme_inbound_roam_config_parse(ogs_yaml_iter_t *inbound_roam_iter)
{
    mme_context_t *self = mme_self();
    ogs_yaml_iter_t roam_iter;

    ogs_assert(self);
    ogs_assert(inbound_roam_iter);

    mme_inbound_roam_apn_policy_clear(self);

    ogs_yaml_iter_recurse(inbound_roam_iter, &roam_iter);
    while (ogs_yaml_iter_next(&roam_iter))
        mme_inbound_roam_config_parse_key(self, &roam_iter);

    mme_inbound_roam_config_log(self);
}

static const mme_inbound_roam_apn_rule_t *mme_inbound_roam_apn_rule_for_ue(
        mme_ue_t *mme_ue)
{
    mme_context_t *self = mme_self();
    int i;

    ogs_assert(mme_ue);

    for (i = 0; i < self->num_of_inbound_roam_apn_rule; i++) {
        mme_inbound_roam_apn_rule_t *rule = &self->inbound_roam_apn_rule[i];

        if (rule->plmn_id_configured &&
                ogs_plmn_id_imsi_prefix_match(
                    mme_ue->imsi_bcd, &rule->plmn_id))
            return rule;
    }

    return NULL;
}

static void mme_inbound_roam_apn_policy_for_ue(mme_ue_t *mme_ue,
        int *num_allow,
        const char (**allow)[OGS_MAX_APN_LEN + 1],
        int *num_deny,
        const char (**deny)[OGS_MAX_APN_LEN + 1])
{
    mme_context_t *self = mme_self();
    const mme_inbound_roam_apn_rule_t *rule = NULL;

    ogs_assert(num_allow);
    ogs_assert(allow);
    ogs_assert(num_deny);
    ogs_assert(deny);

    rule = mme_inbound_roam_apn_rule_for_ue(mme_ue);

    if (rule && rule->num_of_allowed_apn > 0) {
        *num_allow = rule->num_of_allowed_apn;
        *allow = rule->allowed_apn;
    } else {
        *num_allow = self->num_of_inbound_roam_allowed_apn;
        *allow = self->inbound_roam_allowed_apn;
    }

    *num_deny = self->num_of_inbound_roam_denied_apn;
    *deny = self->inbound_roam_denied_apn;
}

bool mme_inbound_roam_apn_allowed(mme_ue_t *mme_ue, const char *apn)
{
    char apn_ni[OGS_MAX_APN_LEN + 1];
    int num_allow = 0, num_deny = 0, num_rule_deny = 0;
    const char (*allow)[OGS_MAX_APN_LEN + 1] = NULL;
    const char (*deny)[OGS_MAX_APN_LEN + 1] = NULL;
    const mme_inbound_roam_apn_rule_t *rule = NULL;

    if (!mme_ue || !apn || !apn[0])
        return true;
    if (!mme_ue_is_inbound_roam(mme_ue))
        return true;

    mme_apn_normalize_ni(apn_ni, sizeof(apn_ni), apn);

    mme_inbound_roam_apn_policy_for_ue(mme_ue,
            &num_allow, &allow, &num_deny, &deny);
    rule = mme_inbound_roam_apn_rule_for_ue(mme_ue);
    if (rule)
        num_rule_deny = rule->num_of_denied_apn;

    if (num_allow == 0 && num_deny == 0 && num_rule_deny == 0)
        return true;

    if (num_deny > 0 && mme_apn_in_list(apn_ni, num_deny, deny))
        return false;
    if (rule && num_rule_deny > 0 &&
            mme_apn_in_list(apn_ni, num_rule_deny, rule->denied_apn))
        return false;

    if (num_allow > 0)
        return mme_apn_in_list(apn_ni, num_allow, allow);

    return true;
}

uint8_t mme_inbound_roam_apn_esm_cause(mme_ue_t *mme_ue, const char *apn)
{
    mme_context_t *self = mme_self();

    if (mme_inbound_roam_apn_allowed(mme_ue, apn))
        return MME_INBOUND_ROAM_APN_ESM_ACCEPT;

    if (self->inbound_roam_apn_reject_cause)
        return self->inbound_roam_apn_reject_cause;

    return OGS_NAS_ESM_CAUSE_MISSING_OR_UNKNOWN_APN;
}
