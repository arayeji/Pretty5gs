/*
 * Copyright (C) 2026 by Ahmad Raeiji <ahmad.rayeji@gmail.com>
 *
 * This file is part of Open5GS / Pretty5GS.
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

#include "mme-apn-policy.h"

#include "mme-apn.h"
#include "mme-context.h"
#include "metrics.h"

static void apn_policy_free(mme_apn_policy_t *rule)
{
    int i;

    ogs_assert(rule);

    if (rule->name)
        ogs_free(rule->name);
    if (rule->target_apn)
        ogs_free(rule->target_apn);
    for (i = 0; i < rule->num_of_imsi_prefix; i++)
        if (rule->imsi_prefix[i])
            ogs_free(rule->imsi_prefix[i]);
    for (i = 0; i < rule->num_of_apn; i++)
        if (rule->apn[i])
            ogs_free(rule->apn[i]);

    ogs_free(rule);
}

void mme_apn_policy_remove_all(void)
{
    mme_apn_policy_t *rule = NULL, *next = NULL;

    ogs_list_for_each_safe(&mme_self()->apn_policy_list, next, rule) {
        ogs_list_remove(&mme_self()->apn_policy_list, rule);
        apn_policy_free(rule);
    }
}

bool mme_apn_policy_configured(void)
{
    return ogs_list_first(&mme_self()->apn_policy_list) != NULL;
}

/* ---- config ---- */

static int apn_policy_str_list(ogs_yaml_iter_t *iter, const char *what,
        char **list, int max_count, int *out_count)
{
    ogs_yaml_iter_t list_iter;
    int count = 0;

    ogs_yaml_iter_recurse(iter, &list_iter);
    if (ogs_yaml_iter_type(&list_iter) == YAML_MAPPING_NODE) {
        ogs_error("mme.apn_correction: `%s' must be a value or a list", what);
        return OGS_ERROR;
    }

    do {
        const char *v = NULL;

        if (ogs_yaml_iter_type(&list_iter) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&list_iter))
                break;
        }
        if (count >= max_count) {
            ogs_warn("mme.apn_correction: `%s' limited to %d entries",
                    what, max_count);
            break;
        }
        v = ogs_yaml_iter_value(&list_iter);
        if (v && v[0]) {
            list[count] = ogs_strdup(v);
            ogs_assert(list[count]);
            count++;
        }
    } while (ogs_yaml_iter_type(&list_iter) == YAML_SEQUENCE_NODE);

    *out_count = count;
    return OGS_OK;
}

static uint8_t apn_policy_pdn_type_from_str(const char *v)
{
    if (!v)
        return 0;
    if (!ogs_strcasecmp(v, "ipv4"))
        return OGS_PDU_SESSION_TYPE_IPV4;
    if (!ogs_strcasecmp(v, "ipv6"))
        return OGS_PDU_SESSION_TYPE_IPV6;
    if (!ogs_strcasecmp(v, "ipv4v6"))
        return OGS_PDU_SESSION_TYPE_IPV4V6;

    ogs_warn("mme.apn_correction: unknown pdn_type `%s' "
            "(use: ipv4, ipv6, ipv4v6)", v);
    return 0;
}

static const char *apn_policy_pdn_type_str(uint8_t type)
{
    switch (type) {
    case OGS_PDU_SESSION_TYPE_IPV4:
        return "ipv4";
    case OGS_PDU_SESSION_TYPE_IPV6:
        return "ipv6";
    case OGS_PDU_SESSION_TYPE_IPV4V6:
        return "ipv4v6";
    default:
        return "-";
    }
}

int mme_apn_policy_parse(ogs_yaml_iter_t *rules_key_iter)
{
    ogs_yaml_iter_t rule_array, rule_iter;
    int count = 0;

    ogs_assert(rules_key_iter);

    /* Replace the whole list (startup parse and SIGHUP reload) */
    mme_apn_policy_remove_all();

    ogs_yaml_iter_recurse(rules_key_iter, &rule_array);
    do {
        mme_apn_policy_t *rule = NULL;

        if (ogs_yaml_iter_type(&rule_array) == YAML_MAPPING_NODE) {
            memcpy(&rule_iter, &rule_array, sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(&rule_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&rule_array))
                break;
            ogs_yaml_iter_recurse(&rule_array, &rule_iter);
        } else {
            break;
        }

        rule = ogs_calloc(1, sizeof(*rule));
        ogs_assert(rule);

        while (ogs_yaml_iter_next(&rule_iter)) {
            const char *rk = ogs_yaml_iter_key(&rule_iter);

            ogs_assert(rk);
            if (!strcmp(rk, "name")) {
                const char *v = ogs_yaml_iter_value(&rule_iter);

                if (v)
                    rule->name = ogs_strdup(v);
            } else if (!strcmp(rk, "imsi_prefix")) {
                apn_policy_str_list(&rule_iter, rk, rule->imsi_prefix,
                        MME_APN_POLICY_MAX_MATCH, &rule->num_of_imsi_prefix);
            } else if (!strcmp(rk, "requested_apn") ||
                    !strcmp(rk, "apn") || !strcmp(rk, "dnn")) {
                apn_policy_str_list(&rule_iter, rk, rule->apn,
                        MME_APN_POLICY_MAX_MATCH, &rule->num_of_apn);
            } else if (!strcmp(rk, "on_apn_mismatch")) {
                const char *v = ogs_yaml_iter_value(&rule_iter);

                if (v && !ogs_strcasecmp(v, "correct"))
                    rule->on_apn_mismatch = MME_APN_POLICY_MISMATCH_CORRECT;
                else if (v && !ogs_strcasecmp(v, "reject"))
                    rule->on_apn_mismatch = MME_APN_POLICY_MISMATCH_REJECT;
                else if (v)
                    ogs_warn("mme.apn_correction: unknown on_apn_mismatch "
                            "`%s' (use: correct, reject)", v);
            } else if (!strcmp(rk, "correct_to")) {
                const char *v = ogs_yaml_iter_value(&rule_iter);

                if (v && !ogs_strcasecmp(v, "default")) {
                    rule->target = MME_APN_POLICY_TARGET_DEFAULT;
                } else if (v && !ogs_strcasecmp(v, "first")) {
                    rule->target = MME_APN_POLICY_TARGET_FIRST;
                } else if (v && v[0]) {
                    rule->target = MME_APN_POLICY_TARGET_NAMED;
                    rule->target_apn = ogs_strdup(v);
                    ogs_assert(rule->target_apn);
                }
            } else if (!strcmp(rk, "on_pdn_type_mismatch")) {
                const char *v = ogs_yaml_iter_value(&rule_iter);

                if (v && !ogs_strcasecmp(v, "correct"))
                    rule->correct_pdn_type = true;
                else if (v && !ogs_strcasecmp(v, "reject"))
                    rule->correct_pdn_type = false;
                else if (v)
                    ogs_warn("mme.apn_correction: unknown "
                            "on_pdn_type_mismatch `%s' "
                            "(use: correct, reject)", v);
            } else if (!strcmp(rk, "pdn_type")) {
                rule->pdn_type = apn_policy_pdn_type_from_str(
                        ogs_yaml_iter_value(&rule_iter));
            } else if (!strcmp(rk, "reject_cause")) {
                const char *v = ogs_yaml_iter_value(&rule_iter);

                if (v) {
                    int cause = atoi(v);

                    if (cause > 0 && cause <= 255)
                        rule->reject_cause = (uint8_t)cause;
                    else
                        ogs_warn("mme.apn_correction: reject_cause `%s' "
                                "out of range", v);
                }
            } else {
                ogs_warn("mme.apn_correction: unknown key `%s'", rk);
            }
        }

        ogs_list_add(&mme_self()->apn_policy_list, rule);
        count++;

        ogs_info("APN correction rule[%s]: imsi_prefix=%d apn=%d "
                "on_apn_mismatch=%s correct_to=%s pdn_type_mismatch=%s "
                "pdn_type=%s",
                rule->name ? rule->name : "-",
                rule->num_of_imsi_prefix, rule->num_of_apn,
                rule->on_apn_mismatch == MME_APN_POLICY_MISMATCH_CORRECT ?
                    "correct" : "reject",
                rule->target == MME_APN_POLICY_TARGET_NAMED ?
                    rule->target_apn :
                    (rule->target == MME_APN_POLICY_TARGET_FIRST ?
                        "first" : "default"),
                rule->correct_pdn_type ? "correct" : "reject",
                apn_policy_pdn_type_str(rule->pdn_type));

    } while (ogs_yaml_iter_type(&rule_array) == YAML_SEQUENCE_NODE);

    return count;
}

/* ---- matching ---- */

static bool apn_policy_apn_matches(mme_apn_policy_t *rule, const char *apn)
{
    char apn_ni[OGS_MAX_APN_LEN + 1];
    char rule_ni[OGS_MAX_APN_LEN + 1];
    int i;

    if (!rule->num_of_apn)
        return true;
    /*
     * The rule names specific APNs, so a UE that sent none cannot
     * match it - it matches only the catch-all rules.
     */
    if (!apn || !apn[0])
        return false;

    mme_apn_normalize_ni(apn_ni, sizeof(apn_ni), apn);

    for (i = 0; i < rule->num_of_apn; i++) {
        if (!rule->apn[i])
            continue;
        if (!strcmp(rule->apn[i], "*"))
            return true;
        mme_apn_normalize_ni(rule_ni, sizeof(rule_ni), rule->apn[i]);
        if (!ogs_strcasecmp(apn_ni, rule_ni))
            return true;
    }

    return false;
}

static bool apn_policy_imsi_matches(mme_apn_policy_t *rule, mme_ue_t *mme_ue)
{
    int i;

    if (!rule->num_of_imsi_prefix)
        return true;
    if (!MME_UE_HAVE_IMSI(mme_ue))
        return false;

    for (i = 0; i < rule->num_of_imsi_prefix; i++) {
        if (!rule->imsi_prefix[i])
            continue;
        if (!strncmp(mme_ue->imsi_bcd, rule->imsi_prefix[i],
                    strlen(rule->imsi_prefix[i])))
            return true;
    }

    return false;
}

static mme_apn_policy_t *apn_policy_find(
        mme_ue_t *mme_ue, const char *requested_apn)
{
    mme_apn_policy_t *rule = NULL;

    if (!mme_ue)
        return NULL;

    ogs_list_for_each(&mme_self()->apn_policy_list, rule) {
        if (!apn_policy_imsi_matches(rule, mme_ue))
            continue;
        if (!apn_policy_apn_matches(rule, requested_apn))
            continue;
        return rule;
    }

    return NULL;
}

/* ---- APN correction ---- */

static ogs_session_t *apn_policy_target_session(
        mme_ue_t *mme_ue, mme_apn_policy_t *rule)
{
    ogs_session_t *session = NULL;

    switch (rule->target) {
    case MME_APN_POLICY_TARGET_NAMED:
        session = mme_session_find_by_apn(mme_ue, rule->target_apn);
        if (session)
            break;
        /*
         * The named APN is not in this subscriber's profile. Falling
         * back to the default is better than rejecting: the operator
         * asked for correction, and one shared rule covers subscribers
         * with slightly different profiles.
         */
        ogs_warn("[%s] APN correction rule[%s]: target APN[%s] not "
                "subscribed; using subscription default",
                mme_ue->imsi_bcd, rule->name ? rule->name : "-",
                rule->target_apn ? rule->target_apn : "-");
        session = mme_default_session(mme_ue);
        break;

    case MME_APN_POLICY_TARGET_FIRST:
        if (mme_ue->num_of_session > 0)
            session = &mme_ue->session[0];
        break;

    case MME_APN_POLICY_TARGET_DEFAULT:
    default:
        session = mme_default_session(mme_ue);
        /* An HSS that never flagged a default still has APNs to offer */
        if (!session && mme_ue->num_of_session > 0)
            session = &mme_ue->session[0];
        break;
    }

    return session;
}

ogs_session_t *mme_apn_policy_correct_apn(
        mme_ue_t *mme_ue, const char *requested_apn, uint8_t *esm_cause)
{
    mme_apn_policy_t *rule = NULL;
    ogs_session_t *session = NULL;

    ogs_assert(esm_cause);

    *esm_cause = OGS_NAS_ESM_CAUSE_MISSING_OR_UNKNOWN_APN;

    if (!mme_ue)
        return NULL;

    rule = apn_policy_find(mme_ue, requested_apn);
    if (!rule)
        return NULL;

    if (rule->on_apn_mismatch != MME_APN_POLICY_MISMATCH_CORRECT) {
        rule->apn_rejected++;
        if (rule->reject_cause)
            *esm_cause = rule->reject_cause;
        ogs_info("[%s] APN correction rule[%s]: reject APN[%s] "
                "esm_cause=%u", mme_ue->imsi_bcd,
                rule->name ? rule->name : "-",
                requested_apn ? requested_apn : "(none)", *esm_cause);
        return NULL;
    }

    session = apn_policy_target_session(mme_ue, rule);
    if (!session || !session->name) {
        rule->apn_rejected++;
        ogs_warn("[%s] APN correction rule[%s]: nothing to correct APN[%s] "
                "to (subscription has no usable APN)",
                mme_ue->imsi_bcd, rule->name ? rule->name : "-",
                requested_apn ? requested_apn : "(none)");
        return NULL;
    }

    rule->apn_corrected++;
    mme_metrics_inst_global_inc(MME_METR_GLOB_CTR_ESM_APN_CORRECTED);
    ogs_info("[%s] APN correction rule[%s]: APN[%s] -> [%s]",
            mme_ue->imsi_bcd, rule->name ? rule->name : "-",
            requested_apn ? requested_apn : "(none)", session->name);

    return session;
}

/* ---- PDN type ---- */

uint8_t mme_apn_policy_pdn_type(
        mme_ue_t *mme_ue, ogs_session_t *session, uint8_t ue_request_type)
{
    mme_apn_policy_t *rule = NULL;
    uint8_t derived;

    ogs_assert(session);

    derived = session->session_type & ue_request_type;

    rule = apn_policy_find(mme_ue,
            session->name ? session->name : NULL);
    if (!rule)
        return derived;

    /*
     * No overlap between what the UE asked for and what it is
     * subscribed to. Stock behaviour rejects with #28; correction hands
     * out the subscribed type instead, which is what the UE would have
     * got had it asked correctly.
     */
    if (derived == 0) {
        if (!rule->correct_pdn_type)
            return 0;

        derived = session->session_type;
        rule->pdn_type_corrected++;
        mme_metrics_inst_global_inc(MME_METR_GLOB_CTR_ESM_PDN_TYPE_CORRECTED);
        ogs_info("[%s] APN correction rule[%s]: PDN type UE[%d] "
                "HSS[%d] -> [%s]",
                mme_ue && MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-",
                rule->name ? rule->name : "-",
                ue_request_type, session->session_type,
                apn_policy_pdn_type_str(derived));
    }

    /*
     * Configured clamp (Huawei's "PDP/PDN Type Policy"). Narrows only
     * when the result is still usable - a rule that says IPv4 must not
     * strand an IPv6-only subscriber with no session at all.
     */
    if (rule->pdn_type && (derived & rule->pdn_type) &&
            derived != (derived & rule->pdn_type)) {
        derived &= rule->pdn_type;
        rule->pdn_type_clamped++;
        ogs_debug("[%s] APN correction rule[%s]: PDN type clamped to [%s]",
                mme_ue && MME_UE_HAVE_IMSI(mme_ue) ? mme_ue->imsi_bcd : "-",
                rule->name ? rule->name : "-",
                apn_policy_pdn_type_str(derived));
    }

    return derived;
}
