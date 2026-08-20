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

#if !defined(MME_APN_POLICY_H_INCLUDED)
#define MME_APN_POLICY_H_INCLUDED

#include "ogs-app.h"
#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mme_ue_s mme_ue_t;

/*
 * APN correction policy (mme.apn_correction).
 *
 * Stock behaviour is the strict 3GPP one: a UE that asks for an APN it
 * is not subscribed to gets ESM #27, and a PDN type that does not
 * intersect the subscription gets #28. That is correct, and on a real
 * network it is also a support queue - handsets carry stale APN
 * profiles, MVNO provisioning drifts, and the subscriber simply has no
 * data.
 *
 * This table is the equivalent of the correction policy every vendor
 * MME exposes (Huawei SMACTCTRL, "correct after subscription data
 * matching failed"): per subscriber range and per requested APN, decide
 * whether a mismatch is corrected to something the subscription does
 * allow, or rejected.
 *
 * Rules are evaluated in file order, first match wins. No matching rule
 * means no policy, which is the stock 3GPP behaviour - so an empty or
 * absent config changes nothing.
 */

typedef enum {
    /* 3GPP: reject the request (default) */
    MME_APN_POLICY_MISMATCH_REJECT = 0,
    /* replace the unknown APN with one the subscription allows */
    MME_APN_POLICY_MISMATCH_CORRECT,
} mme_apn_policy_mismatch_e;

typedef enum {
    /* the HSS default APN (matching Context-Identifier) */
    MME_APN_POLICY_TARGET_DEFAULT = 0,
    /* the first APN in the subscription */
    MME_APN_POLICY_TARGET_FIRST,
    /* a named APN, which must itself be subscribed */
    MME_APN_POLICY_TARGET_NAMED,
} mme_apn_policy_target_e;

#define MME_APN_POLICY_MAX_MATCH 16

typedef struct mme_apn_policy_s {
    ogs_lnode_t lnode;

    char *name;                 /* label for logs and /apn-policy */

    /* Match keys. All present keys must match; absent = any. */
    int num_of_imsi_prefix;
    char *imsi_prefix[MME_APN_POLICY_MAX_MATCH];
    /*
     * NI-normalized APN: the one the UE asked for when correcting an
     * unknown APN, the one in use when reconciling the PDN type.
     */
    int num_of_apn;
    char *apn[MME_APN_POLICY_MAX_MATCH];

    /* Actions */
    mme_apn_policy_mismatch_e on_apn_mismatch;
    mme_apn_policy_target_e target;
    char *target_apn;           /* MME_APN_POLICY_TARGET_NAMED */
    bool correct_pdn_type;      /* empty UE-subscription intersection */
    uint8_t pdn_type;           /* clamp, OGS_PDU_SESSION_TYPE_*, 0 = none */
    uint8_t reject_cause;       /* ESM cause on reject, 0 = #27 */

    /* Counters, surfaced like Huawei's CHR report of APN correction */
    uint64_t apn_corrected;
    uint64_t apn_rejected;
    uint64_t pdn_type_corrected;
    uint64_t pdn_type_clamped;
} mme_apn_policy_t;

/* Replaces the whole list (startup parse and SIGHUP reload) */
int mme_apn_policy_parse(ogs_yaml_iter_t *rules_key_iter);
void mme_apn_policy_remove_all(void);
bool mme_apn_policy_configured(void);

/*
 * The UE asked for requested_apn (NULL when it sent none) and the
 * subscription has no such APN. Returns the substitute subscription
 * entry, or NULL with *esm_cause set to the cause to reject with.
 */
ogs_session_t *mme_apn_policy_correct_apn(
        mme_ue_t *mme_ue, const char *requested_apn, uint8_t *esm_cause);

/*
 * Effective PDN type for this session: the UE request intersected with
 * the subscription, then corrected and/or clamped per policy. Returns 0
 * when the request cannot be satisfied and must be rejected with #28.
 */
uint8_t mme_apn_policy_pdn_type(
        mme_ue_t *mme_ue, ogs_session_t *session, uint8_t ue_request_type);

#ifdef __cplusplus
}
#endif

#endif /* MME_APN_POLICY_H_INCLUDED */
