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

#include "mme-roam-access.h"

#include "mme-apn.h"
#include "mme-context.h"

static void mme_access_control_entry_types(bool *has_prefix, bool *has_plmn)
{
    mme_context_t *self = mme_self();
    int i;

    ogs_assert(has_prefix);
    ogs_assert(has_plmn);

    *has_prefix = false;
    *has_plmn = false;

    for (i = 0; i < self->num_of_access_control; i++) {
        mme_access_control_t *ac = &self->access_control[i];

        if (ac->imsi_prefix[0])
            *has_prefix = true;
        if (ac->plmn_id_configured)
            *has_plmn = true;
    }
}

static mme_access_control_t *mme_access_control_find_inbound(
        const char *imsi_bcd)
{
    mme_context_t *self = mme_self();
    int i, best = -1, best_prefix_len = -1;

    ogs_assert(imsi_bcd);

    for (i = 0; i < self->num_of_access_control; i++) {
        mme_access_control_t *ac = &self->access_control[i];
        size_t prefix_len;

        if (ac->imsi_prefix[0]) {
            prefix_len = strlen(ac->imsi_prefix);
            if (prefix_len == 0)
                continue;
            if (strncmp(imsi_bcd, ac->imsi_prefix, prefix_len) != 0)
                continue;
            if ((int)prefix_len > best_prefix_len) {
                best_prefix_len = (int)prefix_len;
                best = i;
            }
            continue;
        }

        if (ac->plmn_id_configured &&
                ogs_plmn_id_imsi_prefix_match(imsi_bcd, &ac->plmn_id)) {
            if (best_prefix_len < 5) {
                best_prefix_len = 5;
                best = i;
            }
        }
    }

    if (best < 0)
        return NULL;

    return &self->access_control[best];
}

static uint8_t mme_access_control_inbound_reject_cause(
        mme_access_control_t *ac, uint8_t default_cause)
{
    mme_context_t *self = mme_self();

    if (ac && ac->reject_cause)
        return ac->reject_cause;
    if (self->default_reject_cause)
        return self->default_reject_cause;
    return default_cause;
}

#include "mme-context.h"

bool mme_access_control_tac_add(mme_access_control_t *ac, uint16_t tac)
{
    uint16_t *key;

    ogs_assert(ac);

    if (!ac->tac_hash)
        ac->tac_hash = ogs_hash_make();

    if (ogs_hash_get(ac->tac_hash, &tac, sizeof(tac)))
        return false;

    key = ogs_calloc(1, sizeof(*key));
    ogs_assert(key);
    *key = tac;
    ogs_hash_set(ac->tac_hash, key, sizeof(*key), (void *)(intptr_t)1);
    return true;
}

bool mme_access_control_enb_add(mme_access_control_t *ac, uint32_t enb_id)
{
    uint32_t *key;

    ogs_assert(ac);

    if (!ac->enb_id_hash)
        ac->enb_id_hash = ogs_hash_make();

    if (ogs_hash_get(ac->enb_id_hash, &enb_id, sizeof(enb_id)))
        return false;

    key = ogs_calloc(1, sizeof(*key));
    ogs_assert(key);
    *key = enb_id;
    ogs_hash_set(ac->enb_id_hash, key, sizeof(*key), (void *)(intptr_t)1);
    return true;
}

void mme_access_control_free_all(void)
{
    mme_context_t *self = mme_self();
    int i;

    for (i = 0; i < self->num_of_access_control; i++) {
        mme_access_control_t *ac = &self->access_control[i];

        if (ac->tac_hash) {
            ogs_hash_index_t *hi;

            for (hi = ogs_hash_first(ac->tac_hash); hi;
                    hi = ogs_hash_next(hi)) {
                void *key;

                ogs_hash_this(hi, (const void **)&key, NULL, NULL);
                ogs_free(key);
            }
            ogs_hash_destroy(ac->tac_hash);
            ac->tac_hash = NULL;
        }
        if (ac->enb_id_hash) {
            ogs_hash_index_t *hi;

            for (hi = ogs_hash_first(ac->enb_id_hash); hi;
                    hi = ogs_hash_next(hi)) {
                void *key;

                ogs_hash_this(hi, (const void **)&key, NULL, NULL);
                ogs_free(key);
            }
            ogs_hash_destroy(ac->enb_id_hash);
            ac->enb_id_hash = NULL;
        }
    }
}

uint8_t mme_inbound_roam_access_emm_cause(
        mme_ue_t *mme_ue, enb_ue_t *enb_ue)
{
    mme_context_t *self = mme_self();
    mme_access_control_t *ac = NULL;
    mme_enb_t *enb = NULL;
    uint16_t tac;
    uint32_t enb_id = 0;
    bool tac_required = false, enb_required = false;
    bool has_prefix_acl = false, has_plmn_acl = false;
    char serving_plmn[OGS_PLMNIDSTRLEN];

    ogs_assert(mme_ue);

    if (!MME_UE_HAVE_IMSI(mme_ue))
        return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;

    if (!mme_ue_is_inbound_roam(mme_ue))
        return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;

    if (self->num_of_access_control == 0)
        return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;

    mme_access_control_entry_types(&has_prefix_acl, &has_plmn_acl);

    tac = mme_ue->tai.tac;
    ogs_plmn_id_to_string(&mme_ue->tai.plmn_id, serving_plmn);

    if (enb_ue) {
        enb = mme_enb_find_by_id(enb_ue->enb_id);
        if (enb && enb->enb_id_presence)
            enb_id = enb->enb_id;
    }

    ac = mme_access_control_find_inbound(mme_ue->imsi_bcd);
    if (!ac) {
        if (has_prefix_acl || has_plmn_acl) {
            uint8_t emm_cause = mme_access_control_inbound_reject_cause(
                    NULL, OGS_NAS_EMM_CAUSE_PLMN_NOT_ALLOWED);

            ogs_debug("[%s] inbound roam IMSI not in access_control allow-list "
                    "[serving_plmn:%s tac:%u eNB:0x%x emm_cause:%d]",
                    mme_ue->imsi_bcd, serving_plmn, tac, enb_id, emm_cause);
            return emm_cause;
        }
        return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;
    }

    tac_required = ac->tac_hash != NULL;
    enb_required = ac->enb_id_hash != NULL;

    if (!tac_required && !enb_required)
        return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;

    if (tac_required &&
            !ogs_hash_get(ac->tac_hash, &tac, sizeof(tac))) {
        uint8_t emm_cause = mme_access_control_inbound_reject_cause(ac,
                OGS_NAS_EMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA);

        ogs_debug("[%s] inbound roam TAC[%u] not in access_control allow-list "
                "[prefix:%s serving_plmn:%s eNB:0x%x emm_cause:%d]",
                mme_ue->imsi_bcd, tac,
                ac->imsi_prefix[0] ? ac->imsi_prefix : "-",
                serving_plmn, enb_id, emm_cause);
        return emm_cause;
    }

    if (enb_required) {
        if (!enb_id) {
            uint8_t emm_cause = mme_access_control_inbound_reject_cause(ac,
                    OGS_NAS_EMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA);

            ogs_debug("[%s] inbound roam eNB-ID unknown for access_control "
                    "[prefix:%s serving_plmn:%s tac:%u emm_cause:%d]",
                    mme_ue->imsi_bcd,
                    ac->imsi_prefix[0] ? ac->imsi_prefix : "-",
                    serving_plmn, tac, emm_cause);
            return emm_cause;
        }
        if (!ogs_hash_get(ac->enb_id_hash, &enb_id, sizeof(enb_id))) {
            uint8_t emm_cause = mme_access_control_inbound_reject_cause(ac,
                    OGS_NAS_EMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA);

            ogs_debug("[%s] inbound roam eNB-ID[0x%x] not in access_control "
                    "allow-list [prefix:%s serving_plmn:%s tac:%u emm_cause:%d]",
                    mme_ue->imsi_bcd, enb_id,
                    ac->imsi_prefix[0] ? ac->imsi_prefix : "-",
                    serving_plmn, tac, emm_cause);
            return emm_cause;
        }
    }

    return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;
}
