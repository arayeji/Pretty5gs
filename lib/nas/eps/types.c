/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
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

#include "ogs-nas-eps.h"

static int eps_tai0_partial_count(ogs_eps_tai0_list_t *list0)
{
    int i;

    ogs_assert(list0);
    for (i = 0; i < OGS_MAX_NUM_OF_EPS_TAI0_PARTIAL_LIST && list0->tai[i].num; i++)
        ;
    return i;
}

static bool serving_tai_is_first(
        ogs_eps_tai0_list_t *list0,
        ogs_eps_tai1_list_t *list1,
        ogs_eps_tai2_list_t *list2,
        const ogs_eps_tai_t *serving)
{
    ogs_assert(serving);

    if (list0 && list0->tai[0].num) {
        return memcmp(&list0->tai[0].plmn_id, &serving->plmn_id,
                    OGS_PLMN_ID_LEN) == 0 &&
            list0->tai[0].tac[0] == serving->tac;
    }

    if (list1 && list1->tai[0].num) {
        return memcmp(&list1->tai[0].plmn_id, &serving->plmn_id,
                    OGS_PLMN_ID_LEN) == 0 &&
            list1->tai[0].tac <= serving->tac &&
            serving->tac < (list1->tai[0].tac + list1->tai[0].num);
    }

    if (list2 && list2->num) {
        return memcmp(&list2->tai[0].plmn_id, &serving->plmn_id,
                    OGS_PLMN_ID_LEN) == 0 &&
            list2->tai[0].tac == serving->tac;
    }

    return false;
}

static void eps_tai1_remove_entry(ogs_eps_tai1_list_t *list1, int index)
{
    int count, i;

    ogs_assert(list1);
    ogs_assert(index >= 0);

    for (count = 0; count < OGS_MAX_NUM_OF_TAI && list1->tai[count].num; count++)
        ;
    ogs_assert(index < count);

    for (i = index; i < count - 1; i++)
        list1->tai[i] = list1->tai[i + 1];
    memset(&list1->tai[count - 1], 0, sizeof(list1->tai[0]));
}

static void eps_tai2_remove_entry(ogs_eps_tai2_list_t *list2, int index)
{
    int i;

    ogs_assert(list2);
    ogs_assert(index >= 0 && index < list2->num);

    for (i = index; i < list2->num - 1; i++)
        list2->tai[i] = list2->tai[i + 1];
    list2->num--;
}

static void ogs_nas_tai_list_prioritize_serving(
        ogs_eps_tai0_list_t *list0,
        ogs_eps_tai1_list_t *list1,
        ogs_eps_tai2_list_t *list2,
        const ogs_eps_tai_t *serving)
{
    int i = 0, j = 0, k = 0;
    int partial_idx = -1, tac_idx = -1;
    int list1_idx = -1;
    int list2_idx = -1;
    int partial_count = 0;
    uint16_t tac_swap = 0;
    uint8_t partial_buf[sizeof(((ogs_eps_tai0_list_t *)0)->tai[0])];

    ogs_assert(serving);

    if (!list0)
        return;

    if (serving_tai_is_first(list0, list1, list2, serving))
        return;

    for (i = 0; i < OGS_MAX_NUM_OF_EPS_TAI0_PARTIAL_LIST &&
            list0->tai[i].num; i++) {
        if (memcmp(&list0->tai[i].plmn_id, &serving->plmn_id,
                    OGS_PLMN_ID_LEN) != 0)
            continue;

        for (k = 0; k < list0->tai[i].num; k++) {
            if (list0->tai[i].tac[k] == serving->tac) {
                partial_idx = i;
                tac_idx = k;
                break;
            }
        }
        if (partial_idx >= 0)
            break;
    }

    if (list1) {
        for (j = 0; list1->tai[j].num; j++) {
            if (memcmp(&list1->tai[j].plmn_id, &serving->plmn_id,
                        OGS_PLMN_ID_LEN) != 0)
                continue;

            if (list1->tai[j].tac <= serving->tac &&
                    serving->tac < (list1->tai[j].tac + list1->tai[j].num)) {
                list1_idx = j;
                break;
            }
        }
    }

    if (list2 && list2->num) {
        for (j = 0; j < list2->num; j++) {
            if (memcmp(&list2->tai[j].plmn_id, &serving->plmn_id,
                        OGS_PLMN_ID_LEN) == 0 &&
                list2->tai[j].tac == serving->tac) {
                list2_idx = j;
                break;
            }
        }
    }

    if (partial_idx < 0 && list1_idx < 0 && list2_idx < 0)
        return;

    if (partial_idx >= 0) {
        if (partial_idx != 0) {
            memcpy(partial_buf, &list0->tai[partial_idx], sizeof(partial_buf));
            memmove(&list0->tai[1], &list0->tai[0],
                    partial_idx * sizeof(list0->tai[0]));
            memcpy(&list0->tai[0], partial_buf, sizeof(partial_buf));
        }

        if (tac_idx != 0) {
            tac_swap = list0->tai[0].tac[0];
            list0->tai[0].tac[0] = list0->tai[0].tac[tac_idx];
            list0->tai[0].tac[tac_idx] = tac_swap;
        }
        return;
    }

    partial_count = eps_tai0_partial_count(list0);
    if (partial_count >= OGS_MAX_NUM_OF_EPS_TAI0_PARTIAL_LIST)
        return;

    if (partial_count > 0) {
        memmove(&list0->tai[1], &list0->tai[0],
                partial_count * sizeof(list0->tai[0]));
    }

    memset(&list0->tai[0], 0, sizeof(list0->tai[0]));
    list0->tai[0].type = OGS_TAI0_TYPE;
    list0->tai[0].num = 1;
    memcpy(&list0->tai[0].plmn_id, &serving->plmn_id, OGS_PLMN_ID_LEN);
    list0->tai[0].tac[0] = serving->tac;

    if (list1_idx >= 0) {
        uint16_t start = list1->tai[list1_idx].tac;
        uint16_t num = list1->tai[list1_idx].num;

        if (num == 1) {
            eps_tai1_remove_entry(list1, list1_idx);
        } else if (serving->tac == start) {
            list1->tai[list1_idx].tac++;
            list1->tai[list1_idx].num--;
        } else if (serving->tac == (start + num - 1)) {
            list1->tai[list1_idx].num--;
        }
    } else if (list2_idx >= 0) {
        eps_tai2_remove_entry(list2, list2_idx);
    }
}

int ogs_nas_tai_list_build_serving_only(
        ogs_nas_tracking_area_identity_list_t *target,
        const ogs_eps_tai_t *serving_tai)
{
    ogs_nas_plmn_id_t ogs_nas_plmn_id;
    ogs_eps_tai2_list_t target2;
    int size;

    ogs_assert(target);
    ogs_assert(serving_tai);

    memset(target, 0, sizeof(*target));
    memset(&target2, 0, sizeof(target2));

    /*
     * TS 24.301 §9.9.3.33 list type 2: one PLMN, non-contiguous TACs.
     * A single serving TAC is always encoded this way (6 octets) so UEs
     * never see a truncated or oversized list from mme.tai.
     */
    target2.type = OGS_TAI2_TYPE;
    target2.num = 0; /* NAS num field = (number of TACs) - 1 */

    memcpy(&target2.tai[0].plmn_id,
            ogs_nas_from_plmn_id(&ogs_nas_plmn_id, &serving_tai->plmn_id),
            OGS_PLMN_ID_LEN);
    target2.tai[0].tac = htobe16(serving_tai->tac);

    size = 1 + (OGS_PLMN_ID_LEN + sizeof(uint16_t));
    ogs_assert(size <= OGS_NAS_EPS_MAX_TAI_LIST_LEN);

    memcpy(target->buffer, &target2, size);
    target->length = size;

    return OGS_OK;
}

int ogs_nas_tai_list_build(
        ogs_nas_tracking_area_identity_list_t *target,
        ogs_eps_tai0_list_t *source0,
        ogs_eps_tai1_list_t *source1,
        ogs_eps_tai2_list_t *source2,
        const ogs_eps_tai_t *serving_tai)
{
    int i = 0, j = 0, size = 0;
    bool tail_truncated = false;

    ogs_eps_tai0_list_t target0;
    ogs_eps_tai1_list_t target1;
    ogs_eps_tai2_list_t target2;
    ogs_nas_plmn_id_t ogs_nas_plmn_id;

    ogs_eps_tai0_list_t local0;
    ogs_eps_tai1_list_t local1;
    ogs_eps_tai2_list_t local2;

    ogs_assert(target);

    memset(target, 0, sizeof(ogs_nas_tracking_area_identity_list_t));
    memset(&target0, 0, sizeof(ogs_eps_tai0_list_t));
    memset(&target1, 0, sizeof(ogs_eps_tai1_list_t));
    memset(&target2, 0, sizeof(ogs_eps_tai2_list_t));

    if (serving_tai && source0) {
        ogs_eps_tai0_list_t *prioritize0 = source0;
        ogs_eps_tai1_list_t *prioritize1 = source1;
        ogs_eps_tai2_list_t *prioritize2 = source2;

        memset(&local0, 0, sizeof(local0));
        memset(&local1, 0, sizeof(local1));
        memset(&local2, 0, sizeof(local2));

        memcpy(&local0, source0, sizeof(local0));
        if (source1)
            memcpy(&local1, source1, sizeof(local1));
        if (source2)
            memcpy(&local2, source2, sizeof(local2));

        ogs_nas_tai_list_prioritize_serving(&local0,
                source1 ? &local1 : NULL,
                source2 ? &local2 : NULL,
                serving_tai);

        prioritize0 = &local0;
        if (source1)
            prioritize1 = &local1;
        if (source2)
            prioritize2 = &local2;

        source0 = prioritize0;
        source1 = prioritize1;
        source2 = prioritize2;
    }

    /*
     * 3GPP TS 24.301: Tracking area identity list value is max 96 octets.
     * Internal served_tai may be larger; split type-0 elements and stop when
     * full instead of failing attach/tau (MME used to assert on OGS_ERROR).
     */
    for (i = 0; source0 && i < OGS_MAX_NUM_OF_EPS_TAI0_PARTIAL_LIST &&
            source0->tai[i].num; i++) {
        int tac_off = 0;

        ogs_assert(source0->tai[i].type == OGS_TAI0_TYPE);
        ogs_assert(source0->tai[i].num <= OGS_MAX_NUM_OF_TAI);

        while (tac_off < source0->tai[i].num) {
            int n_tac = source0->tai[i].num - tac_off;

            size = (1 + 3 + 2 * n_tac);
            if ((target->length + size) > OGS_NAS_EPS_MAX_TAI_LIST_LEN) {
                int room = OGS_NAS_EPS_MAX_TAI_LIST_LEN - target->length;

                if (room < (1 + 3 + 2 * 1)) {
                    tail_truncated = true;
                    goto tai_list_done;
                }
                n_tac = (room - 1 - 3) / 2;
                ogs_assert(n_tac >= 1);
                size = (1 + 3 + 2 * n_tac);
            }

            target0.tai[0].type = source0->tai[i].type;
            /* <Spec> NAS num field = (number of TACs) - 1 */
            target0.tai[0].num = n_tac - 1;
            memcpy(&target0.tai[0].plmn_id,
                ogs_nas_from_plmn_id(&ogs_nas_plmn_id,
                    &source0->tai[i].plmn_id),
                OGS_PLMN_ID_LEN);

            for (j = 0; j < n_tac; j++) {
                target0.tai[0].tac[j] =
                    htobe16(source0->tai[i].tac[tac_off + j]);
            }

            memcpy(target->buffer + target->length, &target0.tai[0], size);
            target->length += size;
            tac_off += n_tac;
        }
    }

    for (i = 0; source1 && source1->tai[i].num; i++) {
        ogs_assert(source1->tai[i].type == OGS_TAI1_TYPE);
        target1.tai[i].type = source1->tai[i].type;

        /* <Spec> target->num = source->num - 1 */
        ogs_assert(source1->tai[i].num <= OGS_MAX_NUM_OF_TAI);
        target1.tai[i].num = source1->tai[i].num - 1;
        memcpy(&target1.tai[i].plmn_id,
            ogs_nas_from_plmn_id(&ogs_nas_plmn_id, &source1->tai[i].plmn_id),
            OGS_PLMN_ID_LEN);

        target1.tai[i].tac = htobe16(source1->tai[i].tac);

        size = (1 + 3 + 2);
        if ((target->length + size) > OGS_NAS_EPS_MAX_TAI_LIST_LEN) {
            tail_truncated = true;
            goto tai_list_done;
        }
        memcpy(target->buffer + target->length, &target1.tai[i], size);
        target->length += size;
    }

    if (source2 && source2->num) {
        memset(&target2, 0, sizeof(target2));

        ogs_assert(source2->type == OGS_TAI2_TYPE);
        target2.type = source2->type;

        /* <Spec> target->num = source->num - 1 */
        ogs_assert(source2->num <= OGS_MAX_NUM_OF_TAI);
        target2.num = source2->num - 1;

        size = (1 + (3 + 2) * source2->num);
        if ((target->length + size) > OGS_NAS_EPS_MAX_TAI_LIST_LEN) {
            tail_truncated = true;
            goto tai_list_done;
        }
        for (i = 0; i < source2->num; i++) {
            memcpy(&target2.tai[i].plmn_id,
                    ogs_nas_from_plmn_id(&ogs_nas_plmn_id,
                        &source2->tai[i].plmn_id),
                    OGS_PLMN_ID_LEN);
            target2.tai[i].tac = htobe16(source2->tai[i].tac);
        }
        memcpy(target->buffer + target->length, &target2, size);
        target->length += size;
    }

tai_list_done:
    if (tail_truncated)
        ogs_warn("NAS TAI list truncated to %u octets (3GPP max %u); remaining "
                "served TAI entries are not sent to the UE",
                (unsigned)target->length,
                (unsigned)OGS_NAS_EPS_MAX_TAI_LIST_LEN);

    /*
     * Avoid sending an empty mandatory TAI list (malformed Attach/TAU Accept).
     */
    if (target->length == 0 && serving_tai) {
        ogs_warn("NAS TAI list empty after build; using serving TAC only");
        return ogs_nas_tai_list_build_serving_only(target, serving_tai);
    }

    return OGS_OK;
}
