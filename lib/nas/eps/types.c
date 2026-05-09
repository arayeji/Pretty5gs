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

int ogs_nas_tai_list_build(
        ogs_nas_tracking_area_identity_list_t *target,
        ogs_eps_tai0_list_t *source0,
        ogs_eps_tai1_list_t *source1,
        ogs_eps_tai2_list_t *source2)
{
    int i = 0, j = 0, size = 0;
    bool tail_truncated = false;

    ogs_eps_tai0_list_t target0;
    ogs_eps_tai1_list_t target1;
    ogs_eps_tai2_list_t target2;
    ogs_nas_plmn_id_t ogs_nas_plmn_id;

    ogs_assert(target);

    memset(target, 0, sizeof(ogs_nas_tracking_area_identity_list_t));
    memset(&target0, 0, sizeof(ogs_eps_tai0_list_t));
    memset(&target1, 0, sizeof(ogs_eps_tai1_list_t));
    memset(&target2, 0, sizeof(ogs_eps_tai2_list_t));

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

    return OGS_OK;
}
