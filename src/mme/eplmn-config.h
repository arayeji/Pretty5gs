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

#if !defined(MME_EPLMN_CONFIG_H_INCLUDED)
#define MME_EPLMN_CONFIG_H_INCLUDED

#include "ogs-app.h"
#include "ogs-nas-eps.h"

#ifdef __cplusplus
extern "C" {
#endif

int mme_eplmn_parse_config(ogs_yaml_iter_t *parent,
        int *num_of_eplmn, ogs_plmn_id_t *eplmn);
int mme_eplmn_validate(int num_of_eplmn);
void mme_eplmn_log_config(int num_of_eplmn, ogs_plmn_id_t *eplmn);
void mme_eplmn_log_serving_only(bool serving_only);
int mme_eplmn_build_nas_list(ogs_nas_plmn_list_t *nas_list,
        int num_of_eplmn, ogs_plmn_id_t *eplmn);
int mme_eplmn_build_nas_list_for_serving(ogs_nas_plmn_list_t *nas_list,
        const ogs_plmn_id_t *serving_plmn, bool serving_only,
        int num_of_eplmn, ogs_plmn_id_t *eplmn);
int mme_eplmn_count_for_serving(const ogs_plmn_id_t *serving_plmn,
        bool serving_only, int num_of_eplmn, ogs_plmn_id_t *eplmn);
int mme_eplmn_add_if_new(int *num_of_eplmn, ogs_plmn_id_t *eplmn,
        const ogs_plmn_id_t *candidate);

#ifdef __cplusplus
}
#endif

#endif /* MME_EPLMN_CONFIG_H_INCLUDED */
