/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef ESM_BUILD_H
#define ESM_BUILD_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

ogs_pkbuf_t *esm_build_pdn_connectivity_reject(
        mme_sess_t *sess, ogs_nas_esm_cause_t esm_cause, int create_action);
ogs_pkbuf_t *esm_build_information_request(mme_bearer_t *bearer);
ogs_pkbuf_t *esm_build_activate_default_bearer_context_request(
        mme_sess_t *sess, int create_action);
ogs_pkbuf_t *esm_build_activate_dedicated_bearer_context_request(
        mme_bearer_t *bearer);
ogs_pkbuf_t *esm_build_modify_bearer_context_request(
        mme_bearer_t *bearer, int qos_presence, int tft_presence);
ogs_pkbuf_t *esm_build_deactivate_bearer_context_request(
        mme_bearer_t *bearer, ogs_nas_esm_cause_t esm_cause);
ogs_pkbuf_t *esm_build_bearer_resource_allocation_reject(
        mme_ue_t *mme_ue, uint8_t pti, ogs_nas_esm_cause_t esm_cause);
ogs_pkbuf_t *esm_build_bearer_resource_modification_reject(
        mme_ue_t *mme_ue, uint8_t pti, ogs_nas_esm_cause_t esm_cause);
/*
 * TS 24.301 7.3.2: response to an ESM message referencing an unknown
 * EPS bearer identity (cause #43) or other ESM protocol errors. The UE
 * locally deactivates the offending bearer only - unlike an EMM reject,
 * which would tear down the whole registration.
 */
ogs_pkbuf_t *esm_build_status(
        mme_ue_t *mme_ue, uint8_t ebi, uint8_t pti,
        ogs_nas_esm_cause_t esm_cause);

#ifdef __cplusplus
}
#endif

#endif /* ESM_BUILD_H */
