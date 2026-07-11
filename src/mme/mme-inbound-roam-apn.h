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

#ifndef MME_INBOUND_ROAM_APN_H
#define MME_INBOUND_ROAM_APN_H

#include "ogs-app.h"
#include "ogs-nas-eps.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mme_ue_s mme_ue_t;

#define MME_MAX_INBOUND_ROAM_APN       32
#define MME_MAX_INBOUND_ROAM_APN_RULE  16

/* Sentinel: APN passed policy (not a NAS ESM reject cause). */
#define MME_INBOUND_ROAM_APN_ESM_ACCEPT 0

typedef struct mme_inbound_roam_apn_rule_s {
    ogs_plmn_id_t plmn_id;
    bool          plmn_id_configured;
    int           num_of_allowed_apn;
    char          allowed_apn[MME_MAX_INBOUND_ROAM_APN][OGS_MAX_APN_LEN + 1];
    int           num_of_denied_apn;
    char          denied_apn[MME_MAX_INBOUND_ROAM_APN][OGS_MAX_APN_LEN + 1];
} mme_inbound_roam_apn_rule_t;

/*
 * Parse/replace the entire mme.inbound_roam YAML block (startup and SIGHUP).
 * Scalar inbound_roam knobs and APN allow/deny lists are applied atomically.
 */
void mme_inbound_roam_config_parse(ogs_yaml_iter_t *inbound_roam_iter);

/*
 * Inbound roam only. Returns true when the APN (NI or FQDN) may proceed.
 * Policy: denied_apn always wins; when allowed_apn is non-empty the APN must
 * be listed. Per-home-PLMN apn_rule entries override the global lists.
 */
bool mme_inbound_roam_apn_allowed(mme_ue_t *mme_ue, const char *apn);

/* ESM cause to return when mme_inbound_roam_apn_allowed() is false. */
uint8_t mme_inbound_roam_apn_esm_cause(mme_ue_t *mme_ue, const char *apn);

#ifdef __cplusplus
}
#endif

#endif /* MME_INBOUND_ROAM_APN_H */
