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

#ifndef MME_FD_PATH_H
#define MME_FD_PATH_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

int mme_fd_init(void);
void mme_fd_final(void);

/* MME Sends Authentication Information Request to HSS */
void mme_s6a_send_air(enb_ue_t *enb_ue, mme_ue_t *mme_ue,
    ogs_nas_authentication_failure_parameter_t
        *authentication_failure_parameter);
void mme_s6a_send_air_from_gn(enb_ue_t *enb_ue, mme_ue_t *mme_ue,
    ogs_gtp_xact_t *gtp_xact);

/* MME Sends Update Location Request to HSS */
void mme_s6a_send_ulr(enb_ue_t *enb_ue, mme_ue_t *mme_ue, uint32_t extra_ulr_flags);
/* MME Sends Purge UE Request to HSS */
void mme_s6a_send_pur(enb_ue_t *enb_ue, mme_ue_t *mme_ue);

/* MME Sends Notify Request to HSS (T-ADS UE-reachability report, URRP-MME) */
void mme_s6a_send_nor(mme_ue_t *mme_ue, uint32_t nor_flags);

/*
 * T-ADS helper: if URRP-MME is armed for this UE, report reachability to
 * the HSS via S6a NOR (UE-Reachable-From-MME) and disarm. No-op otherwise.
 * Called from any ECM-IDLE -> ECM-CONNECTED transition.
 */
void mme_s6a_report_urrp(mme_ue_t *mme_ue);

void mme_s6a_timer_start(mme_ue_t *mme_ue, uint16_t cmd_code);
void mme_s6a_timer_stop(mme_ue_t *mme_ue);

#ifdef __cplusplus
}
#endif

#endif /* MME_FD_PATH_H */

