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

/*
 * 3GPP TS 29.212 clause 4.5.21 (PCRF failure and restoration):
 * when the Gx peer becomes available again, the PCEF re-establishes
 * IP-CAN session signalling for active bearers (CCR-I replay).
 */

#include "gx-restoration.h"

#include "event.h"
#include "fd-path.h"
#include "smf-sm.h"

static bool smf_gx_restoration_eligible(smf_sess_t *sess)
{
    if (!sess || !sess->epc)
        return false;

    if (!OGS_FSM_CHECK(&sess->sm, smf_gsm_state_operational))
        return false;

    if (sess->collision_replace)
        return false;

    if (!sess->ipv4 && !sess->ipv6)
        return false;

    if (!sess->upf_n4_seid)
        return false;

    if (sess->sm_data.gx_restoration_in_flight)
        return false;

    return true;
}

void smf_gx_restoration_on_peer_connect(void)
{
    smf_ue_t *smf_ue = NULL;
    smf_sess_t *sess = NULL;
    char buf4[OGS_ADDRSTRLEN];
    char buf6[OGS_ADDRSTRLEN];
    int count = 0;

    if (!ogs_diam_is_relay_or_app_advertised(OGS_DIAM_GX_APPLICATION_ID)) {
        ogs_debug("Gx peer connect: Gx application not advertised yet");
        return;
    }

    ogs_list_for_each(&smf_self()->smf_ue_list, smf_ue) {
        ogs_list_for_each(&smf_ue->sess_list, sess) {
            if (!smf_gx_restoration_eligible(sess))
                continue;

            if (sess->gx_sid) {
                ogs_free(sess->gx_sid);
                sess->gx_sid = NULL;
            }

            sess->sm_data.gx_restoration_in_flight = true;
            if (smf_gx_send_ccr(sess, OGS_INVALID_POOL_ID,
                        OGS_DIAM_GX_CC_REQUEST_TYPE_INITIAL_REQUEST) != OGS_OK) {
                sess->sm_data.gx_restoration_in_flight = false;
                ogs_warn("[%s] Gx restoration CCR-I failed DNN:%s",
                        smf_ue->imsi_bcd,
                        sess->session.name ? sess->session.name : "-");
                continue;
            }

            count++;
            ogs_info("[%s] Gx restoration CCR-I DNN:%s IPv4:%s IPv6:%s",
                    smf_ue->imsi_bcd,
                    sess->session.name ? sess->session.name : "-",
                    sess->ipv4 ?
                        OGS_INET_NTOP(&sess->ipv4->addr, buf4) : "-",
                    sess->ipv6 ?
                        OGS_INET6_NTOP(&sess->ipv6->addr, buf6) : "-");
        }
    }

    if (count)
        ogs_info("Gx restoration: replayed CCR-I for %d active session(s)", count);
}

void smf_gx_peer_connect_event_push(void)
{
    smf_event_t *e = NULL;
    int rv;

    e = smf_event_new(SMF_EVT_GX_PEER_CONNECT);
    ogs_assert(e);

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        ogs_event_free(e);
        return;
    }

    ogs_pollset_notify(ogs_app()->pollset);
}
