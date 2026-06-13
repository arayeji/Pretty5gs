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

#ifndef SMF_COLLISION_REPLACE_H
#define SMF_COLLISION_REPLACE_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

void smf_ue_collision_abort(smf_ue_t *smf_ue);

bool smf_sess_upf_established(smf_sess_t *sess);

smf_sess_t *smf_sess_find_collision_for_gtp2(ogs_gtp2_message_t *message);
smf_sess_t *smf_sess_find_collision_for_gtp1(ogs_gtp1_message_t *message);
smf_sess_t *smf_sess_find_collision_by_ipv4_gtp2(ogs_gtp2_message_t *message);

bool smf_sess_collision_replace_begin_gtp2(
        smf_sess_t *old_sess, smf_event_t *e,
        ogs_gtp2_sender_f_teid_t *sender_f_teid);
bool smf_sess_collision_replace_begin_gtp1(
        smf_sess_t *old_sess, smf_event_t *e);

void smf_sess_collision_replace_complete(smf_sess_t *old_sess);
void smf_sess_collision_on_pfcp_delete_timeout(smf_sess_t *sess);

#ifdef __cplusplus
}
#endif

#endif /* SMF_COLLISION_REPLACE_H */
