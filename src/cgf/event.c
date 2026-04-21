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

#include "event.h"

cgf_event_t *cgf_event_new(int id)
{
    cgf_event_t *e = ogs_event_size(id, sizeof(cgf_event_t));
    ogs_assert(e);
    e->h.id = id;
    return e;
}

void cgf_event_free(cgf_event_t *e)
{
    if (!e) return;
    if (e->pkbuf) ogs_pkbuf_free(e->pkbuf);
    ogs_event_free(e);
}

const char *cgf_event_get_name(cgf_event_t *e)
{
    if (!e) return OGS_FSM_NAME_INIT_SIG;
    switch (e->h.id) {
    case OGS_FSM_ENTRY_SIG:      return OGS_FSM_NAME_ENTRY_SIG;
    case OGS_FSM_EXIT_SIG:       return OGS_FSM_NAME_EXIT_SIG;
    case CGF_EVENT_GTPP_RECV:    return "CGF_EVENT_GTPP_RECV";
    case CGF_EVENT_ECHO_TIMER:   return "CGF_EVENT_ECHO_TIMER";
    case CGF_EVENT_RTO_TIMER:    return "CGF_EVENT_RTO_TIMER";
    case CGF_EVENT_SPOOL_TIMER:  return "CGF_EVENT_SPOOL_TIMER";
    default: break;
    }
    return "UNKNOWN_EVENT";
}
