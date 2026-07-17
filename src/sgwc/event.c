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

#include "event.h"
#include "context.h"

/*
 * Events cross threads in SMP mode (the RX router allocates, a worker
 * frees), so they come from ogs_calloc — the talloc wrappers in
 * lib/core/ogs-memory.c are serialized behind a mutex — instead of the
 * single-thread ogs_pool allocator.
 */
void sgwc_event_init(void)
{
}

void sgwc_event_term(void)
{
    ogs_queue_term(ogs_app()->queue);
    ogs_pollset_notify(ogs_app()->pollset);
}

void sgwc_event_final(void)
{
}

sgwc_event_t *sgwc_event_new(sgwc_event_e id)
{
    sgwc_event_t *e = NULL;

    e = ogs_calloc(1, sizeof(*e));
    ogs_assert(e);

    e->id = id;

    return e;
}

void sgwc_event_free(sgwc_event_t *e)
{
    ogs_assert(e);
    if (e->admin_upf_addr)
        ogs_freeaddrinfo(e->admin_upf_addr);
    ogs_free(e);
}

int sgwc_event_push_local(sgwc_event_t *e)
{
    int rv;
    ogs_worker_t *worker = ogs_worker_self();

    ogs_assert(e);

    if (worker) {
        rv = ogs_worker_post(worker, e);
    } else {
        rv = ogs_queue_push(ogs_app()->queue, e);
        if (rv == OGS_OK)
            ogs_pollset_notify(ogs_app()->pollset);
    }

    if (rv != OGS_OK) {
        ogs_error("sgwc_event_push_local() failed [%d]", (int)rv);
        sgwc_event_free(e);
    }

    return rv;
}

const char *sgwc_event_get_name(sgwc_event_t *e)
{
    if (e == NULL)
        return OGS_FSM_NAME_INIT_SIG;

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG: 
        return OGS_FSM_NAME_ENTRY_SIG;
    case OGS_FSM_EXIT_SIG: 
        return OGS_FSM_NAME_EXIT_SIG;

    case SGWC_EVT_S11_MESSAGE:
        return "SGWC_EVT_S11_MESSAGE";
    case SGWC_EVT_S5C_MESSAGE:
        return "SGWC_EVT_S5C_MESSAGE";
    case SGWC_EVT_GN_MESSAGE:
        return "SGWC_EVT_GN_MESSAGE";

    case SGWC_EVT_SXA_MESSAGE:
        return "SGWC_EVT_SXA_MESSAGE";
    case SGWC_EVT_SXA_TIMER:
        return "SGWC_EVT_SXA_TIMER";
    case SGWC_EVT_SXA_NO_HEARTBEAT:
        return "SGWC_EVT_SXA_NO_HEARTBEAT";
    case SGWC_EVT_SXA_REASSOCIATE:
        return "SGWC_EVT_SXA_REASSOCIATE";

    case SGWC_EVT_CONFIG_RELOAD:
        return "SGWC_EVT_CONFIG_RELOAD";

    case SGWC_EVT_ADMIN_MAINTENANCE_ENABLE:
        return "SGWC_EVT_ADMIN_MAINTENANCE_ENABLE";
    case SGWC_EVT_ADMIN_MAINTENANCE_DISABLE:
        return "SGWC_EVT_ADMIN_MAINTENANCE_DISABLE";
    case SGWC_EVT_ADMIN_MAINTENANCE_DRAIN:
        return "SGWC_EVT_ADMIN_MAINTENANCE_DRAIN";
    case SGWC_EVT_ADMIN_DETACH_SESSION:
        return "SGWC_EVT_ADMIN_DETACH_SESSION";
    case SGWC_EVT_ADMIN_DETACH_SESS_ONE:
        return "SGWC_EVT_ADMIN_DETACH_SESS_ONE";
    case SGWC_EVT_ADMIN_PURGE_ORPHANS:
        return "SGWC_EVT_ADMIN_PURGE_ORPHANS";
    case SGWC_EVT_ADMIN_PURGE_SEID:
        return "SGWC_EVT_ADMIN_PURGE_SEID";

    case SGWC_EVT_ORPHAN_SWEEP:
        return "SGWC_EVT_ORPHAN_SWEEP";
    case SGWC_EVT_PEER_ECHO_SETUP:
        return "SGWC_EVT_PEER_ECHO_SETUP";

    default:
       break;
    }

    return "UNKNOWN_EVENT";
}
