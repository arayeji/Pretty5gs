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

#include "context.h"
#include "event.h"
#include "cgf-sm.h"
#include "gtpp-path.h"
#include "spool.h"

#ifdef OPEN5GS_ADMIN_WATCHER
#include "cgf-admin-watcher.h"
#endif

static ogs_thread_t *thread;
static void cgf_main(void *data);
static bool started = false;

static void echo_timer_expired(void *data)
{
    cgf_event_t *e = cgf_event_new(CGF_EVENT_ECHO_TIMER);
    (void)data;
    if (ogs_queue_push(ogs_app()->queue, e) != OGS_OK)
        cgf_event_free(e);
    ogs_pollset_notify(ogs_app()->pollset);
}

static void rto_timer_expired(void *data)
{
    cgf_event_t *e = cgf_event_new(CGF_EVENT_RTO_TIMER);
    (void)data;
    if (ogs_queue_push(ogs_app()->queue, e) != OGS_OK)
        cgf_event_free(e);
    ogs_pollset_notify(ogs_app()->pollset);
}

static void spool_timer_expired(void *data)
{
    cgf_event_t *e = cgf_event_new(CGF_EVENT_SPOOL_TIMER);
    (void)data;
    if (ogs_queue_push(ogs_app()->queue, e) != OGS_OK)
        cgf_event_free(e);
    ogs_pollset_notify(ogs_app()->pollset);
}

int cgf_initialize(void)
{
    int rv;

#define APP_NAME "cgf"
    rv = ogs_app_parse_local_conf(APP_NAME);
    if (rv != OGS_OK) return rv;

    cgf_context_init();

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    rv = cgf_context_parse_config();
    if (rv != OGS_OK) return rv;

    rv = cgf_gtpp_open();
    if (rv != OGS_OK) return OGS_ERROR;

    cgf_self()->t_echo = ogs_timer_add(ogs_app()->timer_mgr,
            echo_timer_expired, NULL);
    cgf_self()->t_rto = ogs_timer_add(ogs_app()->timer_mgr,
            rto_timer_expired, NULL);
    cgf_self()->t_spool = ogs_timer_add(ogs_app()->timer_mgr,
            spool_timer_expired, NULL);
    if (!cgf_self()->t_echo || !cgf_self()->t_rto || !cgf_self()->t_spool)
        return OGS_ERROR;

    thread = ogs_thread_create(cgf_main, NULL);
    if (!thread) return OGS_ERROR;

#ifdef OPEN5GS_ADMIN_WATCHER
    /* Best-effort: if the admin API isn't reachable the CGF still
     * runs with its on-disk config. */
    (void)cgf_admin_watcher_init();
#endif

    started = true;
    return OGS_OK;
}

void cgf_terminate(void)
{
    if (!started) return;

#ifdef OPEN5GS_ADMIN_WATCHER
    cgf_admin_watcher_final();
#endif

    /* Wake up the main loop and let it unwind naturally. */
    ogs_queue_term(ogs_app()->queue);
    ogs_pollset_notify(ogs_app()->pollset);
    ogs_thread_destroy(thread);

    if (cgf_self()->t_echo)  ogs_timer_delete(cgf_self()->t_echo);
    if (cgf_self()->t_rto)   ogs_timer_delete(cgf_self()->t_rto);
    if (cgf_self()->t_spool) ogs_timer_delete(cgf_self()->t_spool);

    cgf_gtpp_close();
    cgf_spool_close();
    cgf_context_final();
}

static void cgf_main(void *data)
{
    ogs_fsm_t sm;
    int rv;
    (void)data;

    ogs_fsm_init(&sm, cgf_state_initial, cgf_state_final, 0);

    for (;;) {
        ogs_pollset_poll(ogs_app()->pollset,
                ogs_timer_mgr_next(ogs_app()->timer_mgr));
        ogs_timer_mgr_expire(ogs_app()->timer_mgr);

        for (;;) {
            cgf_event_t *e = NULL;
            rv = ogs_queue_trypop(ogs_app()->queue, (void **)&e);
            ogs_assert(rv != OGS_ERROR);

            if (rv == OGS_DONE) goto done;
            if (rv == OGS_RETRY) break;

            ogs_assert(e);
            ogs_fsm_dispatch(&sm, &e->h);
            cgf_event_free(e);
        }
    }

done:
    ogs_fsm_fini(&sm, 0);
}
