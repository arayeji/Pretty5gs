/*
 * Copyright (C) 2026 by Ahmad Raeiji <ahmad.rayeji@gmail.com>
 *
 * This file is part of Open5GS / Pretty5GS.
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

#ifndef SMF_SBI_RELAY_H
#define SMF_SBI_RELAY_H

#include "event.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 5GC sessions are sharded like EPC ones, but the SBI stack (server
 * streams, clients, xacts and their timers, NRF state) stays on smf-main:
 *  - main parses each SBI request / response and hands a copy to the
 *    session owner (smf_sbi_relay_server_request / _client_response);
 *  - responses a worker sends go back to main (send hook);
 *  - a worker runs xact / client work on main via smf_main_call().
 */
void smf_sbi_relay_init(void);
void smf_sbi_relay_final(void);

/* True on a shard worker: SBI work must hop to main. */
bool smf_sbi_on_worker(void);

/*
 * Run fn(arg) on smf-main and wait for it (inline when already on main).
 * The caller must not hold smf_ctx_lock(). OGS_ERROR when main is
 * exiting; fn then never runs.
 */
typedef void (*smf_main_call_f)(void *arg);
int smf_main_call(smf_main_call_f fn, void *arg);
/* smf-main loop exit: fail current and future calls. */
void smf_main_call_shutdown(void);

/* smf-main handlers for SMF_EVT_MAIN_CALL / SMF_EVT_SBI_SEND. */
void smf_main_call_dispatch(smf_event_t *e);
void smf_sbi_relay_send_dispatch(smf_event_t *e);

/*
 * smf-main, OGS_EVENT_SBI_SERVER after parse: true when the request was
 * handed to (or refused for) the owning worker.
 */
bool smf_sbi_relay_server_request(smf_event_t *e, ogs_sbi_message_t *message);

/*
 * smf-main, OGS_EVENT_SBI_CLIENT after the xact was consumed: true when
 * the response now belongs to the owning worker (caller must not free it).
 */
bool smf_sbi_relay_client_response(smf_event_t *e,
        ogs_pool_id_t sess_id, ogs_pool_id_t assoc_stream_id);

#ifdef __cplusplus
}
#endif

#endif /* SMF_SBI_RELAY_H */
