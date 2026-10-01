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

#ifndef SMF_WORKERS_H
#define SMF_WORKERS_H

#include "event.h"
#include "smf-shard.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SMP protocol shards for the SMF (smf.workers: N, 0..15).
 *
 * Shard ids: 0 = main thread, 1..N = smf-w0..smf-w(N-1) (worker index
 * = shard - 1). A UE and all of its sessions are owned by one shard;
 * every locally allocated TEID/SEID carries the owner in its top
 * OGS_WORKER_ID_BITS, so GTP-C / PFCP traffic routes with a shift.
 * Node-level work (PFCP association/heartbeat, GTP Echo, SBI, Diameter
 * peer state, admin/reload) stays on main.
 */

/* Parse smf.workers. Call before smf_workers_start(). */
int smf_workers_parse_config(void);

/* Configured count from YAML (before start). Runtime count after start. */
int smf_workers_configured(void);
int smf_workers_count(void);
bool smf_workers_active(void);

/* Bring up / tear down protocol shard workers. No-op when count==0. */
int smf_workers_start(void);
/* Join worker threads (timer managers stay alive for context final). */
void smf_workers_stop(void);
/* Free worker resources; call AFTER smf_context_final(). */
void smf_workers_final(void);

/*
 * Deliver an event to a shard (0 = main, 1..N = workers). Non-blocking;
 * frees the event (and any pkbuf / PFCP message it owns) on failure.
 */
int smf_event_push_shard(int shard, smf_event_t *e);
/* Same, but never frees: caller keeps ownership when rv != OGS_OK. */
int smf_event_post_shard(int shard, smf_event_t *e);
/* From a Diameter/helper thread to the session owner (never frees). */
int smf_event_post_to_sess_owner(const smf_sess_t *sess, smf_event_t *e);

/*
 * One copy of `tmpl` (id, timer_id, gnode, pfcp_node) to every shard,
 * main included, so each thread acts on the UEs it owns. Without
 * workers the single copy goes to the calling thread's queue.
 */
int smf_event_fanout(const smf_event_t *tmpl);
/* Same, skipping the calling thread (it handles its share inline). */
int smf_event_fanout_others(const smf_event_t *tmpl);

/* Shard helpers used by the RX routers. All return a SHARD id. */
int smf_shard_from_teid(uint32_t teid);
int smf_shard_from_seid(uint64_t seid);
int smf_shard_from_xid(uint32_t xid);
/* Sticky shard for a brand-new UE (workers only; never main). */
int smf_shard_for_new_imsi(const char *imsi_bcd);
/* Clamp a shard decoded from a peer-supplied value to a live shard. */
int smf_shard_clamp(int shard, uint32_t fallback_key);

/*
 * Foreign-shard guard for GTP-C RX events: when the UE/session the
 * parsed message resolves to is owned by another shard (router
 * misroute), re-post the event there and return true (pkbuf moved).
 * MUST run after parse and BEFORE ogs_gtp_xact_receive(): xacts are
 * per shard.
 */
bool smf_worker_rehome_gtp2(smf_event_t *e, ogs_gtp2_message_t *message);
bool smf_worker_rehome_gtp1(smf_event_t *e, ogs_gtp1_message_t *message);

/* /admin/queues style introspection. */
int smf_workers_queue_depth(int wid);

#ifdef __cplusplus
}
#endif

#endif /* SMF_WORKERS_H */
