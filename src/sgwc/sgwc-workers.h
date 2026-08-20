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

#ifndef SGWC_WORKERS_H
#define SGWC_WORKERS_H

#include "event.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Parse sgwc.workers (0..15 / OGS_MAX_WORKERS-1). Call before start. */
int sgwc_workers_parse_config(void);

/* Configured count from YAML (before start). Runtime count after start. */
int sgwc_workers_configured(void);
int sgwc_workers_count(void);
bool sgwc_workers_active(void);

/* Bring up / tear down protocol shard workers. No-op when count==0. */
int sgwc_workers_start(void);
/* Join worker threads (timer managers stay alive for context final). */
void sgwc_workers_stop(void);
/* Free worker resources; call AFTER sgwc_context_final(). */
void sgwc_workers_final(void);

ogs_worker_t *sgwc_worker_by_id(int wid);

/* Push event to shard; frees event on failure. */
int sgwc_event_push_to_worker(int wid, sgwc_event_t *e);

/* Fan-out a copy of a control event to every shard (maintenance/drain/…).
 * Does not deliver to the main thread. */
int sgwc_event_fanout_workers(sgwc_event_e id, int admin_force);

/* Cross-owner sweeps: one event copy to every worker AND the main queue,
 * so each thread acts on the UEs it owns. */
int sgwc_event_fanout_restart_purge(ogs_gtp_node_t *gnode, int kind);
int sgwc_event_fanout_sxa_restore(ogs_pfcp_node_t *pfcp_node);

/* Shard selection helpers used by the RX router. */
int sgwc_shard_from_teid(uint32_t teid);
int sgwc_shard_from_seid(uint64_t seid);
int sgwc_shard_from_xid(uint32_t xid);
int sgwc_shard_from_imsi_bcd(const char *imsi_bcd);

/* Peek IMSI BCD from a raw GTPv2 Create Session Request (teid==0 path). */
int sgwc_gtpv2_peek_imsi_bcd(ogs_pkbuf_t *pkbuf, char *bcd, size_t bcd_size);

/*
 * Foreign-shard guard for GTP RX events: if the UE/session resolved
 * from the parsed message is owned by another shard (router misroute:
 * failed IMSI peek, truncated S5 TEID, stale bits), re-post the event
 * to the owner and return true. MUST run after parse and BEFORE
 * ogs_gtp_xact_receive() — xacts are per-shard. Takes the pkbuf.
 */
bool sgwc_worker_rehome_gtp2(sgwc_event_t *e, ogs_gtp2_message_t *message);
bool sgwc_worker_rehome_gtp1(sgwc_event_t *e, ogs_gtp1_message_t *message);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_WORKERS_H */
