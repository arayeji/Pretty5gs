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

/* Parse sgwc.workers (0..8). Call before sgwc_context_init when >0 path. */
int sgwc_workers_parse_config(void);

/* Configured count from YAML (before start). Runtime count after start. */
int sgwc_workers_configured(void);
int sgwc_workers_count(void);
bool sgwc_workers_active(void);

/* Bring up / tear down protocol shard workers. No-op when count==0. */
int sgwc_workers_start(void);
void sgwc_workers_stop(void);

ogs_worker_t *sgwc_worker_by_id(int wid);

/* Push event to shard; frees event on failure. */
int sgwc_event_push_to_worker(int wid, sgwc_event_t *e);

/* Fan-out a copy of a control event to every shard (maintenance/drain/…).
 * Does not deliver to the main thread. */
int sgwc_event_fanout_workers(sgwc_event_e id, int admin_force);

/* Shard selection helpers used by the RX router. */
int sgwc_shard_from_teid(uint32_t teid);
int sgwc_shard_from_seid(uint64_t seid);
int sgwc_shard_from_xid(uint32_t xid);
int sgwc_shard_from_imsi_bcd(const char *imsi_bcd);

/* Peek IMSI BCD from a raw GTPv2 Create Session Request (teid==0 path). */
int sgwc_gtpv2_peek_imsi_bcd(ogs_pkbuf_t *pkbuf, char *bcd, size_t bcd_size);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_WORKERS_H */
