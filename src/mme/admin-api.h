/*
 * Copyright (C) 2026 by Open5GS contributors
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/*
 * Admin (mutating) endpoints for the MME Prometheus HTTP server.
 *
 *   POST /admin/enb/detach?enb_id=<N>[&force=1]    ; or
 *   GET  /admin/enb/detach?enb_id=<N>[&force=1]
 *
 *     Drops the named eNB. Match priority: enb_id > ip.
 *
 *     Default (force=0): send S1AP Reset (s1_Interface) to the eNB,
 *     wait ~2 s for it to process, then release every UE on that eNB
 *     via S11 Delete-Session and finally tear down the SCTP. This
 *     is the standard 3GPP procedure: eNB sees the Reset PDU and
 *     cleans up its UE contexts cooperatively.
 *
 *     force=1: skip the Reset PDU; release UEs and close SCTP
 *     immediately. Equivalent to the previous (pre-3GPP) behaviour;
 *     use when the eNB is half-dead and you just want the state gone.
 *
 *   POST /admin/ue/detach?imsi=<15 digits>[&force=1]   ; or
 *   GET  /admin/ue/detach?imsi=<15 digits>[&force=1]
 *
 *     Detach the named UE.
 *
 *     Default (force=0): MME-initiated explicit detach (TS 23.401
 *     §5.3.8.3). If the UE is ECM-CONNECTED, MME sends a NAS Detach
 *     Request, the UE replies Detach Accept, and then SGW/PGW state
 *     is torn down. If the UE is ECM-IDLE, MME pages the UE first
 *     (paging type = DETACH_TO_UE) and then runs the connected flow.
 *
 *     force=1: implicit detach (UE not notified over the air); SGW/
 *     SMF/PGW are still cleaned up via the standard cascade. The UE
 *     finds out it has been detached only on next interaction.
 *
 *   GET /admin/trace/imsi?imsi=<prefix>              add runtime DEBUG filter
 *   GET /admin/trace/imsi?imsi=<prefix>&replace=1    set only this prefix
 *   GET /admin/trace/imsi?imsi=<prefix>&remove=1     remove one prefix
 *   GET /admin/trace/imsi?imsi=<prefix>&match=exact  exact IMSI match
 *   GET /admin/trace/imsi?imsi=list                  list active prefixes
 *   GET /admin/trace/imsi?force=1                    clear all filters
 *   GET /admin/trace/imsi?imsi=<p>&sync=sgwc,smf     MME: push to peers
 *
 *   Same contract on SGWC/SMF metrics ports (without sync).
 *   JSON: {"ok":true,"detail":"...","trace_imsi":["..."]}
 *
 *   GET  /admin/maintenance
 *   GET  /admin/maintenance/status
 *        JSON status: maintenance flag + ue_count (local clients only).
 *
 *   POST /admin/maintenance/enable
 *   POST /admin/maintenance/disable
 *        Toggle maintenance mode (blocks new attach / PDN).
 *
 *   POST /admin/maintenance/drain[?force=1]
 *        Enable maintenance and graceful-detach every UE (default).
 *        force=1 uses implicit detach (no NAS to UE).
 *
 * Access control is NOT enforced inside the daemon - the metrics
 * port is expected to be firewalled at the host or network level.
 * Every admin call is logged with the caller's address so detaches
 * can be audited after the fact.
 */

#pragma once

#include "ogs-metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

void mme_admin_api_register(void);

int mme_admin_enb_detach(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len);
int mme_admin_ue_detach(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len);
int mme_admin_trace_imsi(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len);

size_t mme_dump_maintenance_status(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q);

int mme_admin_maintenance_enable(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len);
int mme_admin_maintenance_disable(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len);
int mme_admin_maintenance_drain(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len);
int mme_admin_maintenance_status(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len);

#ifdef __cplusplus
}
#endif
