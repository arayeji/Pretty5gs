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

#ifndef SMF_RADIUS_PATH_H
#define SMF_RADIUS_PATH_H

#include "context.h"

/* Access-Request + Access-Accept/Reject. Parses Framed-IP-Address,
 * Framed-IPv6-Prefix and Class AVP(s) into the session. */
int smf_radius_authorize_for_session(smf_sess_t *sess);

/* Accounting lifecycle. */
void smf_radius_accounting_session_started(smf_sess_t *sess);
void smf_radius_accounting_session_stopping(smf_sess_t *sess);

/* Send an Accounting-Request (Interim-Update). Intended to be called from
 * the PFCP Session Report Request handler after the UPF's periodic URR
 * Usage Report has been parsed into sess->gy.ul_octets / dl_octets. */
void smf_radius_accounting_interim_update(smf_sess_t *sess);

/* RFC 5176 Disconnect-Message listener (a.k.a. Packet-of-Disconnect / PoD).
 * Opens a UDP server bound to pod_port. Returns OGS_OK even when PoD is
 * disabled in config (no-op). */
int smf_radius_pod_open(void);
void smf_radius_pod_close(void);

/* Free any per-session radius resources (called from smf_sess_remove()). */
void smf_radius_sess_clear(smf_sess_t *sess);

/* Cancel the PoD-teardown watchdog armed by pod_recv_cb() after a
 * Delete Bearer Request was issued. Safe to call when no timer is
 * armed. Should be called as soon as the MME's Delete Bearer Response
 * arrives so the watchdog cannot fire concurrently with the normal
 * DBR-Response -> PFCP-deletion chain. */
void smf_radius_pod_teardown_cancel(smf_sess_t *sess);

#endif /* SMF_RADIUS_PATH_H */
