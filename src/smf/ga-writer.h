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

/*
 * Ga interface CDR writer.
 *
 * The SMF builds 3GPP TS 32.298 PGWRecord CDRs and appends them to a
 * local spool directory. A separate daemon (see src/cgf/) is responsible
 * for shipping them to the CGF over GTP' so that SMF session handling
 * is never gated on CGF availability.
 *
 * This module is deliberately self-contained: no socket I/O, no timers,
 * no event-loop integration. All entry points are safe to call from the
 * SMF main thread and return immediately on errors (the CDR is logged
 * and dropped rather than propagating failure upwards).
 */

#ifndef SMF_GA_WRITER_H
#define SMF_GA_WRITER_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Open the spool directory, reserve the active file, load the persisted
 * localSequenceNumber. No-op if smf.cdr.enabled is false. Safe to call
 * more than once. Returns OGS_OK or OGS_ERROR. */
int smf_ga_writer_open(void);

/* Rotate the active file into ready/ and close any open file descriptors.
 * Persists the localSequenceNumber to <spool_dir>/.seq on a best-effort
 * basis so the next SMF process resumes from the same counter. */
void smf_ga_writer_close(void);

/* Emit a "session start" partial record (TS 32.298 causeForRecClosing =
 * normalRelease / partial = 17 is not used here; the stop record uses
 * the captured cause instead). Called right after the PDN/PDU session
 * becomes active, alongside smf_radius_accounting_session_started(). */
void smf_ga_cdr_session_start(smf_sess_t *sess);

/* Emit a partial record triggered by a PFCP URR Usage Report. Called
 * from the n4-handler after the report has been merged into
 * sess->gy.ul_octets / dl_octets, alongside
 * smf_radius_accounting_interim_update(). */
void smf_ga_cdr_session_interim(smf_sess_t *sess);

/* Emit the final record. Called from smf_sess_remove() alongside
 * smf_radius_accounting_session_stopping(). The cause is taken from
 * sess->cdr.cause_for_rec_closing (callers set it before remove; if
 * unset, causeForRecClosing defaults to 0 = normalRelease). */
void smf_ga_cdr_session_stop(smf_sess_t *sess);

/* Free any per-session CDR resources (currently only snapshots; included
 * for symmetry with smf_radius_sess_clear()). */
void smf_ga_sess_clear(smf_sess_t *sess);

/*
 * Hot-apply a new CDR configuration coming from the admin watcher.
 *
 * Behavior, in order:
 *   1. Rotate the currently-open spool file into ready/ (existing CDRs
 *      are preserved). Writer is then in a closed state.
 *   2. Free any strings the writer previously owned and replace with
 *      duplicates of the strings inside `new_cfg` so the SMF context
 *      cleanly owns its own memory.
 *   3. Atomically swap the rotation thresholds, triggers, and enabled
 *      flag into smf_self()->cdr.
 *   4. If the new config is enabled, re-open the writer (mkdir -p,
 *      load .seq, etc).
 *
 * MUST be called from the SMF main thread (the one that owns the
 * timer_mgr / file FDs). Returns OGS_OK on success, OGS_ERROR on a
 * fatal reopen failure (the writer is left disabled in that case so
 * the SMF keeps serving sessions). */
int smf_ga_writer_apply_runtime(const smf_cdr_config_t *new_cfg);

#ifdef __cplusplus
}
#endif

#endif /* SMF_GA_WRITER_H */
