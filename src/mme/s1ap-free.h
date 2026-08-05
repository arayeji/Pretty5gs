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

#ifndef S1AP_FREE_H
#define S1AP_FREE_H

#include "ogs-s1ap.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Deferred ASN.1 / pkbuf free (s1ap-free worker).
 *
 * After S1AP handlers return they must not retain pointers into the PDU.
 * Main (and Stage-C shards) can hand heap-decoded PDUs + the owning
 * pkbuf to this worker so CHOICE_free / ogs_talloc_free / pkbuf free
 * do not burn cycles on mme-main under the global allocator mutex.
 *
 * Heap PDUs only — never pass a stack ogs_s1ap_message_t.
 * On queue-full or worker-down, frees synchronously on the caller.
 */

int s1ap_free_start(void);
void s1ap_free_stop(void);
bool s1ap_free_active(void);

/* Takes ownership of pdu and/or pkbuf (either may be NULL). */
void s1ap_free_defer(ogs_s1ap_message_t *pdu, ogs_pkbuf_t *pkbuf);

#ifdef __cplusplus
}
#endif

#endif /* S1AP_FREE_H */
