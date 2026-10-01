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

#ifndef NGAP_FREE_H
#define NGAP_FREE_H

#include "ogs-ngap.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Deferred free of RX-worker-decoded NGAP PDUs: the ASN.1 tree walk
 * and the pkbuf free run on one helper thread instead of amf_main.
 * Started with the RX workers. Only heap PDUs (ogs_calloc'd by an RX
 * worker) may be deferred, never a stack ogs_ngap_message_t.
 */
int ngap_free_start(void);
void ngap_free_stop(void);

/* Takes ownership of pdu (heap) and pkbuf; either may be NULL. Frees
 * inline when the helper is not running or its queue is full. */
void ngap_free_defer(ogs_ngap_message_t *pdu, ogs_pkbuf_t *pkbuf);

#ifdef __cplusplus
}
#endif

#endif /* NGAP_FREE_H */
