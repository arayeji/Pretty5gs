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

#ifndef CGF_EVENT_H
#define CGF_EVENT_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cgf_event_s {
    ogs_event_t h;

    /* For timer / recv events we only need the peer index; for recv
     * events we also pass the received datagram. */
    int peer_idx;
    ogs_pkbuf_t *pkbuf;
} cgf_event_t;

/* Using the generic OGS_EVENT_ID_USER range so we don't collide with
 * SBI/GTP event ids defined elsewhere. */
#define CGF_EVENT_GTPP_RECV     (OGS_MAX_NUM_OF_PROTO_EVENT + 1)
#define CGF_EVENT_ECHO_TIMER    (OGS_MAX_NUM_OF_PROTO_EVENT + 2)
#define CGF_EVENT_RTO_TIMER     (OGS_MAX_NUM_OF_PROTO_EVENT + 3)
#define CGF_EVENT_SPOOL_TIMER   (OGS_MAX_NUM_OF_PROTO_EVENT + 4)

OGS_STATIC_ASSERT(OGS_EVENT_SIZE >= sizeof(cgf_event_t));

cgf_event_t *cgf_event_new(int id);
void cgf_event_free(cgf_event_t *e);
const char *cgf_event_get_name(cgf_event_t *e);

#ifdef __cplusplus
}
#endif

#endif /* CGF_EVENT_H */
