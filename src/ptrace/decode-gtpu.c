/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "decode.h"

int ptrace_decode_gtpu(const uint8_t *data, int len, ptrace_event_t *evt)
{
    uint8_t flags, type;
    uint32_t teid;

    if (!data || len < 8 || !evt)
        return OGS_ERROR;

    flags = data[0];
    type = data[1];
    if (!(flags & 0x30))
        return OGS_ERROR; /* version/PT sanity */

    teid = (uint32_t)((data[4] << 24) | (data[5] << 16) |
            (data[6] << 8) | data[7]);

    evt->protocol = PTRACE_PROTO_GTPU;
    evt->msg_type = type;
    ogs_cpystrn(evt->message, type == 255 ? "G-PDU" : "GTP-U",
            sizeof(evt->message));
    evt->ids.teid = teid;
    evt->ids.has_teid = true;
    ptrace_ids_add_teid(&evt->ids, teid);
    snprintf(evt->fields, sizeof(evt->fields),
            "teid=%u len=%d", teid, len);
    return OGS_OK;
}
