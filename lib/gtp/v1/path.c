/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 * Copyright (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Copyright (C) 2023 by Sukchan Lee <acetcom@gmail.com>
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

#include "ogs-gtp.h"

ogs_pkbuf_t *ogs_gtp1_handle_echo_req(ogs_pkbuf_t *pkb)
{
    ogs_gtp1_header_t *gtph = NULL;
    ogs_pkbuf_t *pkb_resp = NULL;
    ogs_gtp1_header_t *gtph_resp = NULL;
    uint16_t length;
    int idx;

    ogs_assert(pkb);

    gtph = (ogs_gtp1_header_t *)pkb->data;
    /* Check GTP version. Now only support GTPv1(version = 1) */
    if (gtph->version != 1) {
        return NULL;
    }

    if (gtph->type != OGS_GTP1_ECHO_REQUEST_TYPE) {
        return NULL;
    }


    pkb_resp = ogs_pkbuf_alloc(NULL,
            100 /* enough for ECHO_RSP; use smaller buffer */);
    if (!pkb_resp) {
        ogs_error("ogs_pkbuf_alloc() failed");
        return NULL;
    }
    ogs_pkbuf_put(pkb_resp, 100);
    gtph_resp = (ogs_gtp1_header_t *)pkb_resp->data;

    /* reply back immediately */
    gtph_resp->version = 1; /* set version */
    gtph_resp->pt = 1; /* set PT */
    gtph_resp->type = OGS_GTP1_ECHO_RESPONSE_TYPE;
    length = 0;     /* length of Recovery IE */
    gtph_resp->length = htobe16(length); /* to be overwriten */
    gtph_resp->teid = 0;
    idx = 8;

    if (gtph->e || gtph->s || gtph->pn) {
        length += 4;
        if (gtph->s) {
            /* sequence exists */
            gtph_resp->s = 1;
            *((uint8_t *)pkb_resp->data + idx) = *((uint8_t *)pkb->data + idx);
            *((uint8_t *)pkb_resp->data + idx + 1) =
                *((uint8_t *)pkb->data + idx + 1);
        } else {
            *((uint8_t *)pkb_resp->data + idx) = 0;
            *((uint8_t *)pkb_resp->data + idx + 1) = 0;
        }
        idx += 2;
        if (gtph->pn) {
            /* sequence exists */
            gtph_resp->pn = 1;
            *((uint8_t *)pkb_resp->data + idx) = *((uint8_t *)pkb->data + idx);
        } else {
            *((uint8_t *)pkb_resp->data + idx) = 0;
        }
        idx++;
        *((uint8_t *)pkb_resp->data + idx) = 0; /* next-extension header */
        idx++;
    }

    /* fill Recovery IE */
    length += 2;
    *((uint8_t *)pkb_resp->data + idx) = 14; idx++; /* type */
    *((uint8_t *)pkb_resp->data + idx) = 0; idx++; /* restart counter */

    gtph_resp->length = htobe16(length);
    ogs_pkbuf_trim(pkb_resp, idx); /* buffer length */

    return pkb_resp;
}

/*
 * Callers (SGW-C PFCP/S5 fail paths) often pass a GTPv2 response type, or
 * the original request type, on a Gn (GTPv1) xact. Aborting the process
 * here took down SGW-C in a restart loop. Map those to a PDP-context
 * response; unknown types are logged and dropped.
 */
static uint8_t gtp1_error_response_type(uint8_t type)
{
    switch (type) {
    case OGS_GTP1_CREATE_PDP_CONTEXT_REQUEST_TYPE:
    case OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE:
    case OGS_GTP2_CREATE_SESSION_REQUEST_TYPE:
    case OGS_GTP2_CREATE_SESSION_RESPONSE_TYPE:
        return OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE;
    case OGS_GTP1_UPDATE_PDP_CONTEXT_REQUEST_TYPE:
    case OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE:
    case OGS_GTP2_MODIFY_BEARER_REQUEST_TYPE:
    case OGS_GTP2_MODIFY_BEARER_RESPONSE_TYPE:
        return OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE;
    case OGS_GTP1_DELETE_PDP_CONTEXT_REQUEST_TYPE:
    case OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE:
    case OGS_GTP2_DELETE_SESSION_REQUEST_TYPE:
    case OGS_GTP2_DELETE_SESSION_RESPONSE_TYPE:
        return OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE;
    default:
        return 0;
    }
}

static uint8_t gtp1_error_cause(uint8_t cause_value)
{
    /* GTP2 causes are 16..127; GTP1 reject causes are 192+. */
    if (cause_value >= OGS_GTP1_CAUSE_REJECT)
        return cause_value;

    switch (cause_value) {
    case OGS_GTP2_CAUSE_REQUEST_ACCEPTED:
    case OGS_GTP2_CAUSE_REQUEST_ACCEPTED_PARTIALLY:
        return OGS_GTP1_CAUSE_REQUEST_ACCEPTED;
    case OGS_GTP2_CAUSE_CONTEXT_NOT_FOUND:
        return OGS_GTP1_CAUSE_NON_EXISTENT;
    case OGS_GTP2_CAUSE_MANDATORY_IE_MISSING:
        return OGS_GTP1_CAUSE_MANDATORY_IE_MISSING;
    case OGS_GTP2_CAUSE_MANDATORY_IE_INCORRECT:
        return OGS_GTP1_CAUSE_MANDATORY_IE_INCORRECT;
    case OGS_GTP2_CAUSE_INVALID_MESSAGE_FORMAT:
        return OGS_GTP1_CAUSE_INVALID_MESSAGE_FORMAT;
    case OGS_GTP2_CAUSE_NO_RESOURCES_AVAILABLE:
        return OGS_GTP1_CAUSE_NO_RESOURCES_AVAILABLE;
    case OGS_GTP2_CAUSE_SERVICE_NOT_SUPPORTED:
        return OGS_GTP1_CAUSE_SERVICE_NOT_SUPPORTED;
    case OGS_GTP2_CAUSE_SYSTEM_FAILURE:
        return OGS_GTP1_CAUSE_SYSTEM_FAILURE;
    case OGS_GTP2_CAUSE_REMOTE_PEER_NOT_RESPONDING:
        return OGS_GTP1_CAUSE_NO_RESOURCES_AVAILABLE;
    default:
        if (cause_value < OGS_GTP1_CAUSE_ACCEPT)
            return OGS_GTP1_CAUSE_SYSTEM_FAILURE;
        return cause_value;
    }
}

void ogs_gtp1_send_error_message(
        ogs_gtp_xact_t *xact, uint32_t teid, uint8_t type, uint8_t cause_value)
{
    int rv;
    ogs_gtp1_message_t errmsg;
    ogs_gtp1_tlv_cause_t *tlv = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    uint8_t rsp_type;

    rsp_type = gtp1_error_response_type(type);
    if (!rsp_type) {
        ogs_error("ogs_gtp1_send_error_message: unsupported type %u "
                "(teid=0x%x cause=%u) - drop, do not abort",
                type, teid, cause_value);
        return;
    }
    if (rsp_type != type)
        ogs_warn("ogs_gtp1_send_error_message: mapped type %u -> %u",
                type, rsp_type);

    memset(&errmsg, 0, sizeof(ogs_gtp1_message_t));
    errmsg.h.type = rsp_type;
    errmsg.h.teid = teid;

    switch (rsp_type) {
    case OGS_GTP1_CREATE_PDP_CONTEXT_RESPONSE_TYPE:
        tlv = &errmsg.create_pdp_context_response.cause;
        break;
    case OGS_GTP1_UPDATE_PDP_CONTEXT_RESPONSE_TYPE:
        tlv = &errmsg.update_pdp_context_response.cause;
        break;
    case OGS_GTP1_DELETE_PDP_CONTEXT_RESPONSE_TYPE:
        tlv = &errmsg.delete_pdp_context_response.cause;
        break;
    default:
        ogs_error("ogs_gtp1_send_error_message: unhandled mapped type %u",
                rsp_type);
        return;
    }

    ogs_assert(tlv);

    tlv->presence = 1;
    tlv->u8 = gtp1_error_cause(cause_value);

    pkbuf = ogs_gtp1_build_msg(&errmsg);
    if (!pkbuf) {
        ogs_error("ogs_gtp1_build_msg() failed");
        return;
    }

    rv = ogs_gtp1_xact_update_tx(xact, &errmsg.h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp1_xact_update_tx() failed");
        return;
    }

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);
}

void ogs_gtp1_send_echo_request(ogs_gtp_node_t *gnode)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp1_header_t h;
    ogs_gtp_xact_t *xact = NULL;

    ogs_assert(gnode);

    ogs_debug("[GTP] Sending Echo Request");

    memset(&h, 0, sizeof(ogs_gtp1_header_t));
    h.type = OGS_GTP1_ECHO_REQUEST_TYPE;
    h.teid = 0;

    pkbuf = ogs_gtp1_build_echo_request(h.type);
    if (!pkbuf) {
        ogs_error("ogs_gtp1_build_echo_request() failed");
        return;
    }

    xact = ogs_gtp1_xact_local_create(gnode, &h, pkbuf, NULL, NULL);

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);
}

void ogs_gtp1_send_echo_response(ogs_gtp_xact_t *xact, uint8_t recovery)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp1_header_t h;

    ogs_assert(xact);

    ogs_debug("[GTP] Sending Echo Response");

    memset(&h, 0, sizeof(ogs_gtp1_header_t));
    h.type = OGS_GTP1_ECHO_RESPONSE_TYPE;
    h.teid = 0;

    pkbuf = ogs_gtp1_build_echo_response(h.type, recovery);
    if (!pkbuf) {
        ogs_error("ogs_gtp1_build_echo_response() failed");
        return;
    }

    rv = ogs_gtp1_xact_update_tx(xact, &h, pkbuf);
    if (rv != OGS_OK) {
        ogs_error("ogs_gtp1_xact_update_tx() failed");
        return;
    }

    rv = ogs_gtp_xact_commit(xact);
    ogs_expect(rv == OGS_OK);
}
