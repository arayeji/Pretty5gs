/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#include "ogs-pfcp.h"
#include "ogs-app.h"

#define PFCP_MIN_XACT_ID             1
#define PFCP_MAX_XACT_ID             0x800000

typedef enum {
    PFCP_XACT_UNKNOWN_STAGE,
    PFCP_XACT_INITIAL_STAGE,
    PFCP_XACT_INTERMEDIATE_STAGE,
    PFCP_XACT_FINAL_STAGE,
} ogs_pfcp_xact_stage_t;

static int ogs_pfcp_xact_initialized = 0;
static uint32_t g_xact_id = 0;

static OGS_POOL(pool, ogs_pfcp_xact_t);

static ogs_pfcp_xact_t *ogs_pfcp_xact_remote_create(
        ogs_pfcp_node_t *node, uint32_t sqn);
static ogs_pfcp_xact_stage_t ogs_pfcp_xact_get_stage(
        uint8_t type, uint32_t xid);
static int ogs_pfcp_xact_update_rx(ogs_pfcp_xact_t *xact, uint8_t type);

/*
 * O(1) transaction index on the PFCP node — same scheme as
 * lib/gtp/xact.c: key (org,xid), keep the FIRST xact per key, fall back
 * to the linear scan on a miss, and clear the slot on delete only when
 * it still points at the dying xact.
 */
static uint64_t xact_index_key(uint8_t org, uint32_t xid)
{
    return ((uint64_t)org << 40) | xid;
}

static void xact_index_add(ogs_pfcp_xact_t *xact)
{
    ogs_hash_t *h = xact->node->xact_hash;

    xact->hash_key = xact_index_key(xact->org, xact->xid);
    if (!ogs_hash_get(h, &xact->hash_key, sizeof(xact->hash_key)))
        ogs_hash_set(h, &xact->hash_key, sizeof(xact->hash_key), xact);
}

static void xact_index_del(ogs_pfcp_xact_t *xact)
{
    ogs_hash_t *h = xact->node->xact_hash;

    if (ogs_hash_get(h, &xact->hash_key, sizeof(xact->hash_key)) == xact)
        ogs_hash_set(h, &xact->hash_key, sizeof(xact->hash_key), NULL);
}

static ogs_pfcp_xact_t *xact_index_get(
        ogs_pfcp_node_t *node, uint8_t org, uint32_t xid)
{
    uint64_t key = xact_index_key(org, xid);
    return ogs_hash_get(node->xact_hash, &key, sizeof(key));
}

static void response_timeout(void *data);
static void holding_timeout(void *data);
static void delayed_commit_timeout(void *data);

static bool ogs_pfcp_xact_on_list(ogs_pfcp_xact_t *xact)
{
    ogs_pfcp_xact_t *iter = NULL;
    ogs_list_t *list = NULL;

    if (!xact || !xact->node)
        return false;

    list = xact->org == OGS_PFCP_LOCAL_ORIGINATOR ?
        &xact->node->local_list : &xact->node->remote_list;

    ogs_list_for_each(list, iter) {
        if (iter == xact)
            return true;
    }

    return false;
}

static ogs_pfcp_xact_t *ogs_pfcp_xact_find_by_id_for_timer(ogs_pool_id_t id)
{
    ogs_pfcp_xact_t *xact = NULL;

    if (id < OGS_MIN_POOL_ID || id > OGS_MAX_POOL_ID)
        return NULL;

    xact = ogs_pfcp_xact_find_by_id(id);
    if (!xact)
        return NULL;

    if (xact->id != id) {
        ogs_warn("Stale PFCP Transaction [%d] (pool id mismatch)", (int)id);
        return NULL;
    }

    if (!ogs_pfcp_xact_on_list(xact)) {
        ogs_warn("Stale PFCP Transaction [%d] (not on peer list)", (int)id);
        return NULL;
    }

    return xact;
}

int ogs_pfcp_xact_init(void)
{
    ogs_assert(ogs_pfcp_xact_initialized == 0);

    ogs_pool_init(&pool, ogs_app()->pool.xact);

    /*
     * Start the SQN space at a random point instead of 0. UDP peers (e.g.
     * upg-vpp) can still be retransmitting responses to the PREVIOUS
     * incarnation's requests after a restart; if the new process reuses the
     * same low sequence numbers, those stale responses are matched to new,
     * unrelated transactions (wrong session, wrong buffered message).
     */
    g_xact_id = ogs_random32() %
            (PFCP_MAX_XACT_ID - PFCP_MIN_XACT_ID) + PFCP_MIN_XACT_ID;

    ogs_pfcp_xact_initialized = 1;

    return OGS_OK;
}

void ogs_pfcp_xact_final(void)
{
    ogs_assert(ogs_pfcp_xact_initialized == 1);

    ogs_pool_final(&pool);

    ogs_pfcp_xact_initialized = 0;
}

ogs_pfcp_xact_t *ogs_pfcp_xact_local_create(ogs_pfcp_node_t *node,
        void (*cb)(ogs_pfcp_xact_t *xact, void *data), void *data)
{
    ogs_pfcp_xact_t *xact = NULL;

    ogs_assert(node);

    ogs_pool_id_calloc(&pool, &xact);
    if (!xact) {
        ogs_error("Maximum number of xact[%lld] reached",
                    (long long)ogs_app()->pool.xact);
        return NULL;
    }
    xact->index = ogs_pool_index(&pool, xact);

    xact->org = OGS_PFCP_LOCAL_ORIGINATOR;
    xact->xid = OGS_NEXT_ID(g_xact_id, PFCP_MIN_XACT_ID, PFCP_MAX_XACT_ID);
    xact->node = node;
    xact->cb = cb;
    xact->data = data;

    xact->tm_response = ogs_timer_add(
            ogs_app()->timer_mgr, response_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_response) {
        ogs_error("Maximum number of xact->tm_response[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_pfcp_xact_delete(xact);
        return NULL;
    }
    xact->response_rcount =
        ogs_local_conf()->time.message.pfcp.n1_response_rcount;

    xact->tm_holding = ogs_timer_add(
            ogs_app()->timer_mgr, holding_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_holding) {
        ogs_error("Maximum number of xact->tm_holding[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_pfcp_xact_delete(xact);
        return NULL;
    }
    xact->holding_rcount =
        ogs_local_conf()->time.message.pfcp.n1_holding_rcount;

    xact->tm_delayed_commit = ogs_timer_add(
            ogs_app()->timer_mgr, delayed_commit_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_delayed_commit) {
        ogs_error("Maximum number of xact->tm_delayed_commit[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_pfcp_xact_delete(xact);
        return NULL;
    }

    ogs_list_add(xact->org == OGS_PFCP_LOCAL_ORIGINATOR ?
            &xact->node->local_list : &xact->node->remote_list, xact);
    xact_index_add(xact);

    ogs_list_init(&xact->pdr_to_create_list);

    ogs_debug("[%d] %s Create  peer %s",
            xact->xid,
            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            ogs_sockaddr_to_string_static(node->addr_list));

    return xact;
}

static ogs_pfcp_xact_t *ogs_pfcp_xact_remote_create(
        ogs_pfcp_node_t *node, uint32_t sqn)
{
    ogs_pfcp_xact_t *xact = NULL;

    ogs_assert(node);

    ogs_pool_id_calloc(&pool, &xact);
    if (!xact) {
        ogs_error("Maximum number of xact[%lld] reached",
                    (long long)ogs_app()->pool.xact);
        return NULL;
    }
    xact->index = ogs_pool_index(&pool, xact);

    xact->org = OGS_PFCP_REMOTE_ORIGINATOR;
    xact->xid = OGS_PFCP_SQN_TO_XID(sqn);
    xact->node = node;

    xact->tm_response = ogs_timer_add(
            ogs_app()->timer_mgr, response_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_response) {
        ogs_error("Maximum number of xact->tm_response[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_pfcp_xact_delete(xact);
        return NULL;
    }
    xact->response_rcount =
        ogs_local_conf()->time.message.pfcp.n1_response_rcount;

    xact->tm_holding = ogs_timer_add(
            ogs_app()->timer_mgr, holding_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_holding) {
        ogs_error("Maximum number of xact->tm_holding[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_pfcp_xact_delete(xact);
        return NULL;
    }
    xact->holding_rcount =
        ogs_local_conf()->time.message.pfcp.n1_holding_rcount;

    xact->tm_delayed_commit = ogs_timer_add(
            ogs_app()->timer_mgr, delayed_commit_timeout,
            OGS_UINT_TO_POINTER(xact->id));
    if (!xact->tm_delayed_commit) {
        ogs_error("Maximum number of xact->tm_delayed_commit[%lld] reached",
                    (long long)ogs_app()->pool.timer);
        ogs_pfcp_xact_delete(xact);
        return NULL;
    }

    ogs_list_add(xact->org == OGS_PFCP_LOCAL_ORIGINATOR ?
            &xact->node->local_list : &xact->node->remote_list, xact);
    xact_index_add(xact);

    ogs_debug("[%d] %s Create  peer %s",
            xact->xid,
            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            ogs_sockaddr_to_string_static(node->addr_list));

    return xact;
}

void ogs_pfcp_xact_delete_all(ogs_pfcp_node_t *node)
{
    ogs_pfcp_xact_t *xact = NULL, *next_xact = NULL;

    ogs_list_for_each_safe(&node->local_list, next_xact, xact)
        ogs_pfcp_xact_delete(xact);
    ogs_list_for_each_safe(&node->remote_list, next_xact, xact)
        ogs_pfcp_xact_delete(xact);
}

ogs_pfcp_xact_t *ogs_pfcp_xact_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&pool, id);
}

int ogs_pfcp_xact_update_tx(ogs_pfcp_xact_t *xact,
        ogs_pfcp_header_t *hdesc, ogs_pkbuf_t *pkbuf)
{
    ogs_pfcp_xact_stage_t stage;
    ogs_pfcp_header_t *h = NULL;
    int pfcp_hlen = 0;

    ogs_assert(xact);
    ogs_assert(xact->node);
    ogs_assert(hdesc);
    ogs_assert(pkbuf);

    ogs_debug("[%d] %s UPD TX-%d  peer %s",
            xact->xid,
            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            hdesc->type,
            ogs_sockaddr_to_string_static(xact->node->addr_list));

    stage = ogs_pfcp_xact_get_stage(hdesc->type, xact->xid);
    if (xact->org == OGS_PFCP_LOCAL_ORIGINATOR) {
        switch (stage) {
        case PFCP_XACT_INITIAL_STAGE:
            if (xact->step != 0) {
                ogs_error("invalid step[%d] type[%d]", xact->step, hdesc->type);
                ogs_pkbuf_free(pkbuf);
                return OGS_ERROR;
            }
            break;

        case PFCP_XACT_INTERMEDIATE_STAGE:
            ogs_expect(0);
            ogs_pkbuf_free(pkbuf);
            return OGS_ERROR;

        case PFCP_XACT_FINAL_STAGE:
            if (xact->step != 2) {
                ogs_error("invalid step[%d] type[%d]", xact->step, hdesc->type);
                ogs_pkbuf_free(pkbuf);
                return OGS_ERROR;
            }
            break;

        default:
            ogs_assert_if_reached();
            break;
        }
    } else if (xact->org == OGS_PFCP_REMOTE_ORIGINATOR) {
        switch (stage) {
        case PFCP_XACT_INITIAL_STAGE:
            ogs_expect(0);
            ogs_pkbuf_free(pkbuf);
            return OGS_ERROR;

        case PFCP_XACT_INTERMEDIATE_STAGE:
        case PFCP_XACT_FINAL_STAGE:
            if (xact->step != 1) {
                ogs_error("invalid step[%d] type[%d]", xact->step, hdesc->type);
                ogs_pkbuf_free(pkbuf);
                return OGS_ERROR;
            }
            break;

        default:
            ogs_error("invalid stage[%d] type[%d]", stage, hdesc->type);
            ogs_pkbuf_free(pkbuf);
            return OGS_ERROR;
        }
    } else {
        ogs_error("invalid org[%d] type[%d]", xact->org, hdesc->type);
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    if (hdesc->type >= OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE) {
        pfcp_hlen = OGS_PFCP_HEADER_LEN;
    } else {
        pfcp_hlen = OGS_PFCP_HEADER_LEN - OGS_PFCP_SEID_LEN;
    }

    ogs_pkbuf_push(pkbuf, pfcp_hlen);
    h = (ogs_pfcp_header_t *)pkbuf->data;
    memset(h, 0, pfcp_hlen);

    h->version = OGS_PFCP_VERSION;
    h->type = hdesc->type;

    if (h->type >= OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE) {
        h->seid_presence = 1;
        h->seid = htobe64(hdesc->seid);
        h->sqn = OGS_PFCP_XID_TO_SQN(xact->xid);
    } else {
        h->seid_presence = 0;
        h->sqn_only = OGS_PFCP_XID_TO_SQN(xact->xid);
    }
    h->length = htobe16(pkbuf->len - 4);

    /* Save Message type and packet of this step */
    xact->seq[xact->step].type = h->type;
    xact->seq[xact->step].pkbuf = pkbuf;

    /* Step */
    xact->step++;

    return OGS_OK;
}

static int ogs_pfcp_xact_update_rx(ogs_pfcp_xact_t *xact, uint8_t type)
{
    ogs_pfcp_xact_stage_t stage;

    ogs_debug("[%d] %s UPD RX-%d  peer %s",
            xact->xid,
            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            type,
            ogs_sockaddr_to_string_static(xact->node->addr_list));

    stage = ogs_pfcp_xact_get_stage(type, xact->xid);
    if (xact->org == OGS_PFCP_LOCAL_ORIGINATOR) {
        switch (stage) {
        case PFCP_XACT_INITIAL_STAGE:
            ogs_expect(0);
            return OGS_ERROR;

        case PFCP_XACT_INTERMEDIATE_STAGE:
            if (xact->seq[1].type == type) {
                ogs_pkbuf_t *pkbuf = NULL;

                if (xact->step != 2 && xact->step != 3) {
                    ogs_error("invalid step[%d] type[%d]", xact->step, type);
                    ogs_pkbuf_free(pkbuf);
                    return OGS_ERROR;
                }

                pkbuf = xact->seq[2].pkbuf;
                if (pkbuf) {
                    if (xact->tm_holding)
                        ogs_timer_start(xact->tm_holding,
                                ogs_local_conf()->time.message.
                                    pfcp.t1_holding_duration);

                    ogs_warn("[%d] %s Request Duplicated. Retransmit!"
                            " for step %d type %d peer %s",
                            xact->xid,
                            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ?
                                "LOCAL " : "REMOTE",
                            xact->step, type,
                            ogs_sockaddr_to_string_static(
                                xact->node->addr_list));
                    ogs_expect(OGS_OK == ogs_pfcp_sendto(xact->node, pkbuf));
                } else {
                    ogs_warn("[%d] %s Request Duplicated. Discard!"
                            " for step %d type %d peer %s",
                            xact->xid,
                            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ?
                                "LOCAL " : "REMOTE",
                            xact->step, type,
                            ogs_sockaddr_to_string_static(
                                xact->node->addr_list));
                }

                return OGS_RETRY;
            }

            if (xact->step != 1) {
                ogs_error("invalid step[%d] type[%d]", xact->step, type);
                return OGS_ERROR;
            }

            if (xact->tm_holding)
                ogs_timer_start(xact->tm_holding,
                        ogs_local_conf()->time.message.pfcp.
                        t1_holding_duration);

            break;

        case PFCP_XACT_FINAL_STAGE:
            if (xact->step != 1) {
                ogs_error("invalid step[%d] type[%d]", xact->step, type);
                return OGS_ERROR;
            }
            /*
             * PFCP transactions are matched by sequence number only. After a
             * CP restart the SQN counter restarts too, so a late/retransmitted
             * response from the UP function (answering the PREVIOUS
             * incarnation's request with the same SQN) can be matched to a
             * brand-new transaction of a DIFFERENT type. Dispatching it would
             * run the wrong handler against the wrong session/buffered
             * message (observed as an SGW-C crash: a stale Session
             * Establishment Response matched a Session Modification xact).
             * A PFCP response type is always request type + 1; discard any
             * response that does not answer what this transaction sent,
             * keeping the transaction alive for its real response.
             */
            if (type != OGS_PFCP_VERSION_NOT_SUPPORTED_RESPONSE_TYPE &&
                xact->seq[0].type + 1 != type) {
                ogs_warn("[%d] LOCAL response type [%d] does not match "
                        "request type [%d]; discarding stale response "
                        "peer %s",
                        xact->xid, type, xact->seq[0].type,
                        ogs_sockaddr_to_string_static(
                            xact->node->addr_list));
                return OGS_RETRY;
            }
            break;

        default:
            ogs_error("invalid stage[%d]", stage);
            return OGS_ERROR;
        }
    } else if (xact->org == OGS_PFCP_REMOTE_ORIGINATOR) {
        switch (stage) {
        case PFCP_XACT_INITIAL_STAGE:
            if (xact->seq[0].type == type) {
                ogs_pkbuf_t *pkbuf = NULL;

                if (xact->step != 1 && xact->step != 2) {
                    ogs_error("invalid step[%d] type[%d]", xact->step, type);
                    return OGS_ERROR;
                }

                pkbuf = xact->seq[1].pkbuf;
                if (pkbuf) {
                    if (xact->tm_holding)
                        ogs_timer_start(xact->tm_holding,
                                ogs_local_conf()->time.message.
                                    pfcp.t1_holding_duration);

                    ogs_warn("[%d] %s Request Duplicated. Retransmit!"
                            " for step %d type %d peer %s",
                            xact->xid,
                            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ?
                                "LOCAL " : "REMOTE",
                            xact->step, type,
                            ogs_sockaddr_to_string_static(
                                xact->node->addr_list));
                    ogs_expect(OGS_OK == ogs_pfcp_sendto(xact->node, pkbuf));
                } else {
                    ogs_warn("[%d] %s Request Duplicated. Discard!"
                            " for step %d type %d peer %s",
                            xact->xid,
                            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ?
                                "LOCAL " : "REMOTE",
                            xact->step, type,
                            ogs_sockaddr_to_string_static(
                                xact->node->addr_list));
                }

                return OGS_RETRY;
            }

            if (xact->step != 0) {
                ogs_error("invalid step[%d] type[%d]", xact->step, type);
                return OGS_ERROR;
            }
            if (xact->tm_holding)
                ogs_timer_start(xact->tm_holding,
                        ogs_local_conf()->time.message.pfcp.
                        t1_holding_duration);

            break;

        case PFCP_XACT_INTERMEDIATE_STAGE:
            ogs_expect(0);
            return OGS_ERROR;

        case PFCP_XACT_FINAL_STAGE:
            if (xact->step != 2) {
                ogs_error("invalid step[%d] type[%d]", xact->step, type);
                return OGS_ERROR;
            }

            /* continue */
            break;

        default:
            ogs_error("invalid stage[%d]", stage);
            return OGS_ERROR;
        }
    } else {
        ogs_error("invalid org[%d]", xact->org);
        return OGS_ERROR;
    }

    if (xact->tm_response)
        ogs_timer_stop(xact->tm_response);

    /* Save Message type of this step */
    xact->seq[xact->step].type = type;

    /* Step */
    xact->step++;

    return OGS_OK;
}

int ogs_pfcp_xact_commit(ogs_pfcp_xact_t *xact)
{
    uint8_t type;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_pfcp_xact_stage_t stage;

    ogs_assert(xact);
    ogs_assert(xact->node);

    ogs_debug("[%d] %s Commit  peer %s",
            xact->xid,
            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            ogs_sockaddr_to_string_static(xact->node->addr_list));

    type = xact->seq[xact->step-1].type;
    stage = ogs_pfcp_xact_get_stage(type, xact->xid);

    if (xact->org == OGS_PFCP_LOCAL_ORIGINATOR) {
        switch (stage) {
        case PFCP_XACT_INITIAL_STAGE:
            if (xact->step != 1) {
                ogs_error("invalid step[%d] type[%d]", xact->step, type);
                ogs_pfcp_xact_delete(xact);
                return OGS_ERROR;
            }

            if (xact->tm_response)
                ogs_timer_start(xact->tm_response,
                        ogs_local_conf()->time.message.pfcp.t1_response_duration);

            break;

        case PFCP_XACT_INTERMEDIATE_STAGE:
            ogs_expect(0);
            ogs_pfcp_xact_delete(xact);
            return OGS_ERROR;

        case PFCP_XACT_FINAL_STAGE:
            if (xact->step != 2 && xact->step != 3) {
                ogs_error("invalid step[%d] type[%d]", xact->step, type);
                ogs_pfcp_xact_delete(xact);
                return OGS_ERROR;
            }
            if (xact->step == 2) {
                ogs_pfcp_xact_delete(xact);
                return OGS_OK;
            }

            break;

        default:
            ogs_error("invalid stage[%d] type[%d]", stage, type);
            ogs_pfcp_xact_delete(xact);
            return OGS_ERROR;
        }
    } else if (xact->org == OGS_PFCP_REMOTE_ORIGINATOR) {
        switch (stage) {
        case PFCP_XACT_INITIAL_STAGE:
            ogs_expect(0);
            ogs_pfcp_xact_delete(xact);
            return OGS_ERROR;

        case PFCP_XACT_INTERMEDIATE_STAGE:
            if (xact->step != 2) {
                ogs_error("invalid step[%d] type[%d]", xact->step, type);
                ogs_pfcp_xact_delete(xact);
                return OGS_ERROR;
            }
            if (xact->tm_response)
                ogs_timer_start(xact->tm_response,
                        ogs_local_conf()->time.message.pfcp.
                        t1_response_duration);

            break;

        case PFCP_XACT_FINAL_STAGE:
            if (xact->step != 2 && xact->step != 3) {
                ogs_error("invalid step[%d] type[%d]", xact->step, type);
                ogs_pfcp_xact_delete(xact);
                return OGS_ERROR;
            }
            if (xact->step == 3) {
                ogs_pfcp_xact_delete(xact);
                return OGS_OK;
            }

            break;

        default:
            ogs_error("invalid stage[%d] type[%d]", stage, type);
            ogs_pfcp_xact_delete(xact);
            return OGS_ERROR;
        }
    } else {
        ogs_error("invalid org[%d] type[%d]", xact->org, type);
        ogs_pfcp_xact_delete(xact);
        return OGS_ERROR;
    }

    pkbuf = xact->seq[xact->step-1].pkbuf;
    ogs_assert(pkbuf);

    ogs_expect(OGS_OK == ogs_pfcp_sendto(xact->node, pkbuf));

    return OGS_OK;
}

void ogs_pfcp_xact_delayed_commit(ogs_pfcp_xact_t *xact, ogs_time_t duration)
{
    ogs_assert(xact);
    ogs_assert(duration);
    ogs_assert(xact->tm_delayed_commit);

    ogs_timer_start(xact->tm_delayed_commit, duration);
}

static void response_timeout(void *data)
{
    ogs_pool_id_t xact_id = OGS_INVALID_POOL_ID;
    ogs_pfcp_xact_t *xact = NULL;

    ogs_assert(data);
    xact_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(xact_id >= OGS_MIN_POOL_ID && xact_id <= OGS_MAX_POOL_ID);

    xact = ogs_pfcp_xact_find_by_id_for_timer(xact_id);
    if (!xact) {
        ogs_warn("PFCP Transaction has already been removed [%d]", xact_id);
        return;
    }
    ogs_assert(xact->node);

    ogs_debug("[%d] %s Response Timeout "
            "for step %d type %d peer %s",
            xact->xid,
            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            xact->step, xact->seq[xact->step-1].type,
            ogs_sockaddr_to_string_static(xact->node->addr_list));

    if (--xact->response_rcount > 0) {
        ogs_pkbuf_t *pkbuf = NULL;

        if (xact->tm_response)
            ogs_timer_start(xact->tm_response,
                    ogs_local_conf()->time.message.pfcp.t1_response_duration);

        pkbuf = xact->seq[xact->step-1].pkbuf;
        ogs_assert(pkbuf);

        ogs_expect(OGS_OK == ogs_pfcp_sendto(xact->node, pkbuf));
    } else {
        ogs_warn("[%d] %s No Reponse. Give up! "
                "for step %d type %d peer %s",
                xact->xid,
                xact->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
                xact->step, xact->seq[xact->step-1].type,
                ogs_sockaddr_to_string_static(xact->node->addr_list));

        if (xact->cb)
            xact->cb(xact, xact->data);

        ogs_pfcp_xact_delete(xact);
    }
}

static void holding_timeout(void *data)
{
    ogs_pool_id_t xact_id = OGS_INVALID_POOL_ID;
    ogs_pfcp_xact_t *xact = NULL;

    ogs_assert(data);
    xact_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(xact_id >= OGS_MIN_POOL_ID && xact_id <= OGS_MAX_POOL_ID);

    xact = ogs_pfcp_xact_find_by_id_for_timer(xact_id);
    if (!xact) {
        ogs_warn("PFCP Transaction has already been removed [%d]", xact_id);
        return;
    }
    ogs_assert(xact->node);

    ogs_debug("[%d] %s Holding Timeout "
            "for step %d type %d peer %s",
            xact->xid,
            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            xact->step, xact->seq[xact->step-1].type,
            ogs_sockaddr_to_string_static(xact->node->addr_list));

    if (--xact->holding_rcount > 0) {
        if (xact->tm_holding)
            ogs_timer_start(xact->tm_holding,
                    ogs_local_conf()->time.message.pfcp.t1_holding_duration);
    } else {
        ogs_debug("[%d] %s Delete Transaction "
                "for step %d type %d peer %s",
                xact->xid,
                xact->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
                xact->step, xact->seq[xact->step-1].type,
                ogs_sockaddr_to_string_static(xact->node->addr_list));
        ogs_pfcp_xact_delete(xact);
    }
}

static void delayed_commit_timeout(void *data)
{
    ogs_pool_id_t xact_id = OGS_INVALID_POOL_ID;
    ogs_pfcp_xact_t *xact = NULL;

    ogs_assert(data);
    xact_id = OGS_POINTER_TO_UINT(data);
    ogs_assert(xact_id >= OGS_MIN_POOL_ID && xact_id <= OGS_MAX_POOL_ID);

    xact = ogs_pfcp_xact_find_by_id_for_timer(xact_id);
    if (!xact) {
        ogs_warn("PFCP Transaction has already been removed [%d]", xact_id);
        return;
    }
    ogs_assert(xact->node);

    ogs_debug("[%d] %s Delayed Send Timeout "
            "for step %d type %d peer %s",
            xact->xid,
            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            xact->step, xact->seq[xact->step-1].type,
            ogs_sockaddr_to_string_static(xact->node->addr_list));

    ogs_pfcp_xact_commit(xact);
}

int ogs_pfcp_xact_receive(
        ogs_pfcp_node_t *node, ogs_pfcp_header_t *h, ogs_pfcp_xact_t **xact)
{
    int rv;

    uint8_t type;
    uint32_t sqn, xid;
    ogs_pfcp_xact_stage_t stage;
    ogs_list_t *list = NULL;
    ogs_pfcp_xact_t *new = NULL;

    ogs_assert(node);
    ogs_assert(h);

    type = h->type;
    sqn = h->sqn;
    xid = OGS_PFCP_SQN_TO_XID(sqn);
    stage = ogs_pfcp_xact_get_stage(type, xid);

    switch (stage) {
    case PFCP_XACT_INITIAL_STAGE:
        list = &node->remote_list;
        break;
    case PFCP_XACT_INTERMEDIATE_STAGE:
        list = &node->local_list;
        break;
    case PFCP_XACT_FINAL_STAGE:
        list = &node->local_list;
        break;
    default:
        ogs_error("[%d] Unexpected type %u from PFCP peer %s",
                xid, type, ogs_sockaddr_to_string_static(node->addr_list));
        return OGS_ERROR;
    }

    ogs_assert(list);

    new = xact_index_get(node,
            list == &node->local_list ?
                OGS_PFCP_LOCAL_ORIGINATOR : OGS_PFCP_REMOTE_ORIGINATOR,
            xid);
    if (new && new->xid != xid)
        new = NULL;

    if (!new)
    ogs_list_for_each(list, new) {
        if (new->xid == xid) {
            ogs_debug("[%d] %s Find    peer %s",
                new->xid,
                new->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
                ogs_sockaddr_to_string_static(node->addr_list));
            break;
        }
    }

    if (!new) {
        ogs_debug("[%d] Cannot find new type %u from PFCP peer %s",
                xid, type, ogs_sockaddr_to_string_static(node->addr_list));
        new = ogs_pfcp_xact_remote_create(node, sqn);
    }
    ogs_assert(new);

    ogs_debug("[%d] %s Receive peer %s",
            new->xid,
            new->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            ogs_sockaddr_to_string_static(node->addr_list));

    rv = ogs_pfcp_xact_update_rx(new, type);
    if (rv == OGS_ERROR) {
        ogs_error("ogs_pfcp_xact_update_rx() failed");
        ogs_pfcp_xact_delete(new);
        return rv;
    } else if (rv == OGS_RETRY) {
        return rv;
    }

    *xact = new;
    return rv;
}

static ogs_pfcp_xact_stage_t ogs_pfcp_xact_get_stage(uint8_t type, uint32_t xid)
{
    ogs_pfcp_xact_stage_t stage = PFCP_XACT_UNKNOWN_STAGE;

    switch (type) {
    case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:
    case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
    case OGS_PFCP_ASSOCIATION_UPDATE_REQUEST_TYPE:
    case OGS_PFCP_ASSOCIATION_RELEASE_REQUEST_TYPE:
    case OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE:
    case OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE:
    case OGS_PFCP_SESSION_DELETION_REQUEST_TYPE:
    case OGS_PFCP_SESSION_REPORT_REQUEST_TYPE:
        stage = PFCP_XACT_INITIAL_STAGE;
        break;
    case OGS_PFCP_HEARTBEAT_RESPONSE_TYPE:
    case OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:
    case OGS_PFCP_ASSOCIATION_UPDATE_RESPONSE_TYPE:
    case OGS_PFCP_ASSOCIATION_RELEASE_RESPONSE_TYPE:
    case OGS_PFCP_VERSION_NOT_SUPPORTED_RESPONSE_TYPE:
    case OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE:
    case OGS_PFCP_SESSION_MODIFICATION_RESPONSE_TYPE:
    case OGS_PFCP_SESSION_DELETION_RESPONSE_TYPE:
    case OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE:
        stage = PFCP_XACT_FINAL_STAGE;
        break;

    default:
        ogs_error("Not implemented PFCPv2 Message Type(%d)", type);
        break;
    }

    return stage;
}

int ogs_pfcp_xact_delete(ogs_pfcp_xact_t *xact)
{
    ogs_assert(xact);
    ogs_assert(xact->node);

    ogs_debug("[%d] %s Delete  peer %s",
            xact->xid,
            xact->org == OGS_PFCP_LOCAL_ORIGINATOR ? "LOCAL " : "REMOTE",
            ogs_sockaddr_to_string_static(xact->node->addr_list));

    /*
     * Stop/delete timers before freeing the xact so holding_timeout and
     * friends never hash-lookup a freed transaction.
     */
    if (xact->tm_response) {
        ogs_timer_stop(xact->tm_response);
        ogs_timer_delete(xact->tm_response);
        xact->tm_response = NULL;
    }
    if (xact->tm_holding) {
        ogs_timer_stop(xact->tm_holding);
        ogs_timer_delete(xact->tm_holding);
        xact->tm_holding = NULL;
    }
    if (xact->tm_delayed_commit) {
        ogs_timer_stop(xact->tm_delayed_commit);
        ogs_timer_delete(xact->tm_delayed_commit);
        xact->tm_delayed_commit = NULL;
    }

    if (xact->seq[0].pkbuf)
        ogs_pkbuf_free(xact->seq[0].pkbuf);
    if (xact->seq[1].pkbuf)
        ogs_pkbuf_free(xact->seq[1].pkbuf);
    if (xact->seq[2].pkbuf)
        ogs_pkbuf_free(xact->seq[2].pkbuf);

    xact_index_del(xact);
    ogs_list_remove(xact->org == OGS_PFCP_LOCAL_ORIGINATOR ?
            &xact->node->local_list : &xact->node->remote_list, xact);
    ogs_pool_id_free(&pool, xact);

    return OGS_OK;
}
