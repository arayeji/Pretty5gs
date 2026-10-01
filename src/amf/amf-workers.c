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

#include "sbi-path.h"
#include "ngap-path.h"
#include "ngap-handler.h"
#include "ngap-free.h"
#include "namf-oam.h"
#include "nsmf-build.h"

static ogs_worker_t *workers[OGS_MAX_WORKERS];
/* configured shard count, valid until amf_workers_final() */
static int worker_count = 0;
/* threads alive: set once all started, cleared after they are joined */
static bool workers_running = false;

static OGS_THREAD_LOCAL int shard_self = -1;
static OGS_THREAD_LOCAL ogs_fsm_t worker_fsm;

/* must-deliver posts: ~100 ms before giving up */
#define AMF_SHARD_POST_MAX_TRIES 100

int amf_workers_count(void)
{
    return worker_count;
}

bool amf_workers_running(void)
{
    return workers_running;
}

int amf_shard_self(void)
{
    return shard_self;
}

ogs_timer_mgr_t *amf_shard_timer_mgr(void)
{
    if (shard_self < 0)
        return NULL;
    return workers[shard_self]->timer_mgr;
}

uint64_t amf_shard_compose_ngap_id(uint32_t index, int wid)
{
    if (wid < 0)
        return index;

    ogs_assert(wid < OGS_MAX_WORKERS - 1);
    return ((uint64_t)(wid + 1) << AMF_SHARD_NGAP_ID_SHIFT) | index;
}

int amf_shard_from_ngap_id(uint64_t amf_ue_ngap_id)
{
    int s = (int)((amf_ue_ngap_id >> AMF_SHARD_NGAP_ID_SHIFT) & 0xf);

    if (s == 0 || s > worker_count)
        return -1;
    return s - 1;
}

uint32_t amf_shard_compose_m_tmsi(uint32_t m_tmsi, int wid)
{
    if (wid < 0)
        return m_tmsi;

    ogs_assert(wid < OGS_MAX_WORKERS - 1);
    return m_tmsi | ((uint32_t)(wid + 1) << AMF_SHARD_M_TMSI_SHIFT);
}

int amf_shard_from_m_tmsi(uint32_t m_tmsi)
{
    int s = (int)((m_tmsi >> AMF_SHARD_M_TMSI_SHIFT) & 0xf);

    if (s == 0 || s > worker_count)
        return -1;
    return s - 1;
}

/* Free an event that is not going to be dispatched */
static void event_discard(amf_event_t *e)
{
    ogs_assert(e);

    switch (e->h.id) {
    case AMF_EVENT_NGAP_MESSAGE:
        if (e->ngap.rx_decoded)
            ngap_free_defer(e->ngap.message, e->pkbuf);
        else if (e->pkbuf)
            ogs_pkbuf_free(e->pkbuf);
        if (e->ngap.addr)
            ogs_free(e->ngap.addr);
        break;
    case OGS_EVENT_SBI_CLIENT:
    case AMF_EVENT_SBI_DISCOVER_CB:
        if (e->h.sbi.response)
            ogs_sbi_response_free(e->h.sbi.response);
        break;
    case OGS_EVENT_SBI_SERVER:
        /* the request belongs to the server (notify_completed) */
        break;
    default:
        if (e->pkbuf)
            ogs_pkbuf_free(e->pkbuf);
        break;
    }

    ogs_event_free(e);
}

int amf_workers_post(int wid, amf_event_t *e)
{
    int rv;

    ogs_assert(e);

    if (wid < 0 || wid >= worker_count || !workers[wid]) {
        ogs_error("amf_workers_post: bad shard %d for %s",
                wid, amf_event_get_name(e));
        event_discard(e);
        return OGS_ERROR;
    }

    rv = ogs_worker_post(workers[wid], e);
    if (rv != OGS_OK) {
        ogs_error("amf-w%d: queue full, %s dropped [%d]",
                wid, amf_event_get_name(e), rv);
        event_discard(e);
    }
    return rv;
}

int amf_workers_post_self(void *event)
{
    ogs_assert(event);
    ogs_assert(shard_self >= 0);

    return ogs_worker_post(workers[shard_self], event);
}

/* Lifecycle fan-out must not be lost to a momentarily full queue */
static int post_must(int wid, amf_event_t *e)
{
    int i, rv = OGS_ERROR;

    ogs_assert(wid >= 0 && wid < worker_count);

    for (i = 0; i < AMF_SHARD_POST_MAX_TRIES; i++) {
        rv = ogs_worker_post(workers[wid], e);
        if (rv != OGS_RETRY)
            break;
        ogs_msleep(1);
    }
    if (rv != OGS_OK) {
        ogs_error("amf-w%d: %s lost [%d]", wid, amf_event_get_name(e), rv);
        event_discard(e);
    }
    return rv;
}

static int push_must_to_main(amf_event_t *e)
{
    int i, rv = OGS_ERROR;

    /* each attempt already retries ~20 ms */
    for (i = 0; i < 25; i++) {
        rv = amf_queue_push_to_main(e);
        if (rv != OGS_RETRY)
            break;
    }
    if (rv != OGS_OK) {
        ogs_error("%s to main lost [%d]", amf_event_get_name(e), rv);
        ogs_event_free(e);
    }
    return rv;
}

/*
 * ---------------------------------------------------------------------
 * NGAP routing (main)
 * ---------------------------------------------------------------------
 */

#define UE_AMF_ID(_val, _name, _ies, _amf) do { \
    NGAP_##_name##_t *_m = &(_val)->value.choice._name; \
    int _i; \
    for (_i = 0; _i < _m->protocolIEs.list.count; _i++) { \
        _ies *_ie = _m->protocolIEs.list.array[_i]; \
        if (_ie->id == NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID || \
            _ie->id == NGAP_ProtocolIE_ID_id_SourceAMF_UE_NGAP_ID) \
            (_amf) = &_ie->value.choice.AMF_UE_NGAP_ID; \
    } \
} while (0)

#define UE_IDS(_val, _name, _ies, _amf, _ran) do { \
    NGAP_##_name##_t *_m = &(_val)->value.choice._name; \
    int _i; \
    for (_i = 0; _i < _m->protocolIEs.list.count; _i++) { \
        _ies *_ie = _m->protocolIEs.list.array[_i]; \
        if (_ie->id == NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID || \
            _ie->id == NGAP_ProtocolIE_ID_id_SourceAMF_UE_NGAP_ID) \
            (_amf) = &_ie->value.choice.AMF_UE_NGAP_ID; \
        else if (_ie->id == NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID) \
            (_ran) = &_ie->value.choice.RAN_UE_NGAP_ID; \
    } \
} while (0)

/* true when the gNB has a ran_ue with this RAN-UE-NGAP-ID */
static bool owner_by_ran_id(amf_gnb_t *gnb, uint64_t ran_ue_ngap_id,
        int *owner)
{
    ran_ue_t *ran_ue = NULL;
    bool found = false;

    amf_ctx_lock();
    ran_ue = ran_ue_find_by_ran_ue_ngap_id(gnb, ran_ue_ngap_id);
    if (ran_ue) {
        *owner = ran_ue->owner_wid;
        found = true;
    }
    amf_ctx_unlock();

    return found;
}

static int owner_by_ids(amf_gnb_t *gnb,
        NGAP_AMF_UE_NGAP_ID_t *amf_id, NGAP_RAN_UE_NGAP_ID_t *ran_id)
{
    uint64_t id;
    int owner = -1;

    if (amf_id) {
        if (asn_INTEGER2uint64(amf_id, &id) != 0)
            return -1;
        return amf_shard_from_ngap_id(id);
    }
    if (ran_id)
        owner_by_ran_id(gnb, *ran_id, &owner);

    return owner;
}

/* NAS identity of an InitialUEMessage; never needs a security context */
static int nas_owner(NGAP_NAS_PDU_t *nas_pdu)
{
    ogs_nas_5gs_message_t message;
    ogs_pkbuf_t *pkbuf = NULL;
    const uint8_t *buf = nas_pdu->buf;
    size_t size = nas_pdu->size;
    int owner = -1;

    if (!buf || size < 3 ||
            buf[0] != OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM)
        return -1;

    switch (buf[1] & 0x0f) {
    case OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE:
        break;
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED:
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT:
        if (size <= sizeof(ogs_nas_5gs_security_header_t) + 2)
            return -1;
        buf += sizeof(ogs_nas_5gs_security_header_t);
        size -= sizeof(ogs_nas_5gs_security_header_t);
        if (buf[0] != OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM)
            return -1;
        break;
    default:
        return -1;
    }

    pkbuf = ogs_pkbuf_alloc(NULL, size);
    if (!pkbuf)
        return -1;
    ogs_pkbuf_put_data(pkbuf, buf, size);

    memset(&message, 0, sizeof(message));
    if (ogs_nas_5gmm_decode(&message, pkbuf) == OGS_OK)
        owner = amf_ue_owner_by_message(&message);

    /* identity IEs point into pkbuf */
    ogs_pkbuf_free(pkbuf);

    return owner;
}

/*
 * A new NAS connection goes where the UE context already is: the
 * shard of a duplicate RAN-UE-NGAP-ID, of the 5G-S-TMSI or of the NAS
 * identity; an unknown UE is spread over the shards.
 */
static int initial_ue_owner(amf_gnb_t *gnb, NGAP_InitiatingMessage_t *im)
{
    NGAP_InitialUEMessage_t *m = &im->value.choice.InitialUEMessage;
    NGAP_RAN_UE_NGAP_ID_t *ran_id = NULL;
    NGAP_NAS_PDU_t *nas_pdu = NULL;
    NGAP_FiveG_S_TMSI_t *s_tmsi = NULL;
    int i, owner = -1;
    uint32_t h;

    for (i = 0; i < m->protocolIEs.list.count; i++) {
        NGAP_InitialUEMessage_IEs_t *ie = m->protocolIEs.list.array[i];
        switch (ie->id) {
        case NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID:
            ran_id = &ie->value.choice.RAN_UE_NGAP_ID;
            break;
        case NGAP_ProtocolIE_ID_id_NAS_PDU:
            nas_pdu = &ie->value.choice.NAS_PDU;
            break;
        case NGAP_ProtocolIE_ID_id_FiveG_S_TMSI:
            s_tmsi = &ie->value.choice.FiveG_S_TMSI;
            break;
        default:
            break;
        }
    }

    /* main answers the protocol error */
    if (!ran_id)
        return -1;

    if (owner_by_ran_id(gnb, *ran_id, &owner))
        return owner;

    if (s_tmsi) {
        ogs_nas_5gs_guti_t nas_guti;
        uint16_t set;
        uint8_t pointer;
        uint32_t m_tmsi;

        memset(&nas_guti, 0, sizeof(nas_guti));
        ogs_nas_from_plmn_id(&nas_guti.nas_plmn_id,
                &amf_self()->served_guami[0].plmn_id);
        ogs_ngap_AMFSetID_to_uint16(&s_tmsi->aMFSetID, &set);
        ogs_ngap_AMFPointer_to_uint8(&s_tmsi->aMFPointer, &pointer);
        ogs_amf_id_build(&nas_guti.amf_id,
                amf_self()->served_guami[0].amf_id.region, set, pointer);
        ogs_asn_OCTET_STRING_to_uint32(&s_tmsi->fiveG_TMSI, &m_tmsi);
        nas_guti.m_tmsi = m_tmsi;

        owner = amf_ue_owner_by_guti(&nas_guti);
        if (owner >= 0)
            return owner;
    }

    if (nas_pdu) {
        owner = nas_owner(nas_pdu);
        if (owner >= 0)
            return owner;
    }

    h = (uint32_t)gnb->id * 2654435761u ^ (uint32_t)*ran_id * 40503u;
    return (int)(h % (uint32_t)worker_count);
}

/* -1: gNB-level (NGSetup, NGReset, RAN configuration) or unknown */
static int ngap_owner(amf_gnb_t *gnb, ogs_ngap_message_t *pdu)
{
    NGAP_AMF_UE_NGAP_ID_t *amf_id = NULL;
    NGAP_RAN_UE_NGAP_ID_t *ran_id = NULL;
    NGAP_InitiatingMessage_t *im = NULL;
    NGAP_SuccessfulOutcome_t *so = NULL;
    NGAP_UnsuccessfulOutcome_t *uo = NULL;

    switch (pdu->present) {
    case NGAP_NGAP_PDU_PR_initiatingMessage:
        im = pdu->choice.initiatingMessage;
        if (!im)
            return -1;
        switch (im->procedureCode) {
        case NGAP_ProcedureCode_id_InitialUEMessage:
            return initial_ue_owner(gnb, im);
        case NGAP_ProcedureCode_id_UplinkNASTransport:
            UE_IDS(im, UplinkNASTransport,
                    NGAP_UplinkNASTransport_IEs_t, amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_UERadioCapabilityInfoIndication:
            UE_IDS(im, UERadioCapabilityInfoIndication,
                    NGAP_UERadioCapabilityInfoIndicationIEs_t,
                    amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_UEContextReleaseRequest:
            UE_IDS(im, UEContextReleaseRequest,
                    NGAP_UEContextReleaseRequest_IEs_t, amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_PathSwitchRequest:
            UE_IDS(im, PathSwitchRequest,
                    NGAP_PathSwitchRequestIEs_t, amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_HandoverPreparation:
            UE_IDS(im, HandoverRequired,
                    NGAP_HandoverRequiredIEs_t, amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_UplinkRANStatusTransfer:
            UE_IDS(im, UplinkRANStatusTransfer,
                    NGAP_UplinkRANStatusTransferIEs_t, amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_HandoverNotification:
            UE_IDS(im, HandoverNotify,
                    NGAP_HandoverNotifyIEs_t, amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_HandoverCancel:
            UE_IDS(im, HandoverCancel,
                    NGAP_HandoverCancelIEs_t, amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_ErrorIndication:
            UE_IDS(im, ErrorIndication,
                    NGAP_ErrorIndicationIEs_t, amf_id, ran_id);
            break;
        default:
            return -1;
        }
        break;

    case NGAP_NGAP_PDU_PR_successfulOutcome:
        so = pdu->choice.successfulOutcome;
        if (!so)
            return -1;
        switch (so->procedureCode) {
        case NGAP_ProcedureCode_id_InitialContextSetup:
            UE_IDS(so, InitialContextSetupResponse,
                    NGAP_InitialContextSetupResponseIEs_t, amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_PDUSessionResourceSetup:
            UE_IDS(so, PDUSessionResourceSetupResponse,
                    NGAP_PDUSessionResourceSetupResponseIEs_t,
                    amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_PDUSessionResourceModify:
            UE_IDS(so, PDUSessionResourceModifyResponse,
                    NGAP_PDUSessionResourceModifyResponseIEs_t,
                    amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_PDUSessionResourceRelease:
            UE_IDS(so, PDUSessionResourceReleaseResponse,
                    NGAP_PDUSessionResourceReleaseResponseIEs_t,
                    amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_UEContextModification:
            UE_IDS(so, UEContextModificationResponse,
                    NGAP_UEContextModificationResponseIEs_t,
                    amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_UEContextRelease:
            UE_IDS(so, UEContextReleaseComplete,
                    NGAP_UEContextReleaseComplete_IEs_t, amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_HandoverResourceAllocation:
            UE_IDS(so, HandoverRequestAcknowledge,
                    NGAP_HandoverRequestAcknowledgeIEs_t, amf_id, ran_id);
            break;
        default:
            return -1;
        }
        break;

    case NGAP_NGAP_PDU_PR_unsuccessfulOutcome:
        uo = pdu->choice.unsuccessfulOutcome;
        if (!uo)
            return -1;
        switch (uo->procedureCode) {
        case NGAP_ProcedureCode_id_InitialContextSetup:
            UE_IDS(uo, InitialContextSetupFailure,
                    NGAP_InitialContextSetupFailureIEs_t, amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_UEContextModification:
            UE_IDS(uo, UEContextModificationFailure,
                    NGAP_UEContextModificationFailureIEs_t,
                    amf_id, ran_id);
            break;
        case NGAP_ProcedureCode_id_HandoverResourceAllocation:
            UE_AMF_ID(uo, HandoverFailure,
                    NGAP_HandoverFailureIEs_t, amf_id);
            break;
        default:
            return -1;
        }
        break;

    default:
        return -1;
    }

    return owner_by_ids(gnb, amf_id, ran_id);
}

static int route_ngap(amf_event_t *e)
{
    amf_gnb_t *gnb = NULL;
    int wid;

    if (!e->pkbuf || !e->ngap.addr ||
            (e->ngap.addr->ogs_sa_family != AF_INET &&
             e->ngap.addr->ogs_sa_family != AF_INET6))
        return -1;

    gnb = amf_gnb_find_by_addr(e->ngap.addr);
    if (!gnb || !gnb->state.ng_setup_success)
        return -1;

    /* shards only take heap PDUs (freed through ngap_free_defer) */
    if (!e->ngap.rx_decoded) {
        ogs_ngap_message_t *pdu = ogs_calloc(1, sizeof(*pdu));
        if (!pdu)
            return -1;
        if (ogs_ngap_decode(pdu, e->pkbuf) != OGS_OK) {
            /* main decodes again and answers the gNB */
            ogs_ngap_free(pdu);
            ogs_free(pdu);
            return -1;
        }
        e->ngap.message = pdu;
        e->ngap.rx_decoded = true;
    }

    wid = ngap_owner(gnb, e->ngap.message);
    if (wid < 0)
        return -1;

    e->gnb_id = gnb->id;
    ogs_free(e->ngap.addr);
    e->ngap.addr = NULL;

    return wid;
}

/*
 * ---------------------------------------------------------------------
 * SBI routing (main)
 * ---------------------------------------------------------------------
 */

/* service name and resource components of a URI, without touching it */
static bool peek_uri(char *uri, ogs_sbi_header_t *h, ogs_sbi_message_t *m)
{
    memset(h, 0, sizeof(*h));
    h->uri = uri;
    return ogs_sbi_parse_header(m, h) == OGS_OK;
}

static void peek_uri_free(ogs_sbi_header_t *h)
{
    h->uri = NULL;
    ogs_sbi_header_free(h);
}

static int route_xact(ogs_pool_id_t xact_id)
{
    ogs_sbi_xact_t *xact = NULL;
    int owner = -1;

    if (xact_id < OGS_MIN_POOL_ID || xact_id > OGS_MAX_POOL_ID)
        return -1;

    /* removal of a UE/session drops its xacts, so sbi_object is live */
    ogs_sbi_lock();
    xact = ogs_sbi_xact_find_by_id(xact_id);
    if (xact && xact->sbi_object) {
        switch (xact->sbi_object->type) {
        case OGS_SBI_OBJ_UE_TYPE:
            owner = amf_ue_owner_by_id(xact->sbi_object_id);
            break;
        case OGS_SBI_OBJ_SESS_TYPE:
            owner = amf_sess_owner_by_id(xact->sbi_object_id);
            break;
        default:
            break;
        }
    }
    ogs_sbi_unlock();

    return owner;
}

static bool route_sbi_server(amf_event_t *e)
{
    ogs_sbi_request_t *request = e->h.sbi.request;
    ogs_sbi_header_t h;
    ogs_sbi_message_t m;
    char *c0, *c1;
    int owner = -1, rv;

    if (!request || !request->h.uri)
        return false;
    if (strstr(request->h.uri, OGS_SBI_SERVICE_NAME_NAMF_OAM))
        return false;

    if (peek_uri(request->h.uri, &h, &m) && m.h.service.name) {
        c0 = m.h.resource.component[0];
        c1 = m.h.resource.component[1];

        if (!strcmp(m.h.service.name, OGS_SBI_SERVICE_NAME_NAMF_COMM)) {
            if (c0 && c1 && !strcmp(c0, OGS_SBI_RESOURCE_NAME_UE_CONTEXTS))
                owner = amf_ue_owner_by_ue_context_id(c1);
        } else if (!strcmp(m.h.service.name,
                    OGS_SBI_SERVICE_NAME_NAMF_CALLBACK)) {
            /* namf-callback/v1/{supi}/... */
            if (c0)
                owner = amf_ue_owner_by_supi(c0);
        }
    }
    peek_uri_free(&h);

    if (owner < 0)
        return false;

    rv = ogs_worker_post(workers[owner], e);
    if (rv != OGS_OK) {
        ogs_sbi_stream_t *stream = NULL;
        ogs_pool_id_t stream_id = OGS_POINTER_TO_UINT(e->h.sbi.data);

        ogs_error("amf-w%d: queue full, SBI request rejected [%d]",
                owner, rv);
        ogs_sbi_lock();
        if (stream_id >= OGS_MIN_POOL_ID && stream_id <= OGS_MAX_POOL_ID)
            stream = ogs_sbi_stream_find_by_id(stream_id);
        if (stream)
            ogs_expect(true == ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_SERVICE_UNAVAILABLE, NULL,
                    "AMF overloaded", NULL, NULL));
        ogs_sbi_unlock();
        ogs_event_free(e);
    }

    return true;
}

static int route_sbi_client(amf_event_t *e)
{
    ogs_sbi_response_t *response = e->h.sbi.response;
    ogs_sbi_header_t h;
    ogs_sbi_message_t m;
    bool nfm = true;

    if (!response || !response->h.uri)
        return -1;

    /* NNRF_NFM carries NF instance / subscription pointers, not xacts */
    if (peek_uri(response->h.uri, &h, &m) && m.h.service.name)
        nfm = !strcmp(m.h.service.name, OGS_SBI_SERVICE_NAME_NNRF_NFM);
    peek_uri_free(&h);

    if (nfm)
        return -1;

    return route_xact(OGS_POINTER_TO_UINT(e->h.sbi.data));
}

bool amf_workers_route(amf_event_t *e)
{
    int wid = -1;

    ogs_assert(e);

    if (!workers_running)
        return false;

    switch (e->h.id) {
    case AMF_EVENT_NGAP_MESSAGE:
        wid = route_ngap(e);
        break;
    case OGS_EVENT_SBI_SERVER:
        return route_sbi_server(e);
    case OGS_EVENT_SBI_CLIENT:
        wid = route_sbi_client(e);
        break;
    case OGS_EVENT_SBI_TIMER:
        if (e->h.timer_id == OGS_TIMER_SBI_CLIENT_WAIT)
            wid = route_xact(OGS_POINTER_TO_UINT(e->h.sbi.data));
        break;
    default:
        break;
    }

    if (wid < 0)
        return false;

    amf_workers_post(wid, e);
    return true;
}

bool amf_workers_post_discover_cb(int status,
        ogs_sbi_response_t *response, void *data)
{
    amf_event_t *e = NULL;
    int owner;

    if (!workers_running)
        return false;

    owner = route_xact(OGS_POINTER_TO_UINT(data));
    if (owner < 0 || owner == shard_self)
        return false;

    e = amf_event_new(AMF_EVENT_SBI_DISCOVER_CB);
    if (!e) {
        ogs_error("amf_event_new() failed");
        if (response)
            ogs_sbi_response_free(response);
        return true;
    }
    e->h.sbi.state = status;
    e->h.sbi.response = response;
    e->h.sbi.data = data;

    /* a lost response is cleaned up by the CLIENT_WAIT timer */
    amf_workers_post(owner, e);
    return true;
}

/*
 * ---------------------------------------------------------------------
 * Fan-out (main)
 * ---------------------------------------------------------------------
 */

static void gnb_remove_done(ogs_pool_id_t gnb_id)
{
    amf_gnb_t *gnb = amf_gnb_find_by_id_any(gnb_id);
    bool last;

    if (!gnb || !gnb->being_removed) {
        ogs_error("[%d] gNB teardown confirm without teardown", gnb_id);
        return;
    }

    amf_ctx_lock();
    last = (--gnb->remove_pending == 0);
    amf_ctx_unlock();

    if (last)
        amf_gnb_remove_finish(gnb);
}

void amf_workers_gnb_teardown(amf_gnb_t *gnb, int state)
{
    ogs_pool_id_t gnb_id;
    int i;

    ogs_assert(gnb);

    if (!workers_running) {
        amf_sbi_send_deactivate_all_ue_in_gnb(gnb, state);
        amf_gnb_remove(gnb);
        return;
    }

    if (gnb->being_removed)
        return;

    gnb_id = gnb->id;
    amf_gnb_remove_begin(gnb);

    amf_ctx_lock();
    gnb->remove_pending = worker_count;
    amf_ctx_unlock();

    /* main owns no UE with workers on; release strays all the same */
    amf_sbi_send_deactivate_own_ue_in_gnb(gnb_id, state);

    for (i = 0; i < worker_count; i++) {
        amf_event_t *e = amf_event_new(AMF_EVENT_SHARD_GNB_REMOVE);
        ogs_assert(e);
        e->gnb_id = gnb_id;
        e->shard_arg = state;
        /* a shard that never hears of it must not keep the gNB alive */
        if (post_must(i, e) != OGS_OK)
            gnb_remove_done(gnb_id);
    }
}

void amf_workers_ng_reset_all(amf_gnb_t *gnb)
{
    int i;

    ogs_assert(gnb);
    ogs_assert(workers_running);

    amf_ctx_lock();
    gnb->ng_reset_all_pending = true;
    amf_ctx_unlock();

    for (i = 0; i < worker_count; i++) {
        amf_event_t *e = amf_event_new(AMF_EVENT_SHARD_NG_RESET_ALL);
        ogs_assert(e);
        e->gnb_id = gnb->id;
        post_must(i, e);
    }

    /* no ran_ue left at all: acknowledge right away */
    amf_gnb_ng_reset_all_try_ack(gnb);
}

bool amf_workers_ng_reset_partial(
        ogs_pool_id_t ran_ue_id, ogs_pool_id_t gnb_id)
{
    amf_event_t *e = NULL;
    int owner;

    if (!workers_running)
        return false;

    owner = ran_ue_owner_by_id(ran_ue_id);
    if (owner < 0)
        /* gone already (its flag went with it), or main's own */
        return ran_ue_find_by_id(ran_ue_id) == NULL;

    e = amf_event_new(AMF_EVENT_SHARD_NG_RESET_PARTIAL);
    ogs_assert(e);
    e->ran_ue_id = ran_ue_id;
    e->gnb_id = gnb_id;
    if (post_must(owner, e) != OGS_OK) {
        ran_ue_t *ran_ue = NULL;

        /* do not let the lost item hold the ACK back forever */
        amf_ctx_lock();
        ran_ue = ran_ue_find_by_id(ran_ue_id);
        if (ran_ue)
            ran_ue->part_of_ng_reset_requested = false;
        amf_ctx_unlock();
    }

    return true;
}

void amf_workers_oam_release_plmn(const ogs_plmn_id_t *plmn_id)
{
    int i;

    ogs_assert(plmn_id);

    for (i = 0; i < worker_count; i++) {
        amf_event_t *e = amf_event_new(AMF_EVENT_SHARD_OAM_RELEASE);
        ogs_assert(e);
        memcpy(&e->plmn_id, plmn_id, sizeof(e->plmn_id));
        amf_workers_post(i, e);
    }
}

void amf_workers_post_ue_evict(int wid, ogs_pool_id_t amf_ue_id)
{
    amf_event_t *e = amf_event_new(AMF_EVENT_SHARD_UE_EVICT);

    ogs_assert(e);
    e->amf_ue_id = amf_ue_id;

    if (wid < 0) {
        push_must_to_main(e);
        return;
    }
    amf_workers_post(wid, e);
}

/*
 * ---------------------------------------------------------------------
 * Shard side
 * ---------------------------------------------------------------------
 */

/*
 * The new owner has already taken the sessions (ue_release_old_any());
 * the NG context is released at once instead of being held until the
 * new registration authenticates, since only this shard may run its
 * timers. Sessions still here (race) are released towards the SMF.
 */
static void ue_evict(ogs_pool_id_t amf_ue_id)
{
    amf_ue_t *amf_ue = NULL;
    ran_ue_t *ran_ue = NULL;
    amf_nsmf_pdusession_sm_context_param_t param;
    int r;

    amf_ue = amf_ue_find_by_id(amf_ue_id);
    if (!amf_ue || amf_ue->owner_wid != shard_self)
        return;

    ogs_warn("[%s] Evicting OLD UE Context",
            amf_ue->supi ? amf_ue->supi :
            amf_ue->suci ? amf_ue->suci : "Unknown");

    ran_ue = ran_ue_find_by_id(amf_ue->ran_ue_id);
    if (ran_ue) {
        amf_ue_deassociate_ran_ue(amf_ue, ran_ue);
        r = ngap_send_ran_ue_context_release_command(ran_ue,
                NGAP_Cause_PR_nas, NGAP_CauseNas_normal_release,
                NGAP_UE_CTX_REL_NG_CONTEXT_REMOVE, 0);
        ogs_expect(r == OGS_OK);
    }

    memset(&param, 0, sizeof(param));
    param.cause = OpenAPI_cause_REL_DUE_TO_UNSPECIFIED_REASON;
    param.ngApCause.group = NGAP_Cause_PR_nas;
    param.ngApCause.value = NGAP_CauseNas_normal_release;

    amf_sbi_send_release_all_sessions(
            NULL, amf_ue, AMF_RELEASE_SM_CONTEXT_NO_STATE, &param);
    amf_ue_remove(amf_ue);
}

void amf_workers_handle_event(amf_event_t *e)
{
    amf_gnb_t *gnb = NULL;
    ran_ue_t *ran_ue = NULL;

    ogs_assert(e);

    /* rare control events: run them whole under the SBI lock */
    ogs_sbi_lock();

    switch (e->h.id) {
    case AMF_EVENT_SHARD_GNB_REMOVE:
        amf_sbi_send_deactivate_own_ue_in_gnb(e->gnb_id, e->shard_arg);
        {
            amf_event_t *done = amf_event_new(
                    AMF_EVENT_SHARD_GNB_REMOVE_DONE);
            ogs_assert(done);
            done->gnb_id = e->gnb_id;
            push_must_to_main(done);
        }
        break;

    case AMF_EVENT_SHARD_GNB_REMOVE_DONE:
        ogs_assert(shard_self < 0);
        gnb_remove_done(e->gnb_id);
        break;

    case AMF_EVENT_SHARD_NG_RESET_ALL:
        amf_sbi_send_deactivate_own_ue_in_gnb(
                e->gnb_id, AMF_REMOVE_S1_CONTEXT_BY_RESET_ALL);
        gnb = amf_gnb_find_by_id(e->gnb_id);
        if (gnb)
            amf_gnb_ng_reset_all_try_ack(gnb);
        break;

    case AMF_EVENT_SHARD_NG_RESET_PARTIAL:
        ran_ue = ran_ue_find_by_id(e->ran_ue_id);
        if (ran_ue && ran_ue->owner_wid == shard_self)
            ngap_ng_reset_partial_release(ran_ue);
        gnb = amf_gnb_find_by_id(e->gnb_id);
        if (gnb)
            ngap_ng_reset_partial_try_ack(gnb);
        break;

    case AMF_EVENT_SHARD_UE_EVICT:
        ue_evict(e->amf_ue_id);
        break;

    case AMF_EVENT_SHARD_OAM_RELEASE:
        amf_namf_oam_release_local_ues_of_plmn(&e->plmn_id);
        break;

    case AMF_EVENT_SBI_DISCOVER_CB:
        amf_sbi_discover_by_nsi_handler(
                e->h.sbi.state, e->h.sbi.response, e->h.sbi.data);
        e->h.sbi.response = NULL;
        break;

    default:
        ogs_error("No shard handler for %s", amf_event_get_name(e));
        break;
    }

    ogs_sbi_unlock();
}

static bool is_shard_event(int id)
{
    return id >= AMF_EVENT_SHARD_GNB_REMOVE && id <= AMF_EVENT_SBI_DISCOVER_CB;
}

static bool is_sbi_event(int id)
{
    return id == OGS_EVENT_SBI_SERVER || id == OGS_EVENT_SBI_CLIENT ||
        id == OGS_EVENT_SBI_TIMER;
}

static void dispatch_one(amf_event_t *e)
{
    if (is_shard_event(e->h.id)) {
        amf_workers_handle_event(e);
        return;
    }

    /*
     * SBI handlers walk lib/sbi state throughout; NGAP/NAS handlers
     * only reach it through helpers that take the lock themselves.
     */
    if (is_sbi_event(e->h.id)) {
        ogs_sbi_lock();
        ogs_fsm_dispatch(&worker_fsm, e);
        ogs_sbi_unlock();
    } else {
        ogs_fsm_dispatch(&worker_fsm, e);
    }
}

static void worker_dispatch(ogs_worker_t *worker, void *data)
{
    amf_event_t *e = data;

    ogs_assert(worker);
    ogs_assert(e);

    amf_event_dispatch_begin();
    do {
        dispatch_one(e);
        ogs_event_free(e);
    } while ((e = amf_event_local_pop()));
    amf_event_dispatch_end();
}

static void worker_thread_init(ogs_worker_t *worker)
{
    ogs_assert(worker);

    shard_self = worker->id;
    amf_pkbuf_thread_pool_attach();
    ogs_fsm_init(&worker_fsm, amf_state_initial, amf_state_final, 0);

    ogs_info("AMF shard worker %d ready", worker->id);
}

static void worker_thread_fini(ogs_worker_t *worker)
{
    ogs_assert(worker);

    ogs_fsm_fini(&worker_fsm, 0);

    ogs_info("AMF shard worker %d stopped", worker->id);
}

static void sbi_hook_enter(void *data)
{
    ogs_sbi_lock();
}

static void sbi_hook_leave(void *data)
{
    ogs_sbi_unlock();
}

int amf_workers_start(int count)
{
    int i;

    if (count <= 0)
        return OGS_OK;

    ogs_assert(count <= OGS_MAX_WORKERS - 1);
    ogs_assert(worker_count == 0);

    /* before any shard can touch the context or lib/sbi */
    amf_ctx_lock_enable();
    ogs_sbi_lock_enable();
    ogs_pollset_set_dispatch_hooks(ogs_app()->pollset,
            sbi_hook_enter, sbi_hook_leave, NULL);

    worker_count = count;

    for (i = 0; i < count; i++) {
        char tname[16];

        /* same cap as the main app queue (ogs-init.c) */
        workers[i] = ogs_worker_create(i,
                ogs_min(ogs_app()->pool.event, 1024 * 1024),
                ogs_app()->pool.timer, 64, worker_dispatch, NULL);
        ogs_assert(workers[i]);
        ogs_worker_hooks(workers[i], worker_thread_init, worker_thread_fini);
        ogs_snprintf(tname, sizeof(tname), "amf-w%d", i);
        ogs_worker_set_name(workers[i], tname);
    }

    workers_running = true;
    for (i = 0; i < count; i++)
        ogs_worker_start(workers[i]);

    ogs_info("AMF SMP workers: %d UE shard(s)", worker_count);

    return OGS_OK;
}

void amf_workers_stop(void)
{
    int i;

    /* join only: UE timers live on the shard timer managers until
     * amf_context_final(); amf_workers_final() frees them */
    for (i = 0; i < worker_count; i++)
        ogs_worker_join(workers[i]);

    workers_running = false;
}

void amf_workers_final(void)
{
    int i;

    for (i = 0; i < worker_count; i++) {
        ogs_worker_destroy(workers[i]);
        workers[i] = NULL;
    }
    worker_count = 0;
}
