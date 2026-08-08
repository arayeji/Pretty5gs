/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * S1AP decode via Open5GS ASN.1 — extract UE S1AP IDs, TAI/ECGI,
 * NAS-PDU, and S1-U GTP TEIDs from Initial Context Setup.
 */

#include "decode.h"
#include "context.h"

#include "ogs-s1ap.h"

/* ASN.1 codec is not safe across decode workers. */
static ogs_thread_mutex_t s1ap_lock;

void ptrace_decode_s1ap_init(void)
{
    ogs_thread_mutex_init(&s1ap_lock);
}

static const char *pdu_proc_name(const ogs_s1ap_message_t *msg)
{
    uint8_t code;

    if (!msg)
        return NULL;
    if (msg->present == S1AP_S1AP_PDU_PR_initiatingMessage &&
            msg->choice.initiatingMessage) {
        code = msg->choice.initiatingMessage->procedureCode;
        switch (code) {
        case S1AP_ProcedureCode_id_initialUEMessage:
            return "Initial UE Message";
        case S1AP_ProcedureCode_id_downlinkNASTransport:
            return "Downlink NAS Transport";
        case S1AP_ProcedureCode_id_uplinkNASTransport:
            return "Uplink NAS Transport";
        case S1AP_ProcedureCode_id_InitialContextSetup:
            return "Initial Context Setup Request";
        case S1AP_ProcedureCode_id_UEContextRelease:
            return "UE Context Release";
        case S1AP_ProcedureCode_id_UEContextReleaseRequest:
            return "UE Context Release Request";
        case S1AP_ProcedureCode_id_E_RABSetup:
            return "E-RAB Setup Request";
        case S1AP_ProcedureCode_id_E_RABModify:
            return "E-RAB Modify Request";
        case S1AP_ProcedureCode_id_E_RABRelease:
            return "E-RAB Release Command";
        default:
            return NULL;
        }
    }
    if (msg->present == S1AP_S1AP_PDU_PR_successfulOutcome &&
            msg->choice.successfulOutcome) {
        code = msg->choice.successfulOutcome->procedureCode;
        switch (code) {
        case S1AP_ProcedureCode_id_InitialContextSetup:
            return "Initial Context Setup Response";
        case S1AP_ProcedureCode_id_UEContextRelease:
            return "UE Context Release Complete";
        case S1AP_ProcedureCode_id_E_RABSetup:
            return "E-RAB Setup Response";
        default:
            return NULL;
        }
    }
    return NULL;
}

static uint32_t teid_from_octet(OCTET_STRING_t *os)
{
    uint32_t teid = 0;
    int i;
    if (!os || !os->buf || os->size <= 0)
        return 0;
    for (i = 0; i < os->size && i < 4; i++)
        teid = (teid << 8) | os->buf[i];
    return teid;
}

static void add_teid(ptrace_event_t *evt, uint32_t teid)
{
    ptrace_ids_add_teid(&evt->ids, teid);
}

static void extract_nas(OCTET_STRING_t *nas_pdu, ptrace_event_t *base,
        ptrace_event_t **extra, int *nextra)
{
    ptrace_event_t *ne;
    if (!nas_pdu || !nas_pdu->buf || nas_pdu->size <= 0)
        return;
    if (*nextra >= PTRACE_MAX_EVENTS_PER_PKT)
        return;
    ne = ptrace_event_alloc();
    if (!ne)
        return;
    ne->ts = base->ts;
    ne->role = base->role;
    ogs_cpystrn(ne->src_ip, base->src_ip, sizeof(ne->src_ip));
    ogs_cpystrn(ne->dst_ip, base->dst_ip, sizeof(ne->dst_ip));
    ne->src_port = base->src_port;
    ne->dst_port = base->dst_port;
    ogs_cpystrn(ne->packet_ref, base->packet_ref, sizeof(ne->packet_ref));
    ne->ids = base->ids; /* inherit S1AP IDs for correlation */
    if (ptrace_decode_nas(nas_pdu->buf, (int)nas_pdu->size, ne) == OGS_OK) {
        /* propagate identities discovered in NAS back to S1AP event */
        if (ne->ids.imsi[0] && !base->ids.imsi[0])
            ogs_cpystrn(base->ids.imsi, ne->ids.imsi, sizeof(base->ids.imsi));
        if (ne->ids.msisdn[0] && !base->ids.msisdn[0])
            ogs_cpystrn(base->ids.msisdn, ne->ids.msisdn,
                    sizeof(base->ids.msisdn));
        if (ne->ids.imei[0] && !base->ids.imei[0])
            ogs_cpystrn(base->ids.imei, ne->ids.imei, sizeof(base->ids.imei));
        if (ne->ids.guti[0] && !base->ids.guti[0])
            ogs_cpystrn(base->ids.guti, ne->ids.guti, sizeof(base->ids.guti));
        if (ne->ids.m_tmsi[0] && !base->ids.m_tmsi[0])
            ogs_cpystrn(base->ids.m_tmsi, ne->ids.m_tmsi,
                    sizeof(base->ids.m_tmsi));
        extra[(*nextra)++] = ne;
    } else {
        ptrace_event_free(ne);
    }
}

static void handle_initial_ue(S1AP_InitialUEMessage_t *msg,
        ptrace_event_t *base, ptrace_event_t **extra, int *nextra)
{
    int i;
    for (i = 0; i < msg->protocolIEs.list.count; i++) {
        S1AP_InitialUEMessage_IEs_t *ie = msg->protocolIEs.list.array[i];
        if (!ie)
            continue;
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            base->ids.enb_ue_s1ap_id = (uint32_t)ie->value.choice.ENB_UE_S1AP_ID;
            base->ids.has_enb_ue_s1ap_id = true;
            break;
        case S1AP_ProtocolIE_ID_id_NAS_PDU:
            extract_nas(&ie->value.choice.NAS_PDU, base, extra, nextra);
            break;
        case S1AP_ProtocolIE_ID_id_TAI:
            if (ie->value.choice.TAI.tAC.size >= 2) {
                base->ids.tac = (uint16_t)(
                        (ie->value.choice.TAI.tAC.buf[0] << 8) |
                        ie->value.choice.TAI.tAC.buf[1]);
                base->ids.has_tac = true;
            }
            break;
        case S1AP_ProtocolIE_ID_id_EUTRAN_CGI:
            if (ie->value.choice.EUTRAN_CGI.cell_ID.size >= 4) {
                uint8_t *b = ie->value.choice.EUTRAN_CGI.cell_ID.buf;
                base->ids.cell_id = ((uint32_t)b[0] << 20) |
                        ((uint32_t)b[1] << 12) |
                        ((uint32_t)b[2] << 4) |
                        ((uint32_t)b[3] >> 4);
                base->ids.has_cell_id = true;
            }
            break;
        default:
            break;
        }
    }
}

static void handle_dl_nas(S1AP_DownlinkNASTransport_t *msg,
        ptrace_event_t *base, ptrace_event_t **extra, int *nextra)
{
    int i;
    for (i = 0; i < msg->protocolIEs.list.count; i++) {
        S1AP_DownlinkNASTransport_IEs_t *ie = msg->protocolIEs.list.array[i];
        if (!ie)
            continue;
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            base->ids.mme_ue_s1ap_id =
                    (uint32_t)ie->value.choice.MME_UE_S1AP_ID;
            base->ids.has_mme_ue_s1ap_id = true;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            base->ids.enb_ue_s1ap_id =
                    (uint32_t)ie->value.choice.ENB_UE_S1AP_ID;
            base->ids.has_enb_ue_s1ap_id = true;
            break;
        case S1AP_ProtocolIE_ID_id_NAS_PDU:
            extract_nas(&ie->value.choice.NAS_PDU, base, extra, nextra);
            break;
        default:
            break;
        }
    }
}

static void handle_ul_nas(S1AP_UplinkNASTransport_t *msg,
        ptrace_event_t *base, ptrace_event_t **extra, int *nextra)
{
    int i;
    for (i = 0; i < msg->protocolIEs.list.count; i++) {
        S1AP_UplinkNASTransport_IEs_t *ie = msg->protocolIEs.list.array[i];
        if (!ie)
            continue;
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            base->ids.mme_ue_s1ap_id =
                    (uint32_t)ie->value.choice.MME_UE_S1AP_ID;
            base->ids.has_mme_ue_s1ap_id = true;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            base->ids.enb_ue_s1ap_id =
                    (uint32_t)ie->value.choice.ENB_UE_S1AP_ID;
            base->ids.has_enb_ue_s1ap_id = true;
            break;
        case S1AP_ProtocolIE_ID_id_NAS_PDU:
            extract_nas(&ie->value.choice.NAS_PDU, base, extra, nextra);
            break;
        default:
            break;
        }
    }
}

static void handle_ics_req(S1AP_InitialContextSetupRequest_t *msg,
        ptrace_event_t *base, ptrace_event_t **extra, int *nextra)
{
    int i, j, k;
    for (i = 0; i < msg->protocolIEs.list.count; i++) {
        S1AP_InitialContextSetupRequestIEs_t *ie =
            msg->protocolIEs.list.array[i];
        if (!ie)
            continue;
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            base->ids.mme_ue_s1ap_id =
                    (uint32_t)ie->value.choice.MME_UE_S1AP_ID;
            base->ids.has_mme_ue_s1ap_id = true;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            base->ids.enb_ue_s1ap_id =
                    (uint32_t)ie->value.choice.ENB_UE_S1AP_ID;
            base->ids.has_enb_ue_s1ap_id = true;
            break;
        case S1AP_ProtocolIE_ID_id_E_RABToBeSetupListCtxtSUReq: {
            S1AP_E_RABToBeSetupListCtxtSUReq_t *list =
                &ie->value.choice.E_RABToBeSetupListCtxtSUReq;
            for (j = 0; j < list->list.count; j++) {
                S1AP_E_RABToBeSetupItemCtxtSUReqIEs_t *item =
                    (S1AP_E_RABToBeSetupItemCtxtSUReqIEs_t *)
                        list->list.array[j];
                S1AP_E_RABToBeSetupItemCtxtSUReq_t *erab;
                uint32_t teid;
                if (!item)
                    continue;
                erab = &item->value.choice.E_RABToBeSetupItemCtxtSUReq;
                teid = teid_from_octet(&erab->gTP_TEID);
                add_teid(base, teid); /* SGW S1-U TEID */
                base->ids.bearer_id = (uint8_t)erab->e_RAB_ID;
                base->ids.has_bearer_id = true;
                if (erab->nAS_PDU)
                    extract_nas(erab->nAS_PDU, base, extra, nextra);
            }
            break;
        }
        case S1AP_ProtocolIE_ID_id_Masked_IMEISV: {
            S1AP_Masked_IMEISV_t *m = &ie->value.choice.Masked_IMEISV;
            if (m->buf && m->size >= 4 && !base->ids.imei[0]) {
                /* best-effort hex of masked IMEISV */
                size_t n = m->size < 8 ? m->size : 8;
                for (k = 0; k < (int)n &&
                        2 * k + 2 < (int)sizeof(base->ids.imei); k++)
                    sprintf(base->ids.imei + 2 * k, "%02x", m->buf[k]);
            }
            break;
        }
        default:
            break;
        }
    }
}

static void handle_ics_rsp(S1AP_InitialContextSetupResponse_t *msg,
        ptrace_event_t *base)
{
    int i, j;
    for (i = 0; i < msg->protocolIEs.list.count; i++) {
        S1AP_InitialContextSetupResponseIEs_t *ie =
            msg->protocolIEs.list.array[i];
        if (!ie)
            continue;
        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            base->ids.mme_ue_s1ap_id =
                    (uint32_t)ie->value.choice.MME_UE_S1AP_ID;
            base->ids.has_mme_ue_s1ap_id = true;
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            base->ids.enb_ue_s1ap_id =
                    (uint32_t)ie->value.choice.ENB_UE_S1AP_ID;
            base->ids.has_enb_ue_s1ap_id = true;
            break;
        case S1AP_ProtocolIE_ID_id_E_RABSetupListCtxtSURes: {
            S1AP_E_RABSetupListCtxtSURes_t *list =
                &ie->value.choice.E_RABSetupListCtxtSURes;
            for (j = 0; j < list->list.count; j++) {
                S1AP_E_RABSetupItemCtxtSUResIEs_t *item =
                    (S1AP_E_RABSetupItemCtxtSUResIEs_t *)list->list.array[j];
                S1AP_E_RABSetupItemCtxtSURes_t *erab;
                uint32_t teid;
                if (!item)
                    continue;
                erab = &item->value.choice.E_RABSetupItemCtxtSURes;
                teid = teid_from_octet(&erab->gTP_TEID);
                add_teid(base, teid); /* eNB S1-U TEID */
                base->ids.bearer_id = (uint8_t)erab->e_RAB_ID;
                base->ids.has_bearer_id = true;
            }
            break;
        }
        default:
            break;
        }
    }
}

static void handle_ue_ids_only_init(S1AP_UEContextReleaseRequest_t *msg,
        ptrace_event_t *base)
{
    int i;
    for (i = 0; i < msg->protocolIEs.list.count; i++) {
        S1AP_UEContextReleaseRequest_IEs_t *ie = msg->protocolIEs.list.array[i];
        if (!ie)
            continue;
        if (ie->id == S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID) {
            base->ids.mme_ue_s1ap_id =
                    (uint32_t)ie->value.choice.MME_UE_S1AP_ID;
            base->ids.has_mme_ue_s1ap_id = true;
        } else if (ie->id == S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID) {
            base->ids.enb_ue_s1ap_id =
                    (uint32_t)ie->value.choice.ENB_UE_S1AP_ID;
            base->ids.has_enb_ue_s1ap_id = true;
        }
    }
}

int ptrace_decode_s1ap(const uint8_t *data, int len,
        ptrace_event_t *base, ptrace_event_t **extra, int *nextra)
{
    ogs_s1ap_message_t message;
    ogs_pkbuf_t *pkbuf;
    const char *name;
    int rv;

    if (!data || len < 2 || !base || !extra || !nextra)
        return OGS_ERROR;
    *nextra = 0;

    pkbuf = ogs_pkbuf_alloc(NULL, len);
    if (!pkbuf)
        return OGS_ERROR;
    ogs_pkbuf_put_data(pkbuf, (uint8_t *)data, len);

    memset(&message, 0, sizeof(message));
    ogs_thread_mutex_lock(&s1ap_lock);
    rv = ogs_s1ap_decode(&message, pkbuf);
    ogs_pkbuf_free(pkbuf);
    if (rv != OGS_OK) {
        /* Failed decode may leave partial ASN contents — free safely. */
        ogs_s1ap_free(&message);
        ogs_thread_mutex_unlock(&s1ap_lock);
        return OGS_ERROR;
    }

    base->protocol = PTRACE_PROTO_S1AP;
    name = pdu_proc_name(&message);
    if (message.present == S1AP_S1AP_PDU_PR_initiatingMessage &&
            message.choice.initiatingMessage)
        base->msg_type = message.choice.initiatingMessage->procedureCode;
    else if (message.present == S1AP_S1AP_PDU_PR_successfulOutcome &&
            message.choice.successfulOutcome)
        base->msg_type = message.choice.successfulOutcome->procedureCode;

    if (name)
        ogs_cpystrn(base->message, name, sizeof(base->message));
    else
        snprintf(base->message, sizeof(base->message),
                "S1AP-%u", base->msg_type);

    if (message.present == S1AP_S1AP_PDU_PR_initiatingMessage &&
            message.choice.initiatingMessage) {
        S1AP_InitiatingMessage_t *im = message.choice.initiatingMessage;
        switch (im->value.present) {
        case S1AP_InitiatingMessage__value_PR_InitialUEMessage:
            handle_initial_ue(&im->value.choice.InitialUEMessage,
                    base, extra, nextra);
            break;
        case S1AP_InitiatingMessage__value_PR_DownlinkNASTransport:
            handle_dl_nas(&im->value.choice.DownlinkNASTransport,
                    base, extra, nextra);
            break;
        case S1AP_InitiatingMessage__value_PR_UplinkNASTransport:
            handle_ul_nas(&im->value.choice.UplinkNASTransport,
                    base, extra, nextra);
            break;
        case S1AP_InitiatingMessage__value_PR_InitialContextSetupRequest:
            handle_ics_req(&im->value.choice.InitialContextSetupRequest,
                    base, extra, nextra);
            break;
        case S1AP_InitiatingMessage__value_PR_UEContextReleaseRequest:
            handle_ue_ids_only_init(
                    &im->value.choice.UEContextReleaseRequest, base);
            break;
        default:
            break;
        }
    } else if (message.present == S1AP_S1AP_PDU_PR_successfulOutcome &&
            message.choice.successfulOutcome) {
        S1AP_SuccessfulOutcome_t *so = message.choice.successfulOutcome;
        if (so->value.present ==
                S1AP_SuccessfulOutcome__value_PR_InitialContextSetupResponse) {
            handle_ics_rsp(&so->value.choice.InitialContextSetupResponse,
                    base);
        }
    }

    snprintf(base->fields, sizeof(base->fields),
            "enb_ue=%u mme_ue=%u teid=%u nteid=%d tac=%u cell=%u "
            "imsi=%s msisdn=%s imei=%s guti=%s",
            base->ids.has_enb_ue_s1ap_id ? base->ids.enb_ue_s1ap_id : 0,
            base->ids.has_mme_ue_s1ap_id ? base->ids.mme_ue_s1ap_id : 0,
            base->ids.has_teid ? base->ids.teid : 0,
            base->ids.num_teids,
            base->ids.has_tac ? base->ids.tac : 0,
            base->ids.has_cell_id ? base->ids.cell_id : 0,
            base->ids.imsi, base->ids.msisdn, base->ids.imei, base->ids.guti);

    ogs_s1ap_free(&message);
    ogs_thread_mutex_unlock(&s1ap_lock);
    return OGS_OK;
}
