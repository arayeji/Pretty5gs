/*
 * Copyright (C) 2019-2026 by Sukchan Lee <acetcom@gmail.com>
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
 * SMP load test: exercises the MME with REAL sharding enabled
 * (load.yaml: workers=4, stage_c=1, s1ap_rx_workers=2, s1ap_tx_workers=2,
 *  s1ap_tx_direct=1, s1ap_io_thread=2, pkbuf_thread_pool=256).
 *
 * Scenarios:
 *   1. S1-Setup churn         - eNB add/remove against the IO threads'
 *                               socket close registry
 *   2. Mass attach/detach     - 4 eNBs in parallel threads, sequential UEs
 *                               per eNB; attach flows land on different UE
 *                               shards (Stage C uplink-NAS/ICSR routing)
 *   3. Idle / SR / TAU        - 4 eNBs in parallel threads; release-to-idle,
 *                               service request, TAU w/ active flag
 *   4. Paging                 - DL data while idle -> S1 Paging -> service
 *                               request -> DL data delivered
 *   5. Cross-eNB idle TAU     - attach on eNB A, idle, TAU on eNB B; the new
 *                               enb_ue lands on a different shard than the
 *                               mme_ue owner (rehome path)
 *
 * Threads never touch ABTS; failures are recorded per worker and asserted
 * on the main thread after join.
 */

#include "test-common.h"

/* Production-ish synthetic load (MCC 999/MNC 70, IMSI 9997037461xxxxx).
 * Scale hits all Stage-C knobs: workers / stage_c / rx / tx / tx_direct / io. */
#define LOAD_NUM_ENB        4
#define LOAD_UES_PER_ENB    12
#define LOAD_LIFECYCLE_UES  4

typedef struct load_result_s {
    bool failed;
    char msg[512];
} load_result_t;

typedef struct load_ue_s {
    test_ue_t *ue;
    test_sess_t *sess;
} load_ue_t;

typedef struct load_worker_s {
    int idx;
    ogs_socknode_t *s1ap;
    load_ue_t ues[LOAD_UES_PER_ENB];
    int nues;
    load_result_t result;
} load_worker_t;

static int load_ue_seq = 0;

/* progress marker on stderr so a hung run shows where it stopped */
#define LOAD_MARK(fmt, ...) \
    fprintf(stderr, "\nLOAD-TEST: " fmt "\n", ##__VA_ARGS__)

static void load_fail(load_result_t *r, const char *fmt, ...)
{
    va_list ap;

    if (r->failed) return; /* keep the first failure */
    r->failed = true;
    va_start(ap, fmt);
    vsnprintf(r->msg, sizeof(r->msg), fmt, ap);
    va_end(ap);
}

static bool load_send(load_result_t *r,
        ogs_socknode_t *s1ap, ogs_pkbuf_t *sendbuf, const char *what)
{
    if (!sendbuf) {
        load_fail(r, "%s: build failed", what);
        return false;
    }
    if (testenb_s1ap_send(s1ap, sendbuf) != OGS_OK) {
        load_fail(r, "%s: send failed", what);
        return false;
    }
    return true;
}

static bool load_recv(load_result_t *r,
        ogs_socknode_t *s1ap, test_ue_t *ue, const char *what)
{
    ogs_pkbuf_t *recvbuf = testenb_s1ap_read(s1ap);
    if (!recvbuf) {
        load_fail(r, "%s: read failed", what);
        return false;
    }
    tests1ap_recv(ue, recvbuf);
    return true;
}

/* Create a test UE + default "internet" session. MAIN THREAD ONLY:
 * test_ue_add_by_suci() mutates the global test context. */
static bool load_ue_setup(load_ue_t *lu, uint32_t cell_id, uint32_t enb_ue_base)
{
    ogs_nas_5gs_mobile_identity_suci_t mobile_identity_suci;
    char scheme_output[16];
    test_ue_t *ue = NULL;

    memset(&mobile_identity_suci, 0, sizeof(mobile_identity_suci));
    mobile_identity_suci.h.supi_format = OGS_NAS_5GS_SUPI_FORMAT_IMSI;
    mobile_identity_suci.h.type = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;
    mobile_identity_suci.routing_indicator1 = 0;
    mobile_identity_suci.routing_indicator2 = 0xf;
    mobile_identity_suci.routing_indicator3 = 0xf;
    mobile_identity_suci.routing_indicator4 = 0xf;
    mobile_identity_suci.protection_scheme_id = OGS_PROTECTION_SCHEME_NULL;
    mobile_identity_suci.home_network_pki_value = 0;

    /* "37461xxxxx" keeps clear of the "3746000006"-style IMSIs used by the
     * other EPC suites */
    ogs_snprintf(scheme_output, sizeof(scheme_output),
            "37461%05d", load_ue_seq++);

    ue = test_ue_add_by_suci(&mobile_identity_suci, scheme_output);
    if (!ue) return false;

    ue->e_cgi.cell_id = cell_id;
    ue->nas.ksi = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    ue->nas.value = OGS_NAS_ATTACH_TYPE_EPS_ATTACH;

    ue->k_string = "465b5ce8b199b49faa5f0a2ee238a6bc";
    ue->opc_string = "e8ed289deba952e4283b54e88e6183ca";

    /* the InitialUEMessage builder pre-increments, so each UE gets a
     * disjoint ENB_UE_S1AP_ID range on its eNB */
    ue->enb_ue_s1ap_id = enb_ue_base;

    lu->ue = ue;
    lu->sess = test_sess_add_by_apn(ue, "internet", OGS_GTP2_RAT_TYPE_EUTRAN);
    if (!lu->sess) return false;

    return true;
}

static void load_ue_teardown(load_ue_t *lu)
{
    if (lu->ue) {
        test_db_remove_ue(lu->ue);
        test_ue_remove(lu->ue);
        lu->ue = NULL;
        lu->sess = NULL;
    }
}

static bool load_s1_setup(load_result_t *r,
        ogs_socknode_t *s1ap, uint32_t enb_id)
{
    ogs_pkbuf_t *sendbuf = test_s1ap_build_s1_setup_request(
            S1AP_ENB_ID_PR_macroENB_ID, enb_id);
    if (!load_send(r, s1ap, sendbuf, "S1SetupRequest"))
        return false;
    return load_recv(r, s1ap, NULL, "S1SetupResponse");
}

/* Full initial attach: Attach Request .. EMM Information.
 * UE ends up EMM-REGISTERED and ECM-CONNECTED. */
static bool load_attach(load_result_t *r, ogs_socknode_t *s1ap, load_ue_t *lu)
{
    test_ue_t *ue = lu->ue;
    test_sess_t *sess = lu->sess;
    test_bearer_t *bearer = NULL;
    ogs_pkbuf_t *emmbuf, *esmbuf, *sendbuf;

    /* Send Attach Request */
    memset(&sess->pdn_connectivity_param,
            0, sizeof(sess->pdn_connectivity_param));
    sess->pdn_connectivity_param.eit = 1;
    sess->pdn_connectivity_param.request_type =
        OGS_NAS_EPS_REQUEST_TYPE_INITIAL;
    esmbuf = testesm_build_pdn_connectivity_request(
            sess, false, OGS_NAS_EPS_PDN_TYPE_IPV4V6);
    if (!esmbuf) { load_fail(r, "pdn_connectivity_request build"); return false; }

    memset(&ue->attach_request_param, 0, sizeof(ue->attach_request_param));
    ue->attach_request_param.drx_parameter = 1;
    ue->attach_request_param.ms_network_capability = 1;
    ue->attach_request_param.tmsi_status = 1;
    ue->attach_request_param.mobile_station_classmark_2 = 1;
    ue->attach_request_param.ue_usage_setting = 1;
    emmbuf = testemm_build_attach_request(ue, esmbuf, true, false);
    if (!emmbuf) { load_fail(r, "attach_request build"); return false; }

    memset(&ue->initial_ue_param, 0, sizeof(ue->initial_ue_param));
    sendbuf = test_s1ap_build_initial_ue_message(
            ue, emmbuf, S1AP_RRC_Establishment_Cause_mo_Signalling, false);
    if (!load_send(r, s1ap, sendbuf, "InitialUEMessage(Attach)")) return false;

    /* Receive Authentication Request */
    if (!load_recv(r, s1ap, ue, "AuthenticationRequest")) return false;

    /* Send Authentication Response */
    emmbuf = testemm_build_authentication_response(ue);
    sendbuf = emmbuf ? test_s1ap_build_uplink_nas_transport(ue, emmbuf) : NULL;
    if (!load_send(r, s1ap, sendbuf, "AuthenticationResponse")) return false;

    /* Receive Security mode Command */
    if (!load_recv(r, s1ap, ue, "SecurityModeCommand")) return false;

    /* Send Security mode Complete */
    ue->mobile_identity_imeisv_presence = true;
    emmbuf = testemm_build_security_mode_complete(ue);
    sendbuf = emmbuf ? test_s1ap_build_uplink_nas_transport(ue, emmbuf) : NULL;
    if (!load_send(r, s1ap, sendbuf, "SecurityModeComplete")) return false;

    /* Receive ESM Information Request */
    if (!load_recv(r, s1ap, ue, "ESMInformationRequest")) return false;

    /* Send ESM Information Response */
    sess->esm_information_param.epco = 1;
    esmbuf = testesm_build_esm_information_response(sess);
    sendbuf = esmbuf ? test_s1ap_build_uplink_nas_transport(ue, esmbuf) : NULL;
    if (!load_send(r, s1ap, sendbuf, "ESMInformationResponse")) return false;

    /* Receive InitialContextSetupRequest + Attach Accept */
    if (!load_recv(r, s1ap, ue, "InitialContextSetupRequest")) return false;

    /* Send UE Capability Info Indication */
    sendbuf = tests1ap_build_ue_radio_capability_info_indication(ue);
    if (!load_send(r, s1ap, sendbuf, "UECapabilityInfoIndication"))
        return false;

    /* Send InitialContextSetupResponse */
    sendbuf = test_s1ap_build_initial_context_setup_response(ue);
    if (!load_send(r, s1ap, sendbuf, "InitialContextSetupResponse"))
        return false;

    /* Send Attach Complete + Activate default EPS bearer context accept */
    bearer = test_bearer_find_by_ue_ebi(ue, 5);
    if (!bearer) { load_fail(r, "no default bearer (EBI 5)"); return false; }
    esmbuf = testesm_build_activate_default_eps_bearer_context_accept(
            bearer, false);
    emmbuf = esmbuf ? testemm_build_attach_complete(ue, esmbuf) : NULL;
    sendbuf = emmbuf ? test_s1ap_build_uplink_nas_transport(ue, emmbuf) : NULL;
    if (!load_send(r, s1ap, sendbuf, "AttachComplete")) return false;

    /* Receive EMM Information */
    if (!load_recv(r, s1ap, ue, "EMMInformation")) return false;

    return true;
}

/* Switch-off detach via InitialUEMessage (S-TMSI): OLD UEContextRelease
 * dance, then release of the new context — same as attach/simple-test. */
static bool load_detach(load_result_t *r, ogs_socknode_t *s1ap, load_ue_t *lu)
{
    test_ue_t *ue = lu->ue;
    ogs_pkbuf_t *emmbuf, *sendbuf;
    uint32_t enb_ue_s1ap_id;

    /* Send Detach Request */
    emmbuf = testemm_build_detach_request(ue, 1, true, false);
    sendbuf = emmbuf ? test_s1ap_build_initial_ue_message(
            ue, emmbuf, S1AP_RRC_Establishment_Cause_mo_Signalling, true) :
            NULL;
    if (!load_send(r, s1ap, sendbuf, "InitialUEMessage(Detach)")) return false;

    /* Receive OLD UEContextReleaseCommand */
    enb_ue_s1ap_id = ue->enb_ue_s1ap_id;
    if (!load_recv(r, s1ap, ue, "OLD UEContextReleaseCommand")) return false;

    /* Send OLD UEContextReleaseComplete */
    sendbuf = test_s1ap_build_ue_context_release_complete(ue);
    if (!load_send(r, s1ap, sendbuf, "OLD UEContextReleaseComplete"))
        return false;

    ue->enb_ue_s1ap_id = enb_ue_s1ap_id;

    /* Receive UEContextReleaseCommand */
    if (!load_recv(r, s1ap, ue, "UEContextReleaseCommand")) return false;

    /* Send UEContextReleaseComplete */
    sendbuf = test_s1ap_build_ue_context_release_complete(ue);
    if (!load_send(r, s1ap, sendbuf, "UEContextReleaseComplete"))
        return false;

    return true;
}

/* eNB-initiated release: UE goes ECM-IDLE, EMM-REGISTERED. */
static bool load_release_to_idle(load_result_t *r,
        ogs_socknode_t *s1ap, load_ue_t *lu)
{
    test_ue_t *ue = lu->ue;
    ogs_pkbuf_t *sendbuf;

    sendbuf = test_s1ap_build_ue_context_release_request(ue,
            S1AP_Cause_PR_radioNetwork, S1AP_CauseRadioNetwork_user_inactivity);
    if (!load_send(r, s1ap, sendbuf, "UEContextReleaseRequest")) return false;

    if (!load_recv(r, s1ap, ue, "UEContextReleaseCommand(idle)")) return false;

    sendbuf = test_s1ap_build_ue_context_release_complete(ue);
    if (!load_send(r, s1ap, sendbuf, "UEContextReleaseComplete(idle)"))
        return false;

    return true;
}

/* Service Request from idle: back to ECM-CONNECTED. */
static bool load_service_request(load_result_t *r,
        ogs_socknode_t *s1ap, load_ue_t *lu)
{
    test_ue_t *ue = lu->ue;
    ogs_pkbuf_t *emmbuf, *sendbuf;

    emmbuf = testemm_build_service_request(ue);
    sendbuf = emmbuf ? test_s1ap_build_initial_ue_message(
            ue, emmbuf, S1AP_RRC_Establishment_Cause_mo_Data, true) : NULL;
    if (!load_send(r, s1ap, sendbuf, "InitialUEMessage(ServiceRequest)"))
        return false;

    /* Receive InitialContextSetupRequest */
    if (!load_recv(r, s1ap, ue, "InitialContextSetupRequest(SR)"))
        return false;

    /* Send InitialContextSetupResponse */
    sendbuf = test_s1ap_build_initial_context_setup_response(ue);
    if (!load_send(r, s1ap, sendbuf, "InitialContextSetupResponse(SR)"))
        return false;

    return true;
}

static void load_tau_request_param_set(test_ue_t *ue)
{
    memset(&ue->tau_request_param, 0, sizeof(ue->tau_request_param));
    ue->tau_request_param.ue_network_capability = 1;
    ue->tau_request_param.last_visited_registered_tai = 1;
    ue->tau_request_param.drx_parameter = 1;
    ue->tau_request_param.eps_bearer_context_status = 0x20; /* EBI:5 */
    ue->tau_request_param.ms_network_capability = 1;
    ue->tau_request_param.tmsi_status = 1;
    ue->tau_request_param.mobile_station_classmark_2 = 1;
    ue->tau_request_param.ue_usage_setting = 1;
    ue->tau_request_param.device_properties = 1;
}

/* TAU with active flag while ECM-CONNECTED: new RRC connection, so the MME
 * releases the OLD context first, then delivers TAU Accept inside a new
 * InitialContextSetupRequest. */
static bool load_tau_connected_active(load_result_t *r,
        ogs_socknode_t *s1ap, load_ue_t *lu)
{
    test_ue_t *ue = lu->ue;
    ogs_pkbuf_t *emmbuf, *sendbuf;
    uint32_t enb_ue_s1ap_id;

    load_tau_request_param_set(ue);
    emmbuf = testemm_build_tau_request(
            ue, true, OGS_NAS_EPS_UPDATE_TYPE_TA_UPDATING, true, true);
    sendbuf = emmbuf ? test_s1ap_build_initial_ue_message(
            ue, emmbuf, S1AP_RRC_Establishment_Cause_mo_Signalling, true) :
            NULL;
    if (!load_send(r, s1ap, sendbuf, "InitialUEMessage(TAU-active)"))
        return false;

    /* Receive OLD UEContextReleaseCommand */
    enb_ue_s1ap_id = ue->enb_ue_s1ap_id;
    if (!load_recv(r, s1ap, ue, "OLD UEContextReleaseCommand(TAU)"))
        return false;

    /* Send OLD UEContextReleaseComplete */
    sendbuf = test_s1ap_build_ue_context_release_complete(ue);
    if (!load_send(r, s1ap, sendbuf, "OLD UEContextReleaseComplete(TAU)"))
        return false;

    ue->enb_ue_s1ap_id = enb_ue_s1ap_id;

    /* Receive TAU Accept (inside InitialContextSetupRequest) */
    if (!load_recv(r, s1ap, ue, "TAUAccept")) return false;

    /* Send InitialContextSetupResponse */
    sendbuf = test_s1ap_build_initial_context_setup_response(ue);
    if (!load_send(r, s1ap, sendbuf, "InitialContextSetupResponse(TAU)"))
        return false;

    return true;
}

/* TAU without active flag from ECM-IDLE (possibly on a different eNB):
 * TAU Accept via DownlinkNASTransport, then UEContextReleaseCommand. */
static bool load_tau_idle(load_result_t *r,
        ogs_socknode_t *s1ap, load_ue_t *lu)
{
    test_ue_t *ue = lu->ue;
    ogs_pkbuf_t *emmbuf, *sendbuf;

    load_tau_request_param_set(ue);
    emmbuf = testemm_build_tau_request(
            ue, false, OGS_NAS_EPS_UPDATE_TYPE_TA_UPDATING, true, true);
    sendbuf = emmbuf ? test_s1ap_build_initial_ue_message(
            ue, emmbuf, S1AP_RRC_Establishment_Cause_mo_Signalling, true) :
            NULL;
    if (!load_send(r, s1ap, sendbuf, "InitialUEMessage(TAU-idle)"))
        return false;

    /* Receive TAU Accept */
    if (!load_recv(r, s1ap, ue, "TAUAccept(idle)")) return false;

    /* Receive UEContextReleaseCommand */
    if (!load_recv(r, s1ap, ue, "UEContextReleaseCommand(TAU-idle)"))
        return false;

    /* Send UEContextReleaseComplete */
    sendbuf = test_s1ap_build_ue_context_release_complete(ue);
    if (!load_send(r, s1ap, sendbuf, "UEContextReleaseComplete(TAU-idle)"))
        return false;

    return true;
}

/* ------------------------------------------------------------------ */
/* Scenario 1: S1-Setup churn                                          */
/* ------------------------------------------------------------------ */
static void test_load_s1setup_churn(abts_case *tc, void *data)
{
    int i, rv;
    ogs_socknode_t *s1ap[8];
    ogs_pkbuf_t *sendbuf, *recvbuf;

    LOAD_MARK("s1setup_churn start");

    /* connect 8 eNBs */
    for (i = 0; i < 8; i++) {
        s1ap[i] = tests1ap_client(AF_INET);
        ABTS_PTR_NOTNULL(tc, s1ap[i]);

        sendbuf = test_s1ap_build_s1_setup_request(
                S1AP_ENB_ID_PR_macroENB_ID, 0x740 + i);
        ABTS_PTR_NOTNULL(tc, sendbuf);
        rv = testenb_s1ap_send(s1ap[i], sendbuf);
        ABTS_INT_EQUAL(tc, OGS_OK, rv);

        recvbuf = testenb_s1ap_read(s1ap[i]);
        ABTS_PTR_NOTNULL(tc, recvbuf);
        tests1ap_recv(NULL, recvbuf);
    }

    /* drop them all; the IO threads must retire the sockets cleanly */
    for (i = 0; i < 8; i++)
        testenb_s1ap_close(s1ap[i]);

    ogs_msleep(100);

    /* and one more full round to prove the MME is still healthy */
    s1ap[0] = tests1ap_client(AF_INET);
    ABTS_PTR_NOTNULL(tc, s1ap[0]);

    sendbuf = test_s1ap_build_s1_setup_request(
            S1AP_ENB_ID_PR_macroENB_ID, 0x74f);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testenb_s1ap_send(s1ap[0], sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testenb_s1ap_read(s1ap[0]);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    tests1ap_recv(NULL, recvbuf);

    testenb_s1ap_close(s1ap[0]);
    ogs_msleep(100);
}

/* ------------------------------------------------------------------ */
/* Scenario 2: mass attach/detach, 4 eNBs in parallel                  */
/* ------------------------------------------------------------------ */
static void load_attach_detach_worker(void *data)
{
    load_worker_t *w = data;
    int i;

    for (i = 0; i < w->nues; i++) {
        load_ue_t *lu = &w->ues[i];

        if (!load_attach(&w->result, w->s1ap, lu)) return;
        if (!load_detach(&w->result, w->s1ap, lu)) return;

        LOAD_MARK("attach/detach eNB[%d] UE[%d] done", w->idx, i);
    }
}

static void test_load_mass_attach_detach(abts_case *tc, void *data)
{
    int e, i;
    load_worker_t w[LOAD_NUM_ENB];
    ogs_thread_t *thread[LOAD_NUM_ENB];
    bson_t *doc = NULL;

    LOAD_MARK("mass_attach_detach start");

    memset(w, 0, sizeof(w));

    for (e = 0; e < LOAD_NUM_ENB; e++) {
        w[e].idx = e;
        w[e].nues = LOAD_UES_PER_ENB;

        w[e].s1ap = tests1ap_client(AF_INET);
        ABTS_PTR_NOTNULL(tc, w[e].s1ap);
        ABTS_TRUE(tc, load_s1_setup(&w[e].result, w[e].s1ap, 0x700 + e));

        for (i = 0; i < w[e].nues; i++) {
            ABTS_TRUE(tc, load_ue_setup(&w[e].ues[i],
                    ((0x700 + e) << 8) | (i + 1), (i + 1) * 100));

            doc = test_db_new_simple(w[e].ues[i].ue);
            ABTS_PTR_NOTNULL(tc, doc);
            ABTS_INT_EQUAL(tc, OGS_OK,
                    test_db_insert_ue(w[e].ues[i].ue, doc));
        }
    }

    for (e = 0; e < LOAD_NUM_ENB; e++) {
        thread[e] = ogs_thread_create(load_attach_detach_worker, &w[e]);
        ABTS_PTR_NOTNULL(tc, thread[e]);
    }

    for (e = 0; e < LOAD_NUM_ENB; e++) {
        ogs_thread_destroy(thread[e]); /* join */

        if (w[e].result.failed)
            ogs_error("load: eNB[%d] worker failed: %s",
                    e, w[e].result.msg);
        ABTS_TRUE(tc, !w[e].result.failed);
    }

    ogs_msleep(300);

    for (e = 0; e < LOAD_NUM_ENB; e++) {
        for (i = 0; i < w[e].nues; i++)
            load_ue_teardown(&w[e].ues[i]);
        testenb_s1ap_close(w[e].s1ap);
    }

    ogs_msleep(100);
}

/* ------------------------------------------------------------------ */
/* Scenario 3: idle / service request / TAU, 4 eNBs in parallel        */
/* ------------------------------------------------------------------ */
static void load_lifecycle_worker(void *data)
{
    load_worker_t *w = data;
    int i;

    for (i = 0; i < w->nues; i++) {
        load_ue_t *lu = &w->ues[i];

        if (!load_attach(&w->result, w->s1ap, lu)) return;
        if (!load_release_to_idle(&w->result, w->s1ap, lu)) return;
        if (!load_service_request(&w->result, w->s1ap, lu)) return;
        if (!load_tau_connected_active(&w->result, w->s1ap, lu)) return;
        if (!load_release_to_idle(&w->result, w->s1ap, lu)) return;

        LOAD_MARK("lifecycle eNB[%d] UE[%d] done", w->idx, i);
    }
}

static void test_load_idle_service_tau(abts_case *tc, void *data)
{
    int e, i;
    load_worker_t w[LOAD_NUM_ENB];
    ogs_thread_t *thread[LOAD_NUM_ENB];
    bson_t *doc = NULL;

    LOAD_MARK("idle_service_tau start");

    memset(w, 0, sizeof(w));

    for (e = 0; e < LOAD_NUM_ENB; e++) {
        w[e].idx = e;
        w[e].nues = LOAD_LIFECYCLE_UES;

        w[e].s1ap = tests1ap_client(AF_INET);
        ABTS_PTR_NOTNULL(tc, w[e].s1ap);
        ABTS_TRUE(tc, load_s1_setup(&w[e].result, w[e].s1ap, 0x710 + e));

        for (i = 0; i < w[e].nues; i++) {
            ABTS_TRUE(tc, load_ue_setup(&w[e].ues[i],
                    ((0x710 + e) << 8) | (i + 1), (i + 1) * 100));

            doc = test_db_new_simple(w[e].ues[i].ue);
            ABTS_PTR_NOTNULL(tc, doc);
            ABTS_INT_EQUAL(tc, OGS_OK,
                    test_db_insert_ue(w[e].ues[i].ue, doc));
        }
    }

    for (e = 0; e < LOAD_NUM_ENB; e++) {
        thread[e] = ogs_thread_create(load_lifecycle_worker, &w[e]);
        ABTS_PTR_NOTNULL(tc, thread[e]);
    }

    for (e = 0; e < LOAD_NUM_ENB; e++) {
        ogs_thread_destroy(thread[e]); /* join */

        if (w[e].result.failed)
            ogs_error("load: eNB[%d] worker failed: %s",
                    e, w[e].result.msg);
        ABTS_TRUE(tc, !w[e].result.failed);
    }

    ogs_msleep(300);

    for (e = 0; e < LOAD_NUM_ENB; e++) {
        for (i = 0; i < w[e].nues; i++)
            load_ue_teardown(&w[e].ues[i]);
        testenb_s1ap_close(w[e].s1ap);
    }

    ogs_msleep(100);
}

/* ------------------------------------------------------------------ */
/* Scenario 4: paging (DL data while idle)                             */
/* ------------------------------------------------------------------ */
static void test_load_paging(abts_case *tc, void *data)
{
    int i, rv;
    ogs_socknode_t *s1ap, *gtpu;
    load_ue_t ues[3];
    load_result_t result;
    ogs_pkbuf_t *recvbuf;
    bson_t *doc = NULL;

    LOAD_MARK("paging start");

    memset(ues, 0, sizeof(ues));
    memset(&result, 0, sizeof(result));

    s1ap = tests1ap_client(AF_INET);
    ABTS_PTR_NOTNULL(tc, s1ap);
    gtpu = test_gtpu_server(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu);

    ABTS_TRUE(tc, load_s1_setup(&result, s1ap, 0x720));

    for (i = 0; i < 3; i++) {
        ABTS_TRUE(tc, load_ue_setup(&ues[i],
                (0x720 << 8) | (i + 1), (i + 1) * 100));

        doc = test_db_new_simple(ues[i].ue);
        ABTS_PTR_NOTNULL(tc, doc);
        ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(ues[i].ue, doc));
    }

    for (i = 0; i < 3; i++) {
        load_ue_t *lu = &ues[i];
        test_bearer_t *bearer = NULL;

        ABTS_TRUE(tc, load_attach(&result, s1ap, lu));
        ABTS_TRUE(tc, load_release_to_idle(&result, s1ap, lu));

        bearer = test_bearer_find_by_ue_ebi(lu->ue, 5);
        ABTS_PTR_NOTNULL(tc, bearer);

        /* DL data while idle -> S1 Paging */
        rv = test_gtpu_send_ping(gtpu, bearer, TEST_PING_IPV4);
        ABTS_INT_EQUAL(tc, OGS_OK, rv);

        /* Receive S1 Paging */
        ABTS_TRUE(tc, load_recv(&result, s1ap, lu->ue, "S1Paging"));

        /* Answer with Service Request */
        ABTS_TRUE(tc, load_service_request(&result, s1ap, lu));

        /* the buffered DL packet must now arrive on GTP-U */
        recvbuf = test_gtpu_read(gtpu);
        ABTS_PTR_NOTNULL(tc, recvbuf);
        if (recvbuf) ogs_pkbuf_free(recvbuf);

        ABTS_TRUE(tc, load_release_to_idle(&result, s1ap, lu));

        LOAD_MARK("paging UE[%d] done", i);
    }

    if (result.failed)
        ogs_error("load: paging scenario failed: %s", result.msg);
    ABTS_TRUE(tc, !result.failed);

    ogs_msleep(300);

    for (i = 0; i < 3; i++)
        load_ue_teardown(&ues[i]);

    testenb_s1ap_close(s1ap);
    test_gtpu_close(gtpu);

    ogs_msleep(100);
}

/* ------------------------------------------------------------------ */
/* Scenario 5: cross-eNB idle TAU (shard rehome)                       */
/* ------------------------------------------------------------------ */
static void test_load_cross_enb_tau(abts_case *tc, void *data)
{
    int i;
    ogs_socknode_t *s1ap_a, *s1ap_b;
    load_ue_t ues[2];
    load_result_t result;
    bson_t *doc = NULL;

    LOAD_MARK("cross_enb_tau start");

    memset(ues, 0, sizeof(ues));
    memset(&result, 0, sizeof(result));

    s1ap_a = tests1ap_client(AF_INET);
    ABTS_PTR_NOTNULL(tc, s1ap_a);
    s1ap_b = tests1ap_client(AF_INET);
    ABTS_PTR_NOTNULL(tc, s1ap_b);

    ABTS_TRUE(tc, load_s1_setup(&result, s1ap_a, 0x730));
    ABTS_TRUE(tc, load_s1_setup(&result, s1ap_b, 0x731));

    for (i = 0; i < 2; i++) {
        ABTS_TRUE(tc, load_ue_setup(&ues[i],
                (0x730 << 8) | (i + 1), (i + 1) * 100));

        doc = test_db_new_simple(ues[i].ue);
        ABTS_PTR_NOTNULL(tc, doc);
        ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(ues[i].ue, doc));
    }

    for (i = 0; i < 2; i++) {
        load_ue_t *lu = &ues[i];

        /* attach + idle on eNB A */
        ABTS_TRUE(tc, load_attach(&result, s1ap_a, lu));
        ABTS_TRUE(tc, load_release_to_idle(&result, s1ap_a, lu));

        /* UE moves: TAU from idle arrives via eNB B. The new enb_ue is
         * allocated fresh, so with mme.workers=4 the mme_ue owner shard
         * (from the original attach) usually differs -> rehome path. */
        lu->ue->e_cgi.cell_id = (0x731 << 8) | (i + 1);
        ABTS_TRUE(tc, load_tau_idle(&result, s1ap_b, lu));

        LOAD_MARK("cross-eNB TAU UE[%d] done", i);
    }

    if (result.failed)
        ogs_error("load: cross-eNB TAU scenario failed: %s", result.msg);
    ABTS_TRUE(tc, !result.failed);

    ogs_msleep(300);

    for (i = 0; i < 2; i++)
        load_ue_teardown(&ues[i]);

    testenb_s1ap_close(s1ap_a);
    testenb_s1ap_close(s1ap_b);

    ogs_msleep(100);
}

abts_suite *test_load(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    LOAD_MARK("knobs: workers=4 stage_c=1 rx=2 tx=2 tx_direct=1 io=2 "
            "pkbuf_thread_pool=256; synthetic PLMN 999/70");
    LOAD_MARK("flows: s1setup_churn | mass_attach_detach(%d eNB x %d UE) | "
            "idle_SR_TAU(%d eNB x %d UE) | paging | cross_enb_tau",
            LOAD_NUM_ENB, LOAD_UES_PER_ENB,
            LOAD_NUM_ENB, LOAD_LIFECYCLE_UES);

    abts_run_test(suite, test_load_s1setup_churn, NULL);
    abts_run_test(suite, test_load_mass_attach_detach, NULL);
    abts_run_test(suite, test_load_idle_service_tau, NULL);
    abts_run_test(suite, test_load_paging, NULL);
    abts_run_test(suite, test_load_cross_enb_tau, NULL);

    LOAD_MARK("all scenarios finished (see ABTS summary)");
    return suite;
}
