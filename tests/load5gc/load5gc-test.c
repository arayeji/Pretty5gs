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
 * AMF SMP load test: exercises the AMF with the NGAP transport offload
 * and the UE shards enabled (load5gc.yaml: workers=2, ngap_rx_workers=2,
 * ngap_io_thread=2, pkbuf_thread_pool=256). The parallel gNBs spread
 * their UEs over the shards, so main routes every UE message.
 *
 * Scenarios:
 *   1. NG-Setup churn         - gNB add/remove against the RX workers and
 *                               the IO threads' socket close registry
 *   2. Mass registration      - 4 gNBs in parallel threads, sequential UEs
 *                               per gNB: registration, PDU session,
 *                               release to idle, de-registration
 *   3. Idle / Service Request - 4 gNBs in parallel threads: release to
 *                               idle, service request, release again
 *
 * Threads never touch ABTS; failures are recorded per worker and asserted
 * on the main thread after join.
 */

#include "test-common.h"

#define LOAD_NUM_GNB        4
#define LOAD_UES_PER_GNB    12
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
    ogs_socknode_t *ngap;
    load_ue_t ues[LOAD_UES_PER_GNB];
    int nues;
    load_result_t result;
} load_worker_t;

static int load_ue_seq = 0;

/* progress marker on stderr so a hung run shows where it stopped */
#define LOAD_MARK(fmt, ...) \
    fprintf(stderr, "\nLOAD5GC-TEST: " fmt "\n", ##__VA_ARGS__)

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
        ogs_socknode_t *ngap, ogs_pkbuf_t *sendbuf, const char *what)
{
    if (!sendbuf) {
        load_fail(r, "%s: build failed", what);
        return false;
    }
    if (testgnb_ngap_send(ngap, sendbuf) != OGS_OK) {
        load_fail(r, "%s: send failed", what);
        return false;
    }
    return true;
}

/* expected < 0: any procedure code is accepted */
static bool load_recv(load_result_t *r,
        ogs_socknode_t *ngap, test_ue_t *ue, int expected, const char *what)
{
    ogs_pkbuf_t *recvbuf = testgnb_ngap_read(ngap);
    if (!recvbuf) {
        load_fail(r, "%s: read failed", what);
        return false;
    }
    if (!ue) {
        ogs_pkbuf_free(recvbuf);
        return true;
    }
    testngap_recv(ue, recvbuf);
    if (expected >= 0 && ue->ngap_procedure_code != expected) {
        load_fail(r, "%s: expected procedure %d, got %d",
                what, expected, (int)ue->ngap_procedure_code);
        return false;
    }
    return true;
}

/* Create a test UE + "internet" session. MAIN THREAD ONLY:
 * test_ue_add_by_suci() mutates the global test context. */
static bool load_ue_setup(load_ue_t *lu, uint32_t ran_ue_ngap_id_base)
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

    /* "0000746xxx" keeps clear of the IMSIs used by the other 5GC suites */
    ogs_snprintf(scheme_output, sizeof(scheme_output),
            "0000746%03d", load_ue_seq++);

    ue = test_ue_add_by_suci(&mobile_identity_suci, scheme_output);
    if (!ue) return false;

    ue->nr_cgi.cell_id = 0x40001;

    ue->nas.registration.tsc = 0;
    ue->nas.registration.ksi = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    ue->nas.registration.follow_on_request = 1;
    ue->nas.registration.value = OGS_NAS_5GS_REGISTRATION_TYPE_INITIAL;

    ue->k_string = "465b5ce8b199b49faa5f0a2ee238a6bc";
    ue->opc_string = "e8ed289deba952e4283b54e88e6183ca";

    /* the InitialUEMessage builder pre-increments, so each UE gets a
     * disjoint RAN_UE_NGAP_ID range on its gNB */
    ue->ran_ue_ngap_id = ran_ue_ngap_id_base;

    lu->ue = ue;
    lu->sess = test_sess_add_by_dnn_and_psi(ue, "internet", 5);
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

static bool load_ng_setup(load_result_t *r,
        ogs_socknode_t *ngap, uint32_t gnb_id)
{
    ogs_pkbuf_t *sendbuf = testngap_build_ng_setup_request(gnb_id, 22);
    if (!load_send(r, ngap, sendbuf, "NGSetupRequest"))
        return false;
    return load_recv(r, ngap, NULL, -1, "NGSetupResponse");
}

/* Initial registration: Registration Request .. Configuration Update.
 * UE ends up RM-REGISTERED and CM-CONNECTED. */
static bool load_register(load_result_t *r,
        ogs_socknode_t *ngap, load_ue_t *lu)
{
    test_ue_t *ue = lu->ue;
    ogs_pkbuf_t *gmmbuf, *nasbuf, *sendbuf;

    memset(&ue->registration_request_param, 0,
            sizeof(ue->registration_request_param));
    ue->registration_request_param.guti = 1;
    gmmbuf = testgmm_build_registration_request(ue, NULL, false, false);
    if (!gmmbuf) { load_fail(r, "registration_request build"); return false; }

    ue->registration_request_param.gmm_capability = 1;
    ue->registration_request_param.s1_ue_network_capability = 1;
    ue->registration_request_param.requested_nssai = 1;
    ue->registration_request_param.last_visited_registered_tai = 1;
    ue->registration_request_param.ue_usage_setting = 1;
    nasbuf = testgmm_build_registration_request(ue, NULL, false, false);
    if (!nasbuf) {
        ogs_pkbuf_free(gmmbuf);
        load_fail(r, "registration_request (full) build");
        return false;
    }

    sendbuf = testngap_build_initial_ue_message(ue, gmmbuf,
            NGAP_RRCEstablishmentCause_mo_Signalling, false, true);
    if (!load_send(r, ngap, sendbuf, "InitialUEMessage(Registration)")) {
        ogs_pkbuf_free(nasbuf);
        return false;
    }

    /* Receive Identity request */
    if (!load_recv(r, ngap, ue, NGAP_ProcedureCode_id_DownlinkNASTransport,
                "IdentityRequest")) {
        ogs_pkbuf_free(nasbuf);
        return false;
    }

    /* Send Identity response */
    gmmbuf = testgmm_build_identity_response(ue);
    sendbuf = gmmbuf ? testngap_build_uplink_nas_transport(ue, gmmbuf) : NULL;
    if (!load_send(r, ngap, sendbuf, "IdentityResponse")) {
        ogs_pkbuf_free(nasbuf);
        return false;
    }

    /* Receive Authentication request */
    if (!load_recv(r, ngap, ue, NGAP_ProcedureCode_id_DownlinkNASTransport,
                "AuthenticationRequest")) {
        ogs_pkbuf_free(nasbuf);
        return false;
    }

    /* Send Authentication response */
    gmmbuf = testgmm_build_authentication_response(ue);
    sendbuf = gmmbuf ? testngap_build_uplink_nas_transport(ue, gmmbuf) : NULL;
    if (!load_send(r, ngap, sendbuf, "AuthenticationResponse")) {
        ogs_pkbuf_free(nasbuf);
        return false;
    }

    /* Receive Security mode command */
    if (!load_recv(r, ngap, ue, NGAP_ProcedureCode_id_DownlinkNASTransport,
                "SecurityModeCommand")) {
        ogs_pkbuf_free(nasbuf);
        return false;
    }

    /* Send Security mode complete (consumes nasbuf) */
    gmmbuf = testgmm_build_security_mode_complete(ue, nasbuf);
    sendbuf = gmmbuf ? testngap_build_uplink_nas_transport(ue, gmmbuf) : NULL;
    if (!load_send(r, ngap, sendbuf, "SecurityModeComplete")) return false;

    /* Receive InitialContextSetupRequest + Registration accept */
    if (!load_recv(r, ngap, ue, NGAP_ProcedureCode_id_InitialContextSetup,
                "InitialContextSetupRequest")) return false;

    /* Send UERadioCapabilityInfoIndication */
    sendbuf = testngap_build_ue_radio_capability_info_indication(ue);
    if (!load_send(r, ngap, sendbuf, "UERadioCapabilityInfoIndication"))
        return false;

    /* Send InitialContextSetupResponse */
    sendbuf = testngap_build_initial_context_setup_response(ue, false);
    if (!load_send(r, ngap, sendbuf, "InitialContextSetupResponse"))
        return false;

    /* Send Registration complete */
    gmmbuf = testgmm_build_registration_complete(ue);
    sendbuf = gmmbuf ? testngap_build_uplink_nas_transport(ue, gmmbuf) : NULL;
    if (!load_send(r, ngap, sendbuf, "RegistrationComplete")) return false;

    /* Receive Configuration update command */
    if (!load_recv(r, ngap, ue, NGAP_ProcedureCode_id_DownlinkNASTransport,
                "ConfigurationUpdateCommand")) return false;

    return true;
}

static bool load_pdu_session(load_result_t *r,
        ogs_socknode_t *ngap, load_ue_t *lu)
{
    test_ue_t *ue = lu->ue;
    test_sess_t *sess = lu->sess;
    ogs_pkbuf_t *gsmbuf, *gmmbuf, *sendbuf;

    sess->ul_nas_transport_param.request_type =
        OGS_NAS_5GS_REQUEST_TYPE_INITIAL;
    sess->ul_nas_transport_param.dnn = 1;
    sess->ul_nas_transport_param.s_nssai = 0;

    sess->pdu_session_establishment_param.ssc_mode = 1;
    sess->pdu_session_establishment_param.epco = 1;

    gsmbuf = testgsm_build_pdu_session_establishment_request(sess);
    gmmbuf = gsmbuf ? testgmm_build_ul_nas_transport(sess,
            OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, gsmbuf) : NULL;
    sendbuf = gmmbuf ? testngap_build_uplink_nas_transport(ue, gmmbuf) : NULL;
    if (!load_send(r, ngap, sendbuf, "PDUSessionEstablishmentRequest"))
        return false;

    /* Receive PDUSessionResourceSetupRequest +
     * DL NAS transport + PDU session establishment accept */
    if (!load_recv(r, ngap, ue, NGAP_ProcedureCode_id_PDUSessionResourceSetup,
                "PDUSessionResourceSetupRequest")) return false;

    /* Send PDUSessionResourceSetupResponse */
    sendbuf = testngap_sess_build_pdu_session_resource_setup_response(sess);
    if (!load_send(r, ngap, sendbuf, "PDUSessionResourceSetupResponse"))
        return false;

    return true;
}

/* gNB-initiated release: UE goes CM-IDLE, RM-REGISTERED. */
static bool load_release_to_idle(load_result_t *r,
        ogs_socknode_t *ngap, load_ue_t *lu)
{
    test_ue_t *ue = lu->ue;
    ogs_pkbuf_t *sendbuf;

    sendbuf = testngap_build_ue_context_release_request(ue,
            NGAP_Cause_PR_radioNetwork, NGAP_CauseRadioNetwork_user_inactivity,
            true);
    if (!load_send(r, ngap, sendbuf, "UEContextReleaseRequest"))
        return false;

    if (!load_recv(r, ngap, ue, NGAP_ProcedureCode_id_UEContextRelease,
                "UEContextReleaseCommand(idle)")) return false;

    sendbuf = testngap_build_ue_context_release_complete(ue);
    if (!load_send(r, ngap, sendbuf, "UEContextReleaseComplete(idle)"))
        return false;

    return true;
}

/* Service Request from idle: back to CM-CONNECTED with the session. */
static bool load_service_request(load_result_t *r,
        ogs_socknode_t *ngap, load_ue_t *lu)
{
    test_ue_t *ue = lu->ue;
    test_sess_t *sess = lu->sess;
    ogs_pkbuf_t *nasbuf, *gmmbuf, *sendbuf;

    memset(&ue->service_request_param, 0, sizeof(ue->service_request_param));
    ue->service_request_param.pdu_session_status = 1;
    ue->service_request_param.psimask.pdu_session_status = 1 << sess->psi;
    nasbuf = testgmm_build_service_request(
            ue, OGS_NAS_SERVICE_TYPE_SIGNALLING, NULL, false, false);
    if (!nasbuf) { load_fail(r, "service_request build"); return false; }

    ue->service_request_param.pdu_session_status = 0;
    gmmbuf = testgmm_build_service_request(
            ue, OGS_NAS_SERVICE_TYPE_SIGNALLING, nasbuf, true, false);
    if (!gmmbuf) {
        load_fail(r, "service_request (container) build");
        return false;
    }

    sendbuf = testngap_build_initial_ue_message(ue, gmmbuf,
            NGAP_RRCEstablishmentCause_mo_Signalling, false, true);
    if (!load_send(r, ngap, sendbuf, "InitialUEMessage(ServiceRequest)"))
        return false;

    /* Receive InitialContextSetupRequest + Service accept */
    if (!load_recv(r, ngap, ue, NGAP_ProcedureCode_id_InitialContextSetup,
                "InitialContextSetupRequest(SR)")) return false;

    /* Send InitialContextSetupResponse */
    sendbuf = testngap_build_initial_context_setup_response(ue, true);
    if (!load_send(r, ngap, sendbuf, "InitialContextSetupResponse(SR)"))
        return false;

    return true;
}

/* Switch-off de-registration from idle, like simple-test. */
static bool load_deregister_idle(load_result_t *r,
        ogs_socknode_t *ngap, load_ue_t *lu)
{
    test_ue_t *ue = lu->ue;
    ogs_pkbuf_t *gmmbuf, *sendbuf;

    gmmbuf = testgmm_build_de_registration_request(ue, 1, true, false);
    sendbuf = gmmbuf ? testngap_build_initial_ue_message(ue, gmmbuf,
            NGAP_RRCEstablishmentCause_mo_Signalling, true, false) : NULL;
    if (!load_send(r, ngap, sendbuf, "InitialUEMessage(Deregistration)"))
        return false;

    if (!load_recv(r, ngap, ue, NGAP_ProcedureCode_id_UEContextRelease,
                "UEContextReleaseCommand(dereg)")) return false;

    sendbuf = testngap_build_ue_context_release_complete(ue);
    if (!load_send(r, ngap, sendbuf, "UEContextReleaseComplete(dereg)"))
        return false;

    return true;
}

static void load_workers_prepare(abts_case *tc,
        load_worker_t *w, int nues, uint32_t gnb_id_base)
{
    int g, i;
    bson_t *doc = NULL;

    memset(w, 0, sizeof(*w) * LOAD_NUM_GNB);

    for (g = 0; g < LOAD_NUM_GNB; g++) {
        w[g].idx = g;
        w[g].nues = nues;

        w[g].ngap = testngap_client(1, AF_INET);
        ABTS_PTR_NOTNULL(tc, w[g].ngap);
        ABTS_TRUE(tc, load_ng_setup(&w[g].result, w[g].ngap,
                    gnb_id_base + g));

        for (i = 0; i < w[g].nues; i++) {
            ABTS_TRUE(tc, load_ue_setup(&w[g].ues[i], (i + 1) * 1000));

            doc = test_db_new_simple(w[g].ues[i].ue);
            ABTS_PTR_NOTNULL(tc, doc);
            ABTS_INT_EQUAL(tc, OGS_OK,
                    test_db_insert_ue(w[g].ues[i].ue, doc));
        }
    }
}

static void load_workers_run(abts_case *tc,
        load_worker_t *w, void (*func)(void *))
{
    int g;
    ogs_thread_t *thread[LOAD_NUM_GNB];

    for (g = 0; g < LOAD_NUM_GNB; g++) {
        thread[g] = ogs_thread_create(func, &w[g]);
        ABTS_PTR_NOTNULL(tc, thread[g]);
    }

    for (g = 0; g < LOAD_NUM_GNB; g++) {
        ogs_thread_destroy(thread[g]); /* join */

        if (w[g].result.failed)
            ogs_error("load5gc: gNB[%d] worker failed: %s",
                    g, w[g].result.msg);
        ABTS_TRUE(tc, !w[g].result.failed);
    }
}

static void load_workers_teardown(load_worker_t *w)
{
    int g, i;

    ogs_msleep(300);

    for (g = 0; g < LOAD_NUM_GNB; g++) {
        for (i = 0; i < w[g].nues; i++)
            load_ue_teardown(&w[g].ues[i]);
        testgnb_ngap_close(w[g].ngap);
    }

    ogs_msleep(100);
}

/* ------------------------------------------------------------------ */
/* Scenario 1: NG-Setup churn                                          */
/* ------------------------------------------------------------------ */
static void test_load_ngsetup_churn(abts_case *tc, void *data)
{
    int i;
    ogs_socknode_t *ngap[8];
    load_result_t result;

    LOAD_MARK("ngsetup_churn start");

    memset(&result, 0, sizeof(result));

    /* connect 8 gNBs */
    for (i = 0; i < 8; i++) {
        ngap[i] = testngap_client(1, AF_INET);
        ABTS_PTR_NOTNULL(tc, ngap[i]);
        ABTS_TRUE(tc, load_ng_setup(&result, ngap[i], 0x4740 + i));
    }

    /* drop them all; RX workers and IO threads must retire the sockets */
    for (i = 0; i < 8; i++)
        testgnb_ngap_close(ngap[i]);

    ogs_msleep(100);

    /* and one more full round to prove the AMF is still healthy */
    ngap[0] = testngap_client(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap[0]);
    ABTS_TRUE(tc, load_ng_setup(&result, ngap[0], 0x474f));

    if (result.failed)
        ogs_error("load5gc: ngsetup churn failed: %s", result.msg);
    ABTS_TRUE(tc, !result.failed);

    testgnb_ngap_close(ngap[0]);
    ogs_msleep(100);
}

/* ------------------------------------------------------------------ */
/* Scenario 2: mass registration, 4 gNBs in parallel                   */
/* ------------------------------------------------------------------ */
static void load_registration_worker(void *data)
{
    load_worker_t *w = data;
    int i;

    for (i = 0; i < w->nues; i++) {
        load_ue_t *lu = &w->ues[i];

        if (!load_register(&w->result, w->ngap, lu)) return;
        if (!load_pdu_session(&w->result, w->ngap, lu)) return;
        if (!load_release_to_idle(&w->result, w->ngap, lu)) return;
        if (!load_deregister_idle(&w->result, w->ngap, lu)) return;

        LOAD_MARK("registration gNB[%d] UE[%d] done", w->idx, i);
    }
}

static void test_load_mass_registration(abts_case *tc, void *data)
{
    load_worker_t w[LOAD_NUM_GNB];

    LOAD_MARK("mass_registration start");

    load_workers_prepare(tc, w, LOAD_UES_PER_GNB, 0x4700);
    load_workers_run(tc, w, load_registration_worker);
    load_workers_teardown(w);
}

/* ------------------------------------------------------------------ */
/* Scenario 3: idle / service request, 4 gNBs in parallel              */
/* ------------------------------------------------------------------ */
static void load_lifecycle_worker(void *data)
{
    load_worker_t *w = data;
    int i;

    for (i = 0; i < w->nues; i++) {
        load_ue_t *lu = &w->ues[i];

        if (!load_register(&w->result, w->ngap, lu)) return;
        if (!load_pdu_session(&w->result, w->ngap, lu)) return;
        if (!load_release_to_idle(&w->result, w->ngap, lu)) return;
        if (!load_service_request(&w->result, w->ngap, lu)) return;
        if (!load_release_to_idle(&w->result, w->ngap, lu)) return;
        if (!load_deregister_idle(&w->result, w->ngap, lu)) return;

        LOAD_MARK("lifecycle gNB[%d] UE[%d] done", w->idx, i);
    }
}

static void test_load_idle_service_request(abts_case *tc, void *data)
{
    load_worker_t w[LOAD_NUM_GNB];

    LOAD_MARK("idle_service_request start");

    load_workers_prepare(tc, w, LOAD_LIFECYCLE_UES, 0x4710);
    load_workers_run(tc, w, load_lifecycle_worker);
    load_workers_teardown(w);
}

abts_suite *test_load5gc(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    LOAD_MARK("knobs: workers=2 ngap_rx_workers=2 ngap_io_thread=2 "
            "pkbuf_thread_pool=256; synthetic PLMN 999/70");
    LOAD_MARK("flows: ngsetup_churn | mass_registration(%d gNB x %d UE) | "
            "idle_service_request(%d gNB x %d UE)",
            LOAD_NUM_GNB, LOAD_UES_PER_GNB,
            LOAD_NUM_GNB, LOAD_LIFECYCLE_UES);

    abts_run_test(suite, test_load_ngsetup_churn, NULL);
    abts_run_test(suite, test_load_mass_registration, NULL);
    abts_run_test(suite, test_load_idle_service_request, NULL);

    LOAD_MARK("all scenarios finished (see ABTS summary)");
    return suite;
}
