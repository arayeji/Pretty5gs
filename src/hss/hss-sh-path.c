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

#include "ogs-crypt.h"

#include "ogs-diameter-sh.h"

#include "hss-context.h"
#include "hss-fd-path.h"
#include "hss-s6a-path.h"
#include "hss-trace.h"
#include "ogs-diameter-s6a.h"

/* AVP codes (3GPP TS 29.328 / 29.329) used while browsing requests */
#define HSS_SH_AVP_CODE_DATA_REFERENCE      703
#define HSS_SH_AVP_CODE_PUBLIC_IDENTITY     601
#define HSS_SH_AVP_CODE_MSISDN              701

/* handler for fallback cb */
static struct disp_hdl *hdl_sh_fb = NULL;
/* handler for User-Data-Request cb */
static struct disp_hdl *hdl_sh_udr = NULL;
/* handler for Subscribe-Notifications-Request cb */
static struct disp_hdl *hdl_sh_snr = NULL;

/*
 * In-memory registry of Sh notification subscriptions (SNR/PNR).
 *
 * Each entry records which Application Server (Origin-Host/Realm) subscribed
 * to notifications for a given identity and Data-Reference, so the HSS can
 * later push a PNR when the underlying data changes (e.g. on S6a NOR after
 * URRP-MME arming).
 */
typedef struct sh_subscription_s {
    ogs_lnode_t lnode;

    char *public_identity;      /* IMPU/MSISDN string carried in PNR */
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];
    uint32_t data_reference;

    char *origin_host;          /* AS Origin-Host -> PNR Destination-Host */
    char *origin_realm;         /* AS Origin-Realm -> PNR Destination-Realm */
} sh_subscription_t;

static ogs_list_t sh_subscription_list;
static ogs_thread_mutex_t sh_subscription_lock;

static void sh_subscription_add(const char *public_identity,
        const char *imsi_bcd, uint32_t data_reference,
        const char *origin_host, const char *origin_realm);
static void sh_subscription_remove(const char *public_identity,
        uint32_t data_reference, const char *origin_host);
static void sh_subscription_remove_all(void);

/* Resolve IMSI(bcd) from an IMPU(Public-Identity) or MSISDN. */
static bool hss_sh_resolve_imsi(
        const char *public_identity, const char *msisdn_bcd,
        char *imsi_bcd, size_t imsi_bcd_len)
{
    int rv;

    if (public_identity) {
        char *imsi = hss_cx_get_imsi_bcd((char *)public_identity);
        if (imsi) {
            ogs_cpystrn(imsi_bcd, imsi, imsi_bcd_len);
            return true;
        }
    }

    if (msisdn_bcd && msisdn_bcd[0]) {
        ogs_msisdn_data_t msisdn_data;
        memset(&msisdn_data, 0, sizeof(msisdn_data));
        rv = hss_db_msisdn_data((char *)msisdn_bcd, &msisdn_data);
        if (rv == OGS_OK && msisdn_data.imsi.bcd[0]) {
            ogs_cpystrn(imsi_bcd, msisdn_data.imsi.bcd, imsi_bcd_len);
            return true;
        }
    }

    return false;
}

/*
 * Build a Sh-Data XML document (3GPP TS 29.328 Annex D) for the requested
 * Data-References. Returns a newly allocated string the caller must free,
 * or NULL if nothing could be provided. *served is set to the number of
 * Data-References that produced data.
 */
static char *hss_sh_build_sh_data(
        const char *public_identity, const char *msisdn_bcd,
        uint32_t *data_references, int num_data_references,
        uint32_t requested_domain, bool requested_domain_present,
        int *served)
{
    char *xml = NULL;
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];
    bool has_imsi = false;
    int i;

    ogs_subscription_data_t subscription_data;
    bool has_subscription = false;
    bool want_reachability = false;

    *served = 0;

    memset(imsi_bcd, 0, sizeof(imsi_bcd));
    memset(&subscription_data, 0, sizeof(subscription_data));

    has_imsi = hss_sh_resolve_imsi(
            public_identity, msisdn_bcd, imsi_bcd, sizeof(imsi_bcd));
    if (has_imsi) {
        if (hss_db_subscription_data(imsi_bcd, &subscription_data) == OGS_OK)
            has_subscription = true;
    }

    xml = ogs_strdup(ogs_diam_sh_xml_version);
    ogs_assert(xml);
    xml = ogs_mstrcatf(xml, "%s", ogs_diam_sh_xml_sh_data_s);
    ogs_assert(xml);

    for (i = 0; i < num_data_references; i++) {
        switch (data_references[i]) {
        case OGS_DIAM_SH_DATA_REF_IMS_USER_STATE:
            if (public_identity) {
                int state =
                    hss_cx_get_server_name((char *)public_identity) ?
                        OGS_DIAM_SH_IMS_USER_STATE_REGISTERED :
                        OGS_DIAM_SH_IMS_USER_STATE_NOT_REGISTERED;
                xml = ogs_mstrcatf(xml, "%s%s%d%s%s",
                        ogs_diam_sh_xml_sh_ims_data_s,
                        ogs_diam_sh_xml_ims_user_state_s,
                        state,
                        ogs_diam_sh_xml_ims_user_state_e,
                        ogs_diam_sh_xml_sh_ims_data_e);
                ogs_assert(xml);
                (*served)++;
            }
            break;

        case OGS_DIAM_SH_DATA_REF_SCSCF_NAME:
            if (public_identity) {
                char *scscf = hss_cx_get_server_name((char *)public_identity);
                if (scscf) {
                    xml = ogs_mstrcatf(xml, "%s%s%s%s%s",
                            ogs_diam_sh_xml_sh_ims_data_s,
                            ogs_diam_sh_xml_scscf_name_s,
                            scscf,
                            ogs_diam_sh_xml_scscf_name_e,
                            ogs_diam_sh_xml_sh_ims_data_e);
                    ogs_assert(xml);
                    (*served)++;
                }
            }
            break;

        case OGS_DIAM_SH_DATA_REF_USER_STATE:
            want_reachability = true;
            /* PS domain user state: only when a real MME is registered. */
            if (!requested_domain_present ||
                    requested_domain == OGS_DIAM_SH_REQUESTED_DOMAIN_PS) {
                if (has_subscription && subscription_data.mme_host) {
                    int state = subscription_data.purge_flag ?
                        OGS_DIAM_SH_PS_USER_STATE_DETACHED :
                        OGS_DIAM_SH_PS_USER_STATE_ATTACHED_REACHABLE;
                    xml = ogs_mstrcatf(xml, "%s%d%s",
                            ogs_diam_sh_xml_ps_user_state_s,
                            state,
                            ogs_diam_sh_xml_ps_user_state_e);
                    ogs_assert(xml);
                    (*served)++;
                }
            }
            /* CS domain user state: derived from the IWF-provided VLR data. */
            if (!requested_domain_present ||
                    requested_domain == OGS_DIAM_SH_REQUESTED_DOMAIN_CS) {
                if (has_subscription && subscription_data.vlr_number) {
                    int state = subscription_data.cs_purge_flag ?
                        OGS_DIAM_SH_CS_USER_STATE_NOT_PROVIDED_FROM_VLR :
                        OGS_DIAM_SH_CS_USER_STATE_ASSUMED_IDLE;
                    xml = ogs_mstrcatf(xml, "%s%d%s",
                            ogs_diam_sh_xml_cs_user_state_s,
                            state,
                            ogs_diam_sh_xml_cs_user_state_e);
                    ogs_assert(xml);
                    (*served)++;
                }
            }
            break;

        case OGS_DIAM_SH_DATA_REF_LOCATION_INFORMATION:
            want_reachability = true;
            /* PS domain: report serving MME as EPSLocationInformation.
             * EPSLocationInformation lives under four nested Extensions
             * (tSh-Data-Extension .. Extension4) per TS 29.328 Annex D. */
            if (!requested_domain_present ||
                    requested_domain == OGS_DIAM_SH_REQUESTED_DOMAIN_PS) {
                if (has_subscription && subscription_data.mme_host) {
                    xml = ogs_mstrcatf(xml,
                            "%s%s%s%s"
                            "%s%s%s%s"
                            "%s%s%s%s",
                            ogs_diam_sh_xml_extension_s,
                            ogs_diam_sh_xml_extension_s,
                            ogs_diam_sh_xml_extension_s,
                            ogs_diam_sh_xml_extension_s,
                            ogs_diam_sh_xml_eps_location_information_s,
                            ogs_diam_sh_xml_mme_name_s,
                            subscription_data.mme_host,
                            ogs_diam_sh_xml_mme_name_e,
                            ogs_diam_sh_xml_eps_location_information_e,
                            ogs_diam_sh_xml_extension_e,
                            ogs_diam_sh_xml_extension_e,
                            ogs_diam_sh_xml_extension_e);
                    ogs_assert(xml);
                    /* close the outermost Extension */
                    xml = ogs_mstrcatf(xml, "%s",
                            ogs_diam_sh_xml_extension_e);
                    ogs_assert(xml);
                    (*served)++;
                }
            }
            /* CS domain: report the VLR Global Title as CSLocationInformation
             * (single Extension), so Kamailio T-ADS can route via CS. */
            if (!requested_domain_present ||
                    requested_domain == OGS_DIAM_SH_REQUESTED_DOMAIN_CS) {
                if (has_subscription && subscription_data.vlr_number &&
                        !subscription_data.cs_purge_flag) {
                    xml = ogs_mstrcatf(xml,
                            "%s%s%s%s%s%s",
                            ogs_diam_sh_xml_extension_s,
                            ogs_diam_sh_xml_cs_location_information_s,
                            ogs_diam_sh_xml_vlr_number_s,
                            subscription_data.vlr_number,
                            ogs_diam_sh_xml_vlr_number_e,
                            ogs_diam_sh_xml_cs_location_information_e);
                    ogs_assert(xml);
                    xml = ogs_mstrcatf(xml, "%s",
                            ogs_diam_sh_xml_extension_e);
                    ogs_assert(xml);
                    (*served)++;
                }
            }
            break;

        default:
            ogs_warn("Sh UDR: unsupported Data-Reference [%d]",
                    data_references[i]);
            break;
        }
    }

    /*
     * UE-Reachable: Kamailio T-ADS reads //UE-Reachable/text() to choose a
     * short vs long paging wait. Emit it whenever location/user-state was
     * requested. Reachable if either domain is currently attached.
     */
    if (has_subscription && want_reachability) {
        bool reachable =
            (subscription_data.mme_host && !subscription_data.purge_flag) ||
            (subscription_data.vlr_number && !subscription_data.cs_purge_flag);
        xml = ogs_mstrcatf(xml, "%s%s%s",
                ogs_diam_sh_xml_ue_reachable_s,
                reachable ? "true" : "false",
                ogs_diam_sh_xml_ue_reachable_e);
        ogs_assert(xml);
    }

    xml = ogs_mstrcatf(xml, "%s", ogs_diam_sh_xml_sh_data_e);
    ogs_assert(xml);

    if (has_subscription)
        ogs_subscription_data_free(&subscription_data);

    return xml;
}

/* Default fallback callback for the Sh application. */
static int hss_ogs_diam_sh_fb_cb(struct msg **msg, struct avp *avp,
        struct session *session, void *opaque, enum disp_action *act)
{
    HSS_TRACE_SCOPE();
    ogs_warn("Unexpected Sh message received!");
    return ENOTSUP;
}

/* Extract Public-Identity / MSISDN from a User-Identity grouped AVP. */
static void hss_sh_get_user_identity(struct msg *qry,
        char **public_identity, char **msisdn_bcd)
{
    int ret;
    struct avp *user_identity = NULL, *child = NULL;
    struct avp_hdr *hdr = NULL;

    *public_identity = NULL;
    *msisdn_bcd = NULL;

    ret = fd_msg_search_avp(qry, ogs_diam_sh_user_identity, &user_identity);
    if (ret != 0 || !user_identity)
        return;

    ret = fd_msg_search_avp(
            user_identity, ogs_diam_sh_public_identity, &child);
    if (ret == 0 && child) {
        ret = fd_msg_avp_hdr(child, &hdr);
        if (ret == 0 && hdr)
            *public_identity = ogs_strndup(
                    (char *)hdr->avp_value->os.data, hdr->avp_value->os.len);
    }

    child = NULL;
    ret = fd_msg_search_avp(user_identity, ogs_diam_sh_msisdn, &child);
    if (ret == 0 && child) {
        ret = fd_msg_avp_hdr(child, &hdr);
        if (ret == 0 && hdr) {
            char buf[OGS_MAX_MSISDN_BCD_LEN+1];
            ogs_buffer_to_bcd(
                    hdr->avp_value->os.data, hdr->avp_value->os.len, buf);
            *msisdn_bcd = ogs_strdup(buf);
        }
    }
}

/* Callback for incoming User-Data-Request messages */
static int hss_ogs_diam_sh_udr_cb(struct msg **msg, struct avp *avp,
        struct session *session, void *opaque, enum disp_action *act)
{
    HSS_TRACE_SCOPE();
    int ret;
    uint32_t result_code = 0;
    struct msg *ans = NULL, *qry = NULL;
    struct avp *avpch = NULL;
    struct avp_hdr *hdr = NULL;
    union avp_value val;

    char *public_identity = NULL;
    char *msisdn_bcd = NULL;
    char *user_data = NULL;

    uint32_t data_references[16];
    int num_data_references = 0;
    uint32_t requested_domain = 0;
    bool requested_domain_present = false;
    int served = 0;
    int error_occurred = 0;

    ogs_debug("Rx User-Data-Request");

    if (!msg || !*msg) {
        ogs_error("Invalid message pointer");
        return EINVAL;
    }

    qry = *msg;
    ret = fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0);
    if (ret != 0) {
        ogs_error("Failed to create answer message");
        return EINVAL;
    }
    ans = *msg;

    /* User-Identity (Public-Identity / MSISDN) */
    hss_sh_get_user_identity(qry, &public_identity, &msisdn_bcd);
    if (!public_identity && !msisdn_bcd) {
        ogs_error("Sh UDR: no User-Identity found");
        result_code = OGS_DIAM_SH_ERROR_USER_UNKNOWN;
        error_occurred = 1;
        goto out;
    }

    {
        char udr_imsi[OGS_MAX_IMSI_BCD_LEN+1];
        memset(udr_imsi, 0, sizeof(udr_imsi));
        (void)hss_sh_resolve_imsi(
                public_identity, msisdn_bcd, udr_imsi, sizeof(udr_imsi));
        hss_trace_event(udr_imsi[0] ? udr_imsi : NULL, "Sh-UDR",
                "Rx User-Data-Request");
    }

    /* Requested-Domain (optional) */
    ret = fd_msg_search_avp(qry, ogs_diam_sh_requested_domain, &avpch);
    if (ret == 0 && avpch) {
        ret = fd_msg_avp_hdr(avpch, &hdr);
        if (ret == 0 && hdr) {
            requested_domain = hdr->avp_value->i32;
            requested_domain_present = true;
        }
    }

    /* Collect all Data-Reference AVPs by walking the request's children */
    ret = fd_msg_browse(qry, MSG_BRW_FIRST_CHILD, &avpch, NULL);
    while (ret == 0 && avpch) {
        struct avp_hdr *chdr = NULL;
        if (fd_msg_avp_hdr(avpch, &chdr) == 0 && chdr &&
                chdr->avp_code == HSS_SH_AVP_CODE_DATA_REFERENCE) {
            if (num_data_references <
                    (int)(sizeof(data_references)/sizeof(data_references[0]))) {
                data_references[num_data_references++] = chdr->avp_value->i32;
            }
        }
        if (fd_msg_browse(avpch, MSG_BRW_NEXT, &avpch, NULL) != 0)
            break;
    }

    if (num_data_references == 0) {
        ogs_error("Sh UDR: no Data-Reference found");
        result_code = OGS_DIAM_SH_ERROR_USER_DATA_NOT_RECOGNIZED;
        error_occurred = 1;
        goto out;
    }

    user_data = hss_sh_build_sh_data(
            public_identity, msisdn_bcd,
            data_references, num_data_references,
            requested_domain, requested_domain_present, &served);
    if (!user_data || served == 0) {
        ogs_error("Sh UDR: requested data cannot be provided");
        result_code = OGS_DIAM_SH_ERROR_USER_DATA_CANNOT_BE_READ;
        error_occurred = 1;
        goto out;
    }

    /* Vendor-Specific-Application-Id */
    ret = ogs_diam_message_vendor_specific_appid_set(
            ans, OGS_DIAM_SH_APPLICATION_ID);
    if (ret != 0) {
        error_occurred = 1;
        goto out;
    }

    /* Auth-Session-State */
    ret = fd_msg_avp_new(ogs_diam_auth_session_state, 0, &avp);
    if (ret != 0) { error_occurred = 1; goto out; }
    val.i32 = OGS_DIAM_AUTH_SESSION_NO_STATE_MAINTAINED;
    ret = fd_msg_avp_setvalue(avp, &val);
    if (ret != 0) { error_occurred = 1; goto out; }
    ret = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp);
    if (ret != 0) { error_occurred = 1; goto out; }

    /* Result-Code: DIAMETER_SUCCESS */
    ret = fd_msg_rescode_set(ans, (char *)"DIAMETER_SUCCESS", NULL, NULL, 1);
    if (ret != 0) { error_occurred = 1; goto out; }

    /* User-Data (Sh-Data XML) */
    ret = fd_msg_avp_new(ogs_diam_sh_user_data, 0, &avp);
    if (ret != 0) { error_occurred = 1; goto out; }
    val.os.data = (uint8_t *)user_data;
    val.os.len  = strlen(user_data);
    ret = fd_msg_avp_setvalue(avp, &val);
    if (ret != 0) { error_occurred = 1; goto out; }
    ret = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp);
    if (ret != 0) { error_occurred = 1; goto out; }

    ret = fd_msg_send(msg, NULL, NULL);
    if (ret != 0) {
        ogs_error("Failed to send User-Data-Answer");
        error_occurred = 1;
        goto out;
    }

    ogs_debug("Tx User-Data-Answer");
    {
        char udr_imsi[OGS_MAX_IMSI_BCD_LEN+1];
        memset(udr_imsi, 0, sizeof(udr_imsi));
        (void)hss_sh_resolve_imsi(
                public_identity, msisdn_bcd, udr_imsi, sizeof(udr_imsi));
        hss_trace_event(udr_imsi[0] ? udr_imsi : NULL, "Sh-UDR",
                "Tx User-Data-Answer");
    }
    OGS_DIAM_STATS_MTX( OGS_DIAM_STATS_INC(nb_echoed); )

    if (user_data) ogs_free(user_data);
    if (public_identity) ogs_free(public_identity);
    if (msisdn_bcd) ogs_free(msisdn_bcd);
    return 0;

out:
    if (ans) {
        ret = ogs_diam_message_vendor_specific_appid_set(
                ans, OGS_DIAM_SH_APPLICATION_ID);
        if (result_code != 0)
            ret = ogs_diam_message_experimental_rescode_set(ans, result_code);

        ret = fd_msg_avp_new(ogs_diam_auth_session_state, 0, &avp);
        if (ret == 0) {
            val.i32 = OGS_DIAM_AUTH_SESSION_NO_STATE_MAINTAINED;
            if (fd_msg_avp_setvalue(avp, &val) == 0)
                fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp);
        }

        ret = fd_msg_send(msg, NULL, NULL);
        if (ret != 0)
            ogs_error("Failed to send Sh UDR error response");
    }

    if (error_occurred) { /* keep static analyzers quiet */ }
    if (user_data) ogs_free(user_data);
    if (public_identity) ogs_free(public_identity);
    if (msisdn_bcd) ogs_free(msisdn_bcd);
    return 0;
}

/* Callback for incoming Subscribe-Notifications-Request messages */
static int hss_ogs_diam_sh_snr_cb(struct msg **msg, struct avp *avp,
        struct session *session, void *opaque, enum disp_action *act)
{
    HSS_TRACE_SCOPE();
    int ret;
    uint32_t result_code = 0;
    struct msg *ans = NULL, *qry = NULL;
    struct avp *avpch = NULL;
    struct avp_hdr *hdr = NULL;
    union avp_value val;

    char *public_identity = NULL;
    char *msisdn_bcd = NULL;
    char *origin_host = NULL;
    char *origin_realm = NULL;
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    uint32_t subs_req_type = OGS_DIAM_SH_SUBS_REQ_TYPE_SUBSCRIBE;
    uint32_t data_references[16];
    int num_data_references = 0;
    int i;
    int error_occurred = 0;

    ogs_debug("Rx Subscribe-Notifications-Request");

    if (!msg || !*msg) {
        ogs_error("Invalid message pointer");
        return EINVAL;
    }

    qry = *msg;
    ret = fd_msg_new_answer_from_req(fd_g_config->cnf_dict, msg, 0);
    if (ret != 0) {
        ogs_error("Failed to create answer message");
        return EINVAL;
    }
    ans = *msg;

    memset(imsi_bcd, 0, sizeof(imsi_bcd));

    hss_sh_get_user_identity(qry, &public_identity, &msisdn_bcd);
    if (!public_identity && !msisdn_bcd) {
        ogs_error("Sh SNR: no User-Identity found");
        result_code = OGS_DIAM_SH_ERROR_USER_UNKNOWN;
        error_occurred = 1;
        goto out;
    }

    /* Subs-Req-Type */
    ret = fd_msg_search_avp(qry, ogs_diam_sh_subs_req_type, &avpch);
    if (ret == 0 && avpch) {
        ret = fd_msg_avp_hdr(avpch, &hdr);
        if (ret == 0 && hdr)
            subs_req_type = hdr->avp_value->i32;
    }

    /* Origin-Host / Origin-Realm of the subscribing AS */
    ret = fd_msg_search_avp(qry, ogs_diam_origin_host, &avpch);
    if (ret == 0 && avpch) {
        ret = fd_msg_avp_hdr(avpch, &hdr);
        if (ret == 0 && hdr)
            origin_host = ogs_strndup(
                    (char *)hdr->avp_value->os.data, hdr->avp_value->os.len);
    }
    ret = fd_msg_search_avp(qry, ogs_diam_origin_realm, &avpch);
    if (ret == 0 && avpch) {
        ret = fd_msg_avp_hdr(avpch, &hdr);
        if (ret == 0 && hdr)
            origin_realm = ogs_strndup(
                    (char *)hdr->avp_value->os.data, hdr->avp_value->os.len);
    }

    /* Collect Data-Reference AVPs */
    ret = fd_msg_browse(qry, MSG_BRW_FIRST_CHILD, &avpch, NULL);
    while (ret == 0 && avpch) {
        struct avp_hdr *chdr = NULL;
        if (fd_msg_avp_hdr(avpch, &chdr) == 0 && chdr &&
                chdr->avp_code == HSS_SH_AVP_CODE_DATA_REFERENCE) {
            if (num_data_references <
                    (int)(sizeof(data_references)/sizeof(data_references[0]))) {
                data_references[num_data_references++] = chdr->avp_value->i32;
            }
        }
        if (fd_msg_browse(avpch, MSG_BRW_NEXT, &avpch, NULL) != 0)
            break;
    }

    (void)hss_sh_resolve_imsi(
            public_identity, msisdn_bcd, imsi_bcd, sizeof(imsi_bcd));

    hss_trace_event(imsi_bcd[0] ? imsi_bcd : NULL, "Sh-SNR",
            "Rx Subscribe-Notifications-Request");

    if (origin_host) {
        const char *key = public_identity ? public_identity : msisdn_bcd;
        for (i = 0; i < num_data_references; i++) {
            if (subs_req_type == OGS_DIAM_SH_SUBS_REQ_TYPE_UNSUBSCRIBE) {
                sh_subscription_remove(
                        key, data_references[i], origin_host);
            } else {
                sh_subscription_add(key, imsi_bcd, data_references[i],
                        origin_host, origin_realm);
            }
        }
    }

    /* Vendor-Specific-Application-Id */
    ret = ogs_diam_message_vendor_specific_appid_set(
            ans, OGS_DIAM_SH_APPLICATION_ID);
    if (ret != 0) { error_occurred = 1; goto out; }

    /* Auth-Session-State */
    ret = fd_msg_avp_new(ogs_diam_auth_session_state, 0, &avp);
    if (ret != 0) { error_occurred = 1; goto out; }
    val.i32 = OGS_DIAM_AUTH_SESSION_NO_STATE_MAINTAINED;
    ret = fd_msg_avp_setvalue(avp, &val);
    if (ret != 0) { error_occurred = 1; goto out; }
    ret = fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp);
    if (ret != 0) { error_occurred = 1; goto out; }

    ret = fd_msg_rescode_set(ans, (char *)"DIAMETER_SUCCESS", NULL, NULL, 1);
    if (ret != 0) { error_occurred = 1; goto out; }

    ret = fd_msg_send(msg, NULL, NULL);
    if (ret != 0) {
        ogs_error("Failed to send Subscribe-Notifications-Answer");
        error_occurred = 1;
        goto out;
    }

    ogs_debug("Tx Subscribe-Notifications-Answer");
    hss_trace_event(imsi_bcd[0] ? imsi_bcd : NULL, "Sh-SNR",
            "Tx Subscribe-Notifications-Answer");
    OGS_DIAM_STATS_MTX( OGS_DIAM_STATS_INC(nb_echoed); )

    /* Kamailio T-ADS: arm UE-reachability on the serving node (IWF/MME). */
    if (subs_req_type == OGS_DIAM_SH_SUBS_REQ_TYPE_SUBSCRIBE && imsi_bcd[0]) {
        for (i = 0; i < num_data_references; i++) {
            if (data_references[i] == OGS_DIAM_SH_DATA_REF_USER_STATE) {
                (void)hss_s6a_send_idr(imsi_bcd,
                        OGS_DIAM_S6A_IDR_FLAGS_UE_REACHABILITY, 0);
                break;
            }
        }
    }

    if (public_identity) ogs_free(public_identity);
    if (msisdn_bcd) ogs_free(msisdn_bcd);
    if (origin_host) ogs_free(origin_host);
    if (origin_realm) ogs_free(origin_realm);
    return 0;

out:
    if (ans) {
        ret = ogs_diam_message_vendor_specific_appid_set(
                ans, OGS_DIAM_SH_APPLICATION_ID);
        if (result_code != 0)
            ret = ogs_diam_message_experimental_rescode_set(ans, result_code);

        ret = fd_msg_avp_new(ogs_diam_auth_session_state, 0, &avp);
        if (ret == 0) {
            val.i32 = OGS_DIAM_AUTH_SESSION_NO_STATE_MAINTAINED;
            if (fd_msg_avp_setvalue(avp, &val) == 0)
                fd_msg_avp_add(ans, MSG_BRW_LAST_CHILD, avp);
        }

        ret = fd_msg_send(msg, NULL, NULL);
        if (ret != 0)
            ogs_error("Failed to send Sh SNR error response");
    }

    if (error_occurred) { /* keep static analyzers quiet */ }
    if (public_identity) ogs_free(public_identity);
    if (msisdn_bcd) ogs_free(msisdn_bcd);
    if (origin_host) ogs_free(origin_host);
    if (origin_realm) ogs_free(origin_realm);
    return 0;
}

/* Callback for the Push-Notification-Answer (we ignore the content). */
static void hss_sh_pna_cb(void *data, struct msg **msg)
{
    int ret;

    if (msg && *msg) {
        ret = fd_msg_free(*msg);
        if (ret != 0)
            ogs_error("Failed to free PNA message");
        *msg = NULL;
    }
}

/*
 * Send a Push-Notification-Request to every Application Server that
 * subscribed (via SNR) to notifications for the given identity and
 * Data-Reference. The PNR carries the freshly-built Sh-Data document.
 */
static void hss_sh_send_pnr(sh_subscription_t *subs)
{
    int ret;
    struct msg *req = NULL;
    struct avp *avp = NULL, *avp_ui = NULL;
    union avp_value val;
    char *user_data = NULL;
    int served = 0;
    uint32_t data_reference;

    ogs_assert(subs);
    data_reference = subs->data_reference;

    user_data = hss_sh_build_sh_data(
            subs->public_identity, NULL, &data_reference, 1,
            OGS_DIAM_SH_REQUESTED_DOMAIN_PS, true, &served);
    if (!user_data || served == 0) {
        ogs_warn("Sh PNR: no data to push for [%s]", subs->public_identity);
        if (user_data) ogs_free(user_data);
        return;
    }

    ret = fd_msg_new(ogs_diam_sh_cmd_pnr, MSGFL_ALLOC_ETEID, &req);
    ogs_assert(ret == 0);

#define OGS_DIAM_SH_APP_SID_OPT "app_sh"
    ret = fd_msg_new_session(req, (os0_t)OGS_DIAM_SH_APP_SID_OPT,
            CONSTSTRLEN(OGS_DIAM_SH_APP_SID_OPT));
    ogs_assert(ret == 0);

    /* Auth-Session-State */
    ret = fd_msg_avp_new(ogs_diam_auth_session_state, 0, &avp);
    ogs_assert(ret == 0);
    val.i32 = OGS_DIAM_AUTH_SESSION_NO_STATE_MAINTAINED;
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* Origin-Host & Origin-Realm */
    ret = fd_msg_add_origin(req, 0);
    ogs_assert(ret == 0);

    /* Destination-Host (the subscribing AS) */
    if (subs->origin_host) {
        ret = fd_msg_avp_new(ogs_diam_destination_host, 0, &avp);
        ogs_assert(ret == 0);
        val.os.data = (uint8_t *)subs->origin_host;
        val.os.len  = strlen(subs->origin_host);
        ret = fd_msg_avp_setvalue(avp, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(ret == 0);
    }

    /* Destination-Realm */
    ret = fd_msg_avp_new(ogs_diam_destination_realm, 0, &avp);
    ogs_assert(ret == 0);
    if (subs->origin_realm) {
        val.os.data = (uint8_t *)subs->origin_realm;
        val.os.len  = strlen(subs->origin_realm);
    } else {
        val.os.data = (uint8_t *)fd_g_config->cnf_diamrlm;
        val.os.len  = strlen(fd_g_config->cnf_diamrlm);
    }
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* User-Identity { Public-Identity } */
    ret = fd_msg_avp_new(ogs_diam_sh_user_identity, 0, &avp_ui);
    ogs_assert(ret == 0);
    if (subs->public_identity) {
        ret = fd_msg_avp_new(ogs_diam_sh_public_identity, 0, &avp);
        ogs_assert(ret == 0);
        val.os.data = (uint8_t *)subs->public_identity;
        val.os.len  = strlen(subs->public_identity);
        ret = fd_msg_avp_setvalue(avp, &val);
        ogs_assert(ret == 0);
        ret = fd_msg_avp_add(avp_ui, MSG_BRW_LAST_CHILD, avp);
        ogs_assert(ret == 0);
    }
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp_ui);
    ogs_assert(ret == 0);

    /* User-Data (Sh-Data XML) */
    ret = fd_msg_avp_new(ogs_diam_sh_user_data, 0, &avp);
    ogs_assert(ret == 0);
    val.os.data = (uint8_t *)user_data;
    val.os.len  = strlen(user_data);
    ret = fd_msg_avp_setvalue(avp, &val);
    ogs_assert(ret == 0);
    ret = fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    ogs_assert(ret == 0);

    /* Vendor-Specific-Application-Id */
    ret = ogs_diam_message_vendor_specific_appid_set(
            req, OGS_DIAM_SH_APPLICATION_ID);
    ogs_assert(ret == 0);

    ret = fd_msg_send(&req, hss_sh_pna_cb, NULL);
    ogs_assert(ret == 0);

    ogs_debug("Tx Push-Notification-Request to [%s]",
            subs->origin_host ? subs->origin_host : "(realm)");
    hss_trace_event(subs->imsi_bcd, "Sh-PNR",
            "Tx Push-Notification-Request to [%s]",
            subs->origin_host ? subs->origin_host : "(realm)");
    OGS_DIAM_STATS_MTX( OGS_DIAM_STATS_INC(nb_sent); )

    ogs_free(user_data);
}

/*
 * Public entry point used by the S6a NOR handler (URRP-MME): when the MME
 * reports a reachability/state change for an IMSI, push a PNR to every
 * Application Server subscribed to that subscriber's data.
 */
void hss_sh_notify_by_imsi(const char *imsi_bcd)
{
    sh_subscription_t *subs = NULL;

    if (!imsi_bcd || !imsi_bcd[0])
        return;

    hss_trace_event(imsi_bcd, "Sh-PNR",
            "Notify subscribed ASs after S6a NOR");

    ogs_thread_mutex_lock(&sh_subscription_lock);
    ogs_list_for_each(&sh_subscription_list, subs) {
        if (strcmp(subs->imsi_bcd, imsi_bcd) == 0)
            hss_sh_send_pnr(subs);
    }
    ogs_thread_mutex_unlock(&sh_subscription_lock);
}

static void sh_subscription_add(const char *public_identity,
        const char *imsi_bcd, uint32_t data_reference,
        const char *origin_host, const char *origin_realm)
{
    sh_subscription_t *subs = NULL;

    if (!public_identity || !origin_host)
        return;

    ogs_thread_mutex_lock(&sh_subscription_lock);

    /* Replace an existing identical subscription, if any. */
    ogs_list_for_each(&sh_subscription_list, subs) {
        if (subs->data_reference == data_reference &&
                strcmp(subs->public_identity, public_identity) == 0 &&
                subs->origin_host &&
                strcmp(subs->origin_host, origin_host) == 0) {
            ogs_thread_mutex_unlock(&sh_subscription_lock);
            return;
        }
    }

    subs = ogs_calloc(1, sizeof(*subs));
    ogs_assert(subs);
    subs->public_identity = ogs_strdup(public_identity);
    if (imsi_bcd)
        ogs_cpystrn(subs->imsi_bcd, imsi_bcd, sizeof(subs->imsi_bcd));
    subs->data_reference = data_reference;
    subs->origin_host = ogs_strdup(origin_host);
    if (origin_realm)
        subs->origin_realm = ogs_strdup(origin_realm);

    ogs_list_add(&sh_subscription_list, subs);

    ogs_thread_mutex_unlock(&sh_subscription_lock);

    ogs_debug("Sh: subscription added [%s] DataRef[%d] AS[%s]",
            public_identity, data_reference, origin_host);
}

static void sh_subscription_free(sh_subscription_t *subs)
{
    if (subs->public_identity) ogs_free(subs->public_identity);
    if (subs->origin_host) ogs_free(subs->origin_host);
    if (subs->origin_realm) ogs_free(subs->origin_realm);
    ogs_free(subs);
}

static void sh_subscription_remove(const char *public_identity,
        uint32_t data_reference, const char *origin_host)
{
    sh_subscription_t *subs = NULL, *next = NULL;

    if (!public_identity || !origin_host)
        return;

    ogs_thread_mutex_lock(&sh_subscription_lock);
    ogs_list_for_each_safe(&sh_subscription_list, next, subs) {
        if (subs->data_reference == data_reference &&
                strcmp(subs->public_identity, public_identity) == 0 &&
                subs->origin_host &&
                strcmp(subs->origin_host, origin_host) == 0) {
            ogs_list_remove(&sh_subscription_list, subs);
            sh_subscription_free(subs);
        }
    }
    ogs_thread_mutex_unlock(&sh_subscription_lock);
}

static void sh_subscription_remove_all(void)
{
    sh_subscription_t *subs = NULL, *next = NULL;

    ogs_thread_mutex_lock(&sh_subscription_lock);
    ogs_list_for_each_safe(&sh_subscription_list, next, subs) {
        ogs_list_remove(&sh_subscription_list, subs);
        sh_subscription_free(subs);
    }
    ogs_thread_mutex_unlock(&sh_subscription_lock);
}

int hss_sh_init(void)
{
    int ret;
    struct disp_when data;

    ogs_list_init(&sh_subscription_list);
    ogs_thread_mutex_init(&sh_subscription_lock);

    ret = ogs_diam_sh_init();
    ogs_assert(ret == 0);

    memset(&data, 0, sizeof(data));
    data.app = ogs_diam_sh_application;

    ret = fd_disp_register(hss_ogs_diam_sh_fb_cb, DISP_HOW_APPID,
                                &data, NULL, &hdl_sh_fb);
    ogs_assert(ret == 0);

    data.command = ogs_diam_sh_cmd_udr;
    ret = fd_disp_register(hss_ogs_diam_sh_udr_cb, DISP_HOW_CC, &data, NULL,
                &hdl_sh_udr);
    ogs_assert(ret == 0);

    data.command = ogs_diam_sh_cmd_snr;
    ret = fd_disp_register(hss_ogs_diam_sh_snr_cb, DISP_HOW_CC, &data, NULL,
                &hdl_sh_snr);
    ogs_assert(ret == 0);

    /* Advertise support for the Sh application to peers */
    ret = fd_disp_app_support(ogs_diam_sh_application, ogs_diam_vendor, 1, 0);
    ogs_assert(ret == 0);

    return OGS_OK;
}

void hss_sh_final(void)
{
    if (hdl_sh_fb)
        (void) fd_disp_unregister(&hdl_sh_fb, NULL);
    if (hdl_sh_udr)
        (void) fd_disp_unregister(&hdl_sh_udr, NULL);
    if (hdl_sh_snr)
        (void) fd_disp_unregister(&hdl_sh_snr, NULL);

    sh_subscription_remove_all();
    ogs_thread_mutex_destroy(&sh_subscription_lock);
}
