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

#if !defined(OGS_DIAMETER_INSIDE) && !defined(OGS_DIAMETER_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_DIAM_SH_MESSAGE_H
#define OGS_DIAM_SH_MESSAGE_H

#ifdef __cplusplus
extern "C" {
#endif

/* 3GPP TS 29.329 Sh interface application identifier */
#define OGS_DIAM_SH_APPLICATION_ID 16777217

extern struct dict_object *ogs_diam_sh_application;

extern struct dict_object *ogs_diam_sh_cmd_udr; /* User-Data-Request 306 */
extern struct dict_object *ogs_diam_sh_cmd_uda; /* User-Data-Answer 306 */
extern struct dict_object *ogs_diam_sh_cmd_pur; /* Profile-Update-Request 307 */
extern struct dict_object *ogs_diam_sh_cmd_pua; /* Profile-Update-Answer 307 */
extern struct dict_object *ogs_diam_sh_cmd_snr; /* Subscribe-Notif-Request 308 */
extern struct dict_object *ogs_diam_sh_cmd_sna; /* Subscribe-Notif-Answer 308 */
extern struct dict_object *ogs_diam_sh_cmd_pnr; /* Push-Notification-Request 309 */
extern struct dict_object *ogs_diam_sh_cmd_pna; /* Push-Notification-Answer 309 */

extern struct dict_object *ogs_diam_sh_user_identity;       /* 700 grouped */
extern struct dict_object *ogs_diam_sh_public_identity;     /* 601 */
extern struct dict_object *ogs_diam_sh_msisdn;              /* 701 */
extern struct dict_object *ogs_diam_sh_user_data;           /* 702 (User-Data-29.329) */
extern struct dict_object *ogs_diam_sh_data_reference;      /* 703 */
extern struct dict_object *ogs_diam_sh_service_indication;  /* 704 */
extern struct dict_object *ogs_diam_sh_subs_req_type;       /* 705 */
extern struct dict_object *ogs_diam_sh_requested_domain;    /* 706 */
extern struct dict_object *ogs_diam_sh_current_location;    /* 707 */
extern struct dict_object *ogs_diam_sh_expiry_time;         /* 709 */
extern struct dict_object *ogs_diam_sh_send_data_indication;/* 710 */
extern struct dict_object *ogs_diam_sh_server_name;         /* 602 */
extern struct dict_object *ogs_diam_sh_supported_features;  /* 628 */

/* Data-Reference (703) - 3GPP TS 29.329 6.3.4 */
#define OGS_DIAM_SH_DATA_REF_REPOSITORY_DATA            0
#define OGS_DIAM_SH_DATA_REF_IMS_PUBLIC_IDENTITY        10
#define OGS_DIAM_SH_DATA_REF_IMS_USER_STATE             11
#define OGS_DIAM_SH_DATA_REF_SCSCF_NAME                 12
#define OGS_DIAM_SH_DATA_REF_INITIAL_FILTER_CRITERIA    13
#define OGS_DIAM_SH_DATA_REF_LOCATION_INFORMATION       14
#define OGS_DIAM_SH_DATA_REF_USER_STATE                 15
#define OGS_DIAM_SH_DATA_REF_CHARGING_INFORMATION       16
#define OGS_DIAM_SH_DATA_REF_MSISDN                      17
#define OGS_DIAM_SH_DATA_REF_PSI_ACTIVATION             18
#define OGS_DIAM_SH_DATA_REF_DSAI                        17
#define OGS_DIAM_SH_DATA_REF_ALIASES_REPOSITORY_DATA    25

/* Subs-Req-Type (705) - 3GPP TS 29.329 6.3.6 */
#define OGS_DIAM_SH_SUBS_REQ_TYPE_SUBSCRIBE             0
#define OGS_DIAM_SH_SUBS_REQ_TYPE_UNSUBSCRIBE           1

/* Requested-Domain (706) - 3GPP TS 29.329 6.3.7 */
#define OGS_DIAM_SH_REQUESTED_DOMAIN_CS                 0
#define OGS_DIAM_SH_REQUESTED_DOMAIN_PS                 1

/* Current-Location (707) - 3GPP TS 29.329 6.3.8 */
#define OGS_DIAM_SH_CURRENT_LOCATION_DO_NOT_NEED        0
#define OGS_DIAM_SH_CURRENT_LOCATION_INITIATE_ACTIVE    1

/* Send-Data-Indication (710) - 3GPP TS 29.329 6.3.17 */
#define OGS_DIAM_SH_SEND_DATA_INDICATION_NOT_REQUESTED  0
#define OGS_DIAM_SH_SEND_DATA_INDICATION_REQUESTED      1

/* IMSUserState enumerated values - 3GPP TS 29.328 Annex D (tIMSUserState) */
#define OGS_DIAM_SH_IMS_USER_STATE_NOT_REGISTERED       0
#define OGS_DIAM_SH_IMS_USER_STATE_REGISTERED           1
#define OGS_DIAM_SH_IMS_USER_STATE_REGISTERED_UNREG     2
#define OGS_DIAM_SH_IMS_USER_STATE_AUTH_PENDING         3

/* tPSUserState - 3GPP TS 29.328 Annex D */
#define OGS_DIAM_SH_PS_USER_STATE_DETACHED              0
#define OGS_DIAM_SH_PS_USER_STATE_ATTACHED_NOT_REACH    1
#define OGS_DIAM_SH_PS_USER_STATE_ATTACHED_REACHABLE    2
#define OGS_DIAM_SH_PS_USER_STATE_CONNECTED_NOT_REACH   3
#define OGS_DIAM_SH_PS_USER_STATE_CONNECTED_REACHABLE   4
#define OGS_DIAM_SH_PS_USER_STATE_NOT_PROVIDED          5
#define OGS_DIAM_SH_PS_USER_STATE_NDNR                  6

/* Experimental Result-Codes - 3GPP TS 29.329 6.2 */
#define OGS_DIAM_SH_SUCCESS_USER_DATA_NOT_AVAILABLE         4100
#define OGS_DIAM_SH_SUCCESS_PRIOR_UPDATE_IN_PROGRESS        4101
#define OGS_DIAM_SH_ERROR_USER_DATA_NOT_RECOGNIZED          5100
#define OGS_DIAM_SH_ERROR_OPERATION_NOT_ALLOWED             5101
#define OGS_DIAM_SH_ERROR_USER_DATA_CANNOT_BE_READ          5102
#define OGS_DIAM_SH_ERROR_USER_DATA_CANNOT_BE_MODIFIED      5103
#define OGS_DIAM_SH_ERROR_USER_DATA_CANNOT_BE_NOTIFIED      5104
#define OGS_DIAM_SH_ERROR_TRANSPARENT_DATA_OUT_OF_SYNC      5105
#define OGS_DIAM_SH_ERROR_SUBS_DATA_ABSENT                  5106
#define OGS_DIAM_SH_ERROR_NO_SUBSCRIPTION_TO_DATA           5107
#define OGS_DIAM_SH_ERROR_DSAI_NOT_AVAILABLE                5108
#define OGS_DIAM_SH_ERROR_USER_UNKNOWN                      5001
#define OGS_DIAM_SH_ERROR_IDENTITIES_DONT_MATCH             5002
#define OGS_DIAM_SH_ERROR_FEATURE_UNSUPPORTED               5011
#define OGS_DIAM_SH_ERROR_TOO_MUCH_DATA                     5008

int ogs_diam_sh_init(void);

/* Sh-Data XML element tags - 3GPP TS 29.328 Annex D */
extern const char *ogs_diam_sh_xml_version;
extern const char *ogs_diam_sh_xml_sh_data_s;
extern const char *ogs_diam_sh_xml_sh_data_e;
extern const char *ogs_diam_sh_xml_public_ids_s;
extern const char *ogs_diam_sh_xml_public_ids_e;
extern const char *ogs_diam_sh_xml_ims_public_identity_s;
extern const char *ogs_diam_sh_xml_ims_public_identity_e;
extern const char *ogs_diam_sh_xml_msisdn_s;
extern const char *ogs_diam_sh_xml_msisdn_e;
extern const char *ogs_diam_sh_xml_sh_ims_data_s;
extern const char *ogs_diam_sh_xml_sh_ims_data_e;
extern const char *ogs_diam_sh_xml_scscf_name_s;
extern const char *ogs_diam_sh_xml_scscf_name_e;
extern const char *ogs_diam_sh_xml_ims_user_state_s;
extern const char *ogs_diam_sh_xml_ims_user_state_e;
extern const char *ogs_diam_sh_xml_cs_user_state_s;
extern const char *ogs_diam_sh_xml_cs_user_state_e;
extern const char *ogs_diam_sh_xml_ps_user_state_s;
extern const char *ogs_diam_sh_xml_ps_user_state_e;
extern const char *ogs_diam_sh_xml_cs_location_information_s;
extern const char *ogs_diam_sh_xml_cs_location_information_e;
extern const char *ogs_diam_sh_xml_ps_location_information_s;
extern const char *ogs_diam_sh_xml_ps_location_information_e;
extern const char *ogs_diam_sh_xml_extension_s;
extern const char *ogs_diam_sh_xml_extension_e;
extern const char *ogs_diam_sh_xml_eps_location_information_s;
extern const char *ogs_diam_sh_xml_eps_location_information_e;
extern const char *ogs_diam_sh_xml_mme_name_s;
extern const char *ogs_diam_sh_xml_mme_name_e;
extern const char *ogs_diam_sh_xml_vlr_number_s;
extern const char *ogs_diam_sh_xml_vlr_number_e;
extern const char *ogs_diam_sh_xml_msc_number_s;
extern const char *ogs_diam_sh_xml_msc_number_e;

#ifdef __cplusplus
}
#endif

#endif /* OGS_DIAM_SH_MESSAGE_H */
