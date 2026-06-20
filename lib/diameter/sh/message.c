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

#include "ogs-diameter-sh.h"

#define CHECK_dict_search( _type, _criteria, _what, _result )    \
    CHECK_FCT(  fd_dict_search( fd_g_config->cnf_dict, (_type), (_criteria), (_what), (_result), ENOENT) );

struct dict_object *ogs_diam_sh_application = NULL;

struct dict_object *ogs_diam_sh_cmd_udr = NULL;
struct dict_object *ogs_diam_sh_cmd_uda = NULL;
struct dict_object *ogs_diam_sh_cmd_pur = NULL;
struct dict_object *ogs_diam_sh_cmd_pua = NULL;
struct dict_object *ogs_diam_sh_cmd_snr = NULL;
struct dict_object *ogs_diam_sh_cmd_sna = NULL;
struct dict_object *ogs_diam_sh_cmd_pnr = NULL;
struct dict_object *ogs_diam_sh_cmd_pna = NULL;

struct dict_object *ogs_diam_sh_user_identity = NULL;
struct dict_object *ogs_diam_sh_public_identity = NULL;
struct dict_object *ogs_diam_sh_msisdn = NULL;
struct dict_object *ogs_diam_sh_user_data = NULL;
struct dict_object *ogs_diam_sh_data_reference = NULL;
struct dict_object *ogs_diam_sh_service_indication = NULL;
struct dict_object *ogs_diam_sh_subs_req_type = NULL;
struct dict_object *ogs_diam_sh_requested_domain = NULL;
struct dict_object *ogs_diam_sh_current_location = NULL;
struct dict_object *ogs_diam_sh_expiry_time = NULL;
struct dict_object *ogs_diam_sh_send_data_indication = NULL;
struct dict_object *ogs_diam_sh_server_name = NULL;
struct dict_object *ogs_diam_sh_supported_features = NULL;

const char *ogs_diam_sh_xml_version =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
const char *ogs_diam_sh_xml_sh_data_s = "<Sh-Data>";
const char *ogs_diam_sh_xml_sh_data_e = "</Sh-Data>";
const char *ogs_diam_sh_xml_public_ids_s = "<PublicIdentifiers>";
const char *ogs_diam_sh_xml_public_ids_e = "</PublicIdentifiers>";
const char *ogs_diam_sh_xml_ims_public_identity_s = "<IMSPublicIdentity>";
const char *ogs_diam_sh_xml_ims_public_identity_e = "</IMSPublicIdentity>";
const char *ogs_diam_sh_xml_msisdn_s = "<MSISDN>";
const char *ogs_diam_sh_xml_msisdn_e = "</MSISDN>";
const char *ogs_diam_sh_xml_sh_ims_data_s = "<Sh-IMS-Data>";
const char *ogs_diam_sh_xml_sh_ims_data_e = "</Sh-IMS-Data>";
const char *ogs_diam_sh_xml_scscf_name_s = "<SCSCFName>";
const char *ogs_diam_sh_xml_scscf_name_e = "</SCSCFName>";
const char *ogs_diam_sh_xml_ims_user_state_s = "<IMSUserState>";
const char *ogs_diam_sh_xml_ims_user_state_e = "</IMSUserState>";
const char *ogs_diam_sh_xml_cs_user_state_s = "<CSUserState>";
const char *ogs_diam_sh_xml_cs_user_state_e = "</CSUserState>";
const char *ogs_diam_sh_xml_ps_user_state_s = "<PSUserState>";
const char *ogs_diam_sh_xml_ps_user_state_e = "</PSUserState>";
const char *ogs_diam_sh_xml_cs_location_information_s =
    "<CSLocationInformation>";
const char *ogs_diam_sh_xml_cs_location_information_e =
    "</CSLocationInformation>";
const char *ogs_diam_sh_xml_ps_location_information_s =
    "<PSLocationInformation>";
const char *ogs_diam_sh_xml_ps_location_information_e =
    "</PSLocationInformation>";
const char *ogs_diam_sh_xml_extension_s = "<Extension>";
const char *ogs_diam_sh_xml_extension_e = "</Extension>";
const char *ogs_diam_sh_xml_eps_location_information_s =
    "<EPSLocationInformation>";
const char *ogs_diam_sh_xml_eps_location_information_e =
    "</EPSLocationInformation>";
const char *ogs_diam_sh_xml_mme_name_s = "<MMEName>";
const char *ogs_diam_sh_xml_mme_name_e = "</MMEName>";
const char *ogs_diam_sh_xml_vlr_number_s = "<VLRNumber>";
const char *ogs_diam_sh_xml_vlr_number_e = "</VLRNumber>";
const char *ogs_diam_sh_xml_msc_number_s = "<MSCNumber>";
const char *ogs_diam_sh_xml_msc_number_e = "</MSCNumber>";
const char *ogs_diam_sh_xml_ue_reachable_s = "<UE-Reachable>";
const char *ogs_diam_sh_xml_ue_reachable_e = "</UE-Reachable>";

extern int ogs_dict_sh_entry(char *conffile);

int ogs_diam_sh_init(void)
{
    application_id_t id = OGS_DIAM_SH_APPLICATION_ID;

    ogs_assert(ogs_dict_sh_entry(NULL) == 0);

    CHECK_dict_search(DICT_APPLICATION, APPLICATION_BY_ID,
            (void *)&id, &ogs_diam_sh_application);

    CHECK_dict_search(DICT_COMMAND, CMD_BY_NAME,
            "3GPP/User-Data-Request", &ogs_diam_sh_cmd_udr);
    CHECK_dict_search(DICT_COMMAND, CMD_BY_NAME,
            "3GPP/User-Data-Answer", &ogs_diam_sh_cmd_uda);
    CHECK_dict_search(DICT_COMMAND, CMD_BY_NAME,
            "3GPP/Profile-Update-Request", &ogs_diam_sh_cmd_pur);
    CHECK_dict_search(DICT_COMMAND, CMD_BY_NAME,
            "3GPP/Profile-Update-Answer", &ogs_diam_sh_cmd_pua);
    CHECK_dict_search(DICT_COMMAND, CMD_BY_NAME,
            "3GPP/Subscribe-Notifications-Request", &ogs_diam_sh_cmd_snr);
    CHECK_dict_search(DICT_COMMAND, CMD_BY_NAME,
            "3GPP/Subscribe-Notifications-Answer", &ogs_diam_sh_cmd_sna);
    CHECK_dict_search(DICT_COMMAND, CMD_BY_NAME,
            "3GPP/Push-Notification-Request", &ogs_diam_sh_cmd_pnr);
    CHECK_dict_search(DICT_COMMAND, CMD_BY_NAME,
            "3GPP/Push-Notification-Answer", &ogs_diam_sh_cmd_pna);

    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "User-Identity", &ogs_diam_sh_user_identity);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Public-Identity", &ogs_diam_sh_public_identity);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "MSISDN", &ogs_diam_sh_msisdn);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "User-Data-29.329", &ogs_diam_sh_user_data);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Data-Reference", &ogs_diam_sh_data_reference);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Service-Indication", &ogs_diam_sh_service_indication);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Subs-Req-Type", &ogs_diam_sh_subs_req_type);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Requested-Domain", &ogs_diam_sh_requested_domain);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Current-Location", &ogs_diam_sh_current_location);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Expiry-Time", &ogs_diam_sh_expiry_time);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Send-Data-Indication", &ogs_diam_sh_send_data_indication);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Server-Name", &ogs_diam_sh_server_name);
    CHECK_dict_search(DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
            "Supported-Features", &ogs_diam_sh_supported_features);

    return 0;
}
