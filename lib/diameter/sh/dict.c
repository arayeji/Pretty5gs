/*
 * Dictionary definitions for the 3GPP Sh interface (TS 29.329).
 *
 * Registers the Sh Diameter application (16777217) and its commands
 * (UDR/UDA 306, PUR/PUA 307, SNR/SNA 308, PNR/PNA 309). All AVPs are
 * already provided by the dict_dcca_3gpp freeDiameter extension; this file
 * only adds the application, the commands and their grouping rules.
 */

#include <freeDiameter/extension.h>

#define CHECK_dict_new( _type, _data, _parent, _ref )  \
  CHECK_FCT(  fd_dict_new( fd_g_config->cnf_dict, (_type), (_data), (_parent), (_ref))  );

#define CHECK_dict_search( _type, _criteria, _what, _result )  \
  CHECK_FCT(  fd_dict_search( fd_g_config->cnf_dict, (_type), (_criteria), (_what), (_result), ENOENT) );

struct local_rules_definition {
  struct dict_avp_request avp_vendor_plus_name;
  enum rule_position  position;
  int       min;
  int      max;
};

#define RULE_ORDER( _position ) ((((_position) == RULE_FIXED_HEAD) || ((_position) == RULE_FIXED_TAIL)) ? 1 : 0 )

#define PARSE_loc_rules( _rulearray, _parent) {                \
  int __ar;                      \
  for (__ar=0; __ar < sizeof(_rulearray) / sizeof((_rulearray)[0]); __ar++) {      \
    struct dict_rule_data __data = { NULL,               \
      (_rulearray)[__ar].position,              \
      0,                     \
      (_rulearray)[__ar].min,                \
      (_rulearray)[__ar].max};              \
    __data.rule_order = RULE_ORDER(__data.rule_position);          \
    CHECK_FCT(  fd_dict_search(                 \
      fd_g_config->cnf_dict,                \
      DICT_AVP,                   \
      AVP_BY_NAME_AND_VENDOR,               \
      &(_rulearray)[__ar].avp_vendor_plus_name,          \
      &__data.rule_avp, 0 ) );              \
    if ( !__data.rule_avp ) {                \
      TRACE_DEBUG(INFO, "AVP Not found: '%s'", (_rulearray)[__ar].avp_vendor_plus_name.avp_name);    \
      return ENOENT;                  \
    }                      \
    CHECK_FCT_DO( fd_dict_new( fd_g_config->cnf_dict, DICT_RULE, &__data, _parent, NULL),  \
      {                          \
        TRACE_DEBUG(INFO, "Error on rule with AVP '%s'",            \
              (_rulearray)[__ar].avp_vendor_plus_name.avp_name);    \
        return EINVAL;                      \
      } );                          \
  }                              \
}

int ogs_dict_sh_entry(char *conffile)
{
  /* Applications section */
  {
    struct dict_object * vendor;
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_VENDOR, VENDOR_BY_NAME, "3GPP", &vendor, ENOENT));
    struct dict_application_data sh = { 16777217, "Sh" };
    CHECK_FCT(fd_dict_new(fd_g_config->cnf_dict, DICT_APPLICATION, &sh, vendor, NULL));
  }

  /* Command section */
  {
    struct dict_object *sh;
    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, APPLICATION_BY_NAME, "Sh", &sh, ENOENT));

    /* User-Data-Request (UDR) Command */
    {
      struct dict_object* cmd;
      struct dict_cmd_data data = {
        306,
        "3GPP/User-Data-Request",
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE
      };
      struct local_rules_definition rules[] =
      {
        {  {                      .avp_name = "Session-Id" }, RULE_FIXED_HEAD, -1, 1 },
        {  {                      .avp_name = "Vendor-Specific-Application-Id" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Auth-Session-State" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Host" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Realm" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Destination-Host" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Destination-Realm" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Supported-Features" }, RULE_OPTIONAL, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "User-Identity" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Wildcarded-Public-Identity" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Wildcarded-IMPU" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Server-Name" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Service-Indication" }, RULE_OPTIONAL, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "Data-Reference" }, RULE_REQUIRED, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "Identity-Set" }, RULE_OPTIONAL, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "Requested-Domain" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Current-Location" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "DSAI-Tag" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "User-Name" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Proxy-Info" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Route-Record" }, RULE_OPTIONAL, -1, -1 }
      };
      CHECK_dict_new(DICT_COMMAND, &data, sh, &cmd);
      PARSE_loc_rules(rules, cmd);
    }

    /* User-Data-Answer (UDA) Command */
    {
      struct dict_object* cmd;
      struct dict_cmd_data data = {
        306,
        "3GPP/User-Data-Answer",
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
        CMD_FLAG_PROXIABLE
      };
      struct local_rules_definition rules[] =
      {
        {  {                      .avp_name = "Session-Id" }, RULE_FIXED_HEAD, -1, 1 },
        {  {                      .avp_name = "Vendor-Specific-Application-Id" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Result-Code" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Experimental-Result" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Auth-Session-State" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Host" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Realm" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Supported-Features" }, RULE_OPTIONAL, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "Wildcarded-Public-Identity" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Wildcarded-IMPU" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "User-Data-29.329" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Failed-AVP" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Proxy-Info" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Route-Record" }, RULE_OPTIONAL, -1, -1 }
      };
      CHECK_dict_new(DICT_COMMAND, &data, sh, &cmd);
      PARSE_loc_rules(rules, cmd);
    }

    /* Profile-Update-Request (PUR) Command */
    {
      struct dict_object* cmd;
      struct dict_cmd_data data = {
        307,
        "3GPP/Profile-Update-Request",
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE
      };
      struct local_rules_definition rules[] =
      {
        {  {                      .avp_name = "Session-Id" }, RULE_FIXED_HEAD, -1, 1 },
        {  {                      .avp_name = "Vendor-Specific-Application-Id" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Auth-Session-State" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Host" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Realm" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Destination-Host" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Destination-Realm" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Supported-Features" }, RULE_OPTIONAL, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "User-Identity" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Wildcarded-Public-Identity" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Wildcarded-IMPU" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "User-Data-29.329" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "User-Name" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Proxy-Info" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Route-Record" }, RULE_OPTIONAL, -1, -1 }
      };
      CHECK_dict_new(DICT_COMMAND, &data, sh, &cmd);
      PARSE_loc_rules(rules, cmd);
    }

    /* Profile-Update-Answer (PUA) Command */
    {
      struct dict_object* cmd;
      struct dict_cmd_data data = {
        307,
        "3GPP/Profile-Update-Answer",
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
        CMD_FLAG_PROXIABLE
      };
      struct local_rules_definition rules[] =
      {
        {  {                      .avp_name = "Session-Id" }, RULE_FIXED_HEAD, -1, 1 },
        {  {                      .avp_name = "Vendor-Specific-Application-Id" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Result-Code" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Experimental-Result" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Auth-Session-State" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Host" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Realm" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Supported-Features" }, RULE_OPTIONAL, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "Wildcarded-Public-Identity" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Wildcarded-IMPU" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Failed-AVP" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Proxy-Info" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Route-Record" }, RULE_OPTIONAL, -1, -1 }
      };
      CHECK_dict_new(DICT_COMMAND, &data, sh, &cmd);
      PARSE_loc_rules(rules, cmd);
    }

    /* Subscribe-Notifications-Request (SNR) Command */
    {
      struct dict_object* cmd;
      struct dict_cmd_data data = {
        308,
        "3GPP/Subscribe-Notifications-Request",
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE
      };
      struct local_rules_definition rules[] =
      {
        {  {                      .avp_name = "Session-Id" }, RULE_FIXED_HEAD, -1, 1 },
        {  {                      .avp_name = "Vendor-Specific-Application-Id" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Auth-Session-State" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Host" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Realm" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Destination-Host" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Destination-Realm" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Supported-Features" }, RULE_OPTIONAL, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "User-Identity" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Wildcarded-Public-Identity" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Wildcarded-IMPU" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Service-Indication" }, RULE_OPTIONAL, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "Send-Data-Indication" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Server-Name" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Subs-Req-Type" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Data-Reference" }, RULE_REQUIRED, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "Identity-Set" }, RULE_OPTIONAL, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "Expiry-Time" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "DSAI-Tag" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "User-Name" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Proxy-Info" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Route-Record" }, RULE_OPTIONAL, -1, -1 }
      };
      CHECK_dict_new(DICT_COMMAND, &data, sh, &cmd);
      PARSE_loc_rules(rules, cmd);
    }

    /* Subscribe-Notifications-Answer (SNA) Command */
    {
      struct dict_object* cmd;
      struct dict_cmd_data data = {
        308,
        "3GPP/Subscribe-Notifications-Answer",
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
        CMD_FLAG_PROXIABLE
      };
      struct local_rules_definition rules[] =
      {
        {  {                      .avp_name = "Session-Id" }, RULE_FIXED_HEAD, -1, 1 },
        {  {                      .avp_name = "Vendor-Specific-Application-Id" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Result-Code" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Experimental-Result" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Auth-Session-State" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Host" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Realm" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Supported-Features" }, RULE_OPTIONAL, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "User-Data-29.329" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Expiry-Time" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Failed-AVP" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Proxy-Info" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Route-Record" }, RULE_OPTIONAL, -1, -1 }
      };
      CHECK_dict_new(DICT_COMMAND, &data, sh, &cmd);
      PARSE_loc_rules(rules, cmd);
    }

    /* Push-Notification-Request (PNR) Command */
    {
      struct dict_object* cmd;
      struct dict_cmd_data data = {
        309,
        "3GPP/Push-Notification-Request",
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE
      };
      struct local_rules_definition rules[] =
      {
        {  {                      .avp_name = "Session-Id" }, RULE_FIXED_HEAD, -1, 1 },
        {  {                      .avp_name = "Vendor-Specific-Application-Id" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Auth-Session-State" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Host" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Realm" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Destination-Host" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Destination-Realm" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Supported-Features" }, RULE_OPTIONAL, -1, -1 },
        {  { .avp_vendor = 10415, .avp_name = "User-Identity" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Wildcarded-Public-Identity" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Wildcarded-IMPU" }, RULE_OPTIONAL, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "User-Data-29.329" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "User-Name" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Proxy-Info" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Route-Record" }, RULE_OPTIONAL, -1, -1 }
      };
      CHECK_dict_new(DICT_COMMAND, &data, sh, &cmd);
      PARSE_loc_rules(rules, cmd);
    }

    /* Push-Notification-Answer (PNA) Command */
    {
      struct dict_object* cmd;
      struct dict_cmd_data data = {
        309,
        "3GPP/Push-Notification-Answer",
        CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
        CMD_FLAG_PROXIABLE
      };
      struct local_rules_definition rules[] =
      {
        {  {                      .avp_name = "Session-Id" }, RULE_FIXED_HEAD, -1, 1 },
        {  {                      .avp_name = "Vendor-Specific-Application-Id" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Result-Code" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Experimental-Result" }, RULE_OPTIONAL, -1, 1 },
        {  {                      .avp_name = "Auth-Session-State" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Host" }, RULE_REQUIRED, -1, 1 },
        {  {                      .avp_name = "Origin-Realm" }, RULE_REQUIRED, -1, 1 },
        {  { .avp_vendor = 10415, .avp_name = "Supported-Features" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Failed-AVP" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Proxy-Info" }, RULE_OPTIONAL, -1, -1 },
        {  {                      .avp_name = "Route-Record" }, RULE_OPTIONAL, -1, -1 }
      };
      CHECK_dict_new(DICT_COMMAND, &data, sh, &cmd);
      PARSE_loc_rules(rules, cmd);
    }
  }

  LOG_D( "Extension 'Dictionary definitions for Sh 3GPP' initialized");
  return 0;
}
