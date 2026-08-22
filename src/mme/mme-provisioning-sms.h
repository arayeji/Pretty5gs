/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * After Attach Complete: if IMSI home PLMN matches a rule and the UE's
 * IMEI is new or changed vs the local tracker, send one binary MT SMS
 * over NAS (no SMSC). Tracker is IMSI → IMEI, persisted to a file.
 */

#pragma once

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MME_PROV_SMS_MAX_USERDATA   160
#define MME_PROV_SMS_MAX_OA_DIGITS  20
#define MME_PROV_SMS_MAX_RULES      16
#define MME_PROV_SMS_IMEI_LEN       15

typedef struct mme_provisioning_sms_rule_s {
    ogs_lnode_t     lnode;

    bool            plmn_present;
    ogs_plmn_id_t   imsi_plmn_id;

    /* Originating address digits (TBCD); empty → "0" */
    char            oa[MME_PROV_SMS_MAX_OA_DIGITS + 1];

    /* TP-DCS (default 0x04 = 8-bit binary) */
    uint8_t         dcs;

    /* Optional application-port UDHI (0 = disabled) */
    uint16_t        dest_port;
    uint16_t        orig_port;

    uint8_t         userdata[MME_PROV_SMS_MAX_USERDATA];
    size_t          userdata_len;
} mme_provisioning_sms_rule_t;

void mme_provisioning_sms_init(void);
void mme_provisioning_sms_final(void);
void mme_provisioning_sms_remove_all(void);

/*
 * Parse mme.provisioning_sms from YAML.
 * Accepts either a rule sequence (legacy) or a mapping:
 *   tracker_file: /var/lib/open5gs/mme-imei-tracker.txt
 *   rules: [ { imsi_plmn_id, userdata_hex, ... }, ... ]
 */
int mme_provisioning_sms_parse(ogs_yaml_iter_t *iter);

/*
 * After successful Attach Complete: if a rule matches IMSI home PLMN and
 * IMEI is unknown/changed for this IMSI, send one binary MT SMS and
 * record the IMEI in the local tracker (on successful send).
 */
void mme_provisioning_sms_on_attach_complete(mme_ue_t *mme_ue);

#ifdef __cplusplus
}
#endif
