/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Stage A: after Attach Complete, optionally send a binary MT SMS over
 * NAS when the attach-embedded PDN Connectivity Request had no APN IE
 * (and ESM Information Response did not supply one either). Matched by
 * IMSI home PLMN. No SMSC — MME builds CP-DATA/RP-DATA/SMS-DELIVER.
 */

#pragma once

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MME_PROV_SMS_MAX_USERDATA   160
#define MME_PROV_SMS_MAX_OA_DIGITS  20
#define MME_PROV_SMS_MAX_RULES      16

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

/* Parse mme.provisioning_sms: list from YAML iterator at that key. */
int mme_provisioning_sms_parse(ogs_yaml_iter_t *iter);

/*
 * After successful Attach Complete: if UE was flagged for missing APN IE
 * and a rule matches IMSI home PLMN, send one binary MT SMS over NAS.
 */
void mme_provisioning_sms_on_attach_complete(mme_ue_t *mme_ue);

#ifdef __cplusplus
}
#endif
