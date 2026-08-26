/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * After Attach Complete, per matching IMSI-home-PLMN rule:
 *  - delivery=s1 (default): if the UE's IMEI is new or changed vs the
 *    MongoDB imei_tracker, send one binary MT SMS over NAS (no SMSC) and
 *    record IMSI → IMEI in the tracker.
 *  - delivery=event: send ONE small UDP/UNIX datagram to an external
 *    provisioner (which sends via osmo-msc SMPP and owns change/rate logic).
 *    Fire-and-forget, non-blocking (MSG_DONTWAIT) -- no logs, no MongoDB,
 *    no S1 SMS, and it can never block MME call processing.
 * Both paths honour require_no_apn: only UEs whose Attach Request carried NO
 * APN IE (relying on the default APN) are provisioned.
 */

#pragma once

#include "mme-context.h"

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MME_PROV_SMS_MAX_USERDATA   160
#define MME_PROV_SMS_MAX_OA_DIGITS  20
#define MME_PROV_SMS_MAX_RULES      16
#define MME_PROV_SMS_IMEI_LEN       15
#define MME_PROV_SMS_MAX_ENDPOINT   108     /* fits sun_path */

typedef enum {
    MME_PROV_SMS_DELIVERY_S1 = 0,   /* MME sends binary MT SMS over NAS */
    MME_PROV_SMS_DELIVERY_EVENT,    /* datagram to external provisioner */
} mme_provisioning_sms_delivery_e;

typedef struct mme_provisioning_sms_rule_s {
    ogs_lnode_t     lnode;

    bool            plmn_present;
    ogs_plmn_id_t   imsi_plmn_id;

    /* Delivery + eligibility */
    int             delivery;       /* mme_provisioning_sms_delivery_e */
    bool            require_no_apn; /* provision only UEs that sent no APN IE */

    /* delivery=event: fire-and-forget datagram target. event_socket is a
     * UNIX-domain path (same host); event_addr is "host:port" for UDP. */
    char            event_socket[MME_PROV_SMS_MAX_ENDPOINT + 1];
    char            event_addr[64];
    int             event_fd;       /* cached client socket, -1 until first use */
    int             event_family;   /* AF_UNIX / AF_INET(6) / 0 = unset */
    struct sockaddr_storage event_sa;
    socklen_t       event_salen;

    char            oa[MME_PROV_SMS_MAX_OA_DIGITS + 1];
    uint8_t         dcs;
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
 * Sequence of rules, or mapping { rules: [ ... ] }.
 * Requires top-level db_uri (MongoDB); collection: imei_tracker.
 */
int mme_provisioning_sms_parse(ogs_yaml_iter_t *iter);

void mme_provisioning_sms_on_attach_complete(mme_ue_t *mme_ue);

#ifdef __cplusplus
}
#endif
