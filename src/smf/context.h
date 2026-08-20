/*
 * Copyright (C) 2019-2025 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef SMF_CONTEXT_H
#define SMF_CONTEXT_H

#include "smf-config.h"

#include "ogs-gtp.h"
#include "ogs-diameter-gx.h"
#include "ogs-diameter-gy.h"
#include "ogs-diameter-rx.h"
#include "ogs-diameter-s6b.h"
#include "ogs-pfcp.h"
#include "ogs-sbi.h"
#include "ogs-app.h"
#include "ogs-ngap.h"
#include "ogs-nas-5gs.h"
#include "ipfw/ogs-ipfw.h"

#include "timer.h"
#include "smf-sm.h"
#include "metrics.h"

#if HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern int __smf_log_domain;
extern int __gsm_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __smf_log_domain

typedef enum {
    SMF_CTF_ENABLED_AUTO = 0,
    SMF_CTF_ENABLED_YES,
    SMF_CTF_ENABLED_NO,
} smf_ctf_enabled_mode_e;

typedef struct smf_ctf_config_s {
    smf_ctf_enabled_mode_e enabled;
} smf_ctf_config_t;

int smf_ctf_config_init(smf_ctf_config_t *ctf_config);

/*
 * RADIUS server selection modes:
 *   PRIMARY_FAILOVER — every request tries servers in declared order,
 *                      falling through on timeout (default).
 *   HASH_IMSI        — hash(IMSI) % num_servers picks the preferred
 *                      server; failover to next on timeout.
 */
typedef enum {
    SMF_RADIUS_SELECT_PRIMARY_FAILOVER = 0,
    SMF_RADIUS_SELECT_HASH_IMSI        = 1,
} smf_radius_select_mode_e;

#define SMF_MAX_RADIUS_SERVERS 4

/*
 * One physical AAA. Each server gets its own shared secret so operators
 * can deploy heterogeneous farms.
 *
 * Health tracking is runtime-only (NOT persisted through apply_runtime):
 *   consecutive_failures — bumped on every timeout, reset on success.
 *   down_since           — 0 when healthy; set to now when the server
 *                          just tripped the blacklist threshold.
 *   last_probe           — gate for re-admitting a server from the
 *                          blacklist.
 */
typedef struct smf_radius_server_s {
    const char *host;      /* owned via smf_radius_cfg_owned_strings() */
    uint16_t    auth_port;
    uint16_t    acct_port;
    const char *secret;    /* owned via smf_radius_cfg_owned_strings() */
    bool        is_primary;
    int         weight;    /* reserved for future weighted selection */

    /* Runtime health (file-static state, not part of config). */
    int         consecutive_failures;
    ogs_time_t  down_since;
    ogs_time_t  last_probe;

    /*
     * Cached transport for the data path. Resolving the host string and
     * opening a UDP socket on every Access-/Accounting-Request is
     * expensive: at 100+ active UEs the SMF spent more time in
     * getaddrinfo/socket/destroy than in the RADIUS exchange itself.
     *
     *   peer_auth / peer_acct - one shot DNS at first use, kept until the
     *                           server slot is replaced.
     *   sock                  - persistent UDP socket reused across all
     *                           requests; recv timeout is refreshed before
     *                           each send so config changes take effect.
     *   sock_timeout_ms       - tracks the timeout currently applied to
     *                           `sock`, lets us skip the setsockopt() when
     *                           cfg->timeout_ms has not moved.
     *   bound_nas_ip          - local address sock was bound to (from
     *                           radius.nas_ip), so a config change forces
     *                           a rebind. NULL means unbound (kernel pick).
     */
    ogs_sockaddr_t *peer_auth;
    ogs_sockaddr_t *peer_acct;
    ogs_sock_t     *sock;
    unsigned        sock_timeout_ms;
    char           *bound_nas_ip;
} smf_radius_server_t;

typedef struct smf_radius_config_s {
    bool enabled;

    /*
     * Legacy single-server knobs. Kept so existing YAML keeps working.
     * At parse time, if `server` is set and servers[] is empty, we
     * synthesize servers[0] from these fields. Callers should ALWAYS go
     * through servers[]; the flat fields are not consulted on the data
     * path.
     */
    const char *server;
    uint16_t    auth_port;     /* default 1812 */
    uint16_t    acct_port;     /* default 1813 */
    const char *secret;

    const char *nas_id;
    /*
     * NAS-IP-Address AVP value AND UDP source bind for Access/Accounting
     * client sockets. AAA servers often key clients by packet source IP;
     * without binding here the kernel picks the egress interface address
     * (which may not match nas_ip).
     */
    const char *nas_ip;
    unsigned timeout_ms;
    int retry;

    /* Interim-Update interval in seconds (0 = disabled). RFC 2869 §2.1 */
    unsigned acct_interim_interval;

    /* RFC 5176 Disconnect-Message / CoA listener */
    bool pod_enabled;
    const char *pod_bind;   /* local bind address, NULL = any */
    uint16_t pod_port;      /* default 3799 */
    const char *pod_secret; /* optional; falls back to 'secret' */

    /*
     * Max time (in ms) to wait for the MME to reply to a GTPv2 Delete
     * Bearer Request triggered by a RADIUS Disconnect. If the MME goes
     * silent (e.g. it paged the UE but never sent a Delete Bearer
     * Response), the SMF forces PFCP Session Deletion so that the UPF
     * tunnel is torn down and a RADIUS Accounting-Stop is emitted.
     * 0 = disabled (keep retransmitting Delete Bearer Request forever).
     */
    uint32_t pod_teardown_timeout_ms;

    /*
     * When true (default), UE IP priority is: HSS/UDM subscription static
     * IP first, then Framed-IP-Address / Framed-IPv6-Prefix from RADIUS
     * Access-Accept (per address family), then the SMF local IP pool.
     * When false, RADIUS may still authenticate and supply Class/routes,
     * but framed addresses are not used for UE IP assignment.
     */
    bool use_framed_ip_for_ue;

    /*
     * Multi-server farm. At least one primary is required when enabled.
     * Parsed from the new `servers:` YAML block or synthesized from the
     * legacy flat `server:` + `secret:` keys.
     */
    smf_radius_server_t servers[SMF_MAX_RADIUS_SERVERS];
    int num_servers;
    smf_radius_select_mode_e select_mode;

    /*
     * Blacklist cool-down for unhealthy servers. After this many ms
     * since down_since we allow one probe attempt. Not operator-tunable
     * yet; compile-time constant good enough for now.
     */
#define SMF_RADIUS_BLACKLIST_COOLDOWN_MS 30000
    /* Consecutive failures before we mark a server down. */
#define SMF_RADIUS_BLACKLIST_THRESHOLD   3
} smf_radius_config_t;

/*
 * Per-APN RADIUS behaviour. Configured beside the APN definition in the
 * smf.session YAML list (NOT under smf.radius):
 *
 *   session:
 *     - subnet: 10.45.0.0/16
 *       dnn: internet
 *       radius:
 *         auth: false            # send Access-Request (default false:
 *                                #   no authentication, only accounting
 *                                #   and the other RADIUS messages)
 *         ip_assignment: false   # accept Framed-IP-Address /
 *                                #   Framed-IPv6-Prefix as UE IP
 *                                #   (default false: never take the UE
 *                                #   IP from RADIUS for this APN)
 *         skip: false            # default false; true = no RADIUS at
 *                                #   all for this APN (no auth, no
 *                                #   accounting)
 *
 * APNs without a `radius:` block get the defaults above. The global
 * smf.radius.enabled and smf.radius.use_framed_ip_for_ue switches still
 * apply on top (both must allow the feature for it to be active).
 */
typedef struct smf_apn_radius_cfg_s {
    char apn[OGS_MAX_DNN_LEN+1];
    bool auth;              /* default false: skip Access-Request */
    bool ip_assignment;     /* default false: ignore Framed-IP(v6) */
    bool skip;              /* default false: RADIUS fully active */
} smf_apn_radius_cfg_t;

#define SMF_MAX_APN_RADIUS_CFG 64

/* NULL when the APN has no explicit `radius:` block (defaults apply). */
const smf_apn_radius_cfg_t *smf_apn_radius_cfg_find(const char *apn);

/* Table maintenance, used by startup parse and SIGHUP reload. */
void smf_apn_radius_cfg_reset(void);
void smf_apn_radius_cfg_add(const char *apn, const smf_apn_radius_cfg_t *tmpl);

/*
 * Scan a smf.session YAML list and (re)register every per-APN `radius:`
 * block found in it. `parent_iter` must be positioned on the `session`
 * key. Call smf_apn_radius_cfg_reset() first for full-replace semantics
 * (SIGHUP); the startup parse relies on smf_context_prepare() doing the
 * reset.
 */
void smf_apn_radius_parse_session_list(ogs_yaml_iter_t *parent_iter);

/* Effective per-APN switches (defaults applied when not configured). */
bool smf_apn_radius_skip(const char *apn);
bool smf_apn_radius_auth_enabled(const char *apn);
bool smf_apn_radius_ip_assignment_enabled(const char *apn);

/*
 * CDR writer configuration (Ga interface / GTP' offline charging).
 *
 * The SMF only builds the ASN.1 BER CDR and appends it to a local spool
 * file under `spool_dir`. A separate daemon (e.g. open5gs-cgfd) reads
 * the rotated files and delivers them to the CGF over GTP'. Keeping
 * network I/O out of the SMF means a slow or unreachable CGF cannot
 * block session handling, and CDRs survive process restarts on disk.
 *
 * Spool layout:
 *   <spool_dir>/current/<node_id>-<epoch_ms>-<pid>.cdr   (active file)
 *   <spool_dir>/ready/<same-name>.cdr                    (after rotation)
 *
 * On-disk record format inside the file (repeated):
 *   4 B  magic       "O5CD"
 *   1 B  version     0x01
 *   1 B  format      0x01 (ASN.1 BER)
 *   2 B  record length N (big endian)
 *   N B  ASN.1-BER-encoded record, e.g. [APPLICATION 79] PGWRecord
 */
typedef struct smf_cdr_config_s {
    bool enabled;

    const char *spool_dir;      /* e.g. /var/spool/open5gs/cdr */
    const char *node_id;        /* value of CDR [18] nodeID, ASCII */
    /*
     * CDR [4] p-GWAddress selection (IPv4):
     *   1) gtpc.server.advertise (ogs_gtp_self()->gtpc_ip)
     *   2) address / pgw_address (manual override below)
     *   3) local_address (last-resort fallback)
     *
     * CDR [6] servingNodeAddress (SGW S5-C / SGSN Gn peer):
     *   1) peer IP from Create Session / Create PDP signalling
     *   2) serving_node_address / sgsn_address / sgw_serving_address
     */
    const char *address;        /* manual CDR [4] override (alias: pgw_address) */
    const char *local_address;  /* last-resort CDR [4] fallback */
    const char *serving_node_address; /* manual CDR [6] fallback */

    /* Rotation thresholds. Whichever is hit first closes the active file
     * and renames it into <spool_dir>/ready/. 0 means disabled. */
    uint32_t rotate_max_records;   /* default 100 */
    uint32_t rotate_max_bytes;     /* default 65536 */
    uint32_t rotate_max_seconds;   /* default 30 */

    /* Which triggers emit a (partial) record, OR'd flags below. */
    uint32_t triggers;
#define SMF_CDR_TRIG_START           (1u << 0)
#define SMF_CDR_TRIG_INTERIM         (1u << 1) /* any URR usage report */
#define SMF_CDR_TRIG_STOP            (1u << 2)
} smf_cdr_config_t;

typedef struct smf_nsmf_pdusession_param_s {
    OpenAPI_request_indication_e request_indication;

    OpenAPI_cause_e cause;

    struct {
        int group;
        int value;
    } ngap_cause;

    int gmm_cause;
    int gsm_cause;

    struct {
    ED4(uint8_t serving_network:1;,
        uint8_t ue_location:1;,
        uint8_t ue_timezone:1;,
        uint8_t spare:4;)
    };

    uint32_t dl_teid;
    ogs_ip_t dl_ip;

    OpenAPI_access_type_e an_type;
    OpenAPI_rat_type_e rat_type;

    OpenAPI_up_cnx_state_e up_cnx_state;

#define QOS_RULE_CODE_FROM_PFCP_FLAGS(pfcp_flags) \
        (pfcp_flags & OGS_PFCP_MODIFY_CREATE) ? \
            OGS_NAS_QOS_CODE_CREATE_NEW_QOS_RULE : \
        (pfcp_flags & OGS_PFCP_MODIFY_REMOVE) ? \
            OGS_NAS_QOS_CODE_DELETE_EXISTING_QOS_RULE : \
        (pfcp_flags & OGS_PFCP_MODIFY_TFT_NEW) ? \
            OGS_NAS_QOS_CODE_CREATE_NEW_QOS_RULE : \
        (pfcp_flags & OGS_PFCP_MODIFY_TFT_ADD) ? \
            OGS_NAS_QOS_CODE_MODIFY_EXISTING_QOS_RULE_AND_ADD_PACKET_FILTERS : \
        (pfcp_flags & OGS_PFCP_MODIFY_TFT_REPLACE) ? \
            OGS_NAS_QOS_CODE_MODIFY_EXISTING_QOS_RULE_AND_REPLACE_ALL_PACKET_FILTERS : \
        (pfcp_flags & OGS_PFCP_MODIFY_TFT_DELETE) ? \
            OGS_NAS_QOS_CODE_MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS : 0
    uint8_t qos_rule_code;
#define QOS_RULE_FLOW_DESCRIPTION_CODE_FROM_PFCP_FLAGS(pfcp_flags) \
        (pfcp_flags & OGS_PFCP_MODIFY_CREATE) ? \
            OGS_NAS_CREATE_NEW_QOS_FLOW_DESCRIPTION : \
        (pfcp_flags & OGS_PFCP_MODIFY_REMOVE) ? \
            OGS_NAS_DELETE_NEW_QOS_FLOW_DESCRIPTION : \
        (pfcp_flags & OGS_PFCP_MODIFY_QOS_MODIFY) ? \
            OGS_NAS_MODIFY_NEW_QOS_FLOW_DESCRIPTION : 0
    uint8_t qos_flow_description_code;

    uint64_t pfcp_flags;

} smf_nsmf_pdusession_param_t;

typedef struct smf_context_s {
    smf_ctf_config_t    ctf_config;
    const char*         diam_conf_path;   /* SMF Diameter conf path */
    ogs_diam_config_t   *diam_config;     /* SMF Diameter config */

#define MAX_NUM_OF_DNS              2
    const char      *dns[MAX_NUM_OF_DNS];
    const char      *dns6[MAX_NUM_OF_DNS];

#define MAX_NUM_OF_P_CSCF           16
    char            *p_cscf[MAX_NUM_OF_P_CSCF];
    int             num_of_p_cscf;
    int             p_cscf_index;
    char            *p_cscf6[MAX_NUM_OF_P_CSCF];
    int             num_of_p_cscf6;
    int             p_cscf6_index;

    ogs_list_t      sgw_s5c_list;   /* SGW GTPC Node List */
    ogs_list_t      ip_pool_list;

    ogs_hash_t      *supi_hash;     /* hash table (SUPI) */
    ogs_hash_t      *imsi_hash;     /* hash table (IMSI) */
    ogs_hash_t      *ipv4_hash;     /* hash table (IPv4 Address) */
    ogs_hash_t      *ipv6_hash;     /* hash table (IPv6 Address) */
    ogs_hash_t      *smf_n4_seid_hash; /* hash table (SMF-N4-SEID) */
    ogs_hash_t      *n1n2message_hash; /* hash table (N1N2Message Location) */

    uint16_t        mtu;            /* IPv4 link MTU in PCO/ePCO (0x0010); always
                                     * sent when non-zero, even if UE did not
                                     * request it in PCO */
    uint32_t        default_pdr_precedence; /* default bearer DL/UL PDR (TS 29.244);
                                             * UPG-VPP may need e.g. 100 vs 65535 */

    struct  {
        const char *integrity_protection_indication;
        const char *confidentiality_protection_indication;
        const char *maximum_integrity_protected_data_rate_uplink;
        const char *maximum_integrity_protected_data_rate_downlink;
    } security_indication;

    smf_radius_config_t radius;

    /* Per-APN RADIUS overrides parsed from the smf.session list. */
    smf_apn_radius_cfg_t apn_radius[SMF_MAX_APN_RADIUS_CFG];
    int num_apn_radius;

    smf_cdr_config_t cdr;
    /*
     * SMF-wide monotonic counter used as [20] localSequenceNumber in each
     * emitted CDR. Incremented exactly once per record written to the
     * spool. Persisted best-effort via <spool_dir>/.seq at shutdown.
     */
    uint32_t cdr_local_seq;

    /* GTPv2-C Recovery counter (TS 29.274) for Echo/CSR interop */
    uint8_t gtpc_recovery;
    const char *recovery_counter_file;

#define SMF_UE_IS_LAST_SESSION(__sMF) \
     ((__sMF) && (ogs_list_count(&(__sMF)->sess_list)) == 1)
    ogs_list_t      smf_ue_list;

    /* Operator maintenance window (HTTP /admin/maintenance endpoints). */
    bool maintenance_mode;

    /*
     * Collapsed SAEGW-C mode (smf.collapsed: true): accept S11 Create Session
     * Requests directly from the MME and serve as combined SGW-C + PGW-C for
     * local subscribers. Home-routed roamers (CSR whose PGW S5/S8 address is
     * not one of our GTP-C addresses) are rejected until the S8 relay role
     * is implemented (phase 2).
     */
    bool collapsed;

    /*
     * Batched /admin/maintenance/drain bookkeeping (see smf-sm.c).
     * Sessions are drained in fixed-size UE batches paced by a timer so
     * a large drain cannot monopolise the main thread or burst-flood
     * the UPF/PGW with PFCP/GTP deletions.
     */
    uint32_t drain_generation;
    bool     drain_force;
    bool     drain_active;
    uint32_t drain_processed;

    /*
     * Periodic orphan-session sweep (EPC only). An "orphan" is an EPC session
     * that never finished establishment (metrics_session_counted == 0) or has
     * no PFCP session bound to the UPF (upf_n4_seid == 0). The sweep runs on
     * the SMF main thread, publishes the smf_sessions_orphan gauge, and -- when
     * purge is enabled -- tears down orphans older than grace_s (so it never
     * aborts a session that is still being set up).
     */
    struct {
        bool enabled;          /* run the periodic sweep (default true)       */
        bool purge;            /* delete aged orphans (default true)          */
        uint32_t interval_s;   /* sweep period seconds (default 60)           */
        uint32_t grace_s;      /* min orphan age before purge (default 30)    */
        ogs_timer_t *t_sweep;  /* main-thread periodic timer                  */
    } orphan;
} smf_context_t;

typedef struct smf_gtp_node_s {
    ogs_gtp_node_t *gnode;
    ogs_metrics_inst_t *metrics[_SMF_METR_GTP_NODE_MAX];

    /* TS 29.274 Recovery: SGW (S5/S8) peer restart detection */
    uint8_t         peer_recovery;
    bool            peer_recovery_valid;
} smf_gtp_node_t;

typedef struct smf_ue_s {
    ogs_lnode_t lnode;
    ogs_pool_id_t id;

    /* SUPI */
    char *supi;

    /* GPSI */
    char *gpsi;

    /* IMSI */
    uint8_t imsi[OGS_MAX_IMSI_LEN];
    int imsi_len;
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];
    bool metrics_plmn_valid;
    ogs_plmn_id_t metrics_plmn_id;

    /* MSISDN */
    uint8_t msisdn[OGS_MAX_MSISDN_LEN];
    int msisdn_len;
    char msisdn_bcd[OGS_MAX_MSISDN_BCD_LEN+1];

    /* IMEI */
    uint8_t imeisv[OGS_MAX_IMEISV_LEN];
    int imeisv_len;
    char  imeisv_bcd[OGS_MAX_IMEISV_BCD_LEN+1];

    /*
     * smf_context_t.drain_generation under which this UE's sessions were
     * last handed to the batched maintenance drain. 0 = never.
     */
    uint32_t drain_generation;

    /*
     * Stashed Create Session / Create PDP Context while an existing session
     * with the same IMSI+APN is torn down on the UPF (PFCP Session Deletion).
     */
    struct {
        bool pending;
        bool gtp2;
        ogs_pkbuf_t *pkbuf;
        ogs_pool_id_t gtp_xact_id;
        ogs_gtp_node_t *gtp_node;
        uint32_t peer_teid;
        bool peer_teid_presence;
    } collision_replace;

    ogs_list_t sess_list;
} smf_ue_t;

#define SMF_SESS_CLEAR(__sESS) \
    do { \
        smf_ue_t *smf_ue = NULL; \
        smf_sess_t *_sess = smf_sess_find_active_by_id((__sESS)->id); \
        if (!_sess) { \
            ogs_warn("Session already removed (sess_id=%d)", \
                    (int)(__sESS)->id); \
            break; \
        } \
        smf_ue = smf_ue_find_active((_sess)->smf_ue_id); \
        if (!smf_ue) { \
            ogs_warn("UE already removed (sess_id=%d)", (int)(_sess)->id); \
            smf_sess_remove(_sess); \
            break; \
        } \
        if (SMF_UE_IS_LAST_SESSION(smf_ue)) \
            smf_ue_remove(smf_ue); \
        else \
            smf_sess_remove(_sess); \
    } while(0)

typedef struct smf_bearer_s smf_bearer_t;
typedef struct smf_sess_s smf_sess_t;

typedef struct smf_pf_s {
    ogs_lnode_t     lnode;
    ogs_lnode_t     to_add_node;

    ogs_pool_id_t   id;

ED3(uint8_t spare:2;,
    uint8_t direction:2;,
    uint8_t identifier:4;)

    uint8_t precedence;             /* Only used in EPC */

    uint32_t sdf_filter_id;         /* SDF Filter ID */

    uint8_t *identifier_node;       /* Pool-Node for Identifier */
    uint8_t *precedence_node;       /* Pool-Node for Precedence */

    ogs_ipfw_rule_t ipfw_rule;
    char *flow_description;

    ogs_pool_id_t bearer_id;
} smf_pf_t;

typedef struct smf_bearer_s {
    ogs_lnode_t     lnode;          /**< A node of list_t */
    ogs_pool_id_t   id;

    ogs_lnode_t     to_modify_node;
    ogs_lnode_t     to_delete_node;

    ogs_pfcp_pdr_t  *dl_pdr;
    ogs_pfcp_pdr_t  *ul_pdr;
    ogs_pfcp_far_t  *dl_far;
    ogs_pfcp_far_t  *ul_far;
    ogs_pfcp_urr_t  *urr;
    ogs_pfcp_qer_t  *qer;

#define SMF_IS_QOF_FLOW(__bEARER) ((__bEARER)->qfi_node)
    uint8_t         *qfi_node;      /* Pool-Node for 5GC-QFI */
    uint8_t         qfi;            /* 5G Core QFI */
    uint8_t         ebi;            /* EPC EBI */

    uint32_t        pgw_s5u_teid;   /* PGW-S5U TEID */
    ogs_sockaddr_t  *pgw_s5u_addr;  /* PGW-S5U IPv4 */
    ogs_sockaddr_t  *pgw_s5u_addr6; /* PGW-S5U IPv6 */

    uint32_t        sgw_s5u_teid;   /* SGW-S5U TEID */
    ogs_ip_t        sgw_s5u_ip;     /* SGW-S5U IPv4/IPv6 */

    /*
     * Collapsed SAEGW-C S8 relay (sess->s11_relay): the UPF forwards
     * GTP-U between the eNB and the home PGW. The access side reuses
     * pgw_s5u_* (UPF local, advertised to the MME as S1-U SGW) and
     * sgw_s5u_* (eNB, learned from Modify Bearer Request). The core side
     * lives here:
     *   - relay_core_*: UPF local F-TEID facing the home PGW
     *     (advertised in the relayed Create Session Request as
     *     "S5/S8-U SGW F-TEID"),
     *   - relay_pgw_s5u_*: the home PGW S5/S8-U F-TEID (UL FAR target).
     */
    uint32_t        relay_core_teid;
    ogs_sockaddr_t  *relay_core_addr;
    ogs_sockaddr_t  *relay_core_addr6;
    uint32_t        relay_pgw_s5u_teid;
    ogs_ip_t        relay_pgw_s5u_ip;

    struct {
        char        *name;          /* EPC: PCC Rule Name */
        char        *id;            /* 5GC: PCC Rule Id */
    } pcc_rule;
    ogs_qos_t       qos;            /* QoS Information */

    OGS_POOL(pf_identifier_pool, uint8_t);

    /* Packet Filter List */
    ogs_list_t      pf_list;
    ogs_list_t      pf_to_add_list;

    uint8_t num_of_pf_to_delete;
    uint8_t pf_to_delete[OGS_MAX_NUM_OF_FLOW_IN_NAS];

    ogs_pool_id_t   sess_id;
} smf_bearer_t;

#define SMF_SESS(pfcp_sess) ogs_container_of(pfcp_sess, smf_sess_t, pfcp)
typedef struct smf_sess_s {
    ogs_sbi_object_t sbi;
    ogs_pool_id_t id;

    uint32_t        index;              /* An index of this node */
    ogs_pool_id_t   *smf_n4_seid_node;  /* A node of SMF-N4-SEID */

    ogs_fsm_t       sm;             /* A state machine */
    struct {
        bool gx_ccr_init_in_flight; /* Waiting for Gx CCA */
        uint32_t gx_cca_init_err; /* Gx CCA RXed error code */
        bool gy_ccr_init_in_flight; /* Waiting for Gy CCA */
        uint32_t gy_cca_init_err; /* Gy CCA RXed error code */
        bool s6b_aar_in_flight; /* Waiting for S6B AAR */
        uint32_t s6b_aaa_err; /* S6B AAA RXed error code */
        bool gx_ccr_term_in_flight; /* Waiting for Gx CCA */
        uint32_t gx_cca_term_err; /* Gx CCA RXed error code */
        bool gy_ccr_term_in_flight; /* Waiting for Gy CCA */
        uint32_t gy_cca_term_err; /* Gy CCA RXed error code */
        bool s6b_str_in_flight; /* Waiting for S6B CCA */
        uint32_t s6b_sta_err; /* S6B CCA RXed error code */
        ogs_pool_id_t create_gtp_xact_id; /* S5/Gn CSR xact awaiting PFCP */
        bool pfcp_ue_ip_purge_pending; /* Orphan UPF session purge in flight */
        bool pfcp_ue_ip_retry_done; /* PFCP establish retried after IP purge */
        bool gx_restoration_in_flight; /* Gx CCR-I replay after PCRF reconnect */
    } sm_data;

    bool            epc;            /**< EPC or 5GC */

    /*
     * Collapsed SAEGW-C: this EPC session was established over S11 directly
     * from the MME (no SGW-C in the path). The SMF terminates S11 and the
     * UPF terminates S1-U from the eNB:
     *   - sgw_s5c_teid/sgw_s5c_ip hold the MME S11 F-TEID,
     *   - bearer->sgw_s5u_teid/sgw_s5u_ip hold the eNB S1-U F-TEID
     *     (unknown at attach; learned from Modify Bearer Request),
     *   - bearer->pgw_s5u_* (the UPF UL F-TEID) is advertised to the MME as
     *     both "S1-U SGW F-TEID" and "S5/S8-U PGW F-TEID".
     */
    bool            s11;

    /*
     * Collapsed SAEGW-C phase 2 (S8 relay): the PGW S5/S8 address chosen
     * by the MME is NOT this SMF (home-routed roamer). The SMF plays the
     * SGW-C role for this session: it relays GTPv2-C between the MME
     * (S11) and the home PGW (S5/S8) and programs the UPF as a pure
     * GTP-U forwarder (no UE IP anchoring, no Gx/Gy). Implies sess->s11.
     */
    bool            s11_relay;
    uint32_t        pgw_s5c_teid;   /* home PGW S5/S8-C TEID (relay) */
    ogs_ip_t        pgw_s5c_ip;     /* home PGW S5/S8-C IP (relay) */
    ogs_gtp_node_t  *pgw_gnode;     /* home PGW GTP-C node (relay) */

    ogs_time_t      created;        /* session creation epoch (orphan aging) */
    bool            collision_replace; /* Re-attach: wait UPF delete before new CSR */
    unsigned        metrics_session_counted : 1;
    unsigned        metrics_rat_labeled : 1;
    unsigned        metrics_visited_labeled : 1; /* outbound-roaming gauge held */
    char            metrics_rat[16];
    char            metrics_gtp_if[8];

    ogs_pfcp_sess_t pfcp;           /* PFCP session context */

    uint64_t        smpolicycontrol_features; /* SBI features */

    uint32_t        smf_n4_teid;    /* SMF-N4-TEID is derived from NODE */

    uint32_t        sgw_s5c_teid;   /* SGW-S5C-TEID is received from SGW */
    ogs_ip_t        sgw_s5c_ip;     /* SGW-S5C IPv4/IPv6 */

    uint64_t        smf_n4_seid;    /* SMF SEID is derived from NODE */
    uint64_t        upf_n4_seid;    /* UPF SEID is received from Peer */

    uint32_t        local_dl_teid;      /* Local Downlink TEID */
    ogs_sockaddr_t  *local_dl_addr;     /* Local Downlink IPv4 */
    ogs_sockaddr_t  *local_dl_addr6;    /* Local Downlink IPv6 */
    uint32_t        remote_dl_teid;     /* Remote Downlink TEID */
    ogs_ip_t        remote_dl_ip;       /* Remote Downlink IPv4/IPv6 */
    uint32_t        local_ul_teid;      /* Local Uplink TEID */
    ogs_sockaddr_t  *local_ul_addr;     /* Local Uplink IPv4 */
    ogs_sockaddr_t  *local_ul_addr6;    /* Local Uplink IPv6 */
    uint32_t        remote_ul_teid;     /* Remote Uplink TEID */
    ogs_ip_t        remote_ul_ip;       /* Remote Uplink IPv4/IPv6 */

    char            *gx_sid;        /* Gx Session ID */
    char            *gy_sid;        /* Gx Session ID */
    char            *s6b_sid;       /* S6b Session ID */

    OGS_POOL(pf_precedence_pool, uint8_t);

#define CLEAR_QOS_FLOW_ID(__sESS) \
    do { \
        ogs_assert((__sESS)); \
        smf_qfi_pool_final(__sESS); \
        smf_qfi_pool_init(__sESS); \
    } while(0)
    OGS_POOL(qfi_pool, uint8_t);

    uint8_t         psi; /* PDU session identity */
    uint8_t         pti; /* 5GS-NAS : Procedure transaction identity */
    uint8_t         request_type;   /* Request type */

    char            *sm_context_ref; /* smContextRef */
    char            *sm_context_status_uri; /* SmContextStatusNotification */
    struct {
        ogs_sbi_client_t *client;
    } namf;

#define PDU_SESSION_IN_VSMF(__sESS)  \
    ((__sESS) && (__sESS)->pdu_session_ref)
#define STORE_PDU_SESSION(__sESS, __rESOURCE_URI, __rEF) \
    do { \
        ogs_assert(__sESS); \
        ogs_assert(__rESOURCE_URI); \
        ogs_assert(__rEF); \
        CLEAR_PDU_SESSION(__sESS); \
        (__sESS)->pdu_session_resource_uri = ogs_strdup(__rESOURCE_URI); \
        ogs_assert((__sESS)->pdu_session_resource_uri); \
        (__sESS)->pdu_session_ref = ogs_strdup(__rEF); \
        ogs_assert((__sESS)->pdu_session_ref); \
    } while(0);
#define CLEAR_PDU_SESSION(__sESS) \
    do { \
        ogs_assert(__sESS); \
        if ((__sESS)->pdu_session_ref) \
            ogs_free((__sESS)->pdu_session_ref); \
        (__sESS)->pdu_session_ref = NULL; \
        if ((__sESS)->pdu_session_resource_uri) \
            ogs_free((__sESS)->pdu_session_resource_uri); \
        (__sESS)->pdu_session_resource_uri = NULL; \
    } while(0);
    char *pdu_session_ref;
    char *pdu_session_resource_uri;

    /* SMF sends the RESPONSE
     * of [POST] /nsmf-pdusession/v1/pdu-sessions */
    struct {
        ogs_sbi_client_t *client;
    } pdu_session;

    /* PCF sends the RESPONSE
     * of [POST] /npcf-smpolocycontrol/v1/policies */
#define PCF_SM_POLICY_ASSOCIATED(__sESS) \
    ((__sESS) && ((__sESS)->policy_association.id))
#define PCF_SM_POLICY_CLEAR(__sESS) \
    do { \
        ogs_assert((__sESS)); \
        if ((__sESS)->policy_association.resource_uri) \
            ogs_free((__sESS)->policy_association.resource_uri); \
        (__sESS)->policy_association.resource_uri = NULL; \
        if ((__sESS)->policy_association.id) \
            ogs_free((__sESS)->policy_association.id); \
        (__sESS)->policy_association.id = NULL; \
    } while(0)
#define PCF_SM_POLICY_STORE(__sESS, __rESOURCE_URI, __iD) \
    do { \
        ogs_assert((__sESS)); \
        ogs_assert((__rESOURCE_URI)); \
        ogs_assert((__iD)); \
        PCF_SM_POLICY_CLEAR(__sESS); \
        (__sESS)->policy_association.resource_uri = ogs_strdup(__rESOURCE_URI); \
        ogs_assert((__sESS)->policy_association.resource_uri); \
        (__sESS)->policy_association.id = ogs_strdup(__iD); \
        ogs_assert((__sESS)->policy_association.id); \
    } while(0)
    struct {
        char *resource_uri;
        char *id;
        ogs_sbi_client_t *client;
    } policy_association;

    /* SubscriptionId of Subscription to Data Change Notification to UDM */
#define UDM_SDM_SUBSCRIBED(__sESS) \
    ((__sESS) && ((__sESS)->data_change_subscription.id))
#define UDM_SDM_CLEAR(__sESS) \
    do { \
        ogs_assert((__sESS)); \
        if ((__sESS)->data_change_subscription.resource_uri) \
            ogs_free((__sESS)->data_change_subscription.resource_uri); \
        (__sESS)->data_change_subscription.resource_uri = NULL; \
        if ((__sESS)->data_change_subscription.id) \
            ogs_free((__sESS)->data_change_subscription.id); \
        (__sESS)->data_change_subscription.id = NULL; \
    } while(0)
#define UDM_SDM_STORE(__sESS, __rESOURCE_URI, __iD) \
    do { \
        ogs_assert((__sESS)); \
        ogs_assert((__rESOURCE_URI)); \
        ogs_assert((__iD)); \
        UDM_SDM_CLEAR(__sESS); \
        (__sESS)->data_change_subscription.resource_uri = \
            ogs_strdup(__rESOURCE_URI); \
        ogs_assert((__sESS)->data_change_subscription.resource_uri); \
        (__sESS)->data_change_subscription.id = ogs_strdup(__iD); \
        ogs_assert((__sESS)->data_change_subscription.id); \
    } while(0)
    struct {
        char *resource_uri;
        char *id;
        ogs_sbi_client_t *client;
    } data_change_subscription;

    OpenAPI_up_cnx_state_e up_cnx_state;

    /* Serving PLMN ID & Home PLMN ID */
    ogs_plmn_id_t serving_plmn_id;
    ogs_plmn_id_t home_plmn_id;

    /* LTE Location */
    ogs_eps_tai_t   e_tai;
    ogs_e_cgi_t     e_cgi;

    /* Gn User Location Information (parsed from GTPv1 ULI IE) */
    uint8_t         uli_geo_loc_type; /* OGS_GTP1_GEO_LOC_TYPE_* */
    uint16_t        uli_lac;
    uint16_t        uli_rac;
    uint16_t        uli_sac;
    uint16_t        uli_ci;

    /* NR Location */
    ogs_5gs_tai_t   nr_tai;
    ogs_nr_cgi_t    nr_cgi;
    ogs_time_t      ue_location_timestamp;

#define HOME_ROUTED_ROAMING_IN_VSMF(__sESS) \
    ((__sESS) && (__sESS)->h_smf_uri)
    char            *h_smf_uri;
    struct {
        ogs_sbi_client_t *client;
    } h_smf;

    char            *h_smf_id;

    /* Saved from H-SMF */
    ogs_nas_extended_protocol_configuration_options_t
        h_smf_extended_protocol_configuration_options;
    ogs_nas_5gsm_cause_t h_smf_gsm_cause;

    /* Saved from H-SMF */
#define CLEAR_QOS_FLOWS_SETUP_LIST(__lIST) \
    do { \
        OpenAPI_lnode_t *node = NULL; \
        OpenAPI_list_for_each((__lIST), node) { \
            OpenAPI_qos_flow_setup_item_t *qosFlowSetupItem = node->data; \
            if (qosFlowSetupItem) \
                OpenAPI_qos_flow_setup_item_free(qosFlowSetupItem); \
        } \
        OpenAPI_list_free((__lIST)); \
        (__lIST) = NULL; \
    } while(0)
    OpenAPI_list_t *h_smf_qos_flows_setup_list;
#define CLEAR_QOS_FLOWS_ADD_MOD_REQUEST_LIST(__lIST) \
    do { \
        OpenAPI_lnode_t *node = NULL; \
        OpenAPI_list_for_each((__lIST), node) { \
            OpenAPI_qos_flow_add_modify_request_item_t \
                *qosFlowAddModifyRequestItem = node->data; \
            if (qosFlowAddModifyRequestItem) \
                OpenAPI_qos_flow_add_modify_request_item_free( \
                        qosFlowAddModifyRequestItem); \
        } \
        OpenAPI_list_free((__lIST)); \
        (__lIST) = NULL; \
    } while(0)
    OpenAPI_list_t *h_smf_qos_flows_add_mod_request_list;
#define CLEAR_QOS_FLOWS_REL_REQUEST_LIST(__lIST) \
    do { \
        OpenAPI_lnode_t *node = NULL; \
        OpenAPI_list_for_each((__lIST), node) { \
            OpenAPI_qos_flow_release_request_item_t \
                *qosFlowReleaseRequestItem = node->data; \
            if (qosFlowReleaseRequestItem) \
                OpenAPI_qos_flow_release_request_item_free( \
                        qosFlowReleaseRequestItem); \
        } \
        OpenAPI_list_free((__lIST)); \
        (__lIST) = NULL; \
    } while(0)
    OpenAPI_list_t *h_smf_qos_flows_rel_request_list;

#define HOME_ROUTED_ROAMING_IN_HSMF(__sESS) \
    ((__sESS) && (__sESS)->vsmf_pdu_session_uri)
    char            *vsmf_pdu_session_uri;
    struct {
        ogs_sbi_client_t *client;
    } v_smf;

    /*
     * Keeps the n1SmMsg Content (n1smbuf) in the context of the V-SMF
     * for use when creating the n1SmBufFromUe to send to the H-SMF.
     */
    ogs_pkbuf_t     *n1SmBufFromUe;

    /* PCF ID */
    char            *pcf_id;

    /* Serving NF (AMF) Id */
    char            *amf_nf_id;

    /* Guami */
    ogs_guami_t     guami;

    /* Integrity protection maximum data rate */
    struct {
        OpenAPI_max_integrity_protected_data_rate_e mbr_dl;
        OpenAPI_max_integrity_protected_data_rate_e mbr_ul;
    } integrity_protection;

    /* S_NSSAI */
    ogs_s_nssai_t s_nssai;
    ogs_s_nssai_t mapped_hplmn;
    bool mapped_hplmn_presence;

    /* PDN Configuration */
    ogs_session_t session;
    uint8_t ue_session_type;
    uint8_t ue_ssc_mode;

    /* PDN Address Allocation (PAA) */
    ogs_paa_t paa;

    /* DNN */
    char *full_dnn;
    ogs_pfcp_ue_ip_t *ipv4;
    ogs_pfcp_ue_ip_t *ipv6;

    /* AN Type */
    OpenAPI_access_type_e an_type;

    /* RAT Type */
    uint8_t gtp_rat_type;
    OpenAPI_rat_type_e sbi_rat_type;

    struct {
        uint8_t version; /* GTPC version */
        ogs_tlv_octet_t ue_pco;
        ogs_tlv_octet_t ue_apco;
        ogs_tlv_octet_t ue_epco;
        ogs_tlv_octet_t user_location_information;
        ogs_tlv_octet_t ue_timezone;
        ogs_tlv_octet_t charging_characteristics;
        bool create_session_response_apn_ambr;
        bool create_session_response_bearer_qos;
        uint8_t selection_mode; /* OGS_GTP{1,2}_SELECTION_MODE_*, same in GTPv1C and 2C. */
        struct {
            uint8_t nsapi;
            ogs_gtp1_common_flags_t common_flags;
            ogs_tlv_octet_t qos; /* Encoded GTPv1C "QoS Profile" IE */
            ogs_gtp1_qos_profile_decoded_t qos_pdec;
            bool peer_supports_apn_ambr;
        } v1;  /* GTPv1C specific fields */
    } gtp; /* Saved from S5-C/Gn */

    struct {
        uint64_t ul_octets;
        uint64_t dl_octets;
        ogs_time_t duration;
        uint32_t reporting_reason; /* OGS_DIAM_GY_REPORTING_REASON_* */
        /* Whether Gy Final-Unit-Indication was received.
         * Triggers session release upon Rx of next PFCP Report Req */
        bool final_unit;
        /* Snapshot of measurement when last report was sent: */
        struct {
            uint64_t ul_octets;
            uint64_t dl_octets;
            ogs_time_t duration;
        } last_report;
    } gy;

    struct {
        ogs_nas_extended_protocol_configuration_options_t ue_epco;
    } nas; /* Saved from NAS-5GS */

    struct {
        ogs_pcc_rule_t  pcc_rule[OGS_MAX_NUM_OF_PCC_RULE];
        int             num_of_pcc_rule;
    } policy; /* Saved from N7 or Gx */

    /* Paging */
    struct {
        char *n1n2message_location;
    } paging;

    /* State */
#define SMF_NGAP_STATE_NONE                                     0
#define SMF_NGAP_STATE_DELETE_TRIGGER_UE_REQUESTED              1
#define SMF_NGAP_STATE_DELETE_TRIGGER_PCF_INITIATED             2
#define SMF_NGAP_STATE_ERROR_INDICATION_RECEIVED_FROM_5G_AN     3
#define SMF_NGAP_STATE_DELETE_TRIGGER_SMF_INITIATED             4
    struct {
        int pdu_session_resource_release;
    } ngap_state;

    /* Handover */
    struct {
        bool prepared;
        bool data_forwarding_not_possible;
        bool indirect_data_forwarding;

        /* NG-U UP Transport Information Saved Temporally */
        uint32_t gnb_n3_teid;
        ogs_ip_t gnb_n3_ip;

        /* Indirect DL Forwarding */
        uint32_t local_dl_teid;
        ogs_sockaddr_t *local_dl_addr;
        ogs_sockaddr_t *local_dl_addr6;
        uint32_t remote_dl_teid;
        ogs_ip_t remote_dl_ip;
    } handover;

    /* Charging */
    struct {
        uint32_t id;
    } charging;

    /* AAA Node Identifier */
    struct {
        char *name;
        char *realm;
    } aaa_server_identifier;

    /* Data Forwarding between the CP and UP functions */
    ogs_pfcp_pdr_t  *cp2up_pdr;
    ogs_pfcp_pdr_t  *up2cp_pdr;
    ogs_pfcp_far_t  *cp2up_far;
    ogs_pfcp_far_t  *up2cp_far;

    ogs_list_t      bearer_list;

    ogs_list_t      pdr_to_modify_list;
    ogs_list_t      qos_flow_to_modify_list;

    ogs_gtp_node_t  *gnode;
    ogs_pfcp_node_t *pfcp_node;

    ogs_pool_id_t smf_ue_id;

    OpenAPI_resource_status_e resource_status;
    bool n1_released;
    bool n2_released;
/*
 * Section 4.3.3.3 'UE or network requested PDU Session Modification
 * (home-routed roaming)'
 * - Step 1a: Nsmf_PDUSession_UpdateSMContext Request (AMF -> V-SMF):
 * - Step 4a: Nsmf_PDUSession_UpdateSMContext Response (V-SMF -> AMF):
 */
    ogs_pool_id_t amf_to_vsmf_modify_stream_id;
/*
 * Section 4.3.3.3 'UE or network requested PDU Session Modification
 * (home-routed roaming)'
 * - Step 3:  Nsmf_PDUSession_UpdateSMContext Request (V-SMF -> H-SMF):
 * - Step 15: Nsmf_PDUSession_UpdateSMContext Response (V-SMF -> H-SMF):
 */
    ogs_pool_id_t vsmf_to_hsmf_modify_stream_id;
/*
 * Section 4.3.4.3 'UE or network requested PDU Session Release for
 * Home-routed Roaming'
 * - Step 1a: Nsmf_PDUSession_UpdateSMContext Request (AMF -> V-SMF):
 * - Step 5b: Nsmf_PDUSession_UpdateSMContext Response (V-SMF -> AMF):
 */
    ogs_pool_id_t amf_to_vsmf_release_stream_id;
/*
 * Section 4.3.4.3 'UE or network requested PDU Session Release for
 * Home-routed Roaming'
 * - Step 3a: Nsmf_PDUSession_UpdateSMContext Request (V-SMF -> H-SMF):
 * - Step 14: Nsmf_PDUSession_UpdateSMContext Response (V-SMF -> H-SMF):
 */
    ogs_pool_id_t vsmf_to_hsmf_release_stream_id;

    smf_nsmf_pdusession_param_t nsmf_param;

    bool establishment_accept_sent;
    ogs_sbi_xact_t *pending_modification_xact;

    /*
     * CDR bookkeeping (filled by src/smf/ga-writer.c). Independent from
     * the radius accounting block so the two can run in parallel.
     */
    struct {
        /* Epoch of session establishment; source of both recordOpeningTime
         * and startTime in the CDR, and basis for the duration field. */
        ogs_time_t start_time;

        /* Per-session counter used as [17] recordSequenceNumber. Starts
         * at 1 for the first partial record and is bumped on every
         * interim/stop record emitted for this session. */
        uint32_t record_seq;

        /* Running snapshot of UL/DL volumes at the time of the last
         * emitted partial record, so the next partial can carry a
         * per-bucket delta in [12] listOfTrafficVolumes when desired. */
        uint64_t last_ul_octets;
        uint64_t last_dl_octets;
        ogs_time_t last_change_time;

        /* TS 32.298 [15] causeForRecClosing. Captured by callers just
         * before smf_sess_remove() so the stop CDR knows why. Default
         * 0 (normalRelease). */
        uint8_t cause_for_rec_closing;
    } cdr;

    struct {
        char *acct_session_id;
        bool acct_started;

        /*
         * RFC 2865 §5.25: raw concatenation of every Class attribute
         * value received in Access-Accept. Echoed verbatim in every
         * Accounting-Request (Start / Interim-Update / Stop).
         */
        uint8_t *class_buf;
        size_t class_len;

        /*
         * Index into smf_self()->radius.servers[] that accepted this
         * session's Access-Accept. Used to keep Interim/Stop for the
         * same session on the same AAA (important for accounting
         * coherence on the server side). -1 = not yet assigned.
         */
        int server_idx;

        /* For Acct-Session-Time */
        ogs_time_t start_time;

        /*
         * PoD teardown watchdog (EPC only).
         *
         * Armed after the SMF sends a GTPv2 Delete Bearer Request in
         * response to a RADIUS Disconnect. If the MME fails to reply
         * within pod_teardown_timeout_ms, the timer forces local
         * PFCP-session deletion so Accounting-Stop is still emitted.
         */
        ogs_timer_t *teardown_timer;
    } radius;

} smf_sess_t;

void smf_context_init(void);
void smf_context_final(void);
smf_context_t *smf_self(void);

int smf_context_parse_config(void);

int smf_use_gy_iface(void);

smf_gtp_node_t *smf_gtp_node_new(ogs_gtp_node_t *gnode);
void smf_gtp_node_free(smf_gtp_node_t *smf_gnode);

/*
 * TS 29.274 Recovery: compare the SGW (S5/S8) peer's restart counter against
 * the last seen value. On an increment (peer restart) delete all PDN
 * connections anchored on that SGW. Returns true if a restart was detected.
 */
bool smf_sgw_recovery_update(smf_gtp_node_t *smf_gnode, uint8_t recovery);

smf_ue_t *smf_ue_add_by_supi(char *supi);
smf_ue_t *smf_ue_add_by_imsi(uint8_t *imsi, int imsi_len);
void smf_ue_remove(smf_ue_t *smf_ue);
void smf_ue_remove_all(void);
smf_ue_t *smf_ue_find_by_supi(char *supi);
smf_ue_t *smf_ue_find_by_imsi(uint8_t *imsi, int imsi_len);
smf_ue_t *smf_ue_find_by_imsi_bcd(const char *imsi_bcd);
void smf_home_plmn_from_imsi_bcd(const char *imsi_bcd, ogs_plmn_id_t *plmn_id);

smf_sess_t *smf_sess_add_by_gtp1_message(ogs_gtp1_message_t *message);
smf_sess_t *smf_sess_add_by_gtp2_message(ogs_gtp2_message_t *message);
smf_sess_t *smf_sess_add_by_apn(smf_ue_t *smf_ue, char *apn, uint8_t rat_type);

smf_sess_t *smf_sess_add_by_sm_context(ogs_sbi_message_t *message);
smf_sess_t *smf_sess_add_by_pdu_session(ogs_sbi_message_t *message);
smf_sess_t *smf_sess_add_by_psi(smf_ue_t *smf_ue, uint8_t psi);

/*
 * PFCP Network Instance toward UPF/VPP (PDR/FAR NWI, Session Establishment
 * apn_dnn, GTP-U resource / FTUP selection). Outbound/inbound roam CSR
 * carries a full APN (e.g. hiweb.mnc012.mcc432.gprs) stored in full_dnn;
 * VPP keys distinct GTP-U endpoints by that NWI. Home NI-only sessions
 * keep session.name. Subnet / RADIUS / UPF peer selection still use NI.
 */
static ogs_inline const char *smf_sess_nwi_for_pfcp(smf_sess_t *sess)
{
    ogs_assert(sess);
    if (sess->full_dnn && sess->full_dnn[0])
        return sess->full_dnn;
    ogs_assert(sess->session.name);
    return sess->session.name;
}

void smf_sess_select_upf(smf_sess_t *sess);
uint8_t smf_sess_set_ue_ip(smf_sess_t *sess);
void smf_sess_set_paging_n1n2message_location(
        smf_sess_t *sess, char *n1n2message_location);

void smf_sess_remove(smf_sess_t *sess);
void smf_sess_remove_all(smf_ue_t *smf_ue);

/*
 * Walk every EPC session and account orphans. When do_purge is true, tear down
 * orphans whose age exceeds 'grace' (use 0 to ignore age). Returns the number
 * of orphan sessions still present after the sweep (the live backlog); if
 * out_purged is non-NULL it receives how many were torn down. Main thread only.
 */
int smf_orphan_sweep(bool do_purge, ogs_time_t grace, int *out_purged);

/* Periodic orphan sweep timer (no-op when smf.orphan.enabled is false). */
void smf_orphan_timer_start(void);
void smf_orphan_timer_stop(void);

bool smf_gtp_apn_parse(
        char *apn_ni, char **full_apn_out,
        void *apn_data, int apn_len);

smf_sess_t *smf_sess_find(uint32_t index);
smf_sess_t *smf_sess_find_by_teid(uint32_t teid);
smf_sess_t *smf_sess_find_by_seid(uint64_t seid);
/* Pool entry still linked on the UE sess_list (not mid-teardown). */
smf_sess_t *smf_sess_find_active_by_id(ogs_pool_id_t id);
smf_sess_t *smf_sess_find_active_by_seid(uint64_t seid);
#define smf_sess_find_active_by_teid(teid) smf_sess_find_active_by_seid(teid)
smf_sess_t *smf_sess_find_by_apn(smf_ue_t *smf_ue, char *apn, uint8_t rat_type);
smf_sess_t *smf_sess_find_by_psi(smf_ue_t *smf_ue, uint8_t psi);
smf_sess_t *smf_sess_find_by_charging_id(uint32_t charging_id);
smf_sess_t *smf_sess_find_by_sm_context_ref(char *sm_context_ref);
smf_sess_t *smf_sess_find_by_pdu_session_ref(char *pdu_session_ref);
smf_sess_t *smf_sess_find_by_ipv4(uint32_t addr);
smf_sess_t *smf_sess_find_by_ipv6(uint32_t *addr6);
smf_sess_t *smf_sess_find_by_paging_n1n2message_location(
        char *n1n2message_location);

void smf_sess_create_indirect_data_forwarding(smf_sess_t *sess);
bool smf_sess_have_indirect_data_forwarding(smf_sess_t *sess);
void smf_sess_delete_indirect_data_forwarding(smf_sess_t *sess);

void smf_sess_create_cp_up_data_forwarding(smf_sess_t *sess);
void smf_sess_delete_cp_up_data_forwarding(smf_sess_t *sess);

ogs_pcc_rule_t *smf_pcc_rule_find_by_id(smf_sess_t *sess, char *pcc_rule_id);

smf_bearer_t *smf_qos_flow_add(smf_sess_t *sess);
smf_bearer_t *smf_qos_flow_find_by_qfi(smf_sess_t *sess, uint8_t qfi);
smf_bearer_t *smf_qos_flow_find_by_pcc_rule_id(
        smf_sess_t *sess, char *pcc_rule_id);

smf_bearer_t *smf_vcn_tunnel_add(smf_sess_t *sess);

smf_bearer_t *smf_bearer_add(smf_sess_t *sess);
int smf_bearer_remove(smf_bearer_t *bearer);
void smf_bearer_remove_all(smf_sess_t *sess);
smf_bearer_t *smf_bearer_find_by_pgw_s5u_teid(
        smf_sess_t *sess, uint32_t pgw_s5u_teid);
smf_bearer_t *smf_bearer_find_by_ebi(smf_sess_t *sess, uint8_t ebi);
smf_bearer_t *smf_bearer_find_by_pcc_rule_name(
        smf_sess_t *sess, char *pcc_rule_name);
smf_bearer_t *smf_bearer_find_by_pdr_id(
        smf_sess_t *sess, ogs_pfcp_pdr_id_t pdr_id);
smf_bearer_t *smf_default_bearer_in_sess(smf_sess_t *sess);

void smf_bearer_tft_update(smf_bearer_t *bearer);
void smf_bearer_qos_update(smf_bearer_t *bearer);

smf_ue_t *smf_ue_find_by_id(ogs_pool_id_t id);
smf_ue_t *smf_ue_find_active(ogs_pool_id_t id);
smf_sess_t *smf_sess_find_by_id(ogs_pool_id_t id);
bool smf_pfcp_peer_in_use(const ogs_pfcp_node_t *node);
smf_bearer_t *smf_bearer_find_by_id(ogs_pool_id_t id);
smf_bearer_t *smf_qos_flow_find_by_id(ogs_pool_id_t id);
smf_pf_t *smf_pf_find_by_id(ogs_pool_id_t id);

smf_pf_t *smf_pf_add(smf_bearer_t *bearer);
int smf_pf_remove(smf_pf_t *pf);
void smf_pf_remove_all(smf_bearer_t *bearer);
smf_pf_t *smf_pf_find_by_identifier(
        smf_bearer_t *bearer, uint8_t identifier);
smf_pf_t *smf_pf_find_by_flow(
    smf_bearer_t *bearer, uint8_t direction, char *flow_description);
smf_pf_t *smf_pf_first(smf_bearer_t *bearer);
smf_pf_t *smf_pf_next(smf_pf_t *pf);

int smf_pco_build(uint8_t *pco_buf, uint8_t *buffer, int length);

void smf_qfi_pool_init(smf_sess_t *sess);
void smf_qfi_pool_final(smf_sess_t *sess);

void smf_pf_identifier_pool_init(smf_bearer_t *bearer);
void smf_pf_identifier_pool_final(smf_bearer_t *bearer);

void smf_pf_precedence_pool_init(smf_sess_t *sess);
void smf_pf_precedence_pool_final(smf_sess_t *sess);

int smf_integrity_protection_indication_value2enum(const char *value);
int smf_confidentiality_protection_indication_value2enum(const char *value);
int smf_maximum_integrity_protected_data_rate_uplink_value2enum(
        const char *value);
int smf_maximum_integrity_protected_data_rate_downlink_value2enum(
        const char *value);
int smf_instance_get_load(void);

#ifdef __cplusplus
}
#endif

#endif /* SMF_CONTEXT_H */
