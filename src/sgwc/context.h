/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef SGWC_CONTEXT_H
#define SGWC_CONTEXT_H

#include "ogs-app.h"
#include "ogs-gtp.h"
#include "ogs-pfcp.h"

#include "timer.h"
#include "sgwc-sm.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __sgwc_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __sgwc_log_domain

typedef struct sgwc_tunnel_s sgwc_tunnel_t;

typedef struct sgwc_sgwu_nwi_rewrite_rule_s {
    ogs_lnode_t lnode;
    char *match;
    char *replace;
} sgwc_sgwu_nwi_rewrite_rule_t;

typedef struct sgwc_mme_peer_s {
    ogs_gtp_node_t *gnode;
    uint8_t peer_recovery;
    bool peer_recovery_valid;
    ogs_timer_t *t_echo;
} sgwc_mme_peer_t;

typedef struct sgwc_pgw_peer_s {
    ogs_gtp_node_t *gnode;
    uint8_t peer_recovery;
    bool peer_recovery_valid;
    ogs_timer_t *t_echo;
} sgwc_pgw_peer_t;

/*
 * Ga / GTP' offline SGW-CDR writer (see lib/cdr/framing.h).
 * Records use OGS_CDR_FORMAT_BER_SGW in the spool header.
 */
typedef struct sgwc_cdr_config_s {
    bool enabled;

    const char *spool_dir;
    const char *node_id;
    const char *local_address;  /* SGW S5/S11 address for CDR [4] s-GWAddress */

    uint32_t interim_interval_s;   /* URR time_threshold, default 300 */
    uint32_t rotate_max_records;
    uint32_t rotate_max_bytes;
    uint32_t rotate_max_seconds;

    uint32_t triggers;
#define SGWC_CDR_TRIG_START           (1u << 0)
#define SGWC_CDR_TRIG_INTERIM         (1u << 1)
#define SGWC_CDR_TRIG_STOP            (1u << 2)
} sgwc_cdr_config_t;

typedef struct sgwc_context_s {
    ogs_list_t mme_s11_list;    /* MME GTPC Node List */
    ogs_list_t pgw_s5c_list;    /* PGW GTPC Node List */

    sgwc_cdr_config_t cdr;
    uint32_t cdr_local_seq;

    ogs_hash_t *imsi_ue_hash;   /* hash table (IMSI : SGW_UE) */
    ogs_hash_t *sgw_s11_teid_hash;  /* hash table (SGW-S11-TEID : SGW_UE) */
    ogs_hash_t *sgwc_sxa_seid_hash; /* hash table (SGWC-SXA-SEID : Session) */

    ogs_list_t sgw_ue_list;    /* SGW_UE List */

    /* GTPv2-C Recovery counter (TS 29.274) for Echo/CSR interop */
    uint8_t gtpc_recovery;
    uint32_t gtpc_echo_interval; /* S11 echo period in seconds (0=60) */

    /*
     * Inbound roam S5: optional local UDP bind (source port only).
     * PGW destination stays gtpc.server.port (2123). Replies to source port
     * are received on this second socket.
     */
    uint16_t inbound_roam_gtpc_source_port;
    /* Include Recovery IE on forwarded S5 Create Session Request. */
    bool inbound_roam_gtpc_send_recovery_on_s5_csr;
    /* Added to pool TEIDs for inbound-roam S11/S5-C (and PFCP SEID lookup). */
    uint32_t inbound_roam_teid_offset;

    /*
     * GTP-U: force SGWC to assign local F-TEID (CH=0) instead of UP (FTUP).
     * teid_offset / teid_range_* apply when encoding pdr->teid for PFCP/GTP-U.
     */
    bool gtpu_force_cp_teid;
    uint32_t gtpu_teid_offset;
    uint8_t gtpu_teid_range_indication;
    uint8_t gtpu_teid_range;

    bool inbound_roam_gtpu_force_cp_teid;
    uint32_t inbound_roam_gtpu_teid_offset;
    uint8_t inbound_roam_gtpu_teid_range_indication;
    uint8_t inbound_roam_gtpu_teid_range;

    ogs_sock_t *roam_gtpc_sock;
    ogs_sock_t *roam_gtpc_sock6;
    ogs_sockaddr_t *roam_gtpc_addr;
    ogs_sockaddr_t *roam_gtpc_addr6;
    ogs_poll_t *roam_gtpc_poll;
    ogs_poll_t *roam_gtpc_poll6;

    /*
     * PFCP Network Instance sent to SGW-U (UPG/VPP): optional rewrite rules.
     * Default NWI is the session APN from GTP. match supports * (case-insensitive).
     */
    ogs_list_t sgwu_nwi_rewrite_list;

    /* Operator maintenance window (/admin/maintenance/*). */
    bool maintenance_mode;
} sgwc_context_t;

typedef struct sgwc_ue_s {
    ogs_lnode_t     lnode;
    ogs_pool_id_t   id;
    ogs_pool_id_t   *sgw_s11_teid_node; /* A node of SGW-S11-TEID */

    uint32_t        sgw_s11_teid;   /* SGW-S11-TEID is derived from NODE */
    uint32_t        mme_s11_teid;   /* MME-S11-TEID is received from MME */

    /* UE identity */
    uint8_t         imsi[OGS_MAX_IMSI_LEN];
    int             imsi_len;
    char            imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    uint8_t         msisdn[OGS_MAX_MSISDN_LEN];
    int             msisdn_len;
    char            msisdn_bcd[OGS_MAX_MSISDN_BCD_LEN+1];

    /* User-Location-Info */
    bool            uli_presence;
    ogs_eps_tai_t   e_tai;
    ogs_e_cgi_t     e_cgi;
    ogs_pkbuf_t     *uli_pkbuf;   /* raw GTPv2 ULI for CDR [32] */

    ogs_list_t      sess_list;

    ogs_gtp_node_t  *gnode;

    /*
     * Deferred Create Session while replacing an existing session (EBI
     * collision): wait for PFCP Session Deletion on the old session before
     * allocating a new one (avoids SEID reuse while UPF still has old session).
     */
    ogs_pool_id_t   csr_replace_s11_xact_id;
    ogs_pkbuf_t     *csr_replace_gtpbuf;
    ogs_pool_id_t   csr_replace_sess_id;
} sgwc_ue_t;

#define SGWC_SESS(pfcp_sess) ogs_container_of(pfcp_sess, sgwc_sess_t, pfcp)
typedef struct sgwc_sess_s {
    ogs_lnode_t     lnode;                  /* A node of list_t */
    ogs_pool_id_t   id;
    ogs_pool_id_t   *sgwc_sxa_seid_node;    /* A node of SGWC-SXA-SEID */

    ogs_pfcp_sess_t pfcp;           /* PFCP session context */

    uint32_t        sgw_s5c_teid;   /* SGW-S5C-TEID is derived from NODE */
    uint32_t        pgw_s5c_teid;   /* PGW-S5C-TEID is received from PGW */

    uint64_t        sgwc_sxa_seid;  /* SGW-C SEID is derived from NODE */
    uint64_t        sgwu_sxa_seid;  /* SGW-U SEID is received from Peer */

    /* APN Configuration */
    ogs_session_t   session;

    /* PDN Address Allocation (PAA) */
    ogs_paa_t       paa;

    uint32_t        charging_id;

    /* Usage from PFCP URR reports (interval deltas summed). */
    uint64_t        usage_ul_octets;
    uint64_t        usage_dl_octets;

    struct {
        ogs_time_t start_time;
        uint32_t record_seq;
        uint64_t last_ul_octets;
        uint64_t last_dl_octets;
        uint32_t last_interval_duration_s;
        uint8_t cause_for_rec_closing;
    } cdr;

    ogs_plmn_id_t   serving_plmn_id;

    ogs_list_t      bearer_list;

    /* Related Context */
    ogs_gtp_node_t  *gnode;
    ogs_pfcp_node_t *pfcp_node;

    ogs_pool_id_t   sgwc_ue_id;

    /* Monotonic start time for create-session latency logging */
    ogs_time_t      create_session_t0;
} sgwc_sess_t;

static inline void sgwc_create_session_phase(
        sgwc_sess_t *sess, sgwc_ue_t *ue, const char *phase)
{
    ogs_time_t elapsed;

    if (!sess || !ue || !phase || !phase[0] || !sess->create_session_t0)
        return;

    elapsed = ogs_time_now() - sess->create_session_t0;
    ogs_info("[%s] create-session phase=%s elapsed=%llums",
            ue->imsi_bcd, phase,
            (unsigned long long)ogs_time_to_msec(elapsed));
}

typedef struct sgwc_bearer_s {
    ogs_lnode_t     lnode;
    ogs_pool_id_t   id;
    ogs_lnode_t     to_modify_node;

    uint8_t         ebi;

    ogs_pfcp_urr_t  *urr;

    ogs_list_t      tunnel_list;
    ogs_pool_id_t   sess_id;
    ogs_pool_id_t   sgwc_ue_id;
} sgwc_bearer_t;

typedef struct sgwc_tunnel_s {
    ogs_lnode_t     lnode;
    ogs_pool_id_t   id;

    uint8_t         interface_type;

    ogs_pfcp_pdr_t  *pdr;
    ogs_pfcp_far_t  *far;

    uint32_t        local_teid;
    ogs_sockaddr_t  *local_addr;
    ogs_sockaddr_t  *local_addr6;

    uint32_t        remote_teid;
    ogs_ip_t        remote_ip;

    /* Related Context */
    ogs_pool_id_t   bearer_id;
    ogs_gtp_node_t  *gnode;
} sgwc_tunnel_t;

void sgwc_context_init(void);
void sgwc_context_final(void);
sgwc_context_t *sgwc_self(void);

int sgwc_context_parse_config(void);

sgwc_mme_peer_t *sgwc_mme_peer_get(ogs_gtp_node_t *gnode);
void sgwc_mme_peer_attach(ogs_gtp_node_t *gnode);
void sgwc_mme_peer_detach(ogs_gtp_node_t *gnode);
bool sgwc_mme_recovery_update(sgwc_mme_peer_t *peer, uint8_t recovery);
void sgwc_mme_echo_schedule(sgwc_mme_peer_t *peer);
void sgwc_mme_echo_reschedule_all(void);

sgwc_pgw_peer_t *sgwc_pgw_peer_get(ogs_gtp_node_t *gnode);
void sgwc_pgw_peer_attach(ogs_gtp_node_t *gnode);
void sgwc_pgw_peer_detach(ogs_gtp_node_t *gnode);
bool sgwc_pgw_recovery_update(sgwc_pgw_peer_t *peer, uint8_t recovery);
void sgwc_pgw_echo_schedule(sgwc_pgw_peer_t *peer);
void sgwc_pgw_echo_reschedule_all(void);

sgwc_ue_t *sgwc_ue_add_by_message(ogs_gtp2_message_t *message);
sgwc_ue_t *sgwc_ue_find_by_imsi(uint8_t *imsi, int imsi_len);
sgwc_ue_t *sgwc_ue_find_by_imsi_bcd(char *imsi_bcd);
sgwc_ue_t *sgwc_ue_find_by_teid(uint32_t teid);

sgwc_ue_t *sgwc_ue_add(uint8_t *imsi, int imsi_len);
int sgwc_ue_remove(sgwc_ue_t *sgwc_ue);
void sgwc_ue_remove_all(void);
sgwc_ue_t *sgwc_ue_find_by_id(ogs_pool_id_t id);

sgwc_sess_t *sgwc_sess_add(sgwc_ue_t *sgwc_ue, char *apn);

bool sgwc_sess_is_inbound_roam(sgwc_sess_t *sess);
void sgwc_inbound_roam_teid_offset_apply(sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess);
void sgwc_sess_sync_pfcp_pdr_nwi(sgwc_sess_t *sess);

void sgwc_sess_select_sgwu(sgwc_sess_t *sess);

int sgwc_sess_remove(sgwc_sess_t *sess);
void sgwc_sess_purge_upf(sgwc_sess_t *sess);
void sgwc_sess_remove_all(sgwc_ue_t *sgwc_ue);

bool sgwc_sess_s5c_teid_matches(sgwc_sess_t *sess, uint32_t teid);
sgwc_sess_t *sgwc_sess_find_by_teid(uint32_t teid);
sgwc_sess_t *sgwc_sess_find_by_seid(uint64_t seid);

sgwc_sess_t *sgwc_sess_find_by_apn(sgwc_ue_t *sgwc_ue, char *apn);
sgwc_sess_t *sgwc_sess_find_by_ebi(sgwc_ue_t *sgwc_ue, uint8_t ebi);
sgwc_sess_t *sgwc_sess_find_by_id(ogs_pool_id_t id);

#define SGWC_SESSION_SYNC_DONE(__sGWC, __tYPE, __fLAGS) \
    (sgwc_sess_pfcp_xact_count(__sGWC, __tYPE, __fLAGS) == 0)
int sgwc_sess_pfcp_xact_count(
        sgwc_ue_t *sgwc_ue, uint8_t pfcp_type, uint64_t modify_flags);

ogs_pfcp_xact_t *sgwc_pfcp_find_session_modify_xact(
        sgwc_sess_t *sess, uint64_t modify_flags);

sgwc_bearer_t *sgwc_bearer_add(sgwc_sess_t *sess);
int sgwc_bearer_remove(sgwc_bearer_t *bearer);
void sgwc_bearer_remove_all(sgwc_sess_t *sess);
sgwc_bearer_t *sgwc_bearer_find_by_sess_ebi(
                                sgwc_sess_t *sess, uint8_t ebi);
sgwc_bearer_t *sgwc_bearer_find_by_ue_ebi(
                                sgwc_ue_t *sgwc_ue, uint8_t ebi);
sgwc_bearer_t *sgwc_default_bearer_in_sess(sgwc_sess_t *sess);
sgwc_bearer_t *sgwc_bearer_find_by_id(ogs_pool_id_t id);

sgwc_tunnel_t *sgwc_tunnel_add(
        sgwc_bearer_t *bearer, uint8_t interface_type);
int sgwc_tunnel_remove(sgwc_tunnel_t *tunnel);
void sgwc_tunnel_remove_all(sgwc_bearer_t *bearer);
sgwc_tunnel_t *sgwc_tunnel_find_by_teid(sgwc_ue_t *sgwc_ue, uint32_t teid);
sgwc_tunnel_t *sgwc_tunnel_find_by_interface_type(
        sgwc_bearer_t *bearer, uint8_t interface_type);
sgwc_tunnel_t *sgwc_tunnel_find_by_pdr_id(
        sgwc_sess_t *sess, ogs_pfcp_pdr_id_t pdr_id);
sgwc_tunnel_t *sgwc_tunnel_find_by_far_id(
        sgwc_sess_t *sess, ogs_pfcp_far_id_t far_id);
sgwc_tunnel_t *sgwc_dl_tunnel_in_bearer(sgwc_bearer_t *bearer);
sgwc_tunnel_t *sgwc_ul_tunnel_in_bearer(sgwc_bearer_t *bearer);
sgwc_tunnel_t *sgwc_tunnel_find_by_id(ogs_pool_id_t id);

void sgwc_bearer_urr_setup(sgwc_bearer_t *bearer);
void sgwc_ue_store_uli_raw(sgwc_ue_t *sgwc_ue, void *data, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_CONTEXT_H */
