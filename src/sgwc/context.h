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
    int selection_order;
} sgwc_sgwu_nwi_rewrite_rule_t;

typedef struct sgwc_gn_pgw_s {
    ogs_lnode_t lnode;
    char imsi_prefix[OGS_MAX_IMSI_BCD_LEN+1];
    int selection_order;
    ogs_gtp2_f_teid_t f_teid;
    int f_teid_len;
} sgwc_gn_pgw_t;

typedef struct sgwc_mme_peer_s {
    ogs_gtp_node_t *gnode;
    uint8_t peer_recovery;
    bool peer_recovery_valid;
    ogs_timer_t *t_echo;
    bool echo_pending; /* worker deferred start onto main timer_mgr */
} sgwc_mme_peer_t;

typedef struct sgwc_sgsn_peer_s {
    ogs_gtp_node_t *gnode;
    ogs_timer_t *t_echo;
    bool echo_pending;
} sgwc_sgsn_peer_t;

typedef struct sgwc_pgw_peer_s {
    ogs_gtp_node_t *gnode;
    uint8_t peer_recovery;
    bool peer_recovery_valid;
    ogs_timer_t *t_echo;
    bool echo_pending;
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

/*
 * Periodic orphan-session sweep.
 *
 * An "orphan" is a session that never finished establishment
 * (metrics_session_counted == 0) or has no PFCP session bound to SGW-U
 * (sgwu_sxa_seid == 0). The sweep runs on the SGW-C main thread, publishes
 * the current orphan backlog to the sgwc_sessions_orphan gauge, and -- when
 * purge is enabled -- tears down orphans older than grace_s (so it never
 * aborts an attach that is still in flight).
 */
typedef struct sgwc_orphan_config_s {
    bool enabled;          /* run the periodic sweep at all (default true)   */
    bool purge;            /* actually delete aged orphans (default true)    */
    uint32_t interval_s;   /* sweep period in seconds (default 60)           */
    uint32_t grace_s;      /* min orphan age before purging (default 30)     */
    ogs_timer_t *t_sweep;  /* main-thread periodic timer                     */
} sgwc_orphan_config_t;

/*
 * DL FAR BUFFER idle policy (TS 29.244 apply-action DROP after page fail /
 * long idle). Stops UPF buffering forever when the UE never returns.
 */
typedef struct sgwc_buffer_idle_config_s {
    bool enabled;          /* default true */
    /*
     * Blanket idle BUFF→DROP conversion (default false). Idle BUFF|NOCP
     * sessions consume no UPF buffer until DL traffic actually arrives,
     * but DROP kills DDN/paging (MT reachability) until the UE itself
     * wakes up. Unable-to-page still DROPs regardless of this flag.
     */
    bool idle_drop;
    uint32_t duration_s;   /* seconds in BUFF before DROP (default 180) */
    uint32_t interval_s;   /* sweep period (default 30) */
    /*
     * DROP→BUFF|NOCP re-arm: after rearm_s seconds in DROP, restore
     * buffering so DDN/paging works again (default 600, 0 = never).
     * Paced at rearm_batch sessions per sweep per shard to avoid a
     * PFCP modification storm (default 1000).
     */
    uint32_t rearm_s;
    uint32_t rearm_batch;
    ogs_timer_t *t_sweep;
} sgwc_buffer_idle_config_t;

typedef struct sgwc_context_s {
    ogs_list_t mme_s11_list;    /* MME GTPC Node List */
    ogs_list_t pgw_s5c_list;    /* PGW GTPC Node List */
    ogs_list_t sgsn_gn_list;    /* SGSN Gn GTPC Node List */

    sgwc_cdr_config_t cdr;
    uint32_t cdr_local_seq;

    sgwc_orphan_config_t orphan;
    sgwc_buffer_idle_config_t buffer_idle;

    /* Create BAR Suggested Buffering Packets Count (0 = omit IE). Default 8. */
    uint8_t bar_suggested_buffering_packets_count;

    ogs_hash_t *imsi_ue_hash;   /* hash table (IMSI : SGW_UE) */
    ogs_hash_t *sgw_s11_teid_hash;  /* hash table (SGW-S11-TEID : SGW_UE) */
    ogs_hash_t *sgwc_sxa_seid_hash; /* hash table (SGWC-SXA-SEID : Session) */

    ogs_list_t sgw_ue_list;    /* SGW_UE List */

    /* GTPv2-C Recovery counter (TS 29.274) for Echo/CSR interop */
    uint8_t gtpc_recovery;
    uint32_t gtpc_echo_interval; /* S11 echo period in seconds (0=60) */
    const char *recovery_counter_file;

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

    /*
     * IPv4 link MTU (PCO/ePCO 0x0010) rewrite on S11 Create Session
     * Response for inbound home-routed roam. 0 = disabled. When set:
     * inject if home PGW omitted MTU; clamp if home MTU > this value.
     */
    uint16_t inbound_roam_mtu;

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

    /* Include PFCP User ID (IMSI/MSISDN) in Session Establishment Request. */
    bool pfcp_send_user_id;

    /* Operator maintenance window (HTTP /admin/maintenance endpoints). */
    bool maintenance_mode;

    /*
     * Attach-storm admission control (sgwc.admission in yaml).
     * max_outstanding caps in-flight Create Session -> PFCP Session
     * Establishment (0 = unlimited); rate_per_sec is an optional token
     * bucket on accepted Create Sessions (0 = disabled). Over-cap or
     * PFCP-all-down requests are rejected immediately with GTP-C entity
     * congestion so the MME can back UEs off (EMM #22 + T3346) instead
     * of piling contexts onto a dead SGW-U.
     */
    int         admission_max_outstanding;
    int         admission_rate_per_sec;
    int         admission_outstanding;      /* current in-flight count */
    int         admission_rate_tokens;
    ogs_time_t  admission_rate_window;      /* 1s token refill window */

    /*
     * Batched /admin/maintenance/drain bookkeeping (see sgwc-sm.c).
     * Sessions are drained in fixed-size UE batches paced by a timer so
     * a large drain cannot monopolise the main thread or burst-flood
     * the MME/SGW-U/SMF with GTP/PFCP deletions.
     */
    uint32_t drain_generation;
    bool     drain_force;
    bool     drain_active;
    uint32_t drain_processed;

    /*
     * GTPv1 Gn (2G/3G SGSN): optional separate listener and PGW/SMF list.
     * When gn.server is omitted, GTPv1 on gtpc.server is dispatched to Gn.
     * gn_pgw_list: ordered rules; first imsi_prefix match wins, else default
     * entry (no imsi_prefix). List order matters — put specific prefixes first.
     */
    bool gn_enabled;
    ogs_list_t gn_server_list;
    ogs_list_t gn_server_list6;
    ogs_sockaddr_t *gn_addr;
    ogs_sockaddr_t *gn_addr6;
    ogs_list_t gn_pgw_list;
    uint8_t gn_gtpc_recovery;
} sgwc_context_t;

typedef struct sgwc_ue_s {
    ogs_lnode_t     lnode;
    ogs_pool_id_t   id;
    ogs_pool_id_t   *sgw_s11_teid_node; /* A node of SGW-S11-TEID */

    uint32_t        sgw_s11_teid;   /* SGW-S11-TEID is derived from NODE */
    uint32_t        mme_s11_teid;   /* MME-S11-TEID is received from MME */
    uint32_t        mme_s11_ipv4;   /* host order, from CSR sender F-TEID */
    unsigned        mme_s11_ipv4_valid : 1;

    /* UE identity */
    uint8_t         imsi[OGS_MAX_IMSI_LEN];
    int             imsi_len;
    char            imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

    uint8_t         msisdn[OGS_MAX_MSISDN_LEN];
    int             msisdn_len;
    char            msisdn_bcd[OGS_MAX_MSISDN_BCD_LEN+1];

    char            imeisv_bcd[OGS_MAX_IMEISV_BCD_LEN+1];
    uint8_t         ue_timezone[2];
    uint8_t         ue_timezone_len;

    /*
     * sgwc_context_t.drain_generation under which this UE's sessions
     * were last handed to the batched maintenance drain. 0 = never.
     */
    uint32_t        drain_generation;

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
    /*
     * Monotonic time the CSR-replace pin was armed. Used by the orphan sweep
     * to detect a pin that never cleared (deferred Create Session lost) so an
     * otherwise-empty UE is not leaked forever in sgwc_ue_remove_if_empty().
     */
    ogs_time_t      csr_replace_t0;

    unsigned        metrics_ue_counted : 1;
    unsigned        metrics_plmn_valid : 1;
    ogs_plmn_id_t   metrics_plmn_id;
    unsigned        gn : 1;         /* UE reached via GTPv1 Gn */
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

    /* Counted in sgwc_context_t.admission_outstanding (exactly-once) */
    unsigned        admission_counted : 1;

    unsigned        metrics_session_counted : 1;
    unsigned        metrics_rat_labeled : 1;
    unsigned        metrics_apn_labeled : 1;
    char            metrics_rat[16];
    char            metrics_gtp_if[8];
    char            metrics_apn[OGS_MAX_APN_LEN+1];
    unsigned        gn : 1;         /* Session from GTPv1 Gn */
    uint8_t         gtp_rat_type;
    unsigned        gtp_selection_mode_set : 1;
    uint8_t         gtp_selection_mode;
    uint8_t         gn_nsapi;
    uint8_t         apn_fqdn[OGS_MAX_APN_LEN + 2];
    uint8_t         apn_fqdn_len;
    ogs_gtp1_qos_profile_decoded_t gn_qos_pdec;

    /*
     * When DL FAR last entered BUFF|NOCP (RAB / Error-Ind deactivate).
     * 0 = not buffering (FORW or DROP). Used by buffer_idle sweep.
     */
    ogs_time_t      dl_buff_since;

    /*
     * When DL FAR entered DROP (Unable-to-page / idle sweep / restore).
     * 0 = not dropped. Used by buffer_idle sweep to re-arm BUFF|NOCP
     * after buffer_idle.rearm seconds so paging reachability recovers.
     */
    ogs_time_t      dl_drop_since;
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
    bool            urr_created;    /* URR already installed on SGW-U:
                                     * a dedicated bearer is created in two
                                     * PFCP modifications (UL then DL leg) that
                                     * share one URR. Only the first leg may
                                     * carry Create URR; re-creating the same
                                     * URR ID makes a strict UPF (e.g. UPG/VPP)
                                     * reject with cause 73. */

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

/*
 * SMP container lock (recursive).
 *
 * The SGW-C context is PROCESS-GLOBAL: one config, one UE list, one set
 * of hashes and pools, initialized exactly once on the init thread.
 * UEs/sessions are OWNED by exactly one thread (the shard bits in their
 * S11 TEID / SXA SEID name the owner) and their fields are only touched
 * there, lock-free. The shared containers — pools, hashes, sgw_ue_list,
 * reloadable config lists — are mutated under this lock. It is the same
 * recursive mutex the metrics/admin HTTP dumpers hold while walking the
 * lists, so readers and mutators can never interleave.
 *
 * Lock order: sgwc_ctx_lock -> (pfcp obj/peer locks, gtp node lock).
 * Never take sgwc_ctx_lock while holding a lib-level lock.
 */
void sgwc_ctx_lock(void);
void sgwc_ctx_unlock(void);

/*
 * Ownership test for global walks: true when the calling thread owns
 * this UE (shard bits of the S11 TEID == our shard id). With sharding
 * off this is always true.
 */
bool sgwc_ue_owned_by_self(sgwc_ue_t *sgwc_ue);

/*
 * Snapshot the pool ids of every UE the calling thread owns (taken under
 * the container lock). Caller frees with ogs_free(); each id must be
 * re-validated with sgwc_ue_find_by_id() when processed.
 */
ogs_pool_id_t *sgwc_ue_ids_collect_owned(int *out_count);

/* Shared GTP peer lists (main + all shard workers). Lock around find/add. */
void sgwc_peers_lock(void);
void sgwc_peers_unlock(void);
ogs_list_t *sgwc_mme_s11_list(void);
ogs_list_t *sgwc_pgw_s5c_list(void);
ogs_list_t *sgwc_sgsn_gn_list(void);

/* Process-wide session counter (atomic). */
int sgwc_session_count(void);

sgwc_mme_peer_t *sgwc_mme_peer_get(ogs_gtp_node_t *gnode);
void sgwc_mme_peer_attach(ogs_gtp_node_t *gnode);
void sgwc_mme_peer_detach(ogs_gtp_node_t *gnode);
bool sgwc_mme_recovery_update(sgwc_mme_peer_t *peer, uint8_t recovery);

/* SGWC_EVT_PEER_RESTART_PURGE kinds (event->timer_id). */
enum {
    SGWC_PEER_RESTART_KIND_MME = 1,
    SGWC_PEER_RESTART_KIND_PGW = 2,
};

/* Purge the calling thread's OWN sessions toward a restarted peer. */
void sgwc_peer_restart_purge_owned(ogs_gtp_node_t *gnode, int kind);

/* Re-establish the calling thread's OWN sessions on a re-associated SGW-U. */
void sgwc_pfcp_restoration_owned(ogs_pfcp_node_t *node);
void sgwc_mme_echo_schedule(sgwc_mme_peer_t *peer);
void sgwc_mme_echo_reschedule_all(void);

sgwc_pgw_peer_t *sgwc_pgw_peer_get(ogs_gtp_node_t *gnode);
void sgwc_pgw_peer_attach(ogs_gtp_node_t *gnode);
void sgwc_pgw_peer_detach(ogs_gtp_node_t *gnode);
bool sgwc_pgw_recovery_update(sgwc_pgw_peer_t *peer, uint8_t recovery);
void sgwc_pgw_echo_schedule(sgwc_pgw_peer_t *peer);
void sgwc_pgw_echo_reschedule_all(void);

sgwc_sgsn_peer_t *sgwc_sgsn_peer_get(ogs_gtp_node_t *gnode);
void sgwc_sgsn_peer_attach(ogs_gtp_node_t *gnode);
void sgwc_sgsn_peer_detach(ogs_gtp_node_t *gnode);
void sgwc_sgsn_peer_setup(ogs_gtp_node_t *gnode);
void sgwc_sgsn_echo_schedule(sgwc_sgsn_peer_t *peer);

sgwc_ue_t *sgwc_ue_add_by_message(ogs_gtp2_message_t *message);
sgwc_ue_t *sgwc_ue_find_by_imsi(uint8_t *imsi, int imsi_len);
sgwc_ue_t *sgwc_ue_find_by_imsi_bcd(const char *imsi_bcd);
sgwc_ue_t *sgwc_ue_find_by_teid(uint32_t teid);

sgwc_ue_t *sgwc_ue_add(uint8_t *imsi, int imsi_len);
int sgwc_ue_remove(sgwc_ue_t *sgwc_ue);
void sgwc_ue_remove_if_empty(sgwc_ue_t *sgwc_ue);
void sgwc_ue_remove_all(void);
sgwc_ue_t *sgwc_ue_find_by_id(ogs_pool_id_t id);

sgwc_sess_t *sgwc_sess_add(sgwc_ue_t *sgwc_ue, char *apn);

bool sgwc_sess_is_inbound_roam(sgwc_sess_t *sess);
void sgwc_home_plmn_from_imsi_bcd(const char *imsi_bcd, ogs_plmn_id_t *plmn_id);
sgwc_gn_pgw_t *sgwc_gn_pgw_find_for_ue(sgwc_ue_t *sgwc_ue);
void sgwc_gn_pgw_yaml_add(ogs_list_t *list, ogs_yaml_iter_t *parent_iter);
void sgwc_gn_pgw_clear_list(ogs_list_t *list);
void sgwc_inbound_roam_teid_offset_apply(sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess);
void sgwc_sess_sync_pfcp_pdr_nwi(sgwc_sess_t *sess);

void sgwc_sess_select_sgwu(sgwc_sess_t *sess);

/*
 * Attach-storm admission control. sgwc_admission_check() returns 0 to
 * accept or a GTP2 cause to reject (GTP-C entity congestion when all
 * PFCP peers are down, over the in-flight cap, or over the rate limit).
 * started/done bracket one in-flight PFCP Session Establishment;
 * done is idempotent (sess->admission_counted).
 */
uint8_t sgwc_admission_check(void);
void sgwc_admission_establish_started(sgwc_sess_t *sess);
void sgwc_admission_establish_done(sgwc_sess_t *sess);

void sgwc_sess_abort_create(sgwc_sess_t *sess);
int sgwc_sess_remove(sgwc_sess_t *sess);
void sgwc_sess_purge_upf(sgwc_sess_t *sess);
void sgwc_sess_remove_all(sgwc_ue_t *sgwc_ue);

/*
 * Walk the calling thread's OWN sessions and account orphans. When do_purge is
 * true, tear down orphans whose age exceeds 'grace' (use 0 to ignore age).
 * Returns the number of orphan sessions still present after the sweep (this
 * shard's live backlog); if out_purged is non-NULL it receives how many were
 * torn down. The process-wide orphan gauges are published internally as the
 * sum over all shards.
 */
int sgwc_orphan_sweep(bool do_purge, ogs_time_t grace, int *out_purged);

void sgwc_sess_note_dl_buffering(sgwc_sess_t *sess);
void sgwc_sess_clear_dl_buffering(sgwc_sess_t *sess);
void sgwc_sess_count_dl_far(sgwc_sess_t *sess,
        int *buff, int *forw, int *drop);
void sgwc_sess_prepare_restoration_drop_idle(sgwc_sess_t *sess);
int sgwc_sess_send_dl_far_drop(sgwc_sess_t *sess);
int sgwc_sess_send_dl_far_rearm(sgwc_sess_t *sess);
int sgwc_buffer_idle_sweep(int *out_dropped);
void sgwc_buffer_idle_timer_start(void);
void sgwc_buffer_idle_timer_stop(void);

/* Periodic orphan sweep timer (no-op when sgwc.orphan.enabled is false). */
void sgwc_orphan_timer_start(void);
void sgwc_orphan_timer_stop(void);

bool sgwc_sess_s5c_teid_matches(sgwc_sess_t *sess, uint32_t teid);
sgwc_sess_t *sgwc_sess_find_by_teid(uint32_t teid);
sgwc_sess_t *sgwc_sess_find_by_seid(uint64_t seid);

sgwc_sess_t *sgwc_sess_find_by_apn(sgwc_ue_t *sgwc_ue, char *apn);
sgwc_sess_t *sgwc_sess_find_by_ebi(sgwc_ue_t *sgwc_ue, uint8_t ebi);
sgwc_sess_t *sgwc_sess_find_by_nsapi(sgwc_ue_t *sgwc_ue, uint8_t nsapi);
sgwc_sess_t *sgwc_sess_find_by_id(ogs_pool_id_t id);
bool sgwc_pfcp_peer_in_use(const ogs_pfcp_node_t *node);
void sgwc_sgwu_nwi_rewrite_clear(void);
void sgwc_sgwu_nwi_rewrite_resort(void);

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
