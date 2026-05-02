/*
 * Open5GS Admin Watcher — public API
 *
 * A tiny polling client that each NF links against. It pulls append-only
 * configuration from the Open5GS Admin API and fires per-row callbacks
 * so the NF can apply new entries into its runtime state.
 *
 * The watcher never notifies about deletes: deletes remove the config
 * row only, never touch live UEs/eNBs. See tools/admin-api/README.md.
 */

#ifndef OPEN5GS_ADMIN_WATCHER_H
#define OPEN5GS_ADMIN_WATCHER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ogs_admin_watcher_s ogs_admin_watcher_t;

/* Callback signatures ------------------------------------------------- */

typedef void (*ogs_admin_plmn_add_cb)(
        const char *mcc,
        const char *mnc,
        int64_t revision,
        void *userdata);

typedef void (*ogs_admin_tac_add_cb)(
        const char *mcc,
        const char *mnc,
        int tac,
        int64_t revision,
        void *userdata);

typedef void (*ogs_admin_dnn_add_cb)(
        const char *name,
        const char *dns1,       /* may be NULL */
        const char *dns2,       /* may be NULL */
        int mtu,                /* 0 if unset */
        int slice_sst,          /* 0 if unset */
        const char *slice_sd,   /* may be NULL */
        int64_t revision,
        void *userdata);

typedef void (*ogs_admin_upf_peer_add_cb)(
        const char *host,
        int port,
        const char *const *dnns,  /* NULL-terminated; may be NULL */
        int64_t revision,
        void *userdata);

typedef void (*ogs_admin_subnet_add_cb)(
        const char *cidr,
        const char *dnn,
        const char *dev,        /* may be NULL */
        const char *gateway,    /* may be NULL */
        int64_t revision,
        void *userdata);

/* Settings: smf/cdr (Ga interface CDR writer).
 *
 * Mirrors smf_cdr_config_t in src/smf/context.h. The watcher fetches
 * /api/v1/settings/smf/cdr on every tick and fires this callback only
 * when the row's revision changed (or the row newly appeared).
 *
 * Field strings have lifetime equal to the callback invocation only:
 * the integrator must dup any it wants to retain. */
typedef struct ogs_admin_smf_cdr_s {
    int       enabled;          /* 0 / 1 */
    const char *spool_dir;      /* may be NULL when enabled == 0 */
    const char *node_id;        /* may be NULL when enabled == 0 */
    const char *local_address;  /* may be NULL */
    uint32_t  rotate_max_records;
    uint32_t  rotate_max_bytes;
    uint32_t  rotate_max_seconds;
    uint32_t  triggers;         /* SMF_CDR_TRIG_* bitmask, see context.h */
} ogs_admin_smf_cdr_t;

typedef void (*ogs_admin_smf_cdr_update_cb)(
        const ogs_admin_smf_cdr_t *cfg,
        int64_t revision,
        void *userdata);

/* Settings: smf/radius (RADIUS client + PoD listener).
 *
 * Up to OGS_ADMIN_MAX_RADIUS_SERVERS peers. The NF is expected to pick
 * one per request using `select_mode`. Pointers inside the struct have
 * lifetime == callback invocation only; the integrator must dup strings
 * it wants to retain. */
#define OGS_ADMIN_MAX_RADIUS_SERVERS 4

typedef struct ogs_admin_radius_server_s {
    const char *host;
    uint16_t    auth_port;
    uint16_t    acct_port;
    const char *secret;
    int         is_primary;    /* 1 if role=="primary" */
    int         weight;
} ogs_admin_radius_server_t;

typedef struct ogs_admin_smf_radius_s {
    int         enabled;
    /* 0 = primary_failover, 1 = hash_imsi. Other values reserved. */
    int         select_mode;
    const char *nas_identifier;
    const char *nas_ip;
    uint32_t    timeout_ms;
    uint32_t    retry;
    uint32_t    acct_interim_interval;

    int         pod_enabled;
    const char *pod_bind;
    uint16_t    pod_port;
    const char *pod_secret;
    uint32_t    pod_teardown_timeout_ms;

    /* 1 = apply Framed-IP from Access-Accept to UE/PFCP (default). 0 = ignore. */
    int         use_framed_ip_for_ue;

    ogs_admin_radius_server_t servers[OGS_ADMIN_MAX_RADIUS_SERVERS];
    int         num_servers;
} ogs_admin_smf_radius_t;

typedef void (*ogs_admin_smf_radius_update_cb)(
        const ogs_admin_smf_radius_t *cfg,
        int64_t revision,
        void *userdata);

/* Settings: cgfd/gtpp (CGF peer list + tunables for open5gs-cgfd). */
#define OGS_ADMIN_MAX_CGF_PEERS 4

typedef struct ogs_admin_cgf_peer_s {
    const char *host;
    uint16_t    port;
    int         is_primary;
} ogs_admin_cgf_peer_t;

typedef struct ogs_admin_cgfd_gtpp_s {
    uint32_t echo_interval_s;
    uint32_t request_rto_ms;
    uint32_t request_retries;
    uint32_t failover_after_missed_echoes;
    uint32_t max_records_per_packet;
    uint32_t max_bytes_per_packet;
    /* -1 = field not present in payload (keep current value);
     *  0 = keep done/ archive (legacy default);
     *  1 = unlink on full ACK. */
    int      purge_on_success;
    ogs_admin_cgf_peer_t peers[OGS_ADMIN_MAX_CGF_PEERS];
    int      num_peers;
} ogs_admin_cgfd_gtpp_t;

typedef void (*ogs_admin_cgfd_gtpp_update_cb)(
        const ogs_admin_cgfd_gtpp_t *cfg,
        int64_t revision,
        void *userdata);

/* Fired when GET /api/v1/settings/{scope}/{kind} returns 404 or after
 * a DELETE — i.e. the operator wants the NF to revert to its file/default
 * configuration. The integrator decides whether to re-load YAML or keep
 * the last known good. */
typedef void (*ogs_admin_settings_clear_cb)(
        const char *scope,
        const char *kind,
        void *userdata);

typedef struct ogs_admin_watcher_cbs_s {
    ogs_admin_plmn_add_cb          on_plmn_add;
    ogs_admin_tac_add_cb           on_tac_add;
    ogs_admin_dnn_add_cb           on_dnn_add;
    ogs_admin_upf_peer_add_cb      on_upf_peer_add;
    ogs_admin_subnet_add_cb        on_subnet_add;
    ogs_admin_smf_cdr_update_cb    on_smf_cdr_update;
    ogs_admin_smf_radius_update_cb on_smf_radius_update;
    ogs_admin_cgfd_gtpp_update_cb  on_cgfd_gtpp_update;
    ogs_admin_settings_clear_cb    on_settings_clear;
    void *userdata;
} ogs_admin_watcher_cbs_t;

/* Watcher configuration ----------------------------------------------- */

typedef struct ogs_admin_watcher_cfg_s {
    /* e.g. "http://127.0.0.1:9998" (no trailing slash required) */
    const char *base_url;

    /* If non-NULL and non-empty, sent as "Authorization: Bearer ...". */
    const char *bearer_token;

    /* "mme" | "smf" | "upf" | ... */
    const char *nf_type;

    /* Unique within the cluster; commonly hostname or hostname-pid. */
    const char *nf_id;

    /* Optional free-form build identifier reported back to the API. */
    const char *nf_version;

    /* Poll cadence; defaults to 5000 ms if set <= 0. */
    int poll_interval_ms;

    /* Total libcurl timeout per request; defaults to 3000 ms if <= 0. */
    int request_timeout_ms;
} ogs_admin_watcher_cfg_t;

/* Lifecycle ----------------------------------------------------------- */

/* Returns NULL on allocation failure or bad config. Caller retains
 * ownership of all strings inside cfg and cbs — they must outlive
 * the watcher. */
ogs_admin_watcher_t *ogs_admin_watcher_new(
        const ogs_admin_watcher_cfg_t *cfg,
        const ogs_admin_watcher_cbs_t *cbs);

/* Spawns the internal poller thread. Returns 0 on success. */
int ogs_admin_watcher_start(ogs_admin_watcher_t *w);

/* Signals the poller thread to stop and joins it. */
void ogs_admin_watcher_stop(ogs_admin_watcher_t *w);

void ogs_admin_watcher_free(ogs_admin_watcher_t *w);

/* Synchronous, single-shot poll. Use this if you prefer to drive the
 * cadence from the NF's event loop instead of using start()/stop().
 * Returns 0 on success, negative on transport error. */
int ogs_admin_watcher_tick(ogs_admin_watcher_t *w);

/* Push a heartbeat independently. The watcher also sends one at the end
 * of every successful tick. */
int ogs_admin_watcher_heartbeat(
        ogs_admin_watcher_t *w,
        int64_t applied_revision,
        const char *last_error /* or NULL */);

/* Most recent applied revision the watcher has fired callbacks up to. */
int64_t ogs_admin_watcher_applied_revision(const ogs_admin_watcher_t *w);

#ifdef __cplusplus
}
#endif

#endif /* OPEN5GS_ADMIN_WATCHER_H */
