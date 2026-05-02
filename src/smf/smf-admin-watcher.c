/*
 * SMF integration with the Open5GS Admin API watcher (C).
 *
 * Thread model
 * ------------
 *   Watcher thread (owned by the watcher library):
 *       - Issues HTTP polls to the admin API.
 *       - In its per-row callbacks (on_upf_peer_add / on_subnet_add /
 *         on_dnn_add) it appends a small opaque record to a mutex-
 *         protected "pending" list and returns immediately. It NEVER
 *         touches libogs or SMF state directly.
 *
 *   SMF main thread (owns timer_mgr, pfcp_peer_list, subnet_list):
 *       - A 1-second libogs timer (`t_drain`) fires on the main thread
 *         and drains the pending lists, calling the real mutators
 *         (smf_pfcp_admin_add_upf_peer, ogs_pfcp_subnet_add) which are
 *         safe because we are on the loop thread.
 *
 * Compile-time: only built when -Dadmin_watcher=true.
 */

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "ogs-app.h"
#include "ogs-pfcp.h"

/* context.h must come before pfcp-path.h / radius-path.h because those
 * headers reference smf_sess_t / smf_bearer_t without forward decls. */
#include "context.h"
#include "smf-admin-watcher.h"
#include "pfcp-path.h"
#include "ga-writer.h"
#include "radius-path.h"

#include "open5gs_admin_watcher.h"

#define DRAIN_INTERVAL_MS 1000

/* ------------------------------------------------------------------ */
/* Pending records                                                     */
/* ------------------------------------------------------------------ */

typedef struct pending_upf_peer_s {
    ogs_lnode_t lnode;
    char   *host;
    int     port;
    char   *dnns[OGS_MAX_NUM_OF_DNN]; /* duped strings; NULL-terminated */
    int     num_of_dnns;
    int64_t revision;
} pending_upf_peer_t;

typedef struct pending_subnet_s {
    ogs_lnode_t lnode;
    char   *cidr;
    char   *dnn;
    char   *dev;
    char   *gateway;
    int64_t revision;
} pending_subnet_t;

/*
 * CDR settings: last-write-wins singleton. The watcher thread writes
 * `g_pending_cdr_next` and sets `g_pending_cdr_has_next` (under the
 * same lock as the list queues). The drain reads it out, clears the
 * flag, and calls smf_ga_writer_apply_runtime() on the main thread.
 *
 * Strings inside the snapshot are heap-owned by the watcher callback
 * and transferred to apply_runtime (which copies them again into SMF
 * context). The drain is responsible for freeing them afterwards.
 */
typedef struct pending_cdr_settings_s {
    bool   has_value;       /* false => settings row was cleared (DELETE) */
    smf_cdr_config_t cfg;   /* scalar fields populated; strings heap-owned */
    int64_t revision;
} pending_cdr_settings_t;

/*
 * RADIUS settings: same pattern. The embedded smf_radius_config_t has
 * strings the watcher duplicates (host, secret, nas_identifier, pod_*)
 * which the drain frees after smf_radius_apply_runtime() has copied
 * them internally.
 */
typedef struct pending_radius_settings_s {
    bool   has_value;
    smf_radius_config_t cfg;
    int64_t revision;
} pending_radius_settings_t;

/* Mutex-protected pending queues — producer = watcher thread,
 * consumer = main thread drain timer. */
static pthread_mutex_t g_pending_lock = PTHREAD_MUTEX_INITIALIZER;
static ogs_list_t g_pending_upf_peers;
static ogs_list_t g_pending_subnets;
static pending_cdr_settings_t g_pending_cdr;
static bool g_pending_cdr_has_next;
static pending_radius_settings_t g_pending_radius;
static bool g_pending_radius_has_next;

static ogs_admin_watcher_t *g_watcher;
static ogs_timer_t         *g_t_drain;

/* ------------------------------------------------------------------ */
/* Watcher-thread callbacks: enqueue, do not apply                     */
/* ------------------------------------------------------------------ */

static void on_dnn_add(
        const char *name,
        const char *dns1, const char *dns2,
        int mtu, int sst, const char *sd,
        int64_t revision, void *ud)
{
    (void)ud; (void)dns1; (void)dns2; (void)mtu; (void)sst; (void)sd;
    /* Open5GS SMF has no standalone DNN list — DNNs are metadata on
     * subnets and on subscriber profiles. Add a subnet (or a UDR entry)
     * with this DNN to actually expose it. We log it for visibility. */
    ogs_info("admin-watcher: observed DNN add name=%s rev=%lld",
            name ? name : "(null)", (long long)revision);
}

static void on_upf_peer_add(
        const char *host, int port,
        const char *const *dnns,
        int64_t revision, void *ud)
{
    (void)ud;
    if (!host) return;

    pending_upf_peer_t *p = ogs_calloc(1, sizeof(*p));
    if (!p) return;
    p->host = ogs_strdup(host);
    p->port = port > 0 ? port : OGS_PFCP_UDP_PORT;
    p->num_of_dnns = 0;
    if (dnns) {
        int i = 0;
        while (dnns[i] && p->num_of_dnns < OGS_MAX_NUM_OF_DNN) {
            p->dnns[p->num_of_dnns++] = ogs_strdup(dnns[i]);
            i++;
        }
    }
    p->revision = revision;

    pthread_mutex_lock(&g_pending_lock);
    ogs_list_add(&g_pending_upf_peers, p);
    pthread_mutex_unlock(&g_pending_lock);
}

static void clear_pending_cdr_strings_locked(void)
{
    smf_cdr_config_t *c = &g_pending_cdr.cfg;
    if (c->spool_dir)     { ogs_free((void *)c->spool_dir);     c->spool_dir = NULL; }
    if (c->node_id)       { ogs_free((void *)c->node_id);       c->node_id = NULL; }
    if (c->local_address) { ogs_free((void *)c->local_address); c->local_address = NULL; }
}

static void on_smf_cdr_update(
        const ogs_admin_smf_cdr_t *cfg,
        int64_t revision, void *ud)
{
    (void)ud;
    if (!cfg) return;

    pthread_mutex_lock(&g_pending_lock);

    /* Coalesce: if a previous pending update is still waiting for the
     * drain, overwrite it. Last-write-wins matches the API semantics. */
    clear_pending_cdr_strings_locked();
    memset(&g_pending_cdr.cfg, 0, sizeof(g_pending_cdr.cfg));

    g_pending_cdr.cfg.enabled            = cfg->enabled ? true : false;
    g_pending_cdr.cfg.spool_dir          = cfg->spool_dir
            ? ogs_strdup(cfg->spool_dir) : NULL;
    g_pending_cdr.cfg.node_id            = cfg->node_id
            ? ogs_strdup(cfg->node_id) : NULL;
    g_pending_cdr.cfg.local_address      = cfg->local_address
            ? ogs_strdup(cfg->local_address) : NULL;
    g_pending_cdr.cfg.rotate_max_records = cfg->rotate_max_records;
    g_pending_cdr.cfg.rotate_max_bytes   = cfg->rotate_max_bytes;
    g_pending_cdr.cfg.rotate_max_seconds = cfg->rotate_max_seconds;
    g_pending_cdr.cfg.triggers           = cfg->triggers;

    g_pending_cdr.has_value = true;
    g_pending_cdr.revision  = revision;
    g_pending_cdr_has_next  = true;

    pthread_mutex_unlock(&g_pending_lock);
}

static void clear_pending_radius_strings_locked(void)
{
    smf_radius_config_t *c = &g_pending_radius.cfg;
    int i;

    if (c->nas_id)     { ogs_free((void *)c->nas_id);     c->nas_id = NULL; }
    if (c->nas_ip)     { ogs_free((void *)c->nas_ip);     c->nas_ip = NULL; }
    if (c->pod_bind)   { ogs_free((void *)c->pod_bind);   c->pod_bind = NULL; }
    if (c->pod_secret) { ogs_free((void *)c->pod_secret); c->pod_secret = NULL; }
    for (i = 0; i < SMF_MAX_RADIUS_SERVERS; i++) {
        if (c->servers[i].host) {
            ogs_free((void *)c->servers[i].host);
            c->servers[i].host = NULL;
        }
        if (c->servers[i].secret) {
            ogs_free((void *)c->servers[i].secret);
            c->servers[i].secret = NULL;
        }
    }
}

static void on_smf_radius_update(
        const ogs_admin_smf_radius_t *cfg,
        int64_t revision, void *ud)
{
    (void)ud;
    int i;

    if (!cfg) return;

    pthread_mutex_lock(&g_pending_lock);

    /* Coalesce any earlier pending update. */
    clear_pending_radius_strings_locked();
    memset(&g_pending_radius.cfg, 0, sizeof(g_pending_radius.cfg));

    g_pending_radius.cfg.enabled = cfg->enabled ? true : false;
    g_pending_radius.cfg.select_mode =
        (cfg->select_mode == 1) ? SMF_RADIUS_SELECT_HASH_IMSI
                                : SMF_RADIUS_SELECT_PRIMARY_FAILOVER;
    g_pending_radius.cfg.nas_id = cfg->nas_identifier
            ? ogs_strdup(cfg->nas_identifier) : NULL;
    g_pending_radius.cfg.nas_ip = cfg->nas_ip
            ? ogs_strdup(cfg->nas_ip) : NULL;
    g_pending_radius.cfg.timeout_ms            = cfg->timeout_ms;
    g_pending_radius.cfg.retry                 = cfg->retry;
    g_pending_radius.cfg.acct_interim_interval = cfg->acct_interim_interval;

    g_pending_radius.cfg.pod_enabled = cfg->pod_enabled ? true : false;
    g_pending_radius.cfg.pod_bind    = cfg->pod_bind
            ? ogs_strdup(cfg->pod_bind) : NULL;
    g_pending_radius.cfg.pod_port    = cfg->pod_port;
    g_pending_radius.cfg.pod_secret  = cfg->pod_secret
            ? ogs_strdup(cfg->pod_secret) : NULL;
    g_pending_radius.cfg.pod_teardown_timeout_ms = cfg->pod_teardown_timeout_ms;

    g_pending_radius.cfg.use_framed_ip_for_ue = cfg->use_framed_ip_for_ue ?
            true : false;

    for (i = 0; i < cfg->num_servers && i < SMF_MAX_RADIUS_SERVERS; i++) {
        const ogs_admin_radius_server_t *s = &cfg->servers[i];
        smf_radius_server_t *d = &g_pending_radius.cfg.servers[i];

        d->host = s->host ? ogs_strdup(s->host) : NULL;
        d->secret = s->secret ? ogs_strdup(s->secret) : NULL;
        d->auth_port = s->auth_port;
        d->acct_port = s->acct_port;
        d->is_primary = s->is_primary ? true : false;
        d->weight = s->weight;
    }
    g_pending_radius.cfg.num_servers = cfg->num_servers;

    g_pending_radius.has_value = true;
    g_pending_radius.revision  = revision;
    g_pending_radius_has_next  = true;

    pthread_mutex_unlock(&g_pending_lock);
}

static void on_settings_clear(const char *scope, const char *kind, void *ud)
{
    (void)ud;
    if (!scope || !kind) return;

    pthread_mutex_lock(&g_pending_lock);
    if (strcmp(scope, "smf") == 0 && strcmp(kind, "cdr") == 0) {
        clear_pending_cdr_strings_locked();
        memset(&g_pending_cdr.cfg, 0, sizeof(g_pending_cdr.cfg));
        g_pending_cdr.has_value = false;
        g_pending_cdr.revision  = 0;
        g_pending_cdr_has_next  = true;
    } else if (strcmp(scope, "smf") == 0 && strcmp(kind, "radius") == 0) {
        clear_pending_radius_strings_locked();
        memset(&g_pending_radius.cfg, 0, sizeof(g_pending_radius.cfg));
        g_pending_radius.has_value = false;
        g_pending_radius.revision  = 0;
        g_pending_radius_has_next  = true;
    }
    pthread_mutex_unlock(&g_pending_lock);
}

static void on_subnet_add(
        const char *cidr, const char *dnn,
        const char *dev, const char *gateway,
        int64_t revision, void *ud)
{
    (void)ud;
    if (!cidr || !dnn) return;

    pending_subnet_t *p = ogs_calloc(1, sizeof(*p));
    if (!p) return;
    p->cidr    = ogs_strdup(cidr);
    p->dnn     = ogs_strdup(dnn);
    p->dev     = dev     ? ogs_strdup(dev)     : NULL;
    p->gateway = gateway ? ogs_strdup(gateway) : NULL;
    p->revision = revision;

    pthread_mutex_lock(&g_pending_lock);
    ogs_list_add(&g_pending_subnets, p);
    pthread_mutex_unlock(&g_pending_lock);
}

/* ------------------------------------------------------------------ */
/* Main-thread drain                                                   */
/* ------------------------------------------------------------------ */

/* Split "10.45.0.0/16" into ipstr="10.45.0.0" prefix="16".
 * Returns 0 on success. */
static int split_cidr(const char *cidr, char *ip, size_t ipcap, char *pref,
                      size_t prefcap)
{
    const char *slash = strchr(cidr, '/');
    if (!slash) return -1;
    size_t ip_len = (size_t)(slash - cidr);
    if (ip_len == 0 || ip_len + 1 > ipcap) return -1;
    memcpy(ip, cidr, ip_len);
    ip[ip_len] = '\0';

    const char *p = slash + 1;
    size_t pl = strlen(p);
    if (pl == 0 || pl + 1 > prefcap) return -1;
    memcpy(pref, p, pl + 1);
    return 0;
}

static void apply_one_upf_peer(pending_upf_peer_t *p)
{
    ogs_sockaddr_t *addr = NULL;

    int rv = ogs_addaddrinfo(&addr, AF_UNSPEC, p->host, p->port, 0);
    if (rv != OGS_OK || !addr) {
        ogs_error("admin-watcher: resolve failed for UPF peer %s:%d",
                p->host, p->port);
        if (addr) ogs_freeaddrinfo(addr);
        return;
    }

    /* Respect global IP version preferences the rest of SMF uses. */
    ogs_filter_ip_version(&addr,
            ogs_global_conf()->parameter.no_ipv4,
            ogs_global_conf()->parameter.no_ipv6,
            ogs_global_conf()->parameter.prefer_ipv4);
    if (!addr) {
        ogs_warn("admin-watcher: UPF peer %s:%d has no usable address family",
                p->host, p->port);
        return;
    }

    ogs_pfcp_node_t *node = smf_pfcp_admin_add_upf_peer(
            addr,
            (const char **)p->dnns, p->num_of_dnns);
    if (!node) {
        ogs_error("admin-watcher: smf_pfcp_admin_add_upf_peer failed for %s:%d",
                p->host, p->port);
        ogs_freeaddrinfo(addr);
        return;
    }

    ogs_info("admin-watcher: added UPF peer %s:%d (rev=%lld)",
            p->host, p->port, (long long)p->revision);
}

static void apply_one_subnet(pending_subnet_t *p)
{
    char ipstr[OGS_ADDRSTRLEN];
    char prefix[8];

    if (split_cidr(p->cidr, ipstr, sizeof(ipstr), prefix, sizeof(prefix)) != 0) {
        ogs_error("admin-watcher: bad CIDR '%s'", p->cidr);
        return;
    }

    /* If no dev was given, reuse the first tun dev if any already exists;
     * otherwise ogs_pfcp_subnet_add with ifname=NULL is valid — see
     * lib/pfcp/context.c. */
    const char *ifname = p->dev;

    ogs_pfcp_subnet_t *subnet = ogs_pfcp_subnet_add(
            ipstr, prefix, p->gateway, p->dnn, ifname);
    if (!subnet) {
        ogs_error("admin-watcher: ogs_pfcp_subnet_add(%s/%s dnn=%s) failed",
                ipstr, prefix, p->dnn);
        return;
    }

    ogs_info("admin-watcher: added subnet %s dnn=%s (rev=%lld)",
            p->cidr, p->dnn, (long long)p->revision);
}

static void free_pending_upf_peer(pending_upf_peer_t *p)
{
    int i;
    ogs_free(p->host);
    for (i = 0; i < p->num_of_dnns; i++) {
        if (p->dnns[i]) ogs_free(p->dnns[i]);
    }
    ogs_free(p);
}

static void free_pending_subnet(pending_subnet_t *p)
{
    ogs_free(p->cidr);
    ogs_free(p->dnn);
    if (p->dev)     ogs_free(p->dev);
    if (p->gateway) ogs_free(p->gateway);
    ogs_free(p);
}

static void drain_cb(void *data)
{
    ogs_list_t upf_peers, subnets;
    bool cdr_pending = false;
    bool cdr_has_value = false;
    smf_cdr_config_t cdr_cfg;
    int64_t cdr_rev = 0;

    memset(&cdr_cfg, 0, sizeof(cdr_cfg));
    ogs_list_init(&upf_peers);
    ogs_list_init(&subnets);

    /* Move everything under the lock into local lists so we can iterate
     * without holding the mutex across potentially-slow libogs calls. */
    pthread_mutex_lock(&g_pending_lock);
    {
        pending_upf_peer_t *p, *n;
        ogs_list_for_each_safe(&g_pending_upf_peers, n, p) {
            ogs_list_remove(&g_pending_upf_peers, p);
            ogs_list_add(&upf_peers, p);
        }
    }
    {
        pending_subnet_t *p, *n;
        ogs_list_for_each_safe(&g_pending_subnets, n, p) {
            ogs_list_remove(&g_pending_subnets, p);
            ogs_list_add(&subnets, p);
        }
    }
    if (g_pending_cdr_has_next) {
        cdr_pending   = true;
        cdr_has_value = g_pending_cdr.has_value;
        cdr_rev       = g_pending_cdr.revision;
        /* Transfer ownership of heap strings to the local snapshot so we
         * can release the lock and call apply_runtime without holding it. */
        cdr_cfg = g_pending_cdr.cfg;
        memset(&g_pending_cdr.cfg, 0, sizeof(g_pending_cdr.cfg));
        g_pending_cdr_has_next = false;
        g_pending_cdr.has_value = false;
    }

    bool radius_pending = false, radius_has_value = false;
    smf_radius_config_t radius_cfg;
    int64_t radius_rev = 0;
    memset(&radius_cfg, 0, sizeof(radius_cfg));
    if (g_pending_radius_has_next) {
        radius_pending   = true;
        radius_has_value = g_pending_radius.has_value;
        radius_rev       = g_pending_radius.revision;
        radius_cfg = g_pending_radius.cfg;
        memset(&g_pending_radius.cfg, 0, sizeof(g_pending_radius.cfg));
        g_pending_radius_has_next = false;
        g_pending_radius.has_value = false;
    }
    pthread_mutex_unlock(&g_pending_lock);

    {
        pending_upf_peer_t *p, *n;
        ogs_list_for_each_safe(&upf_peers, n, p) {
            apply_one_upf_peer(p);
            ogs_list_remove(&upf_peers, p);
            free_pending_upf_peer(p);
        }
    }
    {
        pending_subnet_t *p, *n;
        ogs_list_for_each_safe(&subnets, n, p) {
            apply_one_subnet(p);
            ogs_list_remove(&subnets, p);
            free_pending_subnet(p);
        }
    }

    if (cdr_pending) {
        if (cdr_has_value) {
            ogs_info("admin-watcher: applying smf/cdr settings rev=%lld",
                    (long long)cdr_rev);
            (void)smf_ga_writer_apply_runtime(&cdr_cfg);
        } else {
            /* Row was cleared — revert to YAML defaults by disabling the
             * writer. Operators who want to restore the YAML settings can
             * SIGHUP the SMF; doing that automatically here would risk
             * overriding an operator who is mid-PUT. */
            smf_cdr_config_t disabled;
            memset(&disabled, 0, sizeof(disabled));
            disabled.enabled = false;
            ogs_info("admin-watcher: smf/cdr cleared by admin, "
                     "disabling CDR writer (rev=%lld)", (long long)cdr_rev);
            (void)smf_ga_writer_apply_runtime(&disabled);
        }
        /* Free the heap strings we took ownership of under the lock. */
        if (cdr_cfg.spool_dir)     ogs_free((void *)cdr_cfg.spool_dir);
        if (cdr_cfg.node_id)       ogs_free((void *)cdr_cfg.node_id);
        if (cdr_cfg.local_address) ogs_free((void *)cdr_cfg.local_address);
    }

    if (radius_pending) {
        if (radius_has_value) {
            ogs_info("admin-watcher: applying smf/radius settings rev=%lld "
                    "(num_servers=%d)",
                    (long long)radius_rev, radius_cfg.num_servers);
            (void)smf_radius_apply_runtime(&radius_cfg);
        } else {
            /* Row cleared — turn RADIUS client + PoD off. YAML-driven
             * restart is how operators restore the file-based config. */
            smf_radius_config_t off;
            memset(&off, 0, sizeof(off));
            off.enabled = false;
            off.pod_enabled = false;
            off.num_servers = 0;
            ogs_info("admin-watcher: smf/radius cleared by admin, "
                    "disabling RADIUS (rev=%lld)", (long long)radius_rev);
            (void)smf_radius_apply_runtime(&off);
        }
        {
            int i;
            if (radius_cfg.nas_id)     ogs_free((void *)radius_cfg.nas_id);
            if (radius_cfg.nas_ip)     ogs_free((void *)radius_cfg.nas_ip);
            if (radius_cfg.pod_bind)   ogs_free((void *)radius_cfg.pod_bind);
            if (radius_cfg.pod_secret) ogs_free((void *)radius_cfg.pod_secret);
            for (i = 0; i < SMF_MAX_RADIUS_SERVERS; i++) {
                if (radius_cfg.servers[i].host)
                    ogs_free((void *)radius_cfg.servers[i].host);
                if (radius_cfg.servers[i].secret)
                    ogs_free((void *)radius_cfg.servers[i].secret);
            }
        }
    }

    if (g_t_drain)
        ogs_timer_start(g_t_drain, ogs_time_from_msec(DRAIN_INTERVAL_MS));
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

int smf_admin_watcher_init(void)
{
    if (g_watcher) return 0;

    /* Runtime kill switch: OPEN5GS_ADMIN_WATCHER=0|false|off|no to skip. */
    {
        const char *dis = getenv("OPEN5GS_ADMIN_WATCHER");
        if (dis && (!strcasecmp(dis, "0") || !strcasecmp(dis, "false") ||
                    !strcasecmp(dis, "off") || !strcasecmp(dis, "no"))) {
            ogs_info("admin-watcher: disabled by OPEN5GS_ADMIN_WATCHER=%s",
                    dis);
            return 0;
        }
    }

    ogs_list_init(&g_pending_upf_peers);
    ogs_list_init(&g_pending_subnets);

    const char *url = getenv("OPEN5GS_ADMIN_URL");
    if (!url || !*url) url = "http://127.0.0.1:9998";
    const char *token = getenv("OPEN5GS_ADMIN_TOKEN");

    char hostname[128] = "smf";
    (void)gethostname(hostname, sizeof(hostname) - 1);
    hostname[sizeof(hostname) - 1] = '\0';
    char nf_id[256];
    snprintf(nf_id, sizeof(nf_id), "%s#%d", hostname, (int)getpid());

    ogs_admin_watcher_cfg_t cfg = {
        .base_url           = url,
        .bearer_token       = (token && *token) ? token : NULL,
        .nf_type            = "smf",
        .nf_id              = nf_id,
        .nf_version         = NULL,
        .poll_interval_ms   = 5000,
        .request_timeout_ms = 3000,
    };
    ogs_admin_watcher_cbs_t cbs = { 0 };
    cbs.on_dnn_add        = on_dnn_add;
    cbs.on_upf_peer_add   = on_upf_peer_add;
    cbs.on_subnet_add     = on_subnet_add;
    cbs.on_smf_cdr_update    = on_smf_cdr_update;
    cbs.on_smf_radius_update = on_smf_radius_update;
    cbs.on_settings_clear    = on_settings_clear;

    g_watcher = ogs_admin_watcher_new(&cfg, &cbs);
    if (!g_watcher) {
        ogs_error("admin-watcher: failed to create watcher");
        return -1;
    }

    /* Register the main-thread drain timer BEFORE starting the watcher,
     * so we don't race a tick that queues before we can drain it. */
    g_t_drain = ogs_timer_add(ogs_app()->timer_mgr, drain_cb, NULL);
    if (!g_t_drain) {
        ogs_error("admin-watcher: failed to allocate drain timer");
        ogs_admin_watcher_free(g_watcher);
        g_watcher = NULL;
        return -1;
    }
    ogs_timer_start(g_t_drain, ogs_time_from_msec(DRAIN_INTERVAL_MS));

    if (ogs_admin_watcher_start(g_watcher) != 0) {
        ogs_error("admin-watcher: failed to start watcher thread");
        ogs_timer_delete(g_t_drain);
        g_t_drain = NULL;
        ogs_admin_watcher_free(g_watcher);
        g_watcher = NULL;
        return -1;
    }

    ogs_info("admin-watcher: started (url=%s nf_id=%s)", url, nf_id);
    return 0;
}

void smf_admin_watcher_final(void)
{
    if (g_watcher) {
        ogs_admin_watcher_stop(g_watcher);
        ogs_admin_watcher_free(g_watcher);
        g_watcher = NULL;
    }
    if (g_t_drain) {
        ogs_timer_delete(g_t_drain);
        g_t_drain = NULL;
    }

    /* Free any remaining pending entries. */
    pthread_mutex_lock(&g_pending_lock);
    {
        pending_upf_peer_t *p, *n;
        ogs_list_for_each_safe(&g_pending_upf_peers, n, p) {
            ogs_list_remove(&g_pending_upf_peers, p);
            free_pending_upf_peer(p);
        }
    }
    {
        pending_subnet_t *p, *n;
        ogs_list_for_each_safe(&g_pending_subnets, n, p) {
            ogs_list_remove(&g_pending_subnets, p);
            free_pending_subnet(p);
        }
    }
    clear_pending_cdr_strings_locked();
    memset(&g_pending_cdr.cfg, 0, sizeof(g_pending_cdr.cfg));
    g_pending_cdr.has_value = false;
    g_pending_cdr_has_next = false;
    clear_pending_radius_strings_locked();
    memset(&g_pending_radius.cfg, 0, sizeof(g_pending_radius.cfg));
    g_pending_radius.has_value = false;
    g_pending_radius_has_next = false;
    pthread_mutex_unlock(&g_pending_lock);
}
