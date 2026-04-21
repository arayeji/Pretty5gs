/*
 * CGF (open5gs-cgfd) integration with the Open5GS Admin API watcher.
 *
 * Thread model mirrors the SMF watcher:
 *   - The watcher library owns its own polling thread.
 *   - Its on_cgfd_gtpp_update callback deposits a coalesced snapshot
 *     into a mutex-protected slot and returns.
 *   - A libogs timer on the CGF main thread (`t_drain`) picks the
 *     snapshot up, calls cgf_gtpp_apply_runtime(), then frees the
 *     strings we had duplicated under the lock.
 *
 * We never touch CGF state (sockets, pollset, context) from the
 * watcher thread — only from the main-thread drain.
 */

#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>

#include "ogs-app.h"

#include "cgf-admin-watcher.h"
#include "context.h"
#include "gtpp-path.h"

#include "open5gs_admin_watcher.h"

#define DRAIN_INTERVAL_MS 1000

/*
 * Pending cgfd/gtpp settings — singleton, last-write-wins. `has_value`
 * is false when the settings row was cleared (DELETE).
 */
typedef struct pending_gtpp_settings_s {
    bool   has_value;
    cgf_hot_config_t cfg;   /* hosts are heap-owned here */
    int64_t revision;
} pending_gtpp_settings_t;

static pthread_mutex_t g_pending_lock = PTHREAD_MUTEX_INITIALIZER;
static pending_gtpp_settings_t g_pending_gtpp;
static bool g_pending_gtpp_has_next;

static ogs_admin_watcher_t *g_watcher;
static ogs_timer_t         *g_t_drain;

static void clear_pending_strings_locked(void)
{
    int i;
    for (i = 0; i < CGF_MAX_PEERS; i++) {
        if (g_pending_gtpp.cfg.peers[i].host) {
            ogs_free((void *)g_pending_gtpp.cfg.peers[i].host);
            g_pending_gtpp.cfg.peers[i].host = NULL;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Watcher-thread callbacks                                            */
/* ------------------------------------------------------------------ */

static void on_cgfd_gtpp_update(
        const ogs_admin_cgfd_gtpp_t *cfg,
        int64_t revision, void *ud)
{
    (void)ud;
    int i;

    if (!cfg) return;

    pthread_mutex_lock(&g_pending_lock);

    clear_pending_strings_locked();
    memset(&g_pending_gtpp.cfg, 0, sizeof(g_pending_gtpp.cfg));

    g_pending_gtpp.cfg.echo_interval_s              = cfg->echo_interval_s;
    g_pending_gtpp.cfg.request_rto_ms               = cfg->request_rto_ms;
    g_pending_gtpp.cfg.request_retries              = cfg->request_retries;
    g_pending_gtpp.cfg.failover_after_missed_echoes =
        cfg->failover_after_missed_echoes;
    g_pending_gtpp.cfg.max_records_per_packet       = cfg->max_records_per_packet;
    g_pending_gtpp.cfg.max_bytes_per_packet         = cfg->max_bytes_per_packet;
    g_pending_gtpp.cfg.purge_on_success             = cfg->purge_on_success;

    for (i = 0; i < cfg->num_peers && i < CGF_MAX_PEERS; i++) {
        const ogs_admin_cgf_peer_t *s = &cfg->peers[i];
        cgf_hot_peer_t *d = &g_pending_gtpp.cfg.peers[i];

        d->host       = s->host ? ogs_strdup(s->host) : NULL;
        d->port       = s->port ? s->port : CGF_DEFAULT_GTPP_PORT;
        d->is_primary = s->is_primary ? 1 : 0;
    }
    g_pending_gtpp.cfg.num_peers = cfg->num_peers;

    g_pending_gtpp.has_value = true;
    g_pending_gtpp.revision  = revision;
    g_pending_gtpp_has_next  = true;

    pthread_mutex_unlock(&g_pending_lock);
}

static void on_settings_clear(const char *scope, const char *kind, void *ud)
{
    (void)ud;
    if (!scope || !kind) return;
    if (strcmp(scope, "cgfd") != 0 || strcmp(kind, "gtpp") != 0) return;

    pthread_mutex_lock(&g_pending_lock);
    clear_pending_strings_locked();
    memset(&g_pending_gtpp.cfg, 0, sizeof(g_pending_gtpp.cfg));
    g_pending_gtpp.has_value = false;
    g_pending_gtpp.revision  = 0;
    g_pending_gtpp_has_next  = true;
    pthread_mutex_unlock(&g_pending_lock);
}

/* ------------------------------------------------------------------ */
/* Main-thread drain                                                   */
/* ------------------------------------------------------------------ */

static void drain_cb(void *data)
{
    bool pending = false, has_value = false;
    cgf_hot_config_t cfg;
    int64_t rev = 0;

    (void)data;
    memset(&cfg, 0, sizeof(cfg));

    pthread_mutex_lock(&g_pending_lock);
    if (g_pending_gtpp_has_next) {
        pending   = true;
        has_value = g_pending_gtpp.has_value;
        rev       = g_pending_gtpp.revision;
        cfg = g_pending_gtpp.cfg;
        memset(&g_pending_gtpp.cfg, 0, sizeof(g_pending_gtpp.cfg));
        g_pending_gtpp_has_next = false;
        g_pending_gtpp.has_value = false;
    }
    pthread_mutex_unlock(&g_pending_lock);

    if (pending) {
        if (has_value) {
            ogs_info("admin-watcher: applying cgfd/gtpp settings rev=%lld "
                    "(num_peers=%d)",
                    (long long)rev, cfg.num_peers);
            (void)cgf_gtpp_apply_runtime(&cfg);
        } else {
            /* Row cleared — drop all peers. Records keep piling up in
             * the spool; they will be sent once an operator re-adds a
             * peer. We do NOT revert to YAML because SIGHUP is the
             * supported way to reload on-disk config.
             *
             * Use the tri-state sentinel (-1) for purge_on_success so
             * the runtime retention policy is preserved; clearing the
             * settings row shouldn't silently flip the retention flag. */
            cgf_hot_config_t empty;
            memset(&empty, 0, sizeof(empty));
            empty.purge_on_success = -1;
            ogs_info("admin-watcher: cgfd/gtpp cleared by admin, "
                    "removing all peers (rev=%lld)", (long long)rev);
            (void)cgf_gtpp_apply_runtime(&empty);
        }
        /* Free the heap-owned hosts we took ownership of above. */
        int i;
        for (i = 0; i < CGF_MAX_PEERS; i++)
            if (cfg.peers[i].host)
                ogs_free((void *)cfg.peers[i].host);
    }

    if (g_t_drain)
        ogs_timer_start(g_t_drain, ogs_time_from_msec(DRAIN_INTERVAL_MS));
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

int cgf_admin_watcher_init(void)
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

    const char *url = getenv("OPEN5GS_ADMIN_URL");
    if (!url || !*url) url = "http://127.0.0.1:9998";
    const char *token = getenv("OPEN5GS_ADMIN_TOKEN");

    char hostname[128] = "cgfd";
    (void)gethostname(hostname, sizeof(hostname) - 1);
    hostname[sizeof(hostname) - 1] = '\0';
    char nf_id[256];
    snprintf(nf_id, sizeof(nf_id), "%s#%d", hostname, (int)getpid());

    ogs_admin_watcher_cfg_t cfg = {
        .base_url           = url,
        .bearer_token       = (token && *token) ? token : NULL,
        .nf_type            = "cgfd",
        .nf_id              = nf_id,
        .nf_version         = NULL,
        .poll_interval_ms   = 5000,
        .request_timeout_ms = 3000,
    };
    ogs_admin_watcher_cbs_t cbs = { 0 };
    cbs.on_cgfd_gtpp_update = on_cgfd_gtpp_update;
    cbs.on_settings_clear   = on_settings_clear;

    g_watcher = ogs_admin_watcher_new(&cfg, &cbs);
    if (!g_watcher) {
        ogs_error("admin-watcher: failed to create watcher");
        return -1;
    }

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

void cgf_admin_watcher_final(void)
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
    pthread_mutex_lock(&g_pending_lock);
    clear_pending_strings_locked();
    memset(&g_pending_gtpp.cfg, 0, sizeof(g_pending_gtpp.cfg));
    g_pending_gtpp.has_value = false;
    g_pending_gtpp_has_next = false;
    pthread_mutex_unlock(&g_pending_lock);
}
