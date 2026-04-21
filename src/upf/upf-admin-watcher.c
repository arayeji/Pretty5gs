/*
 * UPF integration with the Open5GS Admin API watcher (C).
 *
 * Thread model mirrors the SMF integration: the watcher thread only
 * enqueues; a libogs timer drains on the main UPF thread and calls
 * ogs_pfcp_subnet_add() there.
 *
 * Caveat: the UPF's data plane relies on `ogstun` (or equivalent) being
 * brought up with the right address range at the OS level. Adding a
 * subnet via ogs_pfcp_subnet_add allocates the pool on the UPF side
 * but does NOT configure the host's tun device. Operators must ensure
 * the device exists with the new pool's gateway/route before UEs attach
 * into it.
 */

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "ogs-app.h"
#include "ogs-pfcp.h"

#include "upf-admin-watcher.h"

#include "open5gs_admin_watcher.h"

#define DRAIN_INTERVAL_MS 1000

typedef struct pending_subnet_s {
    ogs_lnode_t lnode;
    char   *cidr;
    char   *dnn;
    char   *dev;
    char   *gateway;
    int64_t revision;
} pending_subnet_t;

static pthread_mutex_t g_pending_lock = PTHREAD_MUTEX_INITIALIZER;
static ogs_list_t g_pending_subnets;

static ogs_admin_watcher_t *g_watcher;
static ogs_timer_t         *g_t_drain;

/* ------------------------------------------------------------------ */

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

static void apply_one_subnet(pending_subnet_t *p)
{
    char ipstr[OGS_ADDRSTRLEN];
    char prefix[8];

    if (split_cidr(p->cidr, ipstr, sizeof(ipstr), prefix, sizeof(prefix)) != 0) {
        ogs_error("admin-watcher: bad CIDR '%s'", p->cidr);
        return;
    }

    ogs_pfcp_subnet_t *subnet = ogs_pfcp_subnet_add(
            ipstr, prefix, p->gateway, p->dnn, p->dev);
    if (!subnet) {
        ogs_error("admin-watcher: ogs_pfcp_subnet_add(%s/%s dnn=%s) failed",
                ipstr, prefix, p->dnn);
        return;
    }

    ogs_info("admin-watcher: added subnet %s dnn=%s dev=%s (rev=%lld)",
            p->cidr, p->dnn,
            p->dev ? p->dev : "(default)",
            (long long)p->revision);
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
    ogs_list_t subnets;
    ogs_list_init(&subnets);

    pthread_mutex_lock(&g_pending_lock);
    {
        pending_subnet_t *p, *n;
        ogs_list_for_each_safe(&g_pending_subnets, n, p) {
            ogs_list_remove(&g_pending_subnets, p);
            ogs_list_add(&subnets, p);
        }
    }
    pthread_mutex_unlock(&g_pending_lock);

    {
        pending_subnet_t *p, *n;
        ogs_list_for_each_safe(&subnets, n, p) {
            apply_one_subnet(p);
            ogs_list_remove(&subnets, p);
            free_pending_subnet(p);
        }
    }

    if (g_t_drain)
        ogs_timer_start(g_t_drain, ogs_time_from_msec(DRAIN_INTERVAL_MS));
}

/* ------------------------------------------------------------------ */

int upf_admin_watcher_init(void)
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

    ogs_list_init(&g_pending_subnets);

    const char *url = getenv("OPEN5GS_ADMIN_URL");
    if (!url || !*url) url = "http://127.0.0.1:9998";
    const char *token = getenv("OPEN5GS_ADMIN_TOKEN");

    char hostname[128] = "upf";
    (void)gethostname(hostname, sizeof(hostname) - 1);
    hostname[sizeof(hostname) - 1] = '\0';
    char nf_id[256];
    snprintf(nf_id, sizeof(nf_id), "%s#%d", hostname, (int)getpid());

    ogs_admin_watcher_cfg_t cfg = {
        .base_url           = url,
        .bearer_token       = (token && *token) ? token : NULL,
        .nf_type            = "upf",
        .nf_id              = nf_id,
        .nf_version         = NULL,
        .poll_interval_ms   = 5000,
        .request_timeout_ms = 3000,
    };
    ogs_admin_watcher_cbs_t cbs = { 0 };
    cbs.on_subnet_add = on_subnet_add;

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

void upf_admin_watcher_final(void)
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
    {
        pending_subnet_t *p, *n;
        ogs_list_for_each_safe(&g_pending_subnets, n, p) {
            ogs_list_remove(&g_pending_subnets, p);
            free_pending_subnet(p);
        }
    }
    pthread_mutex_unlock(&g_pending_lock);
}
