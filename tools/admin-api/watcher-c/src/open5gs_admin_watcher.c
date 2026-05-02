/*
 * Open5GS Admin Watcher — implementation.
 *
 * Dependencies: libcurl, cJSON, pthreads (all already available in the
 * Open5GS build graph).
 *
 * Thread model: one internal poller thread. Every tick issues five GETs
 * (one per resource kind) plus one POST for the heartbeat. Callbacks are
 * invoked inline on the poller thread — the NF integrator is responsible
 * for marshalling onto its own event loop if its state is not thread-safe.
 */

#include "open5gs_admin_watcher.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <curl/curl.h>

/*
 * cJSON: prefer the system library (pkg-config libcjson or
 * /usr/include/cjson/cJSON.h) when available, otherwise fall back to
 * the copy Open5GS vendors under lib/sbi/openapi/external/cJSON.[ch].
 * meson.build injects the corresponding include dir.
 */
#if defined(OGS_ADMIN_WATCHER_USE_VENDORED_CJSON)
#include "cJSON.h"
#else
#include <cjson/cJSON.h>
#endif

#ifndef OW_DEFAULT_POLL_MS
#define OW_DEFAULT_POLL_MS 5000
#endif

#ifndef OW_DEFAULT_TIMEOUT_MS
#define OW_DEFAULT_TIMEOUT_MS 3000
#endif

#define OW_LOG(level, fmt, ...) \
    fprintf(stderr, "[admin-watcher] " level ": " fmt "\n", ##__VA_ARGS__)
#define OW_ERR(fmt, ...)  OW_LOG("error", fmt, ##__VA_ARGS__)
#define OW_WARN(fmt, ...) OW_LOG("warn",  fmt, ##__VA_ARGS__)
#define OW_INFO(fmt, ...) OW_LOG("info",  fmt, ##__VA_ARGS__)

struct ogs_admin_watcher_s {
    /* config — strings owned by caller */
    char     *base_url;      /* duped so watcher owns it */
    char     *bearer_token;  /* duped, or NULL */
    char     *nf_type;       /* duped */
    char     *nf_id;         /* duped */
    char     *nf_version;    /* duped or NULL */
    int       poll_interval_ms;
    int       request_timeout_ms;

    ogs_admin_watcher_cbs_t cbs;

    /* runtime */
    int64_t           applied_revision;
    pthread_mutex_t   applied_lock;
    pthread_t         thread;
    volatile bool     running;
    volatile bool     stop;

    /* Per-settings-kind apply cursor. Each "kind" gets one slot — when
     * we add more kinds these become a small open-addressed map. */
    int64_t           smf_cdr_applied_revision;
    bool              smf_cdr_present;
    int64_t           smf_radius_applied_revision;
    bool              smf_radius_present;
    int64_t           cgfd_gtpp_applied_revision;
    bool              cgfd_gtpp_present;

    CURL             *curl;        /* reused on poller thread */
    struct curl_slist *headers;    /* includes Authorization if any */
};

/* Small growable buffer for libcurl responses. */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} ow_buf_t;

static size_t ow_write_cb(void *ptr, size_t size, size_t nmemb, void *udata)
{
    ow_buf_t *b = (ow_buf_t *)udata;
    size_t n = size * nmemb;
    if (b->len + n + 1 > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 4096;
        while (ncap < b->len + n + 1) ncap *= 2;
        char *r = (char *)realloc(b->data, ncap);
        if (!r) return 0;
        b->data = r;
        b->cap = ncap;
    }
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    b->data[b->len] = '\0';
    return n;
}

static char *ow_strdup(const char *s)
{
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *d = (char *)malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

static void ow_sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000L * 1000L;
    nanosleep(&ts, NULL);
}

static long ow_clamp_long(cJSON *item, long fallback)
{
    if (!cJSON_IsNumber(item)) return fallback;
    return (long)item->valuedouble;
}

static const char *ow_str_or_null(cJSON *item)
{
    if (!cJSON_IsString(item) || !item->valuestring) return NULL;
    return item->valuestring;
}

/* ------------------------------------------------------------------ */
/* HTTP primitives                                                     */
/* ------------------------------------------------------------------ */

/* GET {base}/{path}. Returns a freshly-allocated body string on success
 * (caller frees) and sets *http_code. Returns NULL on error. */
static char *ow_http_get(
        ogs_admin_watcher_t *w, const char *path, long *http_code)
{
    char url[1024];
    int n = snprintf(url, sizeof(url), "%s%s", w->base_url, path);
    if (n <= 0 || (size_t)n >= sizeof(url)) {
        OW_ERR("url too long: %s%s", w->base_url, path);
        return NULL;
    }

    ow_buf_t buf = { 0 };

    curl_easy_reset(w->curl);
    curl_easy_setopt(w->curl, CURLOPT_URL, url);
    curl_easy_setopt(w->curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(w->curl, CURLOPT_WRITEFUNCTION, ow_write_cb);
    curl_easy_setopt(w->curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(w->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(w->curl, CURLOPT_TIMEOUT_MS,
                     (long)w->request_timeout_ms);
    if (w->headers) {
        curl_easy_setopt(w->curl, CURLOPT_HTTPHEADER, w->headers);
    }

    CURLcode rc = curl_easy_perform(w->curl);
    if (rc != CURLE_OK) {
        OW_WARN("GET %s failed: %s", url, curl_easy_strerror(rc));
        free(buf.data);
        return NULL;
    }

    curl_easy_getinfo(w->curl, CURLINFO_RESPONSE_CODE, http_code);
    if (*http_code >= 400) {
        OW_WARN("GET %s -> HTTP %ld", url, *http_code);
        free(buf.data);
        return NULL;
    }
    return buf.data;
}

/* POST {base}/{path} with a JSON body. Returns 0 on HTTP 2xx. */
static int ow_http_post_json(
        ogs_admin_watcher_t *w, const char *path, const char *body)
{
    char url[1024];
    int n = snprintf(url, sizeof(url), "%s%s", w->base_url, path);
    if (n <= 0 || (size_t)n >= sizeof(url)) return -1;

    ow_buf_t buf = { 0 };

    struct curl_slist *hdrs = NULL;
    if (w->headers) {
        /* Copy the auth header list and add Content-Type. */
        for (struct curl_slist *it = w->headers; it; it = it->next)
            hdrs = curl_slist_append(hdrs, it->data);
    }
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    curl_easy_reset(w->curl);
    curl_easy_setopt(w->curl, CURLOPT_URL, url);
    curl_easy_setopt(w->curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(w->curl, CURLOPT_WRITEFUNCTION, ow_write_cb);
    curl_easy_setopt(w->curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(w->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(w->curl, CURLOPT_TIMEOUT_MS,
                     (long)w->request_timeout_ms);
    curl_easy_setopt(w->curl, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(w->curl);
    int ret = -1;
    if (rc == CURLE_OK) {
        long code = 0;
        curl_easy_getinfo(w->curl, CURLINFO_RESPONSE_CODE, &code);
        if (code >= 200 && code < 300) ret = 0;
        else OW_WARN("POST %s -> HTTP %ld", url, code);
    } else {
        OW_WARN("POST %s failed: %s", url, curl_easy_strerror(rc));
    }

    curl_slist_free_all(hdrs);
    free(buf.data);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Per-kind apply                                                      */
/* ------------------------------------------------------------------ */

static int64_t ow_apply_plmns(
        ogs_admin_watcher_t *w, cJSON *arr, int64_t min_rev)
{
    int64_t max_rev = min_rev;
    cJSON *it;
    cJSON_ArrayForEach(it, arr) {
        long rev = ow_clamp_long(cJSON_GetObjectItem(it, "revision"), 0);
        if (rev <= min_rev) continue;
        if (rev > max_rev) max_rev = rev;
        if (!w->cbs.on_plmn_add) continue;

        const char *mcc = ow_str_or_null(cJSON_GetObjectItem(it, "mcc"));
        const char *mnc = ow_str_or_null(cJSON_GetObjectItem(it, "mnc"));
        if (!mcc || !mnc) continue;

        w->cbs.on_plmn_add(mcc, mnc, rev, w->cbs.userdata);
    }
    return max_rev;
}

static int64_t ow_apply_tacs(
        ogs_admin_watcher_t *w, cJSON *arr, int64_t min_rev)
{
    int64_t max_rev = min_rev;
    cJSON *it;
    cJSON_ArrayForEach(it, arr) {
        long rev = ow_clamp_long(cJSON_GetObjectItem(it, "revision"), 0);
        if (rev <= min_rev) continue;
        if (rev > max_rev) max_rev = rev;
        if (!w->cbs.on_tac_add) continue;

        const char *mcc = ow_str_or_null(cJSON_GetObjectItem(it, "mcc"));
        const char *mnc = ow_str_or_null(cJSON_GetObjectItem(it, "mnc"));
        int tac = (int)ow_clamp_long(cJSON_GetObjectItem(it, "tacValue"), -1);
        if (!mcc || !mnc || tac < 0) continue;

        w->cbs.on_tac_add(mcc, mnc, tac, rev, w->cbs.userdata);
    }
    return max_rev;
}

static int64_t ow_apply_dnns(
        ogs_admin_watcher_t *w, cJSON *arr, int64_t min_rev)
{
    int64_t max_rev = min_rev;
    cJSON *it;
    cJSON_ArrayForEach(it, arr) {
        long rev = ow_clamp_long(cJSON_GetObjectItem(it, "revision"), 0);
        if (rev <= min_rev) continue;
        if (rev > max_rev) max_rev = rev;
        if (!w->cbs.on_dnn_add) continue;

        const char *name = ow_str_or_null(cJSON_GetObjectItem(it, "name"));
        if (!name) continue;
        const char *dns1 = ow_str_or_null(cJSON_GetObjectItem(it, "dns1"));
        const char *dns2 = ow_str_or_null(cJSON_GetObjectItem(it, "dns2"));
        int mtu = (int)ow_clamp_long(cJSON_GetObjectItem(it, "mtu"), 0);
        int sst = (int)ow_clamp_long(cJSON_GetObjectItem(it, "sliceSst"), 0);
        const char *sd = ow_str_or_null(cJSON_GetObjectItem(it, "sliceSd"));

        w->cbs.on_dnn_add(name, dns1, dns2, mtu, sst, sd, rev,
                          w->cbs.userdata);
    }
    return max_rev;
}

static int64_t ow_apply_upf_peers(
        ogs_admin_watcher_t *w, cJSON *arr, int64_t min_rev)
{
    int64_t max_rev = min_rev;
    cJSON *it;
    cJSON_ArrayForEach(it, arr) {
        long rev = ow_clamp_long(cJSON_GetObjectItem(it, "revision"), 0);
        if (rev <= min_rev) continue;
        if (rev > max_rev) max_rev = rev;
        if (!w->cbs.on_upf_peer_add) continue;

        const char *host = ow_str_or_null(cJSON_GetObjectItem(it, "host"));
        int port = (int)ow_clamp_long(cJSON_GetObjectItem(it, "port"), 8805);
        if (!host) continue;

        /* Turn dnns[] into a NULL-terminated C array of pointers. */
        cJSON *dnns = cJSON_GetObjectItem(it, "dnns");
        const char **argv = NULL;
        size_t argc = 0;
        if (cJSON_IsArray(dnns)) {
            argc = (size_t)cJSON_GetArraySize(dnns);
            argv = (const char **)calloc(argc + 1, sizeof(char *));
            if (argv) {
                size_t i = 0;
                cJSON *d;
                cJSON_ArrayForEach(d, dnns) {
                    const char *s = ow_str_or_null(d);
                    if (s) argv[i++] = s;
                }
                argv[i] = NULL;
            }
        }

        w->cbs.on_upf_peer_add(host, port, argv, rev, w->cbs.userdata);
        free(argv);
    }
    return max_rev;
}

static int64_t ow_apply_subnets(
        ogs_admin_watcher_t *w, cJSON *arr, int64_t min_rev)
{
    int64_t max_rev = min_rev;
    cJSON *it;
    cJSON_ArrayForEach(it, arr) {
        long rev = ow_clamp_long(cJSON_GetObjectItem(it, "revision"), 0);
        if (rev <= min_rev) continue;
        if (rev > max_rev) max_rev = rev;
        if (!w->cbs.on_subnet_add) continue;

        const char *cidr = ow_str_or_null(cJSON_GetObjectItem(it, "cidr"));
        const char *dnn  = ow_str_or_null(cJSON_GetObjectItem(it, "dnn"));
        const char *dev  = ow_str_or_null(cJSON_GetObjectItem(it, "dev"));
        const char *gw   = ow_str_or_null(cJSON_GetObjectItem(it, "gateway"));
        if (!cidr || !dnn) continue;

        w->cbs.on_subnet_add(cidr, dnn, dev, gw, rev, w->cbs.userdata);
    }
    return max_rev;
}

/* ------------------------------------------------------------------ */
/* Settings: GET /api/v1/settings/smf/cdr                              */
/* ------------------------------------------------------------------ */

static void ow_apply_smf_cdr_payload(
        ogs_admin_watcher_t *w, cJSON *payload, int64_t revision)
{
    if (!w->cbs.on_smf_cdr_update) return;

    ogs_admin_smf_cdr_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    cJSON *en = cJSON_GetObjectItem(payload, "enabled");
    cfg.enabled = (en && cJSON_IsBool(en) && cJSON_IsTrue(en)) ? 1 : 0;

    cfg.spool_dir     = ow_str_or_null(cJSON_GetObjectItem(payload, "spool_dir"));
    cfg.node_id       = ow_str_or_null(cJSON_GetObjectItem(payload, "node_id"));
    cfg.local_address = ow_str_or_null(cJSON_GetObjectItem(payload, "local_address"));

    cfg.rotate_max_records =
        (uint32_t)ow_clamp_long(cJSON_GetObjectItem(payload, "max_records"), 100);
    cfg.rotate_max_bytes =
        (uint32_t)ow_clamp_long(cJSON_GetObjectItem(payload, "max_bytes"), 65536);
    cfg.rotate_max_seconds =
        (uint32_t)ow_clamp_long(cJSON_GetObjectItem(payload, "max_seconds"), 30);
    cfg.triggers =
        (uint32_t)ow_clamp_long(cJSON_GetObjectItem(payload, "triggers"), 0x7);

    w->cbs.on_smf_cdr_update(&cfg, revision, w->cbs.userdata);
}

/* ------------------------------------------------------------------ */
/* Settings: GET /api/v1/settings/smf/radius                           */
/* ------------------------------------------------------------------ */

static void ow_apply_smf_radius_payload(
        ogs_admin_watcher_t *w, cJSON *payload, int64_t revision)
{
    if (!w->cbs.on_smf_radius_update) return;

    ogs_admin_smf_radius_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    cJSON *en = cJSON_GetObjectItem(payload, "enabled");
    cfg.enabled = (en && cJSON_IsBool(en) && cJSON_IsTrue(en)) ? 1 : 0;

    const char *sm = ow_str_or_null(cJSON_GetObjectItem(payload, "select_mode"));
    cfg.select_mode = (sm && strcmp(sm, "hash_imsi") == 0) ? 1 : 0;

    cfg.nas_identifier =
        ow_str_or_null(cJSON_GetObjectItem(payload, "nas_identifier"));
    cfg.nas_ip =
        ow_str_or_null(cJSON_GetObjectItem(payload, "nas_ip"));

    cfg.timeout_ms =
        (uint32_t)ow_clamp_long(cJSON_GetObjectItem(payload, "timeout_ms"), 3000);
    cfg.retry =
        (uint32_t)ow_clamp_long(cJSON_GetObjectItem(payload, "retry"), 3);
    cfg.acct_interim_interval = (uint32_t)ow_clamp_long(
        cJSON_GetObjectItem(payload, "acct_interim_interval"), 0);

    cJSON *pod_en = cJSON_GetObjectItem(payload, "pod_enabled");
    cfg.pod_enabled = (pod_en && cJSON_IsBool(pod_en) && cJSON_IsTrue(pod_en))
            ? 1 : 0;
    cfg.pod_bind =
        ow_str_or_null(cJSON_GetObjectItem(payload, "pod_bind"));
    cfg.pod_port =
        (uint16_t)ow_clamp_long(cJSON_GetObjectItem(payload, "pod_port"), 3799);
    cfg.pod_secret =
        ow_str_or_null(cJSON_GetObjectItem(payload, "pod_secret"));
    cfg.pod_teardown_timeout_ms = (uint32_t)ow_clamp_long(
        cJSON_GetObjectItem(payload, "pod_teardown_timeout_ms"), 5000);

    {
        cJSON *fi = cJSON_GetObjectItem(payload, "use_framed_ip_for_ue");
        cfg.use_framed_ip_for_ue =
                (!fi || !cJSON_IsBool(fi) || cJSON_IsTrue(fi)) ? 1 : 0;
    }

    cJSON *servers = cJSON_GetObjectItem(payload, "servers");
    if (cJSON_IsArray(servers)) {
        cJSON *s;
        cJSON_ArrayForEach(s, servers) {
            if (cfg.num_servers >= OGS_ADMIN_MAX_RADIUS_SERVERS) break;
            ogs_admin_radius_server_t *d = &cfg.servers[cfg.num_servers];
            d->host = ow_str_or_null(cJSON_GetObjectItem(s, "host"));
            if (!d->host) continue;
            d->auth_port = (uint16_t)ow_clamp_long(
                    cJSON_GetObjectItem(s, "auth_port"), 1812);
            d->acct_port = (uint16_t)ow_clamp_long(
                    cJSON_GetObjectItem(s, "acct_port"), 1813);
            d->secret = ow_str_or_null(cJSON_GetObjectItem(s, "secret"));
            const char *role =
                ow_str_or_null(cJSON_GetObjectItem(s, "role"));
            d->is_primary = (role && strcmp(role, "primary") == 0) ? 1 : 0;
            d->weight = (int)ow_clamp_long(
                    cJSON_GetObjectItem(s, "weight"), 1);
            cfg.num_servers++;
        }
    }

    w->cbs.on_smf_radius_update(&cfg, revision, w->cbs.userdata);
}

static void ow_apply_cgfd_gtpp_payload(
        ogs_admin_watcher_t *w, cJSON *payload, int64_t revision)
{
    if (!w->cbs.on_cgfd_gtpp_update) return;

    ogs_admin_cgfd_gtpp_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.echo_interval_s = (uint32_t)ow_clamp_long(
            cJSON_GetObjectItem(payload, "echo_interval_s"), 60);
    cfg.request_rto_ms = (uint32_t)ow_clamp_long(
            cJSON_GetObjectItem(payload, "request_rto_ms"), 5000);
    cfg.request_retries = (uint32_t)ow_clamp_long(
            cJSON_GetObjectItem(payload, "request_retries"), 5);
    cfg.failover_after_missed_echoes = (uint32_t)ow_clamp_long(
            cJSON_GetObjectItem(payload, "failover_after_missed_echoes"), 3);
    cfg.max_records_per_packet = (uint32_t)ow_clamp_long(
            cJSON_GetObjectItem(payload, "max_records_per_packet"), 200);
    cfg.max_bytes_per_packet = (uint32_t)ow_clamp_long(
            cJSON_GetObjectItem(payload, "max_bytes_per_packet"), 32768);

    /* Tri-state: -1 when absent so cgf_gtpp_apply_runtime() preserves the
     * daemon's existing purge setting instead of silently resetting it. */
    cJSON *pos_item = cJSON_GetObjectItem(payload, "purge_on_success");
    if (pos_item && cJSON_IsBool(pos_item))
        cfg.purge_on_success = cJSON_IsTrue(pos_item) ? 1 : 0;
    else if (pos_item && cJSON_IsNumber(pos_item))
        cfg.purge_on_success = (pos_item->valueint != 0) ? 1 : 0;
    else
        cfg.purge_on_success = -1;

    cJSON *peers = cJSON_GetObjectItem(payload, "peers");
    if (cJSON_IsArray(peers)) {
        cJSON *p;
        cJSON_ArrayForEach(p, peers) {
            if (cfg.num_peers >= OGS_ADMIN_MAX_CGF_PEERS) break;
            ogs_admin_cgf_peer_t *d = &cfg.peers[cfg.num_peers];
            d->host = ow_str_or_null(cJSON_GetObjectItem(p, "host"));
            if (!d->host) continue;
            d->port = (uint16_t)ow_clamp_long(
                    cJSON_GetObjectItem(p, "port"), 3386);
            const char *role =
                ow_str_or_null(cJSON_GetObjectItem(p, "role"));
            d->is_primary = (role && strcmp(role, "primary") == 0) ? 1 : 0;
            cfg.num_peers++;
        }
    }

    w->cbs.on_cgfd_gtpp_update(&cfg, revision, w->cbs.userdata);
}

/* Generic settings fetcher for a single (scope, kind) singleton. */
static void ow_fetch_settings_kind(
        ogs_admin_watcher_t *w,
        const char *scope, const char *kind,
        int64_t *applied_rev, bool *present,
        void (*apply)(ogs_admin_watcher_t *, cJSON *, int64_t))
{
    char path[128];
    int n = snprintf(path, sizeof(path),
                     "/api/v1/settings/%s/%s", scope, kind);
    if (n <= 0 || (size_t)n >= sizeof(path)) return;

    long code = 0;
    char *body = ow_http_get(w, path, &code);
    if (!body) {
        if (code == 404 && *present) {
            *present = false;
            *applied_rev = 0;
            if (w->cbs.on_settings_clear)
                w->cbs.on_settings_clear(scope, kind, w->cbs.userdata);
        }
        return;
    }

    cJSON *root = cJSON_Parse(body);
    free(body);
    if (!root) {
        OW_WARN("settings/%s/%s: JSON parse error", scope, kind);
        return;
    }

    int64_t rev = (int64_t)ow_clamp_long(
            cJSON_GetObjectItem(root, "revision"), 0);
    cJSON *payload = cJSON_GetObjectItem(root, "payload");

    if (rev <= *applied_rev && *present) {
        cJSON_Delete(root);
        return;
    }
    if (cJSON_IsObject(payload)) {
        apply(w, payload, rev);
        *present = true;
        *applied_rev = rev;
    } else {
        OW_WARN("settings/%s/%s: missing or non-object payload", scope, kind);
    }
    cJSON_Delete(root);
}

/* Fetch {path}, parse as JSON array, invoke applier. Updates max_rev. */
static void ow_fetch_and_apply(
        ogs_admin_watcher_t *w,
        const char *path,
        int64_t min_rev,
        int64_t *max_rev,
        int64_t (*applier)(ogs_admin_watcher_t *, cJSON *, int64_t))
{
    long code = 0;
    char *body = ow_http_get(w, path, &code);
    if (!body) return;

    cJSON *root = cJSON_Parse(body);
    if (!root) {
        OW_WARN("GET %s: JSON parse error", path);
        free(body);
        return;
    }
    if (cJSON_IsArray(root)) {
        int64_t m = applier(w, root, min_rev);
        if (m > *max_rev) *max_rev = m;
    }
    cJSON_Delete(root);
    free(body);
}

/* ------------------------------------------------------------------ */
/* Public entry points                                                 */
/* ------------------------------------------------------------------ */

int ogs_admin_watcher_tick(ogs_admin_watcher_t *w)
{
    if (!w) return -1;

    pthread_mutex_lock(&w->applied_lock);
    int64_t min_rev = w->applied_revision;
    pthread_mutex_unlock(&w->applied_lock);

    int64_t max_rev = min_rev;

    ow_fetch_and_apply(w, "/api/v1/plmns",     min_rev, &max_rev, ow_apply_plmns);
    ow_fetch_and_apply(w, "/api/v1/tacs",      min_rev, &max_rev, ow_apply_tacs);
    ow_fetch_and_apply(w, "/api/v1/dnns",      min_rev, &max_rev, ow_apply_dnns);
    ow_fetch_and_apply(w, "/api/v1/upf-peers", min_rev, &max_rev, ow_apply_upf_peers);
    ow_fetch_and_apply(w, "/api/v1/subnets",   min_rev, &max_rev, ow_apply_subnets);

    /* Settings — last-write-wins; tracked per kind, not by max_rev.
     * Each fetch is a no-op if no relevant callback is registered. */
    if (w->cbs.on_smf_cdr_update || w->cbs.on_settings_clear)
        ow_fetch_settings_kind(w, "smf", "cdr",
                &w->smf_cdr_applied_revision,
                &w->smf_cdr_present,
                ow_apply_smf_cdr_payload);
    if (w->cbs.on_smf_radius_update || w->cbs.on_settings_clear)
        ow_fetch_settings_kind(w, "smf", "radius",
                &w->smf_radius_applied_revision,
                &w->smf_radius_present,
                ow_apply_smf_radius_payload);
    if (w->cbs.on_cgfd_gtpp_update || w->cbs.on_settings_clear)
        ow_fetch_settings_kind(w, "cgfd", "gtpp",
                &w->cgfd_gtpp_applied_revision,
                &w->cgfd_gtpp_present,
                ow_apply_cgfd_gtpp_payload);

    if (max_rev > min_rev) {
        pthread_mutex_lock(&w->applied_lock);
        if (max_rev > w->applied_revision) w->applied_revision = max_rev;
        pthread_mutex_unlock(&w->applied_lock);
    }

    ogs_admin_watcher_heartbeat(w, max_rev, NULL);
    return 0;
}

int ogs_admin_watcher_heartbeat(
        ogs_admin_watcher_t *w,
        int64_t applied_revision,
        const char *last_error)
{
    if (!w) return -1;

    cJSON *o = cJSON_CreateObject();
    if (!o) return -1;
    cJSON_AddStringToObject(o, "nfId", w->nf_id ? w->nf_id : "unknown");
    cJSON_AddStringToObject(o, "nfType", w->nf_type ? w->nf_type : "unknown");
    cJSON_AddNumberToObject(o, "appliedRevision", (double)applied_revision);
    if (last_error) cJSON_AddStringToObject(o, "lastError", last_error);
    if (w->nf_version) cJSON_AddStringToObject(o, "version", w->nf_version);

    char *body = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    if (!body) return -1;

    int rc = ow_http_post_json(w, "/api/v1/apply-status/heartbeat", body);
    /* cJSON_PrintUnformatted() allocates via the cJSON hooks. In Open5GS's
     * vendored cJSON those hooks are ogs_malloc / ogs_free, which are NOT
     * interchangeable with glibc free() — using free(body) here aborts
     * with "free(): invalid pointer". Always use cJSON_free so we match
     * whichever allocator cJSON was built with. */
    cJSON_free(body);
    return rc;
}

int64_t ogs_admin_watcher_applied_revision(const ogs_admin_watcher_t *w)
{
    if (!w) return 0;
    /* mutable-through-const-is-ugly but const-correct read */
    ogs_admin_watcher_t *mw = (ogs_admin_watcher_t *)w;
    pthread_mutex_lock(&mw->applied_lock);
    int64_t v = mw->applied_revision;
    pthread_mutex_unlock(&mw->applied_lock);
    return v;
}

/* ------------------------------------------------------------------ */
/* Thread loop                                                         */
/* ------------------------------------------------------------------ */

static void *ow_thread_main(void *arg)
{
    ogs_admin_watcher_t *w = (ogs_admin_watcher_t *)arg;
    OW_INFO("watcher thread started (nf=%s id=%s url=%s)",
            w->nf_type, w->nf_id, w->base_url);

    while (!w->stop) {
        (void)ogs_admin_watcher_tick(w);

        /* sleep in small slices so stop() is responsive */
        int remaining = w->poll_interval_ms;
        while (remaining > 0 && !w->stop) {
            int slice = remaining > 200 ? 200 : remaining;
            ow_sleep_ms(slice);
            remaining -= slice;
        }
    }

    OW_INFO("watcher thread stopping");
    return NULL;
}

int ogs_admin_watcher_start(ogs_admin_watcher_t *w)
{
    if (!w) return -1;
    if (w->running) return 0;
    w->stop = false;
    int rc = pthread_create(&w->thread, NULL, ow_thread_main, w);
    if (rc != 0) {
        OW_ERR("pthread_create failed: %s", strerror(rc));
        return -1;
    }
    w->running = true;
    return 0;
}

void ogs_admin_watcher_stop(ogs_admin_watcher_t *w)
{
    if (!w || !w->running) return;
    w->stop = true;
    pthread_join(w->thread, NULL);
    w->running = false;
}

/*
 * libcurl global init. Per libcurl docs this must be called at least
 * once per program, from a thread-safe context (i.e. the main thread
 * before any worker threads that use libcurl are spawned), BEFORE
 * curl_easy_init is called.
 *
 * Some NFs (SMF, AMF, ...) link libogssbi which already calls
 * curl_global_init during its own startup, so this is redundant there.
 * Other NFs (MME, UPF, CGF) don't touch libcurl except through this
 * watcher, so we must do it ourselves — otherwise OpenSSL/GnuTLS global
 * state is set up from the watcher worker thread on first request,
 * which races with signal handling and usually SIGSEGVs within
 * seconds.
 *
 * Using pthread_once keeps us safe if multiple NFs in one process, or
 * multiple watchers, are ever created. curl_global_init is itself
 * idempotent across calls (reference-counted) so double-init via SBI
 * is also fine.
 */
static pthread_once_t ow_curl_once = PTHREAD_ONCE_INIT;
static CURLcode       ow_curl_global_rc = CURLE_OK;
static void ow_curl_global_init_once(void)
{
    ow_curl_global_rc = curl_global_init(CURL_GLOBAL_DEFAULT);
}

ogs_admin_watcher_t *ogs_admin_watcher_new(
        const ogs_admin_watcher_cfg_t *cfg,
        const ogs_admin_watcher_cbs_t *cbs)
{
    if (!cfg || !cbs) return NULL;
    if (!cfg->base_url || !cfg->nf_type || !cfg->nf_id) return NULL;

    /* MUST happen on this (caller / main) thread, before any watcher
     * worker thread is created by ogs_admin_watcher_start(). */
    pthread_once(&ow_curl_once, ow_curl_global_init_once);
    if (ow_curl_global_rc != CURLE_OK) {
        OW_ERR("curl_global_init failed: %s",
                curl_easy_strerror(ow_curl_global_rc));
        return NULL;
    }

    ogs_admin_watcher_t *w = (ogs_admin_watcher_t *)calloc(1, sizeof(*w));
    if (!w) return NULL;

    w->base_url     = ow_strdup(cfg->base_url);
    w->bearer_token = cfg->bearer_token && cfg->bearer_token[0]
                        ? ow_strdup(cfg->bearer_token) : NULL;
    w->nf_type      = ow_strdup(cfg->nf_type);
    w->nf_id        = ow_strdup(cfg->nf_id);
    w->nf_version   = cfg->nf_version && cfg->nf_version[0]
                        ? ow_strdup(cfg->nf_version) : NULL;
    w->poll_interval_ms   = cfg->poll_interval_ms > 0
                            ? cfg->poll_interval_ms
                            : OW_DEFAULT_POLL_MS;
    w->request_timeout_ms = cfg->request_timeout_ms > 0
                            ? cfg->request_timeout_ms
                            : OW_DEFAULT_TIMEOUT_MS;
    w->cbs = *cbs;

    pthread_mutex_init(&w->applied_lock, NULL);

    w->curl = curl_easy_init();
    if (!w->curl) {
        OW_ERR("curl_easy_init failed");
        ogs_admin_watcher_free(w);
        return NULL;
    }

    if (w->bearer_token) {
        char hdr[1024];
        int n = snprintf(hdr, sizeof(hdr),
                "Authorization: Bearer %s", w->bearer_token);
        if (n > 0 && (size_t)n < sizeof(hdr)) {
            w->headers = curl_slist_append(w->headers, hdr);
        }
    }

    return w;
}

void ogs_admin_watcher_free(ogs_admin_watcher_t *w)
{
    if (!w) return;
    ogs_admin_watcher_stop(w);
    if (w->headers) curl_slist_free_all(w->headers);
    if (w->curl) curl_easy_cleanup(w->curl);
    free(w->base_url);
    free(w->bearer_token);
    free(w->nf_type);
    free(w->nf_id);
    free(w->nf_version);
    pthread_mutex_destroy(&w->applied_lock);
    free(w);
}
