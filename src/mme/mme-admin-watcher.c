/*
 * MME integration with the Open5GS Admin API watcher (C).
 *
 * Scope today: hot-add of (mcc, mnc, tac) tuples into
 *   mme_self()->served_tai[0].list2
 * for PLMNs that already have a list2 entry, or into a new
 * served_tai[num_of_served_tai] slot otherwise.
 *
 * Intentional constraints (per operator requirements):
 *   - Adds are append-only; nothing is shifted or reallocated. eNBs that
 *     are already connected keep working; the new TAI becomes visible to
 *     the next UE attach. No S1 Reset is issued to existing eNBs.
 *   - Deletes are ignored here. Deletion from the admin API simply removes
 *     the config row.
 *
 * Concurrency: the watcher callback runs on its own libcurl thread. The
 * MME main loop reads served_tai without locks. We use a simple mutex
 * strictly around our writes, and treat readers as lock-free: they may
 * miss a newly-appended entry for one event cycle, which is acceptable
 * because attaches retry and attach-reject does not tear the ecosystem
 * down. If you ever need strict synchronization, push an MME event into
 * the main-loop queue instead of mutating state inline.
 *
 * Compile-time: only built when -Dadmin_watcher=true.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "mme-admin-watcher.h"
#include "mme-context.h"

#include "open5gs_admin_watcher.h"

static ogs_admin_watcher_t *g_watcher;
static pthread_mutex_t g_apply_lock = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------ */
/* Apply logic                                                         */
/* ------------------------------------------------------------------ */

/* Returns index of the served_tai entry whose list2 already has an entry
 * with this PLMN, or -1 if none. */
static int find_served_tai_by_plmn(const ogs_plmn_id_t *plmn_id)
{
    mme_context_t *mme = mme_self();
    int i, j;

    for (i = 0; i < mme->num_of_served_tai; i++) {
        ogs_eps_tai2_list_t *list2 = &mme->served_tai[i].list2;
        for (j = 0; j < list2->num; j++) {
            if (memcmp(&list2->tai[j].plmn_id, plmn_id,
                       sizeof(*plmn_id)) == 0) {
                return i;
            }
        }
    }
    return -1;
}

static bool tac_already_present(int entry, const ogs_plmn_id_t *plmn_id, int tac)
{
    mme_context_t *mme = mme_self();
    ogs_eps_tai2_list_t *list2 = &mme->served_tai[entry].list2;
    int j;
    for (j = 0; j < list2->num; j++) {
        if (memcmp(&list2->tai[j].plmn_id, plmn_id,
                   sizeof(*plmn_id)) == 0 &&
            list2->tai[j].tac == tac) {
            return true;
        }
    }
    return false;
}

static void on_tac_add(
        const char *mcc, const char *mnc, int tac,
        int64_t revision, void *ud)
{
    (void)ud;
    (void)revision;

    if (!mcc || !mnc) return;
    if (tac < 0 || tac > 0xFFFFFF) return;

    ogs_plmn_id_t plmn_id;
    ogs_plmn_id_build(&plmn_id, atoi(mcc), atoi(mnc), (int)strlen(mnc));

    pthread_mutex_lock(&g_apply_lock);

    mme_context_t *mme = mme_self();
    int entry = find_served_tai_by_plmn(&plmn_id);
    ogs_eps_tai2_list_t *list2;

    if (entry < 0) {
        /* New served_tai slot. Capacity checked against the MME's compile
         * bound — the admin API already enforces a softer cap, but we
         * re-check defensively. */
        if (mme->num_of_served_tai >= OGS_MAX_NUM_OF_SUPPORTED_TA) {
            ogs_error("admin-watcher: served_tai full, dropping "
                      "mcc=%s mnc=%s tac=%d", mcc, mnc, tac);
            goto out;
        }
        entry = mme->num_of_served_tai;
        list2 = &mme->served_tai[entry].list2;
        list2->type = OGS_TAI2_TYPE;
    } else {
        list2 = &mme->served_tai[entry].list2;
    }

    if (tac_already_present(entry, &plmn_id, tac)) {
        goto out;
    }

    if (list2->num >= OGS_MAX_NUM_OF_TAI) {
        ogs_error("admin-watcher: list2 full for mcc=%s mnc=%s, "
                  "dropping tac=%d", mcc, mnc, tac);
        goto out;
    }

    list2->tai[list2->num].plmn_id = plmn_id;
    list2->tai[list2->num].tac = tac;
    /* Publish num last so readers that race see either the old count
     * or a fully-initialized entry. `list2->num` is a uint8_t:5
     * bit-field so we can't take its address for __atomic_store_n;
     * instead emit an explicit release fence before a plain store
     * (single-byte, naturally aligned; safe on all supported archs). */
    {
        uint8_t new_num = (uint8_t)(list2->num + 1);
        __atomic_thread_fence(__ATOMIC_RELEASE);
        list2->num = new_num;
    }

    if (entry == mme->num_of_served_tai) {
        __atomic_store_n(&mme->num_of_served_tai,
                         mme->num_of_served_tai + 1, __ATOMIC_RELEASE);
    }

    ogs_info("admin-watcher: added TAC mcc=%s mnc=%s tac=%d (rev=%lld)",
             mcc, mnc, tac, (long long)revision);

out:
    pthread_mutex_unlock(&g_apply_lock);
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

int mme_admin_watcher_init(void)
{
    if (g_watcher) return 0;

    /* Runtime kill switch: set OPEN5GS_ADMIN_WATCHER=0 (or =false / =off /
     * =no) to skip starting the watcher entirely. Use this to bisect
     * whether a crash is in the watcher path when the build already
     * enables -Dadmin_watcher. */
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

    char nf_id[256];
    char hostname[128] = "mme";
    (void)gethostname(hostname, sizeof(hostname) - 1);
    hostname[sizeof(hostname) - 1] = '\0';
    snprintf(nf_id, sizeof(nf_id), "%s#%d", hostname, (int)getpid());

    ogs_admin_watcher_cfg_t cfg = {
        .base_url           = url,
        .bearer_token       = (token && *token) ? token : NULL,
        .nf_type            = "mme",
        .nf_id              = nf_id,
        .nf_version         = NULL,
        .poll_interval_ms   = 5000,
        .request_timeout_ms = 3000,
    };

    ogs_admin_watcher_cbs_t cbs = { 0 };
    cbs.on_tac_add = on_tac_add;

    g_watcher = ogs_admin_watcher_new(&cfg, &cbs);
    if (!g_watcher) {
        ogs_error("admin-watcher: failed to create watcher");
        return -1;
    }
    if (ogs_admin_watcher_start(g_watcher) != 0) {
        ogs_error("admin-watcher: failed to start watcher thread");
        ogs_admin_watcher_free(g_watcher);
        g_watcher = NULL;
        return -1;
    }

    ogs_info("admin-watcher: started (url=%s nf_id=%s)", url, nf_id);
    return 0;
}

void mme_admin_watcher_final(void)
{
    if (!g_watcher) return;
    ogs_admin_watcher_stop(g_watcher);
    ogs_admin_watcher_free(g_watcher);
    g_watcher = NULL;
}
