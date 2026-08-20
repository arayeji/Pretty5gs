/*
 * MME integration with the Open5GS Admin API watcher (C).
 *
 * Scope today: hot-add of (mcc, mnc, tac) tuples into served_tai list2
 * for PLMNs that already have a list2 entry, or into a new served_tai
 * slot otherwise.
 *
 * The watcher callback runs on a libcurl thread. Mutations are queued as
 * MME_EVENT_ADMIN_TAC_ADD and applied on the MME main thread.
 *
 * Compile-time: only built when -Dadmin_watcher=true.
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "mme-admin-watcher.h"
#include "mme-context.h"
#include "mme-event.h"

#include "open5gs_admin_watcher.h"

static ogs_admin_watcher_t *g_watcher;

/* ------------------------------------------------------------------ */
/* Apply logic (MME main thread only)                                  */
/* ------------------------------------------------------------------ */

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

void mme_admin_tac_add_apply(const char *mcc, const char *mnc, int tac)
{
    mme_context_t *mme = mme_self();
    int entry;
    ogs_eps_tai2_list_t *list2;
    ogs_plmn_id_t plmn_id;

    if (!mcc || !mnc)
        return;
    if (tac < 0 || tac > 0xFFFFFF)
        return;

    ogs_plmn_id_build(&plmn_id, atoi(mcc), atoi(mnc), (int)strlen(mnc));

    mme_ctx_lock();

    entry = find_served_tai_by_plmn(&plmn_id);
    if (entry < 0) {
        if (mme->num_of_served_tai >= OGS_MAX_NUM_OF_SUPPORTED_TA) {
            mme_ctx_unlock();
            ogs_error("admin-watcher: served_tai full, dropping "
                      "mcc=%s mnc=%s tac=%d", mcc, mnc, tac);
            return;
        }
        entry = mme->num_of_served_tai;
    }

    if (entry < mme->num_of_served_tai &&
            tac_already_present(entry, &plmn_id, tac)) {
        mme_ctx_unlock();
        return;
    }

    list2 = &mme->served_tai[entry].list2;
    if (list2->num >= OGS_MAX_NUM_OF_TAI) {
        mme_ctx_unlock();
        ogs_error("admin-watcher: list2 full for mcc=%s mnc=%s, "
                  "dropping tac=%d", mcc, mnc, tac);
        return;
    }

    /* Invalidate before mutating so served-TAI hot path cannot race. */
    mme_served_tai_map_invalidate();

    list2->type = OGS_TAI2_TYPE;
    list2->tai[list2->num].plmn_id = plmn_id;
    list2->tai[list2->num].tac = tac;
    list2->num++;

    if (entry == mme->num_of_served_tai)
        mme->num_of_served_tai++;

    mme_ctx_unlock();

    ogs_info("admin-watcher: added TAC mcc=%s mnc=%s tac=%d",
             mcc, mnc, tac);
}

/* ------------------------------------------------------------------ */
/* Watcher callback -> MME event queue                                 */
/* ------------------------------------------------------------------ */

static void on_tac_add(
        const char *mcc, const char *mnc, int tac,
        int64_t revision, void *ud)
{
    mme_event_t *e;
    int rv;

    (void)ud;
    (void)revision;

    if (!mcc || !mnc)
        return;
    if (tac < 0 || tac > 0xFFFFFF)
        return;

    e = mme_event_new(MME_EVENT_ADMIN_TAC_ADD);
    if (!e) {
        ogs_error("admin-watcher: event_new failed");
        return;
    }

    ogs_cpystrn(e->admin_mcc, mcc, sizeof(e->admin_mcc));
    ogs_cpystrn(e->admin_mnc, mnc, sizeof(e->admin_mnc));
    e->admin_tac = tac;

    rv = mme_queue_push_main(e);
    if (rv != OGS_OK) {
        ogs_error("admin-watcher: event dropped:%d", rv);
        mme_event_free(e);
    }
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

int mme_admin_watcher_init(void)
{
    if (g_watcher)
        return 0;

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
    if (!url || !*url)
        url = "http://127.0.0.1:9998";

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
    if (!g_watcher)
        return;
    ogs_admin_watcher_stop(g_watcher);
    ogs_admin_watcher_free(g_watcher);
    g_watcher = NULL;
}
