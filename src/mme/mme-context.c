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

#include "ogs-sctp.h"
#include <limits.h>

#include "mme-context.h"
#include "mme-pgw-host.h"
#include "eplmn-config.h"
#include "mme-event.h"
#include "mme-path.h"
#include "mme-fd-path.h"
#include "mme-roam-access.h"
#include "mme-timer.h"
#include "mme-trace.h"
#include "nas-path.h"
#include "mme-reload-lists.h"
#include "s1ap-path.h"
#include "s1ap-handler.h"
#include "mme-sm.h"
#include "mme-gtp-path.h"
#include "metrics.h"
#include "mme-apn.h"

#include <errno.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#define mme_recovery_mkdir(p) _mkdir(p)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define mme_recovery_mkdir(p) mkdir((p), 0755)
#endif

#define MAX_CELL_PER_ENB            8

#define MME_RECOVERY_COUNTER_FILE "/var/lib/open5gs/mme_recovery_counter"

/* Returns the persisted counter (0..255), or -1 if the file is missing
 * or unreadable so the caller can fall back to a time-based seed. */
static int
mme_load_recovery_counter(const char *path)
{
    FILE *f = NULL;
    uint8_t val = 0;
    size_t n;

    if (!path)
        return -1;

    f = fopen(path, "rb");
    if (!f)
        return -1;
    n = fread(&val, 1, 1, f);
    fclose(f);
    if (n != 1)
        return -1;
    return (int)val;
}

/* Best-effort recursive directory creation (e.g. /var/lib/open5gs). */
static void
mme_recovery_mkdir_p(const char *dir)
{
    char tmp[512];
    char *p = NULL;
    size_t len;

    if (!dir || !dir[0])
        return;

    ogs_cpystrn(tmp, dir, sizeof(tmp));
    len = strlen(tmp);
    if (len && tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mme_recovery_mkdir(tmp) != 0 && errno != EEXIST)
                ogs_warn("mkdir(%s) failed: %s", tmp, strerror(errno));
            *p = '/';
        }
    }
    if (mme_recovery_mkdir(tmp) != 0 && errno != EEXIST)
        ogs_warn("mkdir(%s) failed: %s", tmp, strerror(errno));
}

/* Returns true if the counter was persisted to disk. */
static bool
mme_save_recovery_counter(const char *path, uint8_t val)
{
    FILE *f = NULL;
    char dir[512];
    char *slash = NULL;
    size_t n;

    if (!path)
        return false;

    /* Make sure the parent directory exists before writing. */
    ogs_cpystrn(dir, path, sizeof(dir));
    slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        mme_recovery_mkdir_p(dir);
    }

    f = fopen(path, "wb");
    if (!f) {
        ogs_error("failed to persist GTP-C recovery counter to %s: %s -- "
                "MME restart detection by peers will be degraded; "
                "fix directory ownership/permissions", path, strerror(errno));
        return false;
    }
    n = fwrite(&val, 1, 1, f);
    fclose(f);
    if (n != 1) {
        ogs_error("failed to write GTP-C recovery counter to %s", path);
        return false;
    }
    return true;
}

static mme_context_t self;
static ogs_diam_config_t g_diam_conf;

/* PLMN-indexed csmap buckets (see mme_csmap_plmn_attach). */
static ogs_hash_t *mme_csmap_plmn_hash;

static ogs_list_t *mme_csmap_plmn_bucket(
        const ogs_plmn_id_t *plmn_id, bool create);
static void mme_csmap_plmn_attach(mme_csmap_t *csmap);
static void mme_csmap_plmn_detach(mme_csmap_t *csmap);
static void mme_csmap_plmn_hash_clear(void);
static void mme_ue_add_abort(mme_ue_t *mme_ue);

static uint16_t mme_yaml_parse_port(const char *v, uint16_t default_port)
{
    long port;
    char *end = NULL;

    if (!v || !*v)
        return default_port;

    port = strtol(v, &end, 10);
    if (*end != '\0' || port <= 0 || port > 65535) {
        ogs_warn("Invalid port `%s`, using default %u", v, default_port);
        return default_port;
    }

    return (uint16_t)port;
}

int __mme_log_domain;
int __emm_log_domain;
int __esm_log_domain;

static OGS_POOL(mme_sgsn_route_pool, mme_sgsn_route_t);
static OGS_POOL(mme_sgsn_pool, mme_sgsn_t);
static OGS_POOL(mme_sgw_pool, mme_sgw_t);
static OGS_POOL(mme_pgw_pool, mme_pgw_t);
static OGS_POOL(mme_vlr_pool, mme_vlr_t);
static OGS_POOL(mme_csmap_pool, mme_csmap_t);
static OGS_POOL(mme_hssmap_pool, mme_hssmap_t);

static OGS_POOL(mme_enb_pool, mme_enb_t);
static OGS_POOL(mme_ue_pool, mme_ue_t);
static OGS_POOL(mme_s11_teid_pool, ogs_pool_id_t);
static OGS_POOL(mme_gn_teid_pool, ogs_pool_id_t);
static OGS_POOL(enb_ue_pool, enb_ue_t);
static OGS_POOL(sgw_ue_pool, sgw_ue_t);
static OGS_POOL(mme_sess_pool, mme_sess_t);
static OGS_POOL(mme_bearer_pool, mme_bearer_t);
static OGS_POOL(mme_emerg_pool, mme_emerg_t);

static OGS_POOL(m_tmsi_pool, mme_m_tmsi_t);

static void mme_ue_add_abort(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    if (mme_ue->mme_s11_teid_node) {
        ogs_hash_set(self.mme_s11_teid_hash,
                &mme_ue->mme_s11_teid, sizeof(mme_ue->mme_s11_teid), NULL);
        ogs_pool_free(&mme_s11_teid_pool, mme_ue->mme_s11_teid_node);
    }
    if (mme_ue->gn.mme_gn_teid_node) {
        ogs_hash_set(self.mme_gn_teid_hash,
                &mme_ue->gn.mme_gn_teid, sizeof(mme_ue->gn.mme_gn_teid), NULL);
        ogs_pool_free(&mme_gn_teid_pool, mme_ue->gn.mme_gn_teid_node);
    }

    if (mme_ue->t3413.timer)
        ogs_timer_delete(mme_ue->t3413.timer);
    if (mme_ue->t3422.timer)
        ogs_timer_delete(mme_ue->t3422.timer);
    if (mme_ue->t3450.timer)
        ogs_timer_delete(mme_ue->t3450.timer);
    if (mme_ue->t3460.timer)
        ogs_timer_delete(mme_ue->t3460.timer);
    if (mme_ue->t3470.timer)
        ogs_timer_delete(mme_ue->t3470.timer);
    if (mme_ue->t_mobile_reachable.timer)
        ogs_timer_delete(mme_ue->t_mobile_reachable.timer);
    if (mme_ue->t_implicit_detach.timer)
        ogs_timer_delete(mme_ue->t_implicit_detach.timer);
    if (mme_ue->gn.t_gn_holding)
        ogs_timer_delete(mme_ue->gn.t_gn_holding);
    if (mme_ue->t_sgs_ts6_1)
        ogs_timer_delete(mme_ue->t_sgs_ts6_1);
    if (mme_ue->t_s6a)
        ogs_timer_delete(mme_ue->t_s6a);

    ogs_pool_id_free(&mme_ue_pool, mme_ue);
}

static int context_initialized = 0;

static int num_of_enb_ue = 0;
static int num_of_mme_sess = 0;

static void stats_add_enb_ue(void);
static void stats_remove_enb_ue(void);
static void stats_add_mme_session(void);
static void stats_remove_mme_session(void);

static void mme_gtpc_client_parse_plmn_id_key(
        ogs_yaml_iter_t *iter, const char *key,
        bool *serving_plmn_parsed, ogs_plmn_id_t *serving_plmn,
        bool *imsi_plmn_parsed, ogs_plmn_id_t *imsi_plmn);
static bool mme_ue_inbound_roam_on_tai(
        mme_ue_t *mme_ue, const ogs_eps_tai_t *tai);
static int mme_gtpc_entry_selection_order(int yaml_index, const char *order_v);

static uint32_t mme_yaml_parse_uint32(const char *v)
{
    ogs_assert(v);

    if (v[0] == '0' && (v[1] == 'x' || v[1] == 'X'))
        return (uint32_t)ogs_uint64_from_string_hexadecimal((char *)v);

    return (uint32_t)strtoul(v, NULL, 10);
}

static void mme_access_control_parse_uint32_list(
        ogs_yaml_iter_t *iter, mme_access_control_t *ac, bool enb)
{
    ogs_yaml_iter_t list_iter;

    ogs_assert(iter);
    ogs_assert(ac);

    ogs_yaml_iter_recurse(iter, &list_iter);
    ogs_assert(ogs_yaml_iter_type(&list_iter) != YAML_MAPPING_NODE);

    do {
        const char *v = NULL;

        if (ogs_yaml_iter_type(&list_iter) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&list_iter))
                break;
        }
        v = ogs_yaml_iter_value(&list_iter);
        if (!v)
            continue;

        if (enb)
            mme_access_control_enb_add(ac, mme_yaml_parse_uint32(v));
        else
            mme_access_control_tac_add(ac, (uint16_t)mme_yaml_parse_uint32(v));
    } while (ogs_yaml_iter_type(&list_iter) == YAML_SEQUENCE_NODE);
}

static bool mme_sgw_is_default(const mme_sgw_t *sgw);
static bool compare_sgw_info(
        mme_sgw_t *node, enb_ue_t *enb_ue, mme_ue_t *mme_ue);
static bool mme_sgw_list_has_filters(void);
static mme_sgw_t *mme_sgw_select_for_ue(enb_ue_t *enb_ue, mme_ue_t *mme_ue);
static mme_sgw_t *selected_sgw_node(
        mme_sgw_t *current, enb_ue_t *enb_ue);
static mme_sgw_t *changed_sgw_node(
        mme_sgw_t *current, enb_ue_t *enb_ue, mme_ue_t *mme_ue);

static ogs_eps_tai0_list_t *mme_served_tai_list0(int index)
{
    ogs_eps_tai0_list_t **list0 = NULL;

    ogs_assert(index >= 0 && index < OGS_MAX_NUM_OF_SUPPORTED_TA);

    list0 = &self.served_tai[index].list0;
    if (*list0 == NULL) {
        *list0 = ogs_calloc(1, sizeof(ogs_eps_tai0_list_t));
        ogs_assert(*list0);
    }

    return *list0;
}

static void mme_served_tai_list0_free_all(void)
{
    int i;

    for (i = 0; i < OGS_MAX_NUM_OF_SUPPORTED_TA; i++) {
        if (self.served_tai[i].list0) {
            ogs_free(self.served_tai[i].list0);
            self.served_tai[i].list0 = NULL;
        }
    }
}

void mme_context_init(void)
{
    ogs_assert(context_initialized == 0);

    /* Initial FreeDiameter Config */
    memset(&g_diam_conf, 0, sizeof(ogs_diam_config_t));

    /* Initialize MME context */
    memset(&self, 0, sizeof(mme_context_t));
    self.diam_config = &g_diam_conf;

    ogs_log_install_domain(&__ogs_sctp_domain, "sctp", ogs_core()->log.level);
    ogs_log_install_domain(&__ogs_s1ap_domain, "s1ap", ogs_core()->log.level);
    ogs_log_install_domain(&__ogs_nas_domain, "nas", ogs_core()->log.level);
    ogs_log_install_domain(&__ogs_diam_domain, "diam", ogs_core()->log.level);
    ogs_log_install_domain(&__mme_log_domain, "mme", ogs_core()->log.level);
    ogs_log_install_domain(&__emm_log_domain, "emm", ogs_core()->log.level);
    ogs_log_install_domain(&__esm_log_domain, "esm", ogs_core()->log.level);

    ogs_list_init(&self.s1ap_list);
    ogs_list_init(&self.s1ap_list6);

    ogs_list_init(&self.sgsn_list);
    ogs_list_init(&self.sgw_list);
    ogs_list_init(&self.pgw_list);
    ogs_list_init(&self.enb_list);
    ogs_list_init(&self.vlr_list);
    ogs_list_init(&self.csmap_list);
    ogs_assert(mme_csmap_plmn_hash == NULL);
    mme_csmap_plmn_hash = ogs_hash_make();
    ogs_assert(mme_csmap_plmn_hash);
    ogs_list_init(&self.hssmap_list);
    ogs_list_init(&self.emerg_list);

    ogs_pool_init(&mme_sgsn_route_pool, ogs_app()->pool.nf);
    ogs_pool_init(&mme_sgsn_pool, ogs_app()->pool.nf);
    ogs_pool_init(&mme_sgw_pool, ogs_app()->pool.nf);
    ogs_pool_init(&mme_pgw_pool, ogs_app()->pool.nf);
    ogs_pool_init(&mme_vlr_pool, ogs_app()->pool.nf);
    ogs_pool_init(&mme_csmap_pool, ogs_app()->pool.csmap);
    ogs_pool_init(&mme_hssmap_pool, ogs_app()->pool.nf);
    ogs_pool_init(&mme_emerg_pool, ogs_app()->pool.emerg);

    /*
     * Allocate TWICE the pool to check if maximum number of eNBs
     * is reached. The S1 Setup gate (maximum_number_of_enbs_is_reached)
     * still uses max.peer as the soft limit; the extra slack absorbs
     * brief reconnect storms without dropping legitimate eNBs.
     *
     * Operators with more than ~64 eNBs MUST raise global.max.peer in
     * the YAML config (default is intentionally conservative). Mismatch
     * here is the classic cause of "/metrics empty response" because
     * rejected eNBs retry forever and saturate the main loop.
     */
    ogs_pool_init(&mme_enb_pool, ogs_global_conf()->max.peer*2);
    ogs_info("eNB capacity: max=%u (pool=%u, configure via "
            "'global.max.peer' in YAML)",
            (unsigned)ogs_global_conf()->max.peer,
            (unsigned)ogs_global_conf()->max.peer*2);

    ogs_pool_init(&mme_ue_pool, ogs_global_conf()->max.ue);
    ogs_pool_init(&mme_s11_teid_pool, ogs_global_conf()->max.ue);
    ogs_pool_random_id_generate(&mme_s11_teid_pool);
    ogs_pool_init(&mme_gn_teid_pool, ogs_global_conf()->max.ue);
    ogs_pool_random_id_generate(&mme_gn_teid_pool);

    ogs_pool_init(&enb_ue_pool, ogs_global_conf()->max.ue);
    ogs_pool_init(&sgw_ue_pool, ogs_global_conf()->max.ue);
    ogs_pool_init(&mme_sess_pool, ogs_app()->pool.sess);
    ogs_pool_init(&mme_bearer_pool, ogs_app()->pool.bearer);
    /* Increase size of TMSI pool (#1827) */
    ogs_pool_init(&m_tmsi_pool, ogs_global_conf()->max.ue*2);
    ogs_pool_random_id_generate(&m_tmsi_pool);
#if 0 /* For debugging : Verify whether there are duplicates of M_TMSI. */
    ogs_pool_assert_if_has_duplicate(&m_tmsi_pool);
#endif

    self.enb_addr_hash = ogs_hash_make();
    ogs_assert(self.enb_addr_hash);
    self.enb_id_hash = ogs_hash_make();
    ogs_assert(self.enb_id_hash);
    self.imsi_ue_hash = ogs_hash_make();
    ogs_assert(self.imsi_ue_hash);
    self.guti_ue_hash = ogs_hash_make();
    ogs_assert(self.guti_ue_hash);
    self.mme_s11_teid_hash = ogs_hash_make();
    ogs_assert(self.mme_s11_teid_hash);
    self.mme_gn_teid_hash = ogs_hash_make();
    ogs_assert(self.mme_gn_teid_hash);

    self.mip_home_agent_host_dns = true;

    self.inbound_roam_gtp_apn_format = MME_INBOUND_ROAM_GTP_APN_FQDN;
    self.inbound_roam_gtp_apn_lowercase = false;
    self.inbound_roam_strip_pap_from_gtp_pco = false;
    self.omit_indication_on_gtp_csr = false;
    self.inbound_roam_force_ipv4_pdn_on_home_pgw = false;
    self.inbound_roam_zero_bearer_mbr_for_non_gbr = false;
    self.inbound_roam_gtpc_plmn_id_is_imsi_plmn = true;

    self.ambr_limit.enabled = false;
    self.ambr_limit.force = false;
    self.ambr_limit.downlink_bps = 200U * 1000000U;
    self.ambr_limit.uplink_bps = 200U * 1000000U;

    mme_pgw_host_cache_init();

    ogs_list_init(&self.mme_ue_list);

    context_initialized = 1;
}

void mme_context_final(void)
{
    ogs_assert(context_initialized == 1);

    mme_enb_remove_all();
    mme_ue_remove_all();

    mme_sgw_remove_all();
    mme_pgw_remove_all();
    mme_csmap_remove_all();
    if (mme_csmap_plmn_hash) {
        ogs_hash_destroy(mme_csmap_plmn_hash);
        mme_csmap_plmn_hash = NULL;
    }
    mme_vlr_remove_all();
    mme_sgsn_remove_all();
    mme_hssmap_remove_all();
    mme_emerg_remove_all();

    mme_served_tai_list0_free_all();

    mme_pgw_host_cache_final();

    mme_access_control_free_all();

    ogs_assert(self.enb_addr_hash);
    ogs_hash_destroy(self.enb_addr_hash);
    ogs_assert(self.enb_id_hash);
    ogs_hash_destroy(self.enb_id_hash);

    ogs_assert(self.imsi_ue_hash);
    ogs_hash_destroy(self.imsi_ue_hash);
    ogs_assert(self.guti_ue_hash);
    ogs_hash_destroy(self.guti_ue_hash);
    ogs_assert(self.mme_s11_teid_hash);
    ogs_hash_destroy(self.mme_s11_teid_hash);
    ogs_assert(self.mme_gn_teid_hash);
    ogs_hash_destroy(self.mme_gn_teid_hash);

    ogs_pool_final(&m_tmsi_pool);
    ogs_pool_final(&mme_emerg_pool);
    ogs_pool_final(&mme_bearer_pool);
    ogs_pool_final(&mme_sess_pool);
    ogs_pool_final(&mme_ue_pool);
    ogs_pool_final(&mme_s11_teid_pool);
    ogs_pool_final(&mme_gn_teid_pool);
    ogs_pool_final(&enb_ue_pool);
    ogs_pool_final(&sgw_ue_pool);

    ogs_pool_final(&mme_enb_pool);

    ogs_pool_final(&mme_sgsn_pool);
    ogs_pool_final(&mme_sgsn_route_pool);
    ogs_pool_final(&mme_sgw_pool);
    ogs_pool_final(&mme_pgw_pool);
    ogs_pool_final(&mme_csmap_pool);
    ogs_pool_final(&mme_vlr_pool);
    ogs_pool_final(&mme_hssmap_pool);

    context_initialized = 0;
}

mme_context_t *mme_self(void)
{
    return &self;
}

void mme_context_pool_dump(void)
{
    /*
     * Read fields directly off the pool struct. The OGS_POOL macro
     * still defines name/size/avail/peak; doing it this way means a
     * partial header sync (only the new accessor macros missing)
     * does not break the dump.
     */
#define MME_POOL_DUMP(_p) \
    ogs_info("[pool] %-22s size=%-10d avail=%-10d used=%-10d peak=%-10d", \
            (_p).name, \
            (_p).size, \
            (_p).avail, \
            (_p).size - (_p).avail, \
            (_p).peak)

    ogs_info("===== MME pool stats =====");
    MME_POOL_DUMP(mme_enb_pool);
    MME_POOL_DUMP(mme_ue_pool);
    MME_POOL_DUMP(enb_ue_pool);
    MME_POOL_DUMP(sgw_ue_pool);
    MME_POOL_DUMP(mme_sess_pool);
    MME_POOL_DUMP(mme_bearer_pool);
    MME_POOL_DUMP(mme_s11_teid_pool);
    MME_POOL_DUMP(mme_gn_teid_pool);
    MME_POOL_DUMP(m_tmsi_pool);
    MME_POOL_DUMP(mme_sgw_pool);
    MME_POOL_DUMP(mme_pgw_pool);
    MME_POOL_DUMP(mme_vlr_pool);
    MME_POOL_DUMP(mme_csmap_pool);
    MME_POOL_DUMP(mme_sgsn_pool);
    MME_POOL_DUMP(mme_sgsn_route_pool);
    MME_POOL_DUMP(mme_hssmap_pool);
    MME_POOL_DUMP(mme_emerg_pool);
    ogs_info("[list] mme_ue_list count=%d  (active in idle = list - enb_ue used)",
            ogs_list_count(&self.mme_ue_list));
    ogs_info("==========================");

#undef MME_POOL_DUMP
}

int mme_context_evict_idle_ues(int want)
{
    static ogs_time_t last_run = 0;
    ogs_time_t now;
    mme_ue_t *mme_ue = NULL, *next = NULL;
    int evicted = 0;
    int avail, size, watermark;

    size = ogs_pool_size(&mme_ue_pool);
    avail = ogs_pool_avail(&mme_ue_pool);

    /*
     * Watermark = 1% of pool, clamped to [16, 4096].
     * Above this many free slots we treat the pool as healthy and skip
     * the O(N) walk entirely.
     */
    watermark = size / 100;
    if (watermark < 16) watermark = 16;
    if (watermark > 4096) watermark = 4096;
    if (avail >= watermark)
        return 0;

    now = ogs_time_now();

    /* Cap at one sweep per second; the queued implicit-detach events
     * need time to drain before the next round makes sense. */
    if (last_run && now - last_run < ogs_time_from_sec(1))
        return 0;
    last_run = now;

    if (want <= 0)
        want = watermark - avail;
    if (want < 16) want = 16;

    /*
     * Single linear pass. We only evict UEs that have been IDLE for at
     * least MIN_IDLE_AGE_SEC so a UE that just released S1 isn't
     * yanked while it might reattach. The list is not sorted, so we
     * pick whatever qualifies in list order. This is good enough: the
     * goal is to free *some* slots, not the absolute LRU set.
     */
#define MIN_IDLE_AGE_SEC 60
    ogs_list_for_each_safe(&self.mme_ue_list, next, mme_ue) {
        if (evicted >= want) break;
        if (mme_ue->idle_since == 0) continue;
        if (now - mme_ue->idle_since <
                ogs_time_from_sec(MIN_IDLE_AGE_SEC)) continue;

        /* Clear the stamp so the next sweep doesn't re-pick the same
         * UE before the implicit-detach event drains and tears it
         * down. */
        mme_ue->idle_since = 0;

        /* Reuse the implicit-detach timer path so the EMM FSM handles
         * the teardown exactly as if T-implicit had fired naturally. */
        mme_timer_implicit_detach_expire(OGS_UINT_TO_POINTER(mme_ue->id));
        evicted++;
    }
#undef MIN_IDLE_AGE_SEC

    if (evicted > 0)
        ogs_warn("[pool] Soft-cap eviction queued implicit-detach for %d "
                "idle UEs (mme_ue_pool size=%d avail=%d, list=%d)",
                evicted, size, ogs_pool_avail(&mme_ue_pool),
                ogs_list_count(&self.mme_ue_list));

    return evicted;
}

static void mme_timer_parse_yaml(
        ogs_yaml_iter_t *time_iter, mme_timer_e id)
{
    ogs_yaml_iter_t iter;
    ogs_time_t duration = 0;
    int max_count = 0;

    ogs_yaml_iter_recurse(time_iter, &iter);
    while (ogs_yaml_iter_next(&iter)) {
        const char *key = ogs_yaml_iter_key(&iter);
        ogs_assert(key);

        if (!strcmp(key, "value")) {
            const char *v = ogs_yaml_iter_value(&iter);
            if (v)
                duration = ogs_time_from_sec(atoll(v));
        } else if (!strcmp(key, "max_count")) {
            const char *v = ogs_yaml_iter_value(&iter);
            if (v)
                max_count = atoi(v);
        } else
            ogs_warn("unknown key `%s` in mme.time.%s",
                    key, mme_timer_get_name(id));
    }

    mme_timer_set(id, duration, max_count);
}

static void mme_attach_accept_set_defaults(void)
{
    self.attach_accept.tai_list_serving_only = true;
    self.attach_accept.equivalent_plmn = true;
    self.attach_accept.equivalent_plmn_serving_only = true;
    self.attach_accept.ims_voice_over_ps = true;
    self.attach_accept.t3402 = false;
    self.attach_accept.esm_cause_pdn_type_mismatch = true;
    self.attach_accept.legacy_gprs_qos = true;
}

static void mme_attach_accept_log_config(void)
{
    ogs_info("Attach/TAU Accept NAS options:");
    ogs_info("  tai_list: %s",
            self.attach_accept.tai_list_serving_only ?
            "serving_only" : "all");
    ogs_info("  equivalent_plmn: %s",
            self.attach_accept.equivalent_plmn ? "enabled" : "disabled");
    ogs_info("  equivalent_plmn_serving_only: %s",
            self.attach_accept.equivalent_plmn_serving_only ?
            "enabled" : "disabled");
    ogs_info("  ims_voice_over_ps: %s",
            self.attach_accept.ims_voice_over_ps ?
            "supported" : "not supported");
    ogs_info("  t3402: %s",
            self.attach_accept.t3402 ? "included" : "omitted");
    ogs_info("  esm_cause_pdn_type_mismatch: %s",
            self.attach_accept.esm_cause_pdn_type_mismatch ?
            "included" : "omitted");
    ogs_info("  legacy_gprs_qos: %s",
            self.attach_accept.legacy_gprs_qos ? "enabled" : "disabled");
}

static void mme_attach_accept_parse_yaml(ogs_yaml_iter_t *parent)
{
    ogs_yaml_iter_t iter;

    ogs_yaml_iter_recurse(parent, &iter);
    while (ogs_yaml_iter_next(&iter)) {
        const char *key = ogs_yaml_iter_key(&iter);
        const char *v = NULL;

        ogs_assert(key);

        if (!strcmp(key, "tai_list")) {
            v = ogs_yaml_iter_value(&iter);
            if (v && !strcmp(v, "all"))
                self.attach_accept.tai_list_serving_only = false;
            else if (v && !strcmp(v, "serving_only"))
                self.attach_accept.tai_list_serving_only = true;
            else if (v)
                ogs_warn("Unknown attach_accept.tai_list `%s' "
                        "(use: serving_only or all)", v);
        } else if (!strcmp(key, "equivalent_plmn")) {
            self.attach_accept.equivalent_plmn = ogs_yaml_iter_bool(&iter);
        } else if (!strcmp(key, "equivalent_plmn_serving_only")) {
            self.attach_accept.equivalent_plmn_serving_only =
                ogs_yaml_iter_bool(&iter);
        } else if (!strcmp(key, "ims_voice_over_ps") ||
                !strcmp(key, "ims_voice_over_ps_in_s1_mode")) {
            self.attach_accept.ims_voice_over_ps = ogs_yaml_iter_bool(&iter);
        } else if (!strcmp(key, "t3402")) {
            self.attach_accept.t3402 = ogs_yaml_iter_bool(&iter);
        } else if (!strcmp(key, "esm_cause_pdn_type_mismatch")) {
            self.attach_accept.esm_cause_pdn_type_mismatch =
                ogs_yaml_iter_bool(&iter);
        } else if (!strcmp(key, "legacy_gprs_qos")) {
            self.attach_accept.legacy_gprs_qos = ogs_yaml_iter_bool(&iter);
        } else
            ogs_warn("unknown key `%s` in mme.attach_accept", key);
    }
}

static void mme_bearer_setup_time_parse_yaml(ogs_yaml_iter_t *time_iter)
{
    ogs_yaml_iter_t iter;
    ogs_time_t duration = 0;
    int max_count = 0;

    ogs_yaml_iter_recurse(time_iter, &iter);
    while (ogs_yaml_iter_next(&iter)) {
        const char *key = ogs_yaml_iter_key(&iter);
        ogs_assert(key);

        if (!strcmp(key, "value")) {
            const char *v = ogs_yaml_iter_value(&iter);
            if (v)
                duration = ogs_time_from_sec(atoll(v));
        } else if (!strcmp(key, "max_count")) {
            const char *v = ogs_yaml_iter_value(&iter);
            if (v)
                max_count = atoi(v);
        } else
            ogs_warn("unknown key `%s` in mme.time.bearer_setup", key);
    }

    if (duration > 0) {
        mme_timer_set(MME_TIMER_T3450, duration, 0);
        mme_timer_set(MME_TIMER_BEARER_SETUP, duration, 0);
    }
    if (max_count > 0) {
        mme_timer_set(MME_TIMER_T3450, 0, max_count);
        mme_timer_set(MME_TIMER_BEARER_SETUP, 0, max_count);
    }
}

static int mme_context_prepare(void)
{
    self.relative_capacity = 0xff;

    self.s1ap_port = OGS_S1AP_SCTP_PORT;
    self.sgsap_port = OGS_SGSAP_SCTP_PORT;
    self.diam_config->cnf_port = DIAMETER_PORT;
    self.diam_config->cnf_port_tls = DIAMETER_SECURE_PORT;

    self.time.t3402.value = 720;  /* 12 minutes */
    self.time.t3396.value = 720;  /* 12 minutes */
    self.time.t3412.value = 600;  /* 10 minutes */
    self.time.idle.mobile_reachable_margin = 240; /* TS 24.301 +4 min */
    self.time.idle.implicit_detach_margin = 240;
    self.time.t3346.value = 0;
    self.time.t3346.include_any_reject = false;

    self.gtpc_recovery = 0;
    self.gtpc_echo_interval = 0;
    self.recovery_counter_file = MME_RECOVERY_COUNTER_FILE;

    mme_attach_accept_set_defaults();

    return OGS_OK;
}

static int mme_context_validation(void)
{
    ogs_nas_gprs_timer_t gprs_timer;

    if (self.diam_conf_path == NULL &&
        (self.diam_config->cnf_diamid == NULL ||
        self.diam_config->cnf_diamrlm == NULL ||
        self.diam_config->cnf_addr == NULL)) {
        ogs_error("No mme.freeDiameter in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }

    if (ogs_list_first(&self.s1ap_list) == NULL &&
        ogs_list_first(&self.s1ap_list6) == NULL) {
        ogs_error("No mme.s1ap.address in '%s'", ogs_app()->file);
        return OGS_RETRY;
    }

    if (ogs_list_first(&ogs_gtp_self()->gtpc_list) == NULL &&
        ogs_list_first(&ogs_gtp_self()->gtpc_list6) == NULL) {
        ogs_error("No mme.gtpc.address in '%s'", ogs_app()->file);
        return OGS_RETRY;
    }

    if (ogs_list_first(&self.sgw_list) == NULL) {
        ogs_error("No sgw.gtpc.address in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }

    if (ogs_list_first(&self.pgw_list) == NULL) {
        ogs_error("No pgw.gtpc.address in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }

    if (self.num_of_served_gummei == 0) {
        ogs_error("No mme.gummei in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }

    if (self.served_gummei[0].num_of_plmn_id == 0) {
        ogs_error("No mme.gummei.plmn_id in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }

    if (self.served_gummei[0].num_of_mme_gid == 0) {
        ogs_error("No mme.gummei.mme_gid in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }

    if (self.served_gummei[0].num_of_mme_code == 0) {
        ogs_error("No mme.gummei.mme_code in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }

    if (self.num_of_served_tai == 0) {
        ogs_error("No mme.tai in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }

    if ((!self.served_tai[0].list0 ||
         self.served_tai[0].list0->tai[0].num == 0) &&
        self.served_tai[0].list1.tai[0].num == 0 &&
        self.served_tai[0].list2.num == 0) {
        ogs_error("No mme.tai.plmn_id|tac in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }

    if (self.num_of_integrity_order == 0) {
        ogs_error("No mme.security.integrity_order in '%s'",
                ogs_app()->file);
        return OGS_ERROR;
    }
    if (self.num_of_ciphering_order == 0) {
        ogs_error("No mme.security.ciphering_order in '%s'",
                ogs_app()->file);
        return OGS_ERROR;
    }
    if (self.time.t3402.value && /* Optional */
        ogs_nas_gprs_timer_from_sec(&gprs_timer, self.time.t3402.value) !=
        OGS_OK) {
        ogs_error("Not support GPRS Timer [%d]", (int)self.time.t3402.value);
        return OGS_ERROR;
    }
    if (self.time.t3396.value && /* Optional */
        ogs_nas_gprs_timer_3_from_sec(&gprs_timer, self.time.t3396.value) !=
        OGS_OK) {
        ogs_error("Not support GPRS Timer 3 [%d]",
                (int)self.time.t3396.value);
        return OGS_ERROR;
    }
    if (!self.time.t3412.value) { /* Mandatory */
        ogs_error("No mme.time.t3412.value in '%s'",
                ogs_app()->file);
        return OGS_ERROR;
    }
    if (ogs_nas_gprs_timer_from_sec(&gprs_timer, self.time.t3412.value) !=
        OGS_OK) {
        ogs_error("Not support GPRS Timer [%d]", (int)self.time.t3412.value);
        return OGS_ERROR;
    }
    if (self.time.t3423.value && /* Optional */
        ogs_nas_gprs_timer_from_sec(&gprs_timer, self.time.t3423.value) !=
            OGS_OK) {
        ogs_error("Not support GPRS Timer [%d]", (int)self.time.t3423.value);
        return OGS_ERROR;
    }

    if (self.time.t3346.value &&
        ogs_nas_gprs_timer_from_sec(&gprs_timer, self.time.t3346.value) !=
            OGS_OK) {
        ogs_error("Not support GPRS Timer 2 (T3346) [%d]",
                (int)self.time.t3346.value);
        return OGS_ERROR;
    }

    if (mme_eplmn_validate(self.num_of_eplmn) != OGS_OK)
        return OGS_ERROR;

    if (self.num_of_eplmn)
        mme_eplmn_log_config(self.num_of_eplmn, self.eplmn);

    mme_attach_accept_log_config();

    if (!self.require_hss_map_explicit &&
            ogs_list_first(&self.hssmap_list) != NULL) {
        self.require_hss_map = true;
        ogs_info("require_hss_map auto-enabled (%d hss_map PLMN(s))",
                ogs_list_count(&self.hssmap_list));
    }

    ogs_info("TAI type-0 partial list limit: %llu (global.max.eps_tai0_partial_list)",
            (unsigned long long)ogs_app_max_eps_tai0_partial_list());

    return OGS_OK;
}

static int parse_plmn_id(ogs_yaml_iter_t *parent_iter, ogs_plmn_id_t *plmn_id)
{
     const char *mcc = NULL;
    const char *mnc = NULL;
    ogs_yaml_iter_t plmn_id_iter;
    ogs_yaml_iter_recurse(parent_iter,
            &plmn_id_iter);

    while (ogs_yaml_iter_next(&plmn_id_iter)) {
        const char *plmn_id_key = ogs_yaml_iter_key(&plmn_id_iter);
        ogs_assert(plmn_id_key);

        if (!strcmp(plmn_id_key, "mcc")) {
            mcc = ogs_yaml_iter_value(&plmn_id_iter);
        } else if (!strcmp(plmn_id_key, "mnc")) {
            mnc = ogs_yaml_iter_value(&plmn_id_iter);
        } else
            ogs_warn("unknown key `%s`", plmn_id_key);
    }

    if (!mcc || ! mnc)
        return OGS_ERROR;

    ogs_plmn_id_build(plmn_id, atoi(mcc), atoi(mnc), strlen(mnc));
    return OGS_OK;
}

static int parse_lai(ogs_yaml_iter_t *parent_iter, ogs_nas_lai_t *lai)
{
    bool plmn_id_parsed = false;
    const char *lac = NULL;
    ogs_plmn_id_t plmn_id;
    ogs_yaml_iter_t lai_iter;
    ogs_yaml_iter_recurse(parent_iter, &lai_iter);
    int rc;

    while (ogs_yaml_iter_next(&lai_iter)) {
        const char *lai_key = ogs_yaml_iter_key(&lai_iter);
        ogs_assert(lai_key);

        if (!strcmp(lai_key, "plmn_id")) {
            rc = parse_plmn_id(&lai_iter, &plmn_id);
            ogs_assert(rc == OGS_OK);
            plmn_id_parsed = true;
        } else if (!strcmp(lai_key, "lac")) {
            lac = ogs_yaml_iter_value(
                    &lai_iter);
        } else
            ogs_warn("unknown key `%s`",
                    lai_key);
    }

    if (!plmn_id_parsed || !lac)
        return OGS_ERROR;

    ogs_nas_from_plmn_id( &lai->nas_plmn_id, &plmn_id);
    lai->lac = atoi(lac);
    return OGS_OK;
}

static int parse_rai(ogs_yaml_iter_t *parent_iter, ogs_nas_rai_t *rai)
{
    bool lai_parsed = false, rac_parsed = false;
    int rc;
    ogs_yaml_iter_t rai_iter;
    ogs_yaml_iter_recurse(parent_iter, &rai_iter);

    while (ogs_yaml_iter_next(&rai_iter)) {
        const char *rai_key = ogs_yaml_iter_key(&rai_iter);
        ogs_assert(rai_key);

        if (!strcmp(rai_key, "lai")) {
                rc = parse_lai(&rai_iter, &rai->lai);
                ogs_assert(rc == OGS_OK);
                lai_parsed = true;
        } else if (!strcmp(rai_key, "rac")) {
            const char *v = ogs_yaml_iter_value(&rai_iter);
            rai->rac = atoi(v);
            rac_parsed = true;
        } else
                ogs_warn("unknown key `%s`", rai_key);
    }

    if (!lai_parsed || !rac_parsed)
        return OGS_ERROR;
    return OGS_OK;
}

int mme_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_app()->document;
    ogs_assert(document);

    rv = mme_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "mme")) {
            ogs_yaml_iter_t mme_iter;
            ogs_yaml_iter_recurse(&root_iter, &mme_iter);
            while (ogs_yaml_iter_next(&mme_iter)) {
                const char *mme_key = ogs_yaml_iter_key(&mme_iter);
                ogs_assert(mme_key);
                if (!strcmp(mme_key, "freeDiameter")) {
                    yaml_node_t *node =
                        yaml_document_get_node(document, mme_iter.pair->value);
                    ogs_assert(node);
                    if (node->type == YAML_SCALAR_NODE) {
                        self.diam_conf_path = ogs_yaml_iter_value(&mme_iter);
                    } else if (node->type == YAML_MAPPING_NODE) {
                        ogs_yaml_iter_t fd_iter;
                        ogs_yaml_iter_recurse(&mme_iter, &fd_iter);

                        while (ogs_yaml_iter_next(&fd_iter)) {
                            const char *fd_key = ogs_yaml_iter_key(&fd_iter);
                            ogs_assert(fd_key);
                            if (!strcmp(fd_key, "identity")) {
                                self.diam_config->cnf_diamid =
                                    ogs_yaml_iter_value(&fd_iter);
                            } else if (!strcmp(fd_key, "realm")) {
                                self.diam_config->cnf_diamrlm =
                                    ogs_yaml_iter_value(&fd_iter);
                            } else if (!strcmp(fd_key, "port")) {
                                const char *v = ogs_yaml_iter_value(&fd_iter);
                                if (v) self.diam_config->cnf_port = atoi(v);
                            } else if (!strcmp(fd_key, "sec_port")) {
                                const char *v = ogs_yaml_iter_value(&fd_iter);
                                if (v) self.diam_config->cnf_port_tls = atoi(v);
                            } else if (!strcmp(fd_key, "listen_on")) {
                                self.diam_config->cnf_addr =
                                    ogs_yaml_iter_value(&fd_iter);
                            } else if (!strcmp(fd_key, "no_fwd")) {
                                self.diam_config->cnf_flags.no_fwd =
                                    ogs_yaml_iter_bool(&fd_iter);
                            } else if (!strcmp(fd_key, "load_extension")) {
                                ogs_yaml_iter_t ext_array, ext_iter;
                                ogs_yaml_iter_recurse(&fd_iter, &ext_array);
                                do {
                                    const char *module = NULL;
                                    const char *conf = NULL;

                                    if (ogs_yaml_iter_type(&ext_array) ==
                                        YAML_MAPPING_NODE) {
                                        memcpy(&ext_iter, &ext_array,
                                                sizeof(ogs_yaml_iter_t));
                                    } else if (ogs_yaml_iter_type(&ext_array) ==
                                        YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&ext_array))
                                            break;
                                        ogs_yaml_iter_recurse(
                                                &ext_array, &ext_iter);
                                    } else if (ogs_yaml_iter_type(&ext_array) ==
                                        YAML_SCALAR_NODE) {
                                        break;
                                    } else
                                        ogs_assert_if_reached();

                                    while (ogs_yaml_iter_next(&ext_iter)) {
                                        const char *ext_key =
                                            ogs_yaml_iter_key(&ext_iter);
                                        ogs_assert(ext_key);
                                        if (!strcmp(ext_key, "module")) {
                                            module =
                                                ogs_yaml_iter_value(&ext_iter);
                                        } else if (!strcmp(ext_key, "conf")) {
                                            conf =
                                                ogs_yaml_iter_value(&ext_iter);
                                        } else
                                            ogs_warn("unknown key `%s`",
                                                    ext_key);
                                    }

                                    if (module) {
                                        self.diam_config->
                                            ext[self.diam_config->num_of_ext].
                                                module = module;
                                        self.diam_config->
                                            ext[self.diam_config->num_of_ext].
                                                conf = conf;
                                        self.diam_config->num_of_ext++;
                                    }
                                } while (ogs_yaml_iter_type(&ext_array) ==
                                        YAML_SEQUENCE_NODE);
                            } else if (!strcmp(fd_key, "connect")) {
                                ogs_yaml_iter_t conn_array, conn_iter;
                                ogs_yaml_iter_recurse(&fd_iter, &conn_array);
                                do {
                                    const char *identity = NULL;
                                    const char *addr = NULL;
                                    uint16_t port = 0;
                                    int tc_timer = 0;

                                    if (ogs_yaml_iter_type(&conn_array) ==
                                        YAML_MAPPING_NODE) {
                                        memcpy(&conn_iter, &conn_array,
                                                sizeof(ogs_yaml_iter_t));
                                    } else if (ogs_yaml_iter_type(
                                        &conn_array) == YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&conn_array))
                                            break;
                                        ogs_yaml_iter_recurse(
                                                &conn_array, &conn_iter);
                                    } else if (ogs_yaml_iter_type(
                                        &conn_array) == YAML_SCALAR_NODE) {
                                        break;
                                    } else
                                        ogs_assert_if_reached();

                                    while (ogs_yaml_iter_next(&conn_iter)) {
                                        const char *conn_key =
                                            ogs_yaml_iter_key(&conn_iter);
                                        ogs_assert(conn_key);
                                        if (!strcmp(conn_key, "identity")) {
                                            identity =
                                                ogs_yaml_iter_value(&conn_iter);
                                        } else if (!strcmp(conn_key,
                                                    "address")) {
                                            addr =
                                                ogs_yaml_iter_value(&conn_iter);
                                        } else if (!strcmp(conn_key, "port")) {
                                            const char *v =
                                                ogs_yaml_iter_value(&conn_iter);
                                            if (v) port = mme_yaml_parse_port(v, port);
                                        } else if (!strcmp(conn_key, "tc_timer")) {
                                            const char *v =
                                                ogs_yaml_iter_value(&conn_iter);
                                            if (v) tc_timer = atoi(v);
                                        } else
                                            ogs_warn("unknown key `%s`",
                                                    conn_key);
                                    }

                                    if (identity && addr) {
                                        self.diam_config->
                                            conn[self.diam_config->num_of_conn].
                                                identity = identity;
                                        self.diam_config->
                                            conn[self.diam_config->num_of_conn].
                                                addr = addr;
                                        self.diam_config->
                                            conn[self.diam_config->num_of_conn].
                                                port = port;
                                        self.diam_config->
                                            conn[self.diam_config->num_of_conn].
                                                tc_timer = tc_timer;
                                        self.diam_config->num_of_conn++;
                                    }
                                } while (ogs_yaml_iter_type(&conn_array) ==
                                        YAML_SEQUENCE_NODE);
                            } else if (!strcmp(fd_key, "tc_timer")) {
                                const char *v = ogs_yaml_iter_value(&fd_iter);
                                if (v) self.diam_config->cnf_timer_tc = atoi(v);
                            } else
                                ogs_warn("unknown key `%s`", fd_key);
                        }
                    }
                } else if (!strcmp(mme_key, "relative_capacity")) {
                    const char *v = ogs_yaml_iter_value(&mme_iter);
                    if (v) self.relative_capacity = atoi(v);
                } else if (!strcmp(mme_key, "s1ap")) {
                    ogs_yaml_iter_t s1ap_iter;
                    ogs_yaml_iter_recurse(&mme_iter, &s1ap_iter);
                    while (ogs_yaml_iter_next(&s1ap_iter)) {
                        const char *s1ap_key = ogs_yaml_iter_key(&s1ap_iter);
                        ogs_assert(s1ap_key);
                        if (!strcmp(s1ap_key, "server")) {
                            ogs_yaml_iter_t server_iter, server_array;
                            ogs_yaml_iter_recurse(&s1ap_iter, &server_array);
                            do {
                                int family = AF_UNSPEC;
                                int i, num = 0;
                                const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
                                uint16_t port = self.s1ap_port;
                                const char *dev = NULL;
                                ogs_sockaddr_t *addr = NULL;

                                ogs_sockopt_t option;
                                bool is_option = false;

                                if (ogs_yaml_iter_type(&server_array) ==
                                        YAML_MAPPING_NODE) {
                                    memcpy(&server_iter, &server_array,
                                            sizeof(ogs_yaml_iter_t));
                                } else if (ogs_yaml_iter_type(&server_array) ==
                                    YAML_SEQUENCE_NODE) {
                                    if (!ogs_yaml_iter_next(&server_array))
                                        break;
                                    ogs_yaml_iter_recurse(
                                            &server_array, &server_iter);
                                } else if (ogs_yaml_iter_type(&server_array) ==
                                    YAML_SCALAR_NODE) {
                                    break;
                                } else
                                    ogs_assert_if_reached();

                                while (ogs_yaml_iter_next(&server_iter)) {
                                    const char *server_key =
                                        ogs_yaml_iter_key(&server_iter);
                                    ogs_assert(server_key);
                                    if (!strcmp(server_key, "family")) {
                                        const char *v =
                                            ogs_yaml_iter_value(&server_iter);
                                        if (v) family = atoi(v);
                                        if (family != AF_UNSPEC &&
                                            family != AF_INET &&
                                            family != AF_INET6) {
                                            ogs_warn("Ignore family(%d) : "
                                                "AF_UNSPEC(%d), "
                                                "AF_INET(%d), AF_INET6(%d) ",
                                                family,
                                                AF_UNSPEC, AF_INET, AF_INET6);
                                            family = AF_UNSPEC;
                                        }
                                    } else if (!strcmp(server_key, "address")) {
                                        ogs_yaml_iter_t hostname_iter;
                                        ogs_yaml_iter_recurse(
                                                &server_iter, &hostname_iter);
                                        ogs_assert(ogs_yaml_iter_type(
                                                &hostname_iter) !=
                                            YAML_MAPPING_NODE);

                                        do {
                                            if (ogs_yaml_iter_type(
                                                        &hostname_iter) ==
                                                    YAML_SEQUENCE_NODE) {
                                                if (!ogs_yaml_iter_next(
                                                            &hostname_iter))
                                                    break;
                                            }

                                            ogs_assert(num <
                                                    OGS_MAX_NUM_OF_HOSTNAME);
                                            hostname[num++] =
                                                ogs_yaml_iter_value(
                                                        &hostname_iter);
                                        } while (ogs_yaml_iter_type(
                                                    &hostname_iter) ==
                                                YAML_SEQUENCE_NODE);
                                    } else if (!strcmp(server_key, "port")) {
                                        const char *v =
                                            ogs_yaml_iter_value(&server_iter);
                                        if (v) port = atoi(v);
                                    } else if (!strcmp(server_key, "dev")) {
                                        dev = ogs_yaml_iter_value(&server_iter);
                                    } else if (!strcmp(server_key, "option")) {
                                        rv = ogs_app_parse_sockopt_config(
                                                &server_iter, &option);
                                        if (rv != OGS_OK) {
                                            ogs_error("ogs_app_parse_sockopt_"
                                                    "config() failed");
                                            return rv;
                                        }
                                        is_option = true;
                                    } else
                                        ogs_warn("unknown key `%s`",
                                                server_key);
                                }

                                addr = NULL;
                                for (i = 0; i < num; i++) {
                                    rv = ogs_addaddrinfo(&addr,
                                            family, hostname[i], port, 0);
                                    ogs_assert(rv == OGS_OK);
                                }

                                if (addr) {
                                    if (ogs_global_conf()->parameter.
                                            no_ipv4 == 0)
                                        ogs_socknode_add(
                                            &self.s1ap_list, AF_INET, addr,
                                            is_option ? &option : NULL);
                                    if (ogs_global_conf()->parameter.
                                            no_ipv6 == 0)
                                        ogs_socknode_add(
                                            &self.s1ap_list6, AF_INET6, addr,
                                            is_option ? &option : NULL);
                                    ogs_freeaddrinfo(addr);
                                }

                                if (dev) {
                                    rv = ogs_socknode_probe(
                                            ogs_global_conf()->parameter.
                                            no_ipv4 ?
                                                NULL : &self.s1ap_list,
                                            ogs_global_conf()->parameter.
                                            no_ipv6 ?
                                                NULL : &self.s1ap_list6,
                                            dev, port,
                                            is_option ? &option : NULL);
                                    ogs_assert(rv == OGS_OK);
                                }

                            } while (ogs_yaml_iter_type(&server_array) ==
                                    YAML_SEQUENCE_NODE);
                        } else
                            ogs_warn("unknown key `%s`", s1ap_key);
                    }
                } else if (!strcmp(mme_key, "gtpc")) {
                    ogs_yaml_iter_t gtpc_iter;
                    ogs_yaml_iter_recurse(&mme_iter, &gtpc_iter);
                    while (ogs_yaml_iter_next(&gtpc_iter)) {
                        const char *gtpc_key = ogs_yaml_iter_key(&gtpc_iter);
                        ogs_assert(gtpc_key);
                        if (!strcmp(gtpc_key, "server")) {
                            /* handle config in gtp library */
                        } else if (!strcmp(gtpc_key, "client")) {
                            ogs_yaml_iter_t client_iter;
                            ogs_yaml_iter_recurse(&gtpc_iter, &client_iter);
                            while (ogs_yaml_iter_next(&client_iter)) {
                                const char *client_key =
                                    ogs_yaml_iter_key(&client_iter);
                                ogs_assert(client_key);
                                if (!strcmp(client_key, "sgwc")) {
                                    ogs_yaml_iter_t sgwc_array, sgwc_iter;
                                    int sgwc_entry_idx = 0;

                                    ogs_yaml_iter_recurse(
                                            &client_iter, &sgwc_array);
                                    do {
                                        mme_sgw_t *sgw = NULL;
                                        ogs_sockaddr_t *addr = NULL;
                                        int family = AF_UNSPEC;
                                        int i, num = 0;
                                        const char *hostname[
                                            OGS_MAX_NUM_OF_HOSTNAME];
                                        uint16_t port =
                                            ogs_gtp_self()->gtpc_port;
                                        const char *order_v = NULL;
                                        char imsi_prefix_buf[
                                            OGS_MAX_IMSI_BCD_LEN + 1];
                                        bool imsi_prefix_set = false;
                                        uint16_t *tac = ogs_calloc(
                                                ogs_global_conf()->max.tai,
                                                sizeof(uint16_t));
                                        int num_of_tac = 0;
                                        uint32_t e_cell_id[
                                            OGS_MAX_NUM_OF_CELL_ID] = {0,};
                                        int num_of_e_cell_id = 0;
                                        bool sgw_serving_plmn_parsed = false;
                                        ogs_plmn_id_t sgw_serving_plmn;
                                        bool sgw_imsi_plmn_parsed = false;
                                        ogs_plmn_id_t sgw_imsi_plmn;

                                        ogs_assert(tac);
                                        imsi_prefix_buf[0] = '\0';
                                        if (ogs_yaml_iter_type(&sgwc_array) ==
                                                YAML_MAPPING_NODE) {
                                            memcpy(&sgwc_iter, &sgwc_array,
                                                    sizeof(ogs_yaml_iter_t));
                                        } else if (ogs_yaml_iter_type(
                                                    &sgwc_array) ==
                                                YAML_SEQUENCE_NODE) {
                                            if (!ogs_yaml_iter_next(
                                                        &sgwc_array)) {
                                                ogs_free(tac);
                                                break;
                                            }
                                            ogs_yaml_iter_recurse(
                                                    &sgwc_array, &sgwc_iter);
                                        } else if (ogs_yaml_iter_type(
                                                    &sgwc_array) ==
                                                YAML_SCALAR_NODE) {
                                            ogs_free(tac);
                                            break;
                                        } else
                                            ogs_assert_if_reached();

                                        while (ogs_yaml_iter_next(&sgwc_iter)) {
                                            const char *sgwc_key =
                                                ogs_yaml_iter_key(&sgwc_iter);
                                            ogs_assert(sgwc_key);
                                            if (!strcmp(sgwc_key, "family")) {
                                                const char *v =
                                                    ogs_yaml_iter_value(
                                                            &sgwc_iter);
                                                if (v) family = atoi(v);
                                                if (family != AF_UNSPEC &&
                                                    family != AF_INET &&
                                                    family != AF_INET6) {
                                                    ogs_warn(
                                                        "Ignore family(%d) : "
                                                        "AF_UNSPEC(%d), "
                                                        "AF_INET(%d), "
                                                        "AF_INET6(%d) ",
                                                        family, AF_UNSPEC,
                                                        AF_INET, AF_INET6);
                                                    family = AF_UNSPEC;
                                                }
                                            } else if (!strcmp(sgwc_key,
                                                        "address")) {
                                                ogs_yaml_iter_t hostname_iter;
                                                ogs_yaml_iter_recurse(
                                                        &sgwc_iter,
                                                        &hostname_iter);
                                                ogs_assert(ogs_yaml_iter_type(
                                                            &hostname_iter) !=
                                                        YAML_MAPPING_NODE);

                                                do {
                                                    if (ogs_yaml_iter_type(
                                                            &hostname_iter) ==
                                                        YAML_SEQUENCE_NODE) {
                                                        if (!ogs_yaml_iter_next(
                                                            &hostname_iter))
                                                            break;
                                                    }

                                                    ogs_assert(num <
                                                    OGS_MAX_NUM_OF_HOSTNAME);
                                                    hostname[num++] =
                                                        ogs_yaml_iter_value(
                                                                &hostname_iter);
                                                } while (
                                                    ogs_yaml_iter_type(
                                                        &hostname_iter) ==
                                                        YAML_SEQUENCE_NODE);
                                            } else if (!strcmp(sgwc_key,
                                                        "port")) {
                                                const char *v =
                                                    ogs_yaml_iter_value(
                                                            &sgwc_iter);
                                                if (v) port = mme_yaml_parse_port(v, port);
                                            } else if (!strcmp(
                                                        sgwc_key, "tac")) {
                                                ogs_yaml_iter_t tac_iter;
                                                ogs_yaml_iter_recurse(
                                                        &sgwc_iter, &tac_iter);
                                                ogs_assert(ogs_yaml_iter_type(
                                                            &tac_iter) !=
                                                        YAML_MAPPING_NODE);

                                                do {
                                                    const char *v = NULL;

                                                    if (ogs_yaml_iter_type(
                                                            &tac_iter) ==
                                                        YAML_SEQUENCE_NODE) {
                                                        if (!ogs_yaml_iter_next(
                                                                    &tac_iter))
                                                            break;
                                                    }

                                                    if (num_of_tac >=
                                                            (int)ogs_global_conf()->
                                                            max.tai) {
                                                        ogs_warn("sgwc tac list "
                                                                "exceeds max.tai "
                                                                "(%d), skipping",
                                                                (int)ogs_global_conf()->
                                                                max.tai);
                                                        break;
                                                    }
                                                    v = ogs_yaml_iter_value(
                                                            &tac_iter);
                                                    if (v) {
                                                        tac[num_of_tac] =
                                                            atoi(v);
                                                        num_of_tac++;
                                                    }
                                                } while (
                                                    ogs_yaml_iter_type(
                                                        &tac_iter) ==
                                                        YAML_SEQUENCE_NODE);
                                            } else if (!strcmp(sgwc_key,
                                                        "e_cell_id")) {
                                                ogs_yaml_iter_t e_cell_id_iter;
                                                ogs_yaml_iter_recurse(
                                                        &sgwc_iter,
                                                        &e_cell_id_iter);
                                                ogs_assert(ogs_yaml_iter_type(
                                                            &e_cell_id_iter) !=
                                                        YAML_MAPPING_NODE);

                                                do {
                                                    const char *v = NULL;

                                                    if (ogs_yaml_iter_type(
                                                            &e_cell_id_iter) ==
                                                        YAML_SEQUENCE_NODE) {
                                                        if (!ogs_yaml_iter_next(
                                                            &e_cell_id_iter))
                                                            break;
                                                    }
                                                    if (num_of_e_cell_id >=
                                                            OGS_MAX_NUM_OF_CELL_ID) {
                                                        ogs_warn("e_cell_id limit "
                                                                "(%d) reached; "
                                                                "extra entries "
                                                                "ignored",
                                                                OGS_MAX_NUM_OF_CELL_ID);
                                                        break;
                                                    }
                                                    v = ogs_yaml_iter_value(
                                                            &e_cell_id_iter);
                                                    if (v) {
                                                        e_cell_id[
                                                            num_of_e_cell_id] =
                                                        ogs_uint64_from_string_hexadecimal(
                                                                (char*)v);
                                                        num_of_e_cell_id++;
                                                    }
                                                } while (ogs_yaml_iter_type(
                                                            &e_cell_id_iter) ==
                                                        YAML_SEQUENCE_NODE);
                                            } else if (!strcmp(sgwc_key,
                                                        "plmn_id") ||
                                                    !strcmp(sgwc_key,
                                                        "serving_plmn_id") ||
                                                    !strcmp(sgwc_key,
                                                        "imsi_plmn_id")) {
                                                mme_gtpc_client_parse_plmn_id_key(
                                                        &sgwc_iter, sgwc_key,
                                                        &sgw_serving_plmn_parsed,
                                                        &sgw_serving_plmn,
                                                        &sgw_imsi_plmn_parsed,
                                                        &sgw_imsi_plmn);
                                            } else if (!strcmp(sgwc_key,
                                                        "order")) {
                                                order_v = ogs_yaml_iter_value(
                                                        &sgwc_iter);
                                            } else if (!strcmp(sgwc_key,
                                                        "imsi_prefix")) {
                                                const char *v =
                                                    ogs_yaml_iter_value(
                                                            &sgwc_iter);
                                                if (v) {
                                                    ogs_cpystrn(imsi_prefix_buf,
                                                            v,
                                                            sizeof(
                                                                imsi_prefix_buf));
                                                    imsi_prefix_set = true;
                                                }
                                            } else
                                                ogs_warn("unknown key `%s`",
                                                        sgwc_key);
                                        }

                                        addr = NULL;
                                        for (i = 0; i < num; i++) {
                                            rv = ogs_addaddrinfo(&addr, family,
                                                    hostname[i], port, 0);
                                            ogs_assert(rv == OGS_OK);
                                        }

                                        ogs_filter_ip_version(&addr,
                                                ogs_global_conf()->parameter.
                                                no_ipv4,
                                                ogs_global_conf()->parameter.
                                                no_ipv6,
                                                ogs_global_conf()->parameter.
                                                prefer_ipv4);

                                        if (addr == NULL) {
                                            ogs_free(tac);
                                            continue;
                                        }

                                        sgw = mme_sgw_add(addr);
                                        ogs_assert(sgw);

                                        sgw->num_of_tac = num_of_tac;
                                        if (num_of_tac != 0)
                                            memcpy(sgw->tac, tac,
                                                    sizeof(uint16_t) *
                                                    num_of_tac);

                                        sgw->num_of_e_cell_id =
                                            num_of_e_cell_id;
                                        if (num_of_e_cell_id != 0)
                                            memcpy(sgw->e_cell_id, e_cell_id,
                                                    sizeof(sgw->e_cell_id));

                                        sgw->serving_plmn_present =
                                            sgw_serving_plmn_parsed;
                                        if (sgw_serving_plmn_parsed)
                                            memcpy(&sgw->serving_plmn_id,
                                                    &sgw_serving_plmn,
                                                    sizeof(ogs_plmn_id_t));
                                        sgw->imsi_plmn_present =
                                            sgw_imsi_plmn_parsed;
                                        if (sgw_imsi_plmn_parsed)
                                            memcpy(&sgw->imsi_plmn_id,
                                                    &sgw_imsi_plmn,
                                                    sizeof(ogs_plmn_id_t));
                                        sgw->selection_order =
                                            mme_gtpc_entry_selection_order(
                                                    sgwc_entry_idx, order_v);
                                        if (imsi_prefix_set)
                                            ogs_cpystrn(sgw->imsi_prefix,
                                                    imsi_prefix_buf,
                                                    sizeof(sgw->imsi_prefix));

                                        ogs_free(tac);
                                        sgwc_entry_idx++;

                                    } while (ogs_yaml_iter_type(&sgwc_array) ==
                                            YAML_SEQUENCE_NODE);

                                } else if (!strcmp(client_key, "smf")) {
                                    ogs_yaml_iter_t smf_array, smf_iter;
                                    int smf_entry_idx = 0;

                                    ogs_yaml_iter_recurse(
                                            &client_iter, &smf_array);
                                    do {
                                        mme_pgw_t *pgw = NULL;
                                        ogs_sockaddr_t *addr = NULL;
                                        int family = AF_UNSPEC;
                                        int i, num = 0;
                                        const char *hostname[
                                            OGS_MAX_NUM_OF_HOSTNAME];
                                        uint16_t port =
                                            ogs_gtp_self()->gtpc_port;
                                        const char *order_v = NULL;
                                        char imsi_prefix_buf[
                                            OGS_MAX_IMSI_BCD_LEN + 1];
                                        bool imsi_prefix_set = false;
                                        const char *apn[
                                            OGS_MAX_NUM_OF_APN] = {NULL,};
                                        uint8_t num_of_apn = 0;
                                        uint16_t *tac = ogs_calloc(
                                                ogs_global_conf()->max.tai,
                                                sizeof(uint16_t));
                                        int num_of_tac = 0;
                                        uint32_t e_cell_id[
                                            OGS_MAX_NUM_OF_CELL_ID] = {0,};
                                        uint8_t num_of_e_cell_id = 0;
                                        bool pgw_serving_plmn_parsed = false;
                                        ogs_plmn_id_t pgw_serving_plmn;
                                        bool pgw_imsi_plmn_parsed = false;
                                        ogs_plmn_id_t pgw_imsi_plmn;

                                        ogs_assert(tac);
                                        imsi_prefix_buf[0] = '\0';
                                        if (ogs_yaml_iter_type(&smf_array) ==
                                                YAML_MAPPING_NODE) {
                                            memcpy(&smf_iter, &smf_array,
                                                    sizeof(ogs_yaml_iter_t));
                                        } else if (ogs_yaml_iter_type(
                                                    &smf_array) ==
                                            YAML_SEQUENCE_NODE) {
                                            if (!ogs_yaml_iter_next(&smf_array)) {
                                                ogs_free(tac);
                                                break;
                                            }
                                            ogs_yaml_iter_recurse(
                                                    &smf_array, &smf_iter);
                                        } else if (ogs_yaml_iter_type(
                                                    &smf_array) ==
                                                YAML_SCALAR_NODE) {
                                            ogs_free(tac);
                                            break;
                                        } else
                                            ogs_assert_if_reached();

                                        while (ogs_yaml_iter_next(&smf_iter)) {
                                            const char *smf_key =
                                                ogs_yaml_iter_key(&smf_iter);
                                            ogs_assert(smf_key);
                                            if (!strcmp(smf_key, "family")) {
                                                const char *v =
                                                    ogs_yaml_iter_value(
                                                            &smf_iter);
                                                if (v) family = atoi(v);
                                                if (family != AF_UNSPEC &&
                                                    family != AF_INET &&
                                                    family != AF_INET6) {
                                                    ogs_warn(
                                                        "Ignore family(%d) : "
                                                        "AF_UNSPEC(%d), "
                                                        "AF_INET(%d), "
                                                        "AF_INET6(%d) ",
                                                        family, AF_UNSPEC,
                                                        AF_INET, AF_INET6);
                                                    family = AF_UNSPEC;
                                                }
                                            } else if (!strcmp(smf_key,
                                                        "address")) {
                                                ogs_yaml_iter_t hostname_iter;
                                                ogs_yaml_iter_recurse(&smf_iter,
                                                        &hostname_iter);
                                                ogs_assert(ogs_yaml_iter_type(
                                                            &hostname_iter) !=
                                                        YAML_MAPPING_NODE);

                                                do {
                                                    if (ogs_yaml_iter_type(
                                                            &hostname_iter) ==
                                                        YAML_SEQUENCE_NODE) {
                                                        if (!ogs_yaml_iter_next(
                                                            &hostname_iter))
                                                            break;
                                                    }

                                                    ogs_assert(num <
                                                    OGS_MAX_NUM_OF_HOSTNAME);
                                                    hostname[num++] =
                                                        ogs_yaml_iter_value(
                                                                &hostname_iter);
                                                } while (ogs_yaml_iter_type(
                                                            &hostname_iter) ==
                                                        YAML_SEQUENCE_NODE);
                                            } else if (!strcmp(
                                                        smf_key, "port")) {
                                                const char *v =
                                                    ogs_yaml_iter_value(
                                                            &smf_iter);
                                                if (v) port = mme_yaml_parse_port(v, port);
                                            } else if (!strcmp(
                                                        smf_key, "apn")) {
                                                ogs_yaml_iter_t apn_iter;
                                                ogs_yaml_iter_recurse(
                                                        &smf_iter, &apn_iter);
                                                ogs_assert(ogs_yaml_iter_type(
                                                            &apn_iter) !=
                                                        YAML_MAPPING_NODE);

                                                do {
                                                    const char *v = NULL;

                                                    if (ogs_yaml_iter_type(
                                                                &apn_iter) ==
                                                        YAML_SEQUENCE_NODE) {
                                                        if (!ogs_yaml_iter_next(
                                                                    &apn_iter))
                                                            break;
                                                    }

                                                    ogs_assert(num_of_apn <
                                                            OGS_MAX_NUM_OF_APN);
                                                    v = ogs_yaml_iter_value(
                                                            &apn_iter);
                                                    if (v) {
                                                        apn[num_of_apn] = v;
                                                        num_of_apn++;
                                                    }
                                                } while (ogs_yaml_iter_type(
                                                            &apn_iter) ==
                                                        YAML_SEQUENCE_NODE);
                                            } else if (!strcmp(
                                                        smf_key, "tac")) {
                                                ogs_yaml_iter_t tac_iter;
                                                ogs_yaml_iter_recurse(
                                                        &smf_iter, &tac_iter);
                                                ogs_assert(ogs_yaml_iter_type(
                                                            &tac_iter) !=
                                                        YAML_MAPPING_NODE);

                                                do {
                                                    const char *v = NULL;

                                                    if (ogs_yaml_iter_type(
                                                                &tac_iter) ==
                                                        YAML_SEQUENCE_NODE) {
                                                        if (!ogs_yaml_iter_next(
                                                                    &tac_iter))
                                                            break;
                                                    }

                                                    if (num_of_tac >=
                                                            (int)ogs_global_conf()->
                                                            max.tai) {
                                                        ogs_warn("smf tac list "
                                                                "exceeds max.tai "
                                                                "(%d), skipping",
                                                                (int)ogs_global_conf()->
                                                                max.tai);
                                                        break;
                                                    }
                                                    v = ogs_yaml_iter_value(
                                                            &tac_iter);
                                                    if (v) {
                                                        tac[num_of_tac] =
                                                            atoi(v);
                                                        num_of_tac++;
                                                    }
                                                } while (ogs_yaml_iter_type(
                                                            &tac_iter) ==
                                                        YAML_SEQUENCE_NODE);
                                            } else if (!strcmp(smf_key,
                                                        "e_cell_id")) {
                                                ogs_yaml_iter_t e_cell_id_iter;
                                                ogs_yaml_iter_recurse(&smf_iter,
                                                        &e_cell_id_iter);
                                                ogs_assert(ogs_yaml_iter_type(
                                                            &e_cell_id_iter) !=
                                                        YAML_MAPPING_NODE);

                                                do {
                                                    const char *v = NULL;

                                                    if (ogs_yaml_iter_type(
                                                            &e_cell_id_iter) ==
                                                        YAML_SEQUENCE_NODE) {
                                                        if (!ogs_yaml_iter_next(
                                                            &e_cell_id_iter))
                                                            break;
                                                    }
                                                    if (num_of_e_cell_id >=
                                                            OGS_MAX_NUM_OF_CELL_ID) {
                                                        ogs_warn("e_cell_id limit "
                                                                "(%d) reached; "
                                                                "extra entries "
                                                                "ignored",
                                                                OGS_MAX_NUM_OF_CELL_ID);
                                                        break;
                                                    }
                                                    v = ogs_yaml_iter_value(
                                                            &e_cell_id_iter);
                                                    if (v) {
                                                        e_cell_id[
                                                            num_of_e_cell_id] =
                                                        ogs_uint64_from_string_hexadecimal(
                                                                (char*)v);
                                                        num_of_e_cell_id++;
                                                    }
                                                } while (ogs_yaml_iter_type(
                                                            &e_cell_id_iter) ==
                                                        YAML_SEQUENCE_NODE);
                                            } else if (!strcmp(smf_key,
                                                        "plmn_id") ||
                                                    !strcmp(smf_key,
                                                        "serving_plmn_id") ||
                                                    !strcmp(smf_key,
                                                        "imsi_plmn_id")) {
                                                mme_gtpc_client_parse_plmn_id_key(
                                                        &smf_iter, smf_key,
                                                        &pgw_serving_plmn_parsed,
                                                        &pgw_serving_plmn,
                                                        &pgw_imsi_plmn_parsed,
                                                        &pgw_imsi_plmn);
                                            } else if (!strcmp(smf_key,
                                                        "order")) {
                                                order_v = ogs_yaml_iter_value(
                                                        &smf_iter);
                                            } else if (!strcmp(smf_key,
                                                        "imsi_prefix")) {
                                                const char *v =
                                                    ogs_yaml_iter_value(
                                                            &smf_iter);
                                                if (v) {
                                                    ogs_cpystrn(imsi_prefix_buf,
                                                            v,
                                                            sizeof(
                                                                imsi_prefix_buf));
                                                    imsi_prefix_set = true;
                                                }
                                            } else
                                                ogs_warn("unknown key `%s`",
                                                        smf_key);
                                        }

                                        addr = NULL;
                                        for (i = 0; i < num; i++) {
                                            rv = ogs_addaddrinfo(&addr, family,
                                                    hostname[i], port, 0);
                                            ogs_assert(rv == OGS_OK);
                                        }

                                        ogs_filter_ip_version(&addr,
                                                ogs_global_conf()->parameter.
                                                no_ipv4,
                                                ogs_global_conf()->parameter.
                                                no_ipv6,
                                                ogs_global_conf()->parameter.
                                                prefer_ipv4);

                                        if (addr == NULL) {
                                            ogs_free(tac);
                                            continue;
                                        }

                                        pgw = mme_pgw_add(addr);
                                        ogs_assert(pgw);

                                        pgw->num_of_apn = num_of_apn;
                                        if (num_of_apn != 0)
                                            memcpy(pgw->apn,
                                                    apn, sizeof(pgw->apn));

                                        pgw->num_of_tac = num_of_tac;
                                        if (num_of_tac != 0)
                                            memcpy(pgw->tac, tac,
                                                    sizeof(uint16_t) *
                                                    num_of_tac);

                                        pgw->num_of_e_cell_id =
                                            num_of_e_cell_id;
                                        if (num_of_e_cell_id != 0)
                                            memcpy(pgw->e_cell_id, e_cell_id,
                                                    sizeof(pgw->e_cell_id));

                                        pgw->serving_plmn_present =
                                            pgw_serving_plmn_parsed;
                                        if (pgw_serving_plmn_parsed)
                                            memcpy(&pgw->serving_plmn_id,
                                                    &pgw_serving_plmn,
                                                    sizeof(ogs_plmn_id_t));
                                        pgw->imsi_plmn_present =
                                            pgw_imsi_plmn_parsed;
                                        if (pgw_imsi_plmn_parsed)
                                            memcpy(&pgw->imsi_plmn_id,
                                                    &pgw_imsi_plmn,
                                                    sizeof(ogs_plmn_id_t));
                                        pgw->selection_order =
                                            mme_gtpc_entry_selection_order(
                                                    smf_entry_idx, order_v);
                                        if (imsi_prefix_set)
                                            ogs_cpystrn(pgw->imsi_prefix,
                                                    imsi_prefix_buf,
                                                    sizeof(pgw->imsi_prefix));

                                        ogs_free(tac);
                                        smf_entry_idx++;

                                    } while (ogs_yaml_iter_type(&smf_array) ==
                                            YAML_SEQUENCE_NODE);
                                } else if (!strcmp(client_key, "sgsn")) {
                                    ogs_yaml_iter_t sgsn_array, sgsn_iter;
                                    ogs_yaml_iter_recurse(&client_iter,
                                            &sgsn_array);
                                    if (ogs_yaml_iter_type(&sgsn_array) !=
                                            YAML_SEQUENCE_NODE) {
                                        ogs_error("mme.gtpc.client.sgsn must "
                                                "be a YAML sequence (list); "
                                                "see mme.yaml example");
                                        break;
                                    }
                                    do {
                                        mme_sgsn_t *sgsn = NULL;

                                        ogs_sockaddr_t *addr = NULL;
                                        int family = AF_UNSPEC;
                                        int i, num = 0;
                                        const char *hostname[
                                            OGS_MAX_NUM_OF_HOSTNAME];
                                        uint16_t port =
                                            ogs_gtp_self()->gtpc_port;

                                        OGS_LIST(route_list);
                                        bool default_route = false;

                                        if (ogs_yaml_iter_type(&sgsn_array) ==
                                                YAML_MAPPING_NODE) {
                                            memcpy(&sgsn_iter, &sgsn_array,
                                                    sizeof(ogs_yaml_iter_t));
                                        } else if (ogs_yaml_iter_type(
                                                    &sgsn_array) ==
                                            YAML_SEQUENCE_NODE) {
                                            if (!ogs_yaml_iter_next(
                                                        &sgsn_array))
                                                break;
                                            ogs_yaml_iter_recurse(&sgsn_array,
                                                    &sgsn_iter);
                                        } else if (ogs_yaml_iter_type(
                                                    &sgsn_array) ==
                                                YAML_SCALAR_NODE) {
                                            break;
                                        } else
                                            ogs_assert_if_reached();

                                        while (ogs_yaml_iter_next(&sgsn_iter)) {
                                            const char *sgsn_key =
                                                ogs_yaml_iter_key(&sgsn_iter);
                                            ogs_assert(sgsn_key);
                                            if (!strcmp(sgsn_key, "family")) {
                                                const char *v =
                                                    ogs_yaml_iter_value(
                                                            &sgsn_iter);
                                                if (v) family = atoi(v);
                                                if (family != AF_UNSPEC &&
                                                    family != AF_INET &&
                                                    family != AF_INET6) {
                                                    ogs_warn("Ignore family(%d)"
                                                        ": AF_UNSPEC(%d), "
                                                        "AF_INET(%d), "
                                                        "AF_INET6(%d) ",
                                                        family, AF_UNSPEC,
                                                        AF_INET, AF_INET6);
                                                    family = AF_UNSPEC;
                                                }
                                            } else if (!strcmp(sgsn_key,
                                                        "address")) {
                                                ogs_yaml_iter_t hostname_iter;
                                                ogs_yaml_iter_recurse(
                                                        &sgsn_iter,
                                                        &hostname_iter);
                                                ogs_assert(ogs_yaml_iter_type(
                                                            &hostname_iter) !=
                                                    YAML_MAPPING_NODE);

                                                do {
                                                    if (ogs_yaml_iter_type(
                                                            &hostname_iter) ==
                                                        YAML_SEQUENCE_NODE) {
                                                        if (!ogs_yaml_iter_next(
                                                                &hostname_iter))
                                                            break;
                                                    }

                                                    ogs_assert(num <
                                                    OGS_MAX_NUM_OF_HOSTNAME);
                                                    hostname[num++] =
                                                        ogs_yaml_iter_value(
                                                                &hostname_iter);
                                                } while (
                                                    ogs_yaml_iter_type(
                                                        &hostname_iter) ==
                                                        YAML_SEQUENCE_NODE);
                                            } else if (!strcmp(sgsn_key,
                                                        "port")) {
                                                const char *v =
                                                    ogs_yaml_iter_value(
                                                            &sgsn_iter);
                                                if (v) port = mme_yaml_parse_port(v, port);
                                            } else if (!strcmp(sgsn_key,
                                                        "routes")) {
                                                ogs_yaml_iter_t routes_array;
                                                ogs_yaml_iter_t routes_iter;
                                                ogs_yaml_iter_recurse(
                                                        &sgsn_iter,
                                                        &routes_array);
                                                do {
                                                    ogs_nas_rai_t rai;
                                                    uint16_t cell_id = 0;
                                                    bool rai_parsed = false;
                                                    bool cell_id_parsed = false;
                                                    mme_sgsn_route_t *sgsn_rt =
                                                        NULL;

                                                    if (ogs_yaml_iter_type(
                                                            &routes_array) ==
                                                            YAML_MAPPING_NODE) {
                                                        memcpy(&routes_iter,
                                                                &routes_array,
                                                            sizeof(
                                                            ogs_yaml_iter_t));
                                                    } else if (
                                                        ogs_yaml_iter_type(
                                                            &routes_array) ==
                                                        YAML_SEQUENCE_NODE) {
                                                        if (!ogs_yaml_iter_next(
                                                                &routes_array))
                                                            break;
                                                        ogs_yaml_iter_recurse(
                                                            &routes_array,
                                                            &routes_iter);
                                                    } else if (
                                                            ogs_yaml_iter_type(
                                                            &routes_array) ==
                                                            YAML_SCALAR_NODE) {
                                                        break;
                                                    } else
                                                        ogs_assert_if_reached();

                                                    while (ogs_yaml_iter_next(
                                                                &routes_iter)) {
                                                        const char *routes_key =
                                                            ogs_yaml_iter_key(
                                                                &routes_iter);
                                                        ogs_assert(routes_key);
                                                        if (!strcmp(routes_key,
                                                                    "rai")) {
                                                            memset(&rai, 0,
                                                                sizeof(rai));
                                                            rv = parse_rai(
                                                                &routes_iter,
                                                                &rai);
                                                            ogs_assert(rv ==
                                                                    OGS_OK);
                                                            rai_parsed = true;
                                                        } else if (!strcmp(
                                                                routes_key,
                                                                "ci")) {
                                        ogs_yaml_iter_t cell_id_iter;
                                        ogs_yaml_iter_recurse(
                                                &routes_iter, &cell_id_iter);
                                        ogs_assert(ogs_yaml_iter_type(
                                                    &cell_id_iter) !=
                                                YAML_MAPPING_NODE);
                                        do {
                                            const char *v = NULL;

                                            if (ogs_yaml_iter_type(
                                                        &cell_id_iter) ==
                                                    YAML_SEQUENCE_NODE) {
                                                if (!ogs_yaml_iter_next(
                                                            &cell_id_iter))
                                                    break;
                                            }
                                            v = ogs_yaml_iter_value(
                                                    &cell_id_iter);
                                            if (v) {
                                                cell_id = atoi((char*)v);
                                                cell_id_parsed = true;
                                            }
                                        } while (
                                            ogs_yaml_iter_type(&cell_id_iter) ==
                                                YAML_SEQUENCE_NODE);

                                                        } else
                                                            ogs_warn("unknown "
                                                                    "key `%s`",
                                                                    routes_key);
                                                    }

                                                    ogs_assert(rai_parsed &&
                                                            cell_id_parsed);
                                                    ogs_pool_alloc(
                                                        &mme_sgsn_route_pool,
                                                        &sgsn_rt);
                                                    ogs_assert(sgsn_rt);
                                                    memcpy(&sgsn_rt->rai, &rai,
                                                            sizeof(rai));
                                                    sgsn_rt->cell_id = cell_id;
                                                    ogs_list_add(&route_list,
                                                            sgsn_rt);

                                                } while (ogs_yaml_iter_type(
                                                            &routes_array) ==
                                                        YAML_SEQUENCE_NODE);
                                            } else if (!strcmp(sgsn_key,
                                                        "default_route")) {
                                                default_route = true;
                                            } else
                                                ogs_warn("unknown key `%s`",
                                                        sgsn_key);
                                        }

                                        addr = NULL;
                                        for (i = 0; i < num; i++) {
                                            rv = ogs_addaddrinfo(&addr,
                                                    family, hostname[i], port,
                                                    0);
                                            ogs_assert(rv == OGS_OK);
                                        }

                                        ogs_filter_ip_version(&addr,
                                                ogs_global_conf()->parameter.
                                                no_ipv4,
                                                ogs_global_conf()->parameter.
                                                no_ipv6,
                                                ogs_global_conf()->parameter.
                                                prefer_ipv4);

                                        if (addr == NULL) continue;

                                        sgsn = mme_sgsn_add(addr);
                                        ogs_assert(sgsn);

                                        if (ogs_list_count(&route_list))
                                            ogs_list_copy(&sgsn->route_list,
                                                    &route_list);

                                        sgsn->default_route = default_route;

                                    } while (ogs_yaml_iter_type(&sgsn_array) ==
                                            YAML_SEQUENCE_NODE);
                                } else
                                    ogs_warn("unknown key `%s`", client_key);
                            }
                        } else if (!strcmp(gtpc_key, "recovery")) {
                            const char *v = ogs_yaml_iter_value(&gtpc_iter);
                            if (v)
                                self.gtpc_recovery = (uint8_t)atoi(v);
                        } else if (!strcmp(gtpc_key, "echo_interval")) {
                            const char *v = ogs_yaml_iter_value(&gtpc_iter);
                            if (v)
                                self.gtpc_echo_interval = atoi(v);
                        } else if (!strcmp(gtpc_key,
                                "recovery_counter_file")) {
                            const char *v = ogs_yaml_iter_value(&gtpc_iter);
                            if (v) self.recovery_counter_file = v;
                        } else
                            ogs_warn("unknown key `%s`", gtpc_key);
                    }
                } else if (!strcmp(mme_key, "gummei")) {
                    ogs_yaml_iter_t gummei_array, gummei_iter;
                    ogs_yaml_iter_recurse(&mme_iter, &gummei_array);
                    do {
                        served_gummei_t *gummei = NULL;

                        if (ogs_yaml_iter_type(&gummei_array) ==
                                YAML_MAPPING_NODE) {
                            memcpy(&gummei_iter, &gummei_array,
                                    sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&gummei_array) ==
                            YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&gummei_array))
                                break;
                            ogs_yaml_iter_recurse(&gummei_array,
                                    &gummei_iter);
                        } else if (ogs_yaml_iter_type(&gummei_array) ==
                            YAML_SCALAR_NODE) {
                            break;
                        } else
                            ogs_assert_if_reached();

                        ogs_assert(self.num_of_served_gummei <
                                OGS_MAX_NUM_OF_SERVED_GUMMEI);
                        gummei = &self.served_gummei[
                            self.num_of_served_gummei];
                        ogs_assert(gummei);

                        while (ogs_yaml_iter_next(&gummei_iter)) {
                            const char *gummei_key =
                                ogs_yaml_iter_key(&gummei_iter);
                            ogs_assert(gummei_key);
                            if (!strcmp(gummei_key, "plmn_id")) {
                                ogs_yaml_iter_t plmn_id_array, plmn_id_iter;
                                ogs_yaml_iter_recurse(&gummei_iter,
                                        &plmn_id_array);
                                do {
                                    ogs_plmn_id_t *plmn_id = NULL;
                                    const char *mcc = NULL, *mnc = NULL;

                                    if (ogs_yaml_iter_type(&plmn_id_array) ==
                                            YAML_MAPPING_NODE) {
                                        memcpy(&plmn_id_iter, &plmn_id_array,
                                                sizeof(ogs_yaml_iter_t));
                                    } else if (ogs_yaml_iter_type(
                                                &plmn_id_array) ==
                                                YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&plmn_id_array))
                                            break;
                                        ogs_yaml_iter_recurse(&plmn_id_array,
                                                &plmn_id_iter);
                                    } else if (ogs_yaml_iter_type(
                                                &plmn_id_array) ==
                                                YAML_SCALAR_NODE) {
                                        break;
                                    } else
                                        ogs_assert_if_reached();

                                    ogs_assert(gummei->num_of_plmn_id <
                                            OGS_MAX_NUM_OF_PLMN_PER_MME);
                                    plmn_id = &gummei->plmn_id[
                                        gummei->num_of_plmn_id];
                                    ogs_assert(plmn_id);

                                    while (ogs_yaml_iter_next(&plmn_id_iter)) {
                                        const char *plmn_id_key =
                                            ogs_yaml_iter_key(&plmn_id_iter);
                                        ogs_assert(plmn_id_key);
                                        if (!strcmp(plmn_id_key, "mcc")) {
                                            mcc = ogs_yaml_iter_value(
                                                    &plmn_id_iter);
                                        } else if (!strcmp(
                                                    plmn_id_key, "mnc")) {
                                            mnc = ogs_yaml_iter_value(
                                                    &plmn_id_iter);
                                        }
                                    }

                                    if (mcc && mnc) {
                                        ogs_plmn_id_build(plmn_id,
                                            atoi(mcc), atoi(mnc), strlen(mnc));
                                        gummei->num_of_plmn_id++;
                                    }

                                } while (ogs_yaml_iter_type(&plmn_id_array) ==
                                        YAML_SEQUENCE_NODE);
                            } else if (!strcmp(gummei_key, "mme_gid")) {
                                ogs_yaml_iter_t mme_gid_iter;
                                ogs_yaml_iter_recurse(
                                        &gummei_iter, &mme_gid_iter);
                                ogs_assert(ogs_yaml_iter_type(
                                        &mme_gid_iter) != YAML_MAPPING_NODE);

                                do {
                                    uint16_t *mme_gid = NULL;
                                    const char *v = NULL;

                                    if (ogs_yaml_iter_type(&mme_gid_iter) ==
                                            YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&mme_gid_iter))
                                            break;
                                    }

                                    ogs_assert(gummei->num_of_mme_gid <
                                            GRP_PER_MME);
                                    mme_gid = &gummei->mme_gid[
                                        gummei->num_of_mme_gid];
                                    ogs_assert(mme_gid);

                                    v = ogs_yaml_iter_value(&mme_gid_iter);
                                    if (v) {
                                        *mme_gid = atoi(v);
                                        gummei->num_of_mme_gid++;
                                    }
                                } while (
                                    ogs_yaml_iter_type(&mme_gid_iter) ==
                                        YAML_SEQUENCE_NODE);
                            } else if (!strcmp(gummei_key, "mme_code")) {
                                ogs_yaml_iter_t mme_code_iter;
                                ogs_yaml_iter_recurse(&gummei_iter,
                                        &mme_code_iter);
                                ogs_assert(ogs_yaml_iter_type(&mme_code_iter) !=
                                    YAML_MAPPING_NODE);

                                do {
                                    uint8_t *mme_code = NULL;
                                    const char *v = NULL;

                                    ogs_assert(gummei->num_of_mme_code <
                                            CODE_PER_MME);
                                    mme_code = &gummei->mme_code[
                                        gummei->num_of_mme_code];
                                    ogs_assert(mme_code);

                                    if (ogs_yaml_iter_type(&mme_code_iter) ==
                                            YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&mme_code_iter))
                                            break;
                                    }

                                    v = ogs_yaml_iter_value(&mme_code_iter);
                                    if (v) {
                                        *mme_code = atoi(v);
                                        gummei->num_of_mme_code++;
                                    }
                                } while (
                                    ogs_yaml_iter_type(&mme_code_iter) ==
                                        YAML_SEQUENCE_NODE);
                            } else
                                ogs_warn("unknown key `%s`", gummei_key);
                        }

                        if (gummei->num_of_plmn_id &&
                            gummei->num_of_mme_gid && gummei->num_of_mme_code) {
                            self.num_of_served_gummei++;
                        } else {
                            ogs_warn("Ignore gummei : "
                                    "plmn_id(%d), mme_gid(%d), mme_code(%d)",
                                gummei->num_of_plmn_id,
                                gummei->num_of_mme_gid,
                                gummei->num_of_mme_code);
                            gummei->num_of_plmn_id = 0;
                            gummei->num_of_mme_gid = 0;
                            gummei->num_of_mme_code = 0;
                        }
                    } while (ogs_yaml_iter_type(&gummei_array) ==
                            YAML_SEQUENCE_NODE);
                } else if (!strcmp(mme_key, "attach_accept")) {
                    mme_attach_accept_parse_yaml(&mme_iter);
                } else if (!strcmp(mme_key, "equivalent_plmn")) {
                    rv = mme_eplmn_parse_config(&mme_iter,
                            &self.num_of_eplmn, self.eplmn);
                    if (rv != OGS_OK)
                        return rv;
                } else if (!strcmp(mme_key, "equivalent_plmn_serving_only")) {
                    self.attach_accept.equivalent_plmn_serving_only =
                        ogs_yaml_iter_bool(&mme_iter);
                } else if (!strcmp(mme_key, "ims_voice_over_ps_in_s1_mode")) {
                    self.attach_accept.ims_voice_over_ps =
                        ogs_yaml_iter_bool(&mme_iter);
                } else if (!strcmp(mme_key, "tai_list_in_accept")) {
                    const char *v = ogs_yaml_iter_value(&mme_iter);
                    if (v && !strcmp(v, "serving_only")) {
                        self.attach_accept.tai_list_serving_only = true;
                    } else if (v && !strcmp(v, "all")) {
                        self.attach_accept.tai_list_serving_only = false;
                    } else if (v) {
                        ogs_warn("Unknown tai_list_in_accept `%s' "
                                "(use: serving_only or all)", v);
                    }
                } else if (!strcmp(mme_key, "mip_home_agent_host_dns")) {
                    self.mip_home_agent_host_dns =
                        ogs_yaml_iter_bool(&mme_iter);
                    ogs_info("MIP-Home-Agent-Host DNS resolve: %s",
                            self.mip_home_agent_host_dns ? "enabled" :
                            "disabled");
                } else if (!strcmp(mme_key, "omit_indication_on_gtp_csr") ||
                        !strcmp(mme_key, "omit_gtp_indication")) {
                    self.omit_indication_on_gtp_csr =
                        ogs_yaml_iter_bool(&mme_iter);
                    ogs_info("GTP Create Session omit Indication IE: %s",
                            self.omit_indication_on_gtp_csr ?
                            "enabled" : "disabled");
                } else if (!strcmp(mme_key, "inbound_roam")) {
                    ogs_yaml_iter_t roam_iter;
                    ogs_yaml_iter_recurse(&mme_iter, &roam_iter);
                    while (ogs_yaml_iter_next(&roam_iter)) {
                        const char *rk = ogs_yaml_iter_key(&roam_iter);
                        const char *rv = ogs_yaml_iter_value(&roam_iter);
                        ogs_assert(rk);
                        if (!strcmp(rk, "gtp_apn_format") ||
                                !strcmp(rk, "apn_format")) {
                            if (rv && (!strcmp(rv, "received") ||
                                        !strcmp(rv, "exact") ||
                                        !strcmp(rv, "as_received"))) {
                                self.inbound_roam_gtp_apn_format =
                                    MME_INBOUND_ROAM_GTP_APN_RECEIVED;
                            } else if (rv && (!strcmp(rv, "fqdn") ||
                                        !strcmp(rv, "full"))) {
                                self.inbound_roam_gtp_apn_format =
                                    MME_INBOUND_ROAM_GTP_APN_FQDN;
                            } else
                                ogs_warn("unknown mme.inbound_roam."
                                        "gtp_apn_format `%s` "
                                        "(use received|fqdn)", rv);
                        } else if (!strcmp(rk, "gtp_apn_lowercase") ||
                                !strcmp(rk, "apn_lowercase") ||
                                !strcmp(rk, "lowercase")) {
                            self.inbound_roam_gtp_apn_lowercase =
                                ogs_yaml_iter_bool(&roam_iter);
                        } else if (!strcmp(rk, "strip_pap_from_gtp_pco") ||
                                !strcmp(rk, "strip_pap_from_pco")) {
                            self.inbound_roam_strip_pap_from_gtp_pco =
                                ogs_yaml_iter_bool(&roam_iter);
                        } else if (!strcmp(rk,
                                    "omit_indication_on_gtp_csr") ||
                                !strcmp(rk, "omit_gtp_indication")) {
                            self.omit_indication_on_gtp_csr =
                                ogs_yaml_iter_bool(&roam_iter);
                            ogs_warn("mme.inbound_roam.omit_indication_on_gtp_csr "
                                    "is deprecated; use mme.omit_indication_on_gtp_csr");
                        } else if (!strcmp(rk, "force_ipv4_pdn_on_home_pgw") ||
                                !strcmp(rk, "force_ipv4_pdn")) {
                            self.inbound_roam_force_ipv4_pdn_on_home_pgw =
                                ogs_yaml_iter_bool(&roam_iter);
                        } else if (!strcmp(rk,
                                    "zero_bearer_mbr_for_non_gbr") ||
                                !strcmp(rk, "non_gbr_zero_bearer_mbr")) {
                            self.inbound_roam_zero_bearer_mbr_for_non_gbr =
                                ogs_yaml_iter_bool(&roam_iter);
                        } else if (!strcmp(rk,
                                    "gtpc_plmn_id_is_imsi_plmn") ||
                                !strcmp(rk, "plmn_id_is_imsi_plmn")) {
                            self.inbound_roam_gtpc_plmn_id_is_imsi_plmn =
                                ogs_yaml_iter_bool(&roam_iter);
                        } else
                            ogs_warn("unknown key `%s` in mme.inbound_roam",
                                    rk);
                    }
                    ogs_info("Inbound roam: apn=%s lowercase=%s "
                            "sanitize_pco=%s "
                            "force_ipv4_pdn=%s non_gbr_zero_mbr=%s "
                            "gtpc_plmn_id_is_imsi_plmn=%s",
                            self.inbound_roam_gtp_apn_format ==
                            MME_INBOUND_ROAM_GTP_APN_FQDN ? "fqdn" :
                            "received",
                            self.inbound_roam_gtp_apn_lowercase ?
                            "true" : "false",
                            self.inbound_roam_strip_pap_from_gtp_pco ?
                            "true" : "false",
                            self.inbound_roam_force_ipv4_pdn_on_home_pgw ?
                            "true" : "false",
                            self.inbound_roam_zero_bearer_mbr_for_non_gbr ?
                            "true" : "false",
                            self.inbound_roam_gtpc_plmn_id_is_imsi_plmn ?
                            "true" : "false");
                } else if (!strcmp(mme_key, "ambr_limit")) {
                    ogs_yaml_iter_t ambr_iter;
                    ogs_yaml_iter_recurse(&mme_iter, &ambr_iter);
                    while (ogs_yaml_iter_next(&ambr_iter)) {
                        const char *ambr_key = ogs_yaml_iter_key(&ambr_iter);
                        ogs_assert(ambr_key);

                        if (!strcmp(ambr_key, "enabled")) {
                            self.ambr_limit.enabled =
                                ogs_yaml_iter_bool(&ambr_iter);
                        } else if (!strcmp(ambr_key, "force")) {
                            self.ambr_limit.force =
                                ogs_yaml_iter_bool(&ambr_iter);
                        } else if (!strcmp(ambr_key, "downlink") ||
                                !strcmp(ambr_key, "downlink_mbps")) {
                            const char *v =
                                ogs_yaml_iter_value(&ambr_iter);
                            if (v) {
                                uint64_t mbps = (uint64_t)atoi(v);
                                uint64_t bps = mbps * 1000000ULL;

                                if (bps > UINT32_MAX)
                                    bps = UINT32_MAX;
                                self.ambr_limit.downlink_bps = (uint32_t)bps;
                            }
                        } else if (!strcmp(ambr_key, "uplink") ||
                                !strcmp(ambr_key, "uplink_mbps")) {
                            const char *v =
                                ogs_yaml_iter_value(&ambr_iter);
                            if (v) {
                                uint64_t mbps = (uint64_t)atoi(v);
                                uint64_t bps = mbps * 1000000ULL;

                                if (bps > UINT32_MAX)
                                    bps = UINT32_MAX;
                                self.ambr_limit.uplink_bps = (uint32_t)bps;
                            }
                        } else
                            ogs_warn("Unknown ambr_limit key `%s'", ambr_key);
                    }
                    if (self.ambr_limit.uplink_bps == 0)
                        self.ambr_limit.uplink_bps =
                            self.ambr_limit.downlink_bps;
                    ogs_info("AMBR limit: %s force=%s DL=%u Mbps UL=%u Mbps",
                            self.ambr_limit.enabled ? "enabled" : "disabled",
                            self.ambr_limit.force ? "yes" : "no",
                            self.ambr_limit.downlink_bps / 1000000,
                            self.ambr_limit.uplink_bps / 1000000);
                } else if (!strcmp(mme_key, "tai")) {
                    int num_of_list0 = 0;
                    int num_of_list1 = 0;
                    ogs_eps_tai0_list_t *list0 = NULL;
                    ogs_eps_tai1_list_t *list1 = NULL;
                    ogs_eps_tai2_list_t *list2 = NULL;

                    ogs_assert(self.num_of_served_tai <
                            OGS_MAX_NUM_OF_SUPPORTED_TA);
                    list0 = mme_served_tai_list0(self.num_of_served_tai);
                    list1 = &self.served_tai[self.num_of_served_tai].list1;
                    list2 = &self.served_tai[self.num_of_served_tai].list2;

                    ogs_yaml_iter_t tai_array, tai_iter;
                    ogs_yaml_iter_recurse(&mme_iter, &tai_array);
                    do {
                        const char *mcc = NULL, *mnc = NULL;
                        int num_of_tac = 0;
                        uint16_t *start = NULL;
                        uint16_t *end = NULL;

                        start = ogs_calloc(ogs_global_conf()->max.tai,
                                sizeof(uint16_t));
                        end = ogs_calloc(ogs_global_conf()->max.tai,
                                sizeof(uint16_t));
                        ogs_assert(start);
                        ogs_assert(end);

                        if (ogs_yaml_iter_type(&tai_array) ==
                                YAML_MAPPING_NODE) {
                            memcpy(&tai_iter, &tai_array,
                                    sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&tai_array) ==
                            YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&tai_array)) {
                                ogs_free(start);
                                ogs_free(end);
                                break;
                            }
                            ogs_yaml_iter_recurse(&tai_array,
                                    &tai_iter);
                        } else if (ogs_yaml_iter_type(&tai_array) ==
                                YAML_SCALAR_NODE) {
                            ogs_free(start);
                            ogs_free(end);
                            break;
                        } else {
                            ogs_free(start);
                            ogs_free(end);
                            ogs_assert_if_reached();
                        }

                        while (ogs_yaml_iter_next(&tai_iter)) {
                            const char *tai_key = ogs_yaml_iter_key(&tai_iter);
                            ogs_assert(tai_key);
                            if (!strcmp(tai_key, "plmn_id")) {
                                ogs_yaml_iter_t plmn_id_iter;

                                ogs_yaml_iter_recurse(&tai_iter, &plmn_id_iter);
                                while (ogs_yaml_iter_next(&plmn_id_iter)) {
                                    const char *plmn_id_key =
                                        ogs_yaml_iter_key(&plmn_id_iter);
                                    ogs_assert(plmn_id_key);
                                    if (!strcmp(plmn_id_key, "mcc")) {
                                        mcc = ogs_yaml_iter_value(
                                                &plmn_id_iter);
                                    } else if (!strcmp(plmn_id_key, "mnc")) {
                                        mnc = ogs_yaml_iter_value(
                                                &plmn_id_iter);
                                    }
                                }
                            } else if (!strcmp(tai_key, "tac")) {
                                ogs_yaml_iter_t tac_iter;
                                ogs_yaml_iter_recurse(&tai_iter, &tac_iter);
                                ogs_assert(ogs_yaml_iter_type(&tac_iter) !=
                                            YAML_MAPPING_NODE);
                                do {
                                    char *v = NULL;
                                    char *low = NULL, *high = NULL;

                                    if (ogs_yaml_iter_type(&tac_iter) ==
                                            YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&tac_iter))
                                            break;
                                    }

                                    v = (char *)ogs_yaml_iter_value(
                                                &tac_iter);
                                    if (v) {
                                        low = strsep(&v, "-");
                                        if (low && strlen(low) == 0)
                                            low = NULL;

                                        high = v;
                                        if (high && strlen(high) == 0)
                                            high = NULL;

                                        if (low) {
                                            if (num_of_tac >=
                                                    (int)ogs_global_conf()->
                                                    max.tai) {
                                                ogs_warn("served tai list "
                                                        "exceeds max.tai (%d), "
                                                        "skipping",
                                                        (int)ogs_global_conf()->
                                                        max.tai);
                                                break;
                                            }
                                            start[num_of_tac] = atoi(low);
                                            if (high) {
                                                end[num_of_tac] = atoi(high);
                                                if (end[num_of_tac] <
                                                    start[num_of_tac])
                                                    ogs_error(
                                                        "Invalid TAI range: "
                                                        "LOW:%s,HIGH:%s",
                                                            low, high);
                                                else if (
                                                    (end[num_of_tac]-
                                                    start[num_of_tac]+1) >
                                                        OGS_MAX_NUM_OF_TAI)
                                                    ogs_error(
                                                        "Overflow TAI range: "
                                                        "LOW:%s,HIGH:%s",
                                                            low, high);
                                                else
                                                    num_of_tac++;
                                            } else {
                                                end[num_of_tac] =
                                                    start[num_of_tac];
                                                num_of_tac++;
                                            }
                                        }
                                    }
                                } while (
                                    ogs_yaml_iter_type(&tac_iter) ==
                                        YAML_SEQUENCE_NODE);
                            } else
                                ogs_warn("unknown key `%s`", tai_key);
                        }

                        if (mcc && mnc && num_of_tac) {
                            if (num_of_tac == 1 && start[0] == end[0]) {
                                if (list2->num >= OGS_MAX_NUM_OF_TAI) {
                                    ogs_error("Too many single-TAC 'tai' "
                                            "entries (%d max). Group multiple "
                                            "TACs into one 'tai' as "
                                            "tac: [t1, t2, ...] so they use "
                                            "type-0 partial lists instead.",
                                            OGS_MAX_NUM_OF_TAI);
                                    ogs_free(start);
                                    ogs_free(end);
                                    return OGS_ERROR;
                                }

                                list2->type = OGS_TAI2_TYPE;

                                ogs_plmn_id_build(
                                    &list2->tai[list2->num].plmn_id,
                                    atoi(mcc), atoi(mnc), strlen(mnc));
                                list2->tai[list2->num].tac = start[0];

                                list2->num++;

                            } else {
                                int tac, count = 0;
                                uint64_t max_list0 =
                                    ogs_app_max_eps_tai0_partial_list();

                                for (tac = 0; tac < num_of_tac; tac++) {
                                    ogs_assert(end[tac] >= start[tac]);
                                    if (start[tac] == end[tac]) {
                                        if (count >= OGS_MAX_NUM_OF_TAI) {
                                            if (num_of_list0 + 1 >=
                                                    max_list0) {
                                                ogs_error(
                                                    "Too many TAI type-0 "
                                                    "partial lists (%llu max, "
                                                    "see global.max."
                                                    "eps_tai0_partial_list in "
                                                    "'%s')",
                                                    (unsigned long long)
                                                    max_list0,
                                                    ogs_app()->file);
                                                ogs_free(start);
                                                ogs_free(end);
                                                return OGS_ERROR;
                                            }
                                            num_of_list0++;
                                            count = 0;
                                        }
                                        if (num_of_list0 >= max_list0) {
                                            ogs_error(
                                                "Too many TAI type-0 partial "
                                                "lists (%llu max, see global."
                                                "max.eps_tai0_partial_list in "
                                                "'%s')",
                                                (unsigned long long)max_list0,
                                                ogs_app()->file);
                                            ogs_free(start);
                                            ogs_free(end);
                                            return OGS_ERROR;
                                        }

                                        list0->tai[num_of_list0].type =
                                            OGS_TAI0_TYPE;

                                        ogs_plmn_id_build(
                                            &list0->tai[num_of_list0].plmn_id,
                                            atoi(mcc), atoi(mnc), strlen(mnc));
                                        list0->tai[num_of_list0].
                                            tac[count] = start[tac];

                                        list0->tai[num_of_list0].num =
                                            ++count;

                                    } else if (start[tac] < end[tac]) {
                                        if (num_of_list1 >=
                                                OGS_MAX_NUM_OF_TAI) {
                                            ogs_error("Too many TAC ranges "
                                                    "(%d max) in 'tai'",
                                                    OGS_MAX_NUM_OF_TAI);
                                            ogs_free(start);
                                            ogs_free(end);
                                            return OGS_ERROR;
                                        }

                                        list1->tai[num_of_list1].type =
                                            OGS_TAI1_TYPE;

                                        ogs_plmn_id_build(
                                            &list1->tai[num_of_list1].plmn_id,
                                            atoi(mcc), atoi(mnc), strlen(mnc));
                                        list1->tai[num_of_list1].tac =
                                            start[tac];

                                        list1->tai[num_of_list1].num =
                                            end[tac]-start[tac]+1;

                                        num_of_list1++;
                                    }
                                }

                                if (count)
                                    num_of_list0++;
                            }
                        } else {
                            ogs_warn("Ignore tai : mcc(%p), mnc(%p), "
                                    "num_of_tac(%d)", mcc, mnc, num_of_tac);
                        }

                        ogs_free(start);
                        ogs_free(end);
                    } while (ogs_yaml_iter_type(&tai_array) ==
                            YAML_SEQUENCE_NODE);

                    if (list2->num || num_of_list1 || num_of_list0) {
                        self.num_of_served_tai++;
                    }
                } else if (!strcmp(mme_key, "access_control")) {
                    ogs_yaml_iter_t access_control_array, access_control_iter;
                    ogs_yaml_iter_recurse(&mme_iter, &access_control_array);
                    do {
                        if (ogs_yaml_iter_type(&access_control_array) ==
                                YAML_MAPPING_NODE) {
                            memcpy(&access_control_iter, &access_control_array,
                                    sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&access_control_array) ==
                            YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&access_control_array))
                                break;
                            ogs_yaml_iter_recurse(&access_control_array,
                                    &access_control_iter);
                        } else if (ogs_yaml_iter_type(&access_control_array) ==
                            YAML_SCALAR_NODE) {
                            break;
                        } else
                            ogs_assert_if_reached();

                        ogs_assert(self.num_of_access_control <
                                OGS_MAX_NUM_OF_PLMN_PER_MME);

                        {
                            mme_access_control_t *ac =
                                &self.access_control[
                                    self.num_of_access_control];
                            bool entry_configured = false;
                            int entry_reject_cause = 0;
                            const char *order_v = NULL;

                            memset(ac, 0, sizeof(*ac));

                            while (ogs_yaml_iter_next(&access_control_iter)) {
                                const char *mnc = NULL, *mcc = NULL;
                                int reject_cause = 0;
                                const char *access_control_key =
                                    ogs_yaml_iter_key(&access_control_iter);
                                ogs_assert(access_control_key);
                                if (!strcmp(access_control_key,
                                            "default_reject_cause")) {
                                    const char *v = ogs_yaml_iter_value(
                                            &access_control_iter);
                                    if (v) self.default_reject_cause = atoi(v);
                                } else if (!strcmp(access_control_key,
                                            "reject_cause")) {
                                    const char *v = ogs_yaml_iter_value(
                                            &access_control_iter);
                                    if (v) entry_reject_cause = atoi(v);
                                } else if (!strcmp(access_control_key,
                                            "imsi_prefix")) {
                                    const char *v = ogs_yaml_iter_value(
                                            &access_control_iter);
                                    if (v) {
                                        ogs_cpystrn(ac->imsi_prefix, v,
                                                sizeof(ac->imsi_prefix));
                                        entry_configured = true;
                                    }
                                } else if (!strcmp(access_control_key,
                                            "plmn_id")) {
                                    ogs_yaml_iter_t plmn_id_iter;

                                    ogs_yaml_iter_recurse(&access_control_iter,
                                            &plmn_id_iter);
                                    while (ogs_yaml_iter_next(&plmn_id_iter)) {
                                        const char *plmn_id_key =
                                            ogs_yaml_iter_key(&plmn_id_iter);
                                        ogs_assert(plmn_id_key);
                                        if (!strcmp(plmn_id_key,
                                                    "reject_cause")) {
                                            const char *v =
                                                ogs_yaml_iter_value(
                                                        &plmn_id_iter);
                                            if (v) reject_cause = atoi(v);
                                        } else if (!strcmp(plmn_id_key,
                                                    "mcc")) {
                                            mcc = ogs_yaml_iter_value(
                                                    &plmn_id_iter);
                                        } else if (!strcmp(plmn_id_key,
                                                    "mnc")) {
                                            mnc = ogs_yaml_iter_value(
                                                    &plmn_id_iter);
                                        }
                                    }

                                    if (mcc && mnc) {
                                        ogs_plmn_id_build(&ac->plmn_id,
                                                atoi(mcc), atoi(mnc),
                                                strlen(mnc));
                                        ac->plmn_id_configured = true;
                                        entry_configured = true;
                                        if (reject_cause)
                                            entry_reject_cause = reject_cause;
                                    }
                                } else if (!strcmp(access_control_key, "tac")) {
                                    mme_access_control_parse_uint32_list(
                                            &access_control_iter, ac, false);
                                } else if (!strcmp(access_control_key,
                                            "enb_id")) {
                                    mme_access_control_parse_uint32_list(
                                            &access_control_iter, ac, true);
                                } else if (!strcmp(access_control_key, "order")) {
                                    order_v = ogs_yaml_iter_value(
                                            &access_control_iter);
                                } else
                                    ogs_warn("unknown key `%s`",
                                            access_control_key);
                            }

                            if (entry_configured) {
                                if (entry_reject_cause)
                                    ac->reject_cause = entry_reject_cause;
                                ac->selection_order =
                                    mme_gtpc_entry_selection_order(
                                            self.num_of_access_control,
                                            order_v);
                                ogs_info("access_control[%d] imsi_prefix=%s "
                                        "plmn=%06x tac=%u enb=%u",
                                        self.num_of_access_control,
                                        ac->imsi_prefix[0] ?
                                            ac->imsi_prefix : "-",
                                        ac->plmn_id_configured ?
                                            ogs_plmn_id_hexdump(&ac->plmn_id) :
                                            0,
                                        ac->tac_hash ?
                                            (unsigned)ogs_hash_count(
                                                ac->tac_hash) : 0,
                                        ac->enb_id_hash ?
                                            (unsigned)ogs_hash_count(
                                                ac->enb_id_hash) : 0);
                                self.num_of_access_control++;
                            }
                        }

                    } while (ogs_yaml_iter_type(&access_control_array) ==
                            YAML_SEQUENCE_NODE);
                } else if (!strcmp(mme_key, "hss_map")) {
                    ogs_yaml_iter_t hss_map_array, hss_map_iter;
                    int hss_map_entry_idx = 0;

                    ogs_yaml_iter_recurse(&mme_iter, &hss_map_array);
                    do {
                        const char *order_v = NULL;

                        if (ogs_yaml_iter_type(&hss_map_array) ==
                                YAML_MAPPING_NODE) {
                            memcpy(&hss_map_iter, &hss_map_array,
                                    sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&hss_map_array) ==
                            YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&hss_map_array))
                                break;
                            ogs_yaml_iter_recurse(&hss_map_array,
                                    &hss_map_iter);
                        } else if (ogs_yaml_iter_type(&hss_map_array) ==
                            YAML_SCALAR_NODE) {
                            break;
                        } else
                            ogs_assert_if_reached();

                        while (ogs_yaml_iter_next(&hss_map_iter)) {
                            const char *mnc = NULL, *mcc = NULL, *realm = NULL, *host = NULL;
                            const char *hss_map_key =
                                ogs_yaml_iter_key(&hss_map_iter);
                            ogs_assert(hss_map_key);
                            if (!strcmp(hss_map_key, "order")) {
                                order_v = ogs_yaml_iter_value(&hss_map_iter);
                            } else if (!strcmp(hss_map_key, "plmn_id")) {
                                ogs_yaml_iter_t plmn_id_iter;

                                ogs_yaml_iter_recurse(&hss_map_iter,
                                        &plmn_id_iter);
                                while (ogs_yaml_iter_next(&plmn_id_iter)) {
                                    const char *plmn_id_key =
                                        ogs_yaml_iter_key(&plmn_id_iter);
                                    ogs_assert(plmn_id_key);
                                    if (!strcmp(plmn_id_key, "host")) {
                                        const char *v = ogs_yaml_iter_value(
                                                &plmn_id_iter);
                                        if (v) host = ogs_strndup(v, OGS_MAX_FQDN_LEN);
                                    } else if (!strcmp(plmn_id_key, "realm")) {
                                        const char *v = ogs_yaml_iter_value(
                                                &plmn_id_iter);
                                        if (v) realm = ogs_strndup(v, OGS_MAX_FQDN_LEN);
                                    } else if (!strcmp(plmn_id_key, "mcc")) {
                                        mcc = ogs_yaml_iter_value(
                                                &plmn_id_iter);
                                    } else if (!strcmp(plmn_id_key, "mnc")) {
                                        mnc = ogs_yaml_iter_value(
                                                &plmn_id_iter);
                                    }
                                }

                                if (mcc && mnc) {
                                    ogs_plmn_id_t plmn_id;
                                    mme_hssmap_t *hssmap = NULL;

                                    ogs_plmn_id_build(&plmn_id,
                                        atoi(mcc), atoi(mnc), strlen(mnc));

                                    hssmap = mme_hssmap_add(&plmn_id, realm, host,
                                            mme_gtpc_entry_selection_order(
                                                    hss_map_entry_idx, order_v));
                                    ogs_assert(hssmap);
                                    hss_map_entry_idx++;
                                }
                            } else
                                ogs_warn("unknown key `%s`",
                                        hss_map_key);
                        }
                    } while (ogs_yaml_iter_type(&hss_map_array) ==
                            YAML_SEQUENCE_NODE);

                    mme_hssmap_resort_by_order();
                } else if (!strcmp(mme_key, "security")) {
                    ogs_yaml_iter_t security_iter;
                    ogs_yaml_iter_recurse(&mme_iter, &security_iter);
                    while (ogs_yaml_iter_next(&security_iter)) {
                        const char *security_key =
                            ogs_yaml_iter_key(&security_iter);
                        ogs_assert(security_key);
                        if (!strcmp(security_key, "integrity_order")) {
                            ogs_yaml_iter_t integrity_order_iter;
                            ogs_yaml_iter_recurse(&security_iter,
                                    &integrity_order_iter);
                            ogs_assert(ogs_yaml_iter_type(
                                        &integrity_order_iter) !=
                                YAML_MAPPING_NODE);

                            do {
                                const char *v = NULL;

                                if (ogs_yaml_iter_type(&integrity_order_iter) ==
                                        YAML_SEQUENCE_NODE) {
                                    if (!ogs_yaml_iter_next(
                                                &integrity_order_iter))
                                        break;
                                }

                                v = ogs_yaml_iter_value(&integrity_order_iter);
                                if (v) {
                                    int integrity_index =
                                        self.num_of_integrity_order;
                                    if (strcmp(v, "EIA0") == 0) {
                                        self.integrity_order[integrity_index] =
                                        OGS_NAS_SECURITY_ALGORITHMS_EIA0;
                                        self.num_of_integrity_order++;
                                    } else if (strcmp(v, "EIA1") == 0) {
                                        self.integrity_order[integrity_index] =
                                        OGS_NAS_SECURITY_ALGORITHMS_128_EIA1;
                                        self.num_of_integrity_order++;
                                    } else if (strcmp(v, "EIA2") == 0) {
                                        self.integrity_order[integrity_index] =
                                        OGS_NAS_SECURITY_ALGORITHMS_128_EIA2;
                                        self.num_of_integrity_order++;
                                    } else if (strcmp(v, "EIA3") == 0) {
                                        self.integrity_order[integrity_index] =
                                        OGS_NAS_SECURITY_ALGORITHMS_128_EIA3;
                                        self.num_of_integrity_order++;
                                    }
                                }
                            } while (
                                ogs_yaml_iter_type(&integrity_order_iter) ==
                                    YAML_SEQUENCE_NODE);
                        } else if (!strcmp(security_key, "ciphering_order")) {
                            ogs_yaml_iter_t ciphering_order_iter;
                            ogs_yaml_iter_recurse(&security_iter,
                                    &ciphering_order_iter);
                            ogs_assert(ogs_yaml_iter_type(
                                &ciphering_order_iter) != YAML_MAPPING_NODE);

                            do {
                                const char *v = NULL;

                                if (ogs_yaml_iter_type(&ciphering_order_iter) ==
                                        YAML_SEQUENCE_NODE) {
                                    if (!ogs_yaml_iter_next(
                                                &ciphering_order_iter))
                                        break;
                                }

                                v = ogs_yaml_iter_value(&ciphering_order_iter);
                                if (v) {
                                    int ciphering_index =
                                        self.num_of_ciphering_order;
                                    if (strcmp(v, "EEA0") == 0) {
                                        self.ciphering_order[ciphering_index] =
                                            OGS_NAS_SECURITY_ALGORITHMS_EEA0;
                                        self.num_of_ciphering_order++;
                                    } else if (strcmp(v, "EEA1") == 0) {
                                        self.ciphering_order[ciphering_index] =
                                        OGS_NAS_SECURITY_ALGORITHMS_128_EEA1;
                                        self.num_of_ciphering_order++;
                                    } else if (strcmp(v, "EEA2") == 0) {
                                        self.ciphering_order[ciphering_index] =
                                        OGS_NAS_SECURITY_ALGORITHMS_128_EEA2;
                                        self.num_of_ciphering_order++;
                                    } else if (strcmp(v, "EEA3") == 0) {
                                        self.ciphering_order[ciphering_index] =
                                        OGS_NAS_SECURITY_ALGORITHMS_128_EEA3;
                                        self.num_of_ciphering_order++;
                                    }
                                }
                            } while (
                                ogs_yaml_iter_type(&ciphering_order_iter) ==
                                    YAML_SEQUENCE_NODE);
                        } else
                            ogs_warn("unknown key `%s`", security_key);
                    }
                } else if (!strcmp(mme_key, "network_name")) {
                    ogs_yaml_iter_t network_name_iter;
                    ogs_yaml_iter_recurse(&mme_iter, &network_name_iter);

                    while (ogs_yaml_iter_next(&network_name_iter)) {
                        const char *network_name_key =
                        ogs_yaml_iter_key(&network_name_iter);
                        ogs_assert(network_name_key);
                        if (!strcmp(network_name_key, "full")) {
                            ogs_nas_network_name_t *network_full_name =
                                &self.full_name;
                            const char *c_network_name =
                                ogs_yaml_iter_value(&network_name_iter);
                            uint8_t size = strlen(c_network_name);
                            uint8_t i;
                            for (i = 0; i < size &&
                                 (((i * 2) + 1) <
                                  (OGS_NAS_MAX_NETWORK_NAME_LEN - 1));
                                 i++) {
                                /* Workaround to convert the ASCII to USC-2 */
                                network_full_name->name[i * 2] = 0;
                                network_full_name->name[i * 2 + 1] =
                                    c_network_name[i];
                            }
                            network_full_name->length = size*2+1;
                            network_full_name->coding_scheme = 1;
                            network_full_name->ext = 1;
                        } else if (!strcmp(network_name_key, "short")) {
                            ogs_nas_network_name_t *network_short_name =
                                &self.short_name;
                            const char *c_network_name =
                                ogs_yaml_iter_value(&network_name_iter);
                            uint8_t size = strlen(c_network_name);
                            uint8_t i;
                            for (i = 0; i < size &&
                                 (((i * 2) + 1) <
                                  (OGS_NAS_MAX_NETWORK_NAME_LEN - 1));
                                 i++) {
                                /* Workaround to convert the ASCII to USC-2 */
                                network_short_name->name[i * 2] = 0;
                                network_short_name->name[i * 2 + 1] =
                                    c_network_name[i];
                            }
                            network_short_name->length = size*2+1;
                            network_short_name->coding_scheme = 1;
                            network_short_name->ext = 1;
                        } else
                            ogs_warn("unknown key `%s`", network_name_key);
                    }
                } else if (!strcmp(mme_key, "sgsap")) {
                    /*
                     * Default per-VLR TAI-LAI mapping cap.
                     *
                     * Each parsed map entry becomes an mme_csmap_t allocated
                     * from mme_csmap_pool (sized by ogs_app()->pool.csmap,
                     * which defaults to global.max.peer — typically thousands
                     * to tens of thousands). So this number is just the
                     * parse-time soft cap; raising it costs nothing at idle
                     * because the parse buffer is heap-allocated below and
                     * freed as soon as the client block finishes.
                     *
                     * Can be overridden in YAML via:
                     *   mme:
                     *     sgsap:
                     *       max_csmap: <N>
                     *       client:
                     *         - address: ...
                     *
                     * The 'max_csmap' key may appear before OR after
                     * 'client:' — a pre-scan below handles either order.
                     */
#define MAX_NUM_OF_CSMAP            8000 /* Default num of TAI-LAI MAP per VLR */
                    int max_csmap = MAX_NUM_OF_CSMAP;
                    {
                        /* Pre-scan sgsap block for 'max_csmap' so YAML
                         * key order does not matter. */
                        ogs_yaml_iter_t prescan_iter;
                        ogs_yaml_iter_recurse(&mme_iter, &prescan_iter);
                        while (ogs_yaml_iter_next(&prescan_iter)) {
                            const char *pk = ogs_yaml_iter_key(&prescan_iter);
                            if (pk && !strcmp(pk, "max_csmap")) {
                                const char *pv =
                                    ogs_yaml_iter_value(&prescan_iter);
                                if (pv) {
                                    int n = atoi(pv);
                                    if (n > 0) max_csmap = n;
                                }
                            }
                        }
                        if (max_csmap < 1) max_csmap = 1;
                        /* Hard ceiling on parse-time buffer
                         * (1,000,000 * 48 B = 48 MB) to keep an
                         * accidentally huge value from OOM'ing init. */
                        if (max_csmap > 1000000) {
                            ogs_warn("sgsap.max_csmap=%d clamped to 1000000",
                                    max_csmap);
                            max_csmap = 1000000;
                        }
                        if (max_csmap != MAX_NUM_OF_CSMAP)
                            ogs_info("sgsap: max_csmap=%d (default %d) "
                                    "TAI-LAI mappings per VLR",
                                    max_csmap, MAX_NUM_OF_CSMAP);
                    }

                    ogs_yaml_iter_t sgsap_iter;
                    ogs_yaml_iter_recurse(&mme_iter, &sgsap_iter);
                    while (ogs_yaml_iter_next(&sgsap_iter)) {
                        const char *sgsap_key = ogs_yaml_iter_key(&sgsap_iter);
                        ogs_assert(sgsap_key);
                        if (!strcmp(sgsap_key, "max_csmap")) {
                            /* Consumed by pre-scan above. */
                            continue;
                        }
                        if (!strcmp(sgsap_key, "client")) {
                            ogs_yaml_iter_t client_iter, client_array;
                            ogs_yaml_iter_recurse(&sgsap_iter, &client_array);
                            do {
                                mme_vlr_t *vlr = NULL;
                                ogs_plmn_id_t plmn_id;
                                /*
                                 * Heap-allocated so 8000+ entries don't
                                 * blow the stack (8000 * 48 B = ~384 KB).
                                 * Freed before the do/while iterates to the
                                 * next client (and on any early return).
                                 */
                                struct csmap_entry_s {
                                    const char *tai_mcc, *tai_mnc;
                                    const char *lai_mcc, *lai_mnc;
                                    const char *tac, *tac_end, *lac;
                                    const char *imsi_prefix;
                                } *map = ogs_calloc(
                                        max_csmap, sizeof(struct csmap_entry_s));
                                if (!map) {
                                    ogs_error("Could not allocate csmap buffer "
                                            "(max_csmap=%d)", max_csmap);
                                    return OGS_ERROR;
                                }
                                int map_num = 0;
                                ogs_sockaddr_t *addr = NULL, *local_addr = NULL;
                                int family = AF_UNSPEC;
                                int i, hostname_num = 0, local_hostname_num = 0;
                                const char *hostname[OGS_MAX_NUM_OF_HOSTNAME],
                                    *local_hostname[OGS_MAX_NUM_OF_HOSTNAME];
                                uint16_t port = self.sgsap_port;

                                ogs_sockopt_t option;
                                bool is_option = false;

                                if (ogs_yaml_iter_type(&client_array) ==
                                        YAML_MAPPING_NODE) {
                                    memcpy(&client_iter, &client_array,
                                            sizeof(ogs_yaml_iter_t));
                                } else if (ogs_yaml_iter_type(&client_array) ==
                                    YAML_SEQUENCE_NODE) {
                                    if (!ogs_yaml_iter_next(&client_array)) {
                                        ogs_free(map);
                                        break;
                                    }
                                    ogs_yaml_iter_recurse(
                                            &client_array, &client_iter);
                                } else if (ogs_yaml_iter_type(&client_array) ==
                                    YAML_SCALAR_NODE) {
                                    ogs_free(map);
                                    break;
                                } else {
                                    ogs_free(map);
                                    ogs_assert_if_reached();
                                }

                                while (ogs_yaml_iter_next(&client_iter)) {
                                    const char *client_key =
                                        ogs_yaml_iter_key(&client_iter);
                                    ogs_assert(client_key);
                                    if (!strcmp(client_key, "family")) {
                                        const char *v =
                                            ogs_yaml_iter_value(&client_iter);
                                        if (v) family = atoi(v);
                                        if (family != AF_UNSPEC &&
                                            family != AF_INET &&
                                            family != AF_INET6) {
                                            ogs_warn("Ignore family(%d) : "
                                                "AF_UNSPEC(%d), "
                                                "AF_INET(%d), AF_INET6(%d) ",
                                                family,
                                                AF_UNSPEC, AF_INET, AF_INET6);
                                            family = AF_UNSPEC;
                                        }
                                    } else if (!strcmp(client_key, "address")) {
                                        ogs_yaml_iter_t hostname_iter;
                                        ogs_yaml_iter_recurse(&client_iter,
                                                &hostname_iter);
                                        ogs_assert(ogs_yaml_iter_type(
                                                    &hostname_iter) !=
                                                YAML_MAPPING_NODE);

                                        do {
                                            if (ogs_yaml_iter_type(
                                                        &hostname_iter) ==
                                                    YAML_SEQUENCE_NODE) {
                                                if (!ogs_yaml_iter_next(
                                                            &hostname_iter))
                                                    break;
                                            }

                                            ogs_assert(hostname_num <
                                                    OGS_MAX_NUM_OF_HOSTNAME);
                                            hostname[hostname_num++] =
                                                ogs_yaml_iter_value(
                                                        &hostname_iter);
                                        } while (ogs_yaml_iter_type(
                                                    &hostname_iter) ==
                                                YAML_SEQUENCE_NODE);
                                    } else if (!strcmp(client_key,
                                                "local_address")) {
                                        ogs_yaml_iter_t local_hostname_iter;
                                        ogs_yaml_iter_recurse(&client_iter,
                                                &local_hostname_iter);
                                        ogs_assert(ogs_yaml_iter_type(
                                                    &local_hostname_iter) !=
                                                YAML_MAPPING_NODE);

                                        do {
                                            if (ogs_yaml_iter_type(
                                                        &local_hostname_iter) ==
                                                    YAML_SEQUENCE_NODE) {
                                                if (!ogs_yaml_iter_next(
                                                        &local_hostname_iter))
                                                    break;
                                            }

                                            ogs_assert(local_hostname_num <
                                                    OGS_MAX_NUM_OF_HOSTNAME);
                                            local_hostname
                                                [local_hostname_num++] =
                                                ogs_yaml_iter_value(
                                                        &local_hostname_iter);
                                        } while (ogs_yaml_iter_type(
                                                    &local_hostname_iter) ==
                                                YAML_SEQUENCE_NODE);
                                    } else if (!strcmp(client_key, "port")) {
                                        const char *v =
                                            ogs_yaml_iter_value(&client_iter);
                                        if (v) {
                                            port = mme_yaml_parse_port(v, port);
                                            self.sgsap_port = port;
                                        }
                                    } else if (!strcmp(client_key, "option")) {
                                        rv = ogs_app_parse_sockopt_config(
                                                &client_iter, &option);
                                        if (rv != OGS_OK) {
                                            ogs_error("ogs_app_parse_sockopt_"
                                                    "config() failed");
                                            ogs_free(map);
                                            return rv;
                                        }
                                        is_option = true;
                                    } else if (!strcmp(client_key, "map")) {
                                        ogs_yaml_iter_t map_iter;
                                        ogs_yaml_iter_recurse(
                                                &client_iter, &map_iter);

                                        map[map_num].tai_mcc = NULL;
                                        map[map_num].tai_mnc = NULL;
                                        map[map_num].tac = NULL;
                                        map[map_num].tac_end = NULL;
                                        map[map_num].lai_mcc = NULL;
                                        map[map_num].lai_mnc = NULL;
                                        map[map_num].lac = NULL;
                                        map[map_num].imsi_prefix = NULL;

                                        while (ogs_yaml_iter_next(&map_iter)) {
                                            const char *map_key =
                                                ogs_yaml_iter_key(&map_iter);
                                            ogs_assert(map_key);
                                            if (!strcmp(map_key, "tai")) {
                                                ogs_yaml_iter_t tai_iter;
                                                ogs_yaml_iter_recurse(&map_iter,
                                                        &tai_iter);

                                                while (ogs_yaml_iter_next(
                                                            &tai_iter)) {
                                                    const char *tai_key =
                                                        ogs_yaml_iter_key(
                                                                &tai_iter);
                                                    ogs_assert(tai_key);

                                                    if (!strcmp(tai_key,
                                                                "plmn_id")) {
                                                        ogs_yaml_iter_t
                                                            plmn_id_iter;
                                                        ogs_yaml_iter_recurse(
                                                                &tai_iter,
                                                                &plmn_id_iter);

                                                        while (
                                                            ogs_yaml_iter_next(
                                                            &plmn_id_iter)) {
                                                            const char
                                                                *plmn_id_key =
                                                            ogs_yaml_iter_key(
                                                                &plmn_id_iter);
                                                            ogs_assert(
                                                                plmn_id_key);

                                                            if (!strcmp(
                                                                    plmn_id_key,
                                                                    "mcc")) {
                                                            map[map_num].
                                                                tai_mcc =
                                                            ogs_yaml_iter_value(
                                                                &plmn_id_iter);
                                                            } else if (!strcmp(
                                                                plmn_id_key,
                                                                "mnc")) {
                                                            map[map_num].
                                                                tai_mnc =
                                                            ogs_yaml_iter_value(
                                                                &plmn_id_iter);
                                                            } else
                                                            ogs_warn(
                                                            "unknown key `%s`",
                                                            plmn_id_key);
                                                        }
                                                    } else if (!strcmp(tai_key,
                                                                "tac")) {
                                                        map[map_num].tac =
                                                            ogs_yaml_iter_value(
                                                                &tai_iter);
                                                    } else if (!strcmp(tai_key,
                                                                "tac_end")) {
                                                        map[map_num].tac_end =
                                                            ogs_yaml_iter_value(
                                                                &tai_iter);
                                                    } else
                                                        ogs_warn(
                                                            "unknown key `%s`",
                                                            tai_key);
                                                }
                                            } else if (!strcmp(map_key,
                                                        "imsi_prefix")) {
                                                map[map_num].imsi_prefix =
                                                    ogs_yaml_iter_value(
                                                            &map_iter);
                                            } else if (!strcmp(map_key,
                                                        "lai")) {
                                                ogs_yaml_iter_t lai_iter;
                                                ogs_yaml_iter_recurse(&map_iter,
                                                        &lai_iter);

                                                while (ogs_yaml_iter_next(
                                                            &lai_iter)) {
                                                    const char *lai_key =
                                                        ogs_yaml_iter_key(
                                                                &lai_iter);
                                                    ogs_assert(lai_key);

                                                    if (!strcmp(lai_key,
                                                                "plmn_id")) {
                                                        ogs_yaml_iter_t
                                                            plmn_id_iter;
                                                        ogs_yaml_iter_recurse(
                                                                &lai_iter,
                                                                &plmn_id_iter);

                                                        while (
                                                            ogs_yaml_iter_next(
                                                            &plmn_id_iter)) {
                                                            const char
                                                                *plmn_id_key =
                                                            ogs_yaml_iter_key(
                                                                &plmn_id_iter);
                                                            ogs_assert(
                                                                plmn_id_key);

                                                            if (!strcmp(
                                                                plmn_id_key,
                                                                "mcc")) {
                                                            map[map_num].
                                                                lai_mcc =
                                                            ogs_yaml_iter_value(
                                                                &plmn_id_iter);
                                                            } else if (!strcmp(
                                                                plmn_id_key,
                                                                "mnc")) {
                                                            map[map_num].
                                                                lai_mnc =
                                                            ogs_yaml_iter_value(
                                                                &plmn_id_iter);
                                                            } else
                                                            ogs_warn(
                                                            "unknown key `%s`",
                                                            plmn_id_key);
                                                        }
                                                    } else if (!strcmp(lai_key,
                                                                "lac")) {
                                                        map[map_num].lac =
                                                            ogs_yaml_iter_value(
                                                                    &lai_iter);
                                                    } else
                                                        ogs_warn(
                                                            "unknown key `%s`",
                                                            lai_key);
                                                }
                                            } else
                                                ogs_warn("unknown key `%s`",
                                                        map_key);
                                        }

                                        if (!map[map_num].tai_mcc) {
                                            ogs_error("No map.tai.plmn_id.mcc "
                                                    "in configuration file");
                                            ogs_free(map);
                                            return OGS_ERROR;
                                        }
                                        if (!map[map_num].tai_mnc) {
                                            ogs_error("No map.tai.plmn_id.mnc "
                                                    "in configuration file");
                                            ogs_free(map);
                                            return OGS_ERROR;
                                        }
                                        if (!map[map_num].tac) {
                                            ogs_error("No map.tai.tac "
                                                    "in configuration file");
                                            ogs_free(map);
                                            return OGS_ERROR;
                                        }
                                        if (!map[map_num].lai_mcc) {
                                            ogs_error("No map.lai.plmn_id.mcc "
                                                    "in configuration file");
                                            ogs_free(map);
                                            return OGS_ERROR;
                                        }
                                        if (!map[map_num].lai_mnc) {
                                            ogs_error("No map.lai.plmn_id.mnc "
                                                    "in configuration file");
                                            ogs_free(map);
                                            return OGS_ERROR;
                                        }
                                        if (!map[map_num].lac) {
                                            ogs_error("No map.lai.lac "
                                                    "in configuration file");
                                            ogs_free(map);
                                            return OGS_ERROR;
                                        }

                                        map_num++;
                                        if (map_num >= max_csmap) {
                                            ogs_error("Too many TAI-LAI "
                                                    "mappings for one VLR "
                                                    "(reached cap %d). "
                                                    "Increase "
                                                    "mme.sgsap.max_csmap.",
                                                    max_csmap);
                                            ogs_free(map);
                                            return OGS_ERROR;
                                        }

                                    } else if (!strcmp(client_key, "tai")) {
                                        ogs_error(
                                            "tai/lai configuraton changed to "
                                            "map.tai/map.lai");
                                        ogs_log_print(OGS_LOG_ERROR,
                                            "sgsap:\n"
                                            "  client\n"
                                            "    address: 127.0.0.2\n"
                                            "    map:\n"
                                            "      tai:\n"
                                            "        plmn_id:\n"
                                            "          mcc: 001\n"
                                            "          mnc: 01\n"
                                            "        tac: 4131\n"
                                            "      lai:\n"
                                            "        plmn_id:\n"
                                            "          mcc: 001\n"
                                            "          mnc: 01\n"
                                            "        lac: 43691\n");
                                        ogs_free(map);
                                        return OGS_ERROR;
                                    } else if (!strcmp(client_key, "lai")) {
                                        ogs_error(
                                            "tai/lai configuraton changed to "
                                            "map.tai/map.lai");
                                        ogs_log_print(OGS_LOG_ERROR,
                                            "sgsap:\n"
                                            "  client\n"
                                            "    address: 127.0.0.2\n"
                                            "    map:\n"
                                            "      tai:\n"
                                            "        plmn_id:\n"
                                            "          mcc: 001\n"
                                            "          mnc: 01\n"
                                            "        tac: 4131\n"
                                            "      lai:\n"
                                            "        plmn_id:\n"
                                            "          mcc: 001\n"
                                            "          mnc: 01\n"
                                            "        lac: 43691\n");
                                        ogs_free(map);
                                        return OGS_ERROR;
                                    } else
                                        ogs_warn("unknown key `%s`",
                                                client_key);

                                }

                                if (map_num == 0) {
                                    ogs_error("No TAI-LAI Map");
                                    ogs_free(map);
                                    return OGS_ERROR;
                                }

                                addr = NULL;
                                for (i = 0; i < hostname_num; i++) {
                                    rv = ogs_addaddrinfo(&addr,
                                            family, hostname[i], port, 0);
                                    ogs_assert(rv == OGS_OK);
                                }

                                ogs_filter_ip_version(&addr,
                                        ogs_global_conf()->parameter.no_ipv4,
                                        ogs_global_conf()->parameter.no_ipv6,
                                        ogs_global_conf()->parameter.
                                        prefer_ipv4);

                                if (addr == NULL) {
                                    ogs_free(map);
                                    continue;
                                }

                                local_addr = NULL;
                                for (i = 0; i < local_hostname_num; i++) {
                                    rv = ogs_addaddrinfo(&local_addr,
                                            family, local_hostname[i], port, 0);
                                    ogs_assert(rv == OGS_OK);
                                }

                                ogs_filter_ip_version(&local_addr,
                                        ogs_global_conf()->parameter.no_ipv4,
                                        ogs_global_conf()->parameter.no_ipv6,
                                        ogs_global_conf()->parameter.
                                        prefer_ipv4);

                                vlr = mme_vlr_add(addr, local_addr,
                                        is_option ? &option : NULL);
                                ogs_assert(vlr);

                                for (i = 0; i < map_num; i++) {
                                    mme_csmap_t *csmap = mme_csmap_add(vlr);
                                    ogs_assert(csmap);

                                    ogs_plmn_id_build(&plmn_id,
                                            atoi(map[i].tai_mcc),
                                            atoi(map[i].tai_mnc),
                                            strlen(map[i].tai_mnc));
                                    ogs_nas_from_plmn_id(
                                            &csmap->tai.nas_plmn_id, &plmn_id);
                                    csmap->tai.tac = atoi(map[i].tac);
                                    csmap->tac_end = 0;
                                    if (map[i].tac_end)
                                        csmap->tac_end = atoi(map[i].tac_end);
                                    ogs_plmn_id_build(&plmn_id,
                                            atoi(map[i].lai_mcc),
                                            atoi(map[i].lai_mnc),
                                            strlen(map[i].lai_mnc));
                                    ogs_nas_from_plmn_id(
                                            &csmap->lai.nas_plmn_id, &plmn_id);
                                    csmap->lai.lac = atoi(map[i].lac);
                                    csmap->imsi_prefix[0] = '\0';
                                    if (map[i].imsi_prefix) {
                                        ogs_cpystrn(csmap->imsi_prefix,
                                                map[i].imsi_prefix,
                                                sizeof(csmap->imsi_prefix));
                                    }
                                    mme_csmap_plmn_attach(csmap);
                                }

                                /* Release per-client parse buffer; the
                                 * permanent storage now lives in
                                 * mme_csmap_pool entries attached to the
                                 * VLR's csmap_list. */
                                ogs_free(map);
                            } while (ogs_yaml_iter_type(&client_array) ==
                                    YAML_SEQUENCE_NODE);
                        } else
                            ogs_warn("unknown key `%s`", sgsap_key);
                    }
                } else if (!strcmp(mme_key, "mme_name")) {
                    self.mme_name = ogs_yaml_iter_value(&mme_iter);
                } else if (!strcmp(mme_key, "time")) {
                    ogs_yaml_iter_t time_iter;
                    ogs_yaml_iter_recurse(&mme_iter, &time_iter);
                    while (ogs_yaml_iter_next(&time_iter)) {
                        const char *time_key = ogs_yaml_iter_key(&time_iter);
                        ogs_assert(time_key);
                        if (!strcmp(time_key, "t3402")) {
                            ogs_yaml_iter_t t3402_iter;
                            ogs_yaml_iter_recurse(&time_iter, &t3402_iter);

                            while (ogs_yaml_iter_next(&t3402_iter)) {
                                const char *t3402_key =
                                    ogs_yaml_iter_key(&t3402_iter);
                                ogs_assert(t3402_key);

                                if (!strcmp(t3402_key, "value")) {
                                    const char *v = ogs_yaml_iter_value(&t3402_iter);
                                    if (v)
                                        self.time.t3402.value = atoll(v);
                                } else
                                    ogs_warn("unknown key `%s`", t3402_key);
                            }
                        } else if (!strcmp(time_key, "t3396")) {
                            ogs_yaml_iter_t t3396_iter;
                            ogs_yaml_iter_recurse(&time_iter, &t3396_iter);

                            while (ogs_yaml_iter_next(&t3396_iter)) {
                                const char *t3396_key =
                                    ogs_yaml_iter_key(&t3396_iter);
                                ogs_assert(t3396_key);

                                if (!strcmp(t3396_key, "value")) {
                                    const char *v = ogs_yaml_iter_value(&t3396_iter);
                                    if (v)
                                        self.time.t3396.value = atoll(v);
                                } else
                                    ogs_warn("unknown key `%s`", t3396_key);
                            }
                        } else if (!strcmp(time_key, "t3412")) {
                            ogs_yaml_iter_t t3412_iter;
                            ogs_yaml_iter_recurse(&time_iter, &t3412_iter);

                            while (ogs_yaml_iter_next(&t3412_iter)) {
                                const char *t3412_key =
                                    ogs_yaml_iter_key(&t3412_iter);
                                ogs_assert(t3412_key);

                                if (!strcmp(t3412_key, "value")) {
                                    const char *v = ogs_yaml_iter_value(&t3412_iter);
                                    if (v)
                                        self.time.t3412.value = atoll(v);
                                } else
                                    ogs_warn("unknown key `%s`", t3412_key);
                            }
                        } else if (!strcmp(time_key, "t3423")) {
                            ogs_yaml_iter_t t3423_iter;
                            ogs_yaml_iter_recurse(&time_iter, &t3423_iter);

                            while (ogs_yaml_iter_next(&t3423_iter)) {
                                const char *t3423_key =
                                    ogs_yaml_iter_key(&t3423_iter);
                                ogs_assert(t3423_key);

                                if (!strcmp(t3423_key, "value")) {
                                    const char *v = ogs_yaml_iter_value(&t3423_iter);
                                    if (v)
                                        self.time.t3423.value = atoll(v);
                                } else
                                    ogs_warn("unknown key `%s`", t3423_key);
                            }
                        } else if (!strcmp(time_key, "idle")) {
                            ogs_yaml_iter_t idle_iter;
                            ogs_yaml_iter_recurse(&time_iter, &idle_iter);

                            while (ogs_yaml_iter_next(&idle_iter)) {
                                const char *idle_key =
                                    ogs_yaml_iter_key(&idle_iter);
                                ogs_assert(idle_key);

                                if (!strcmp(idle_key,
                                            "mobile_reachable_margin")) {
                                    const char *v =
                                        ogs_yaml_iter_value(&idle_iter);
                                    if (v)
                                        self.time.idle.mobile_reachable_margin =
                                            atoll(v);
                                } else if (!strcmp(idle_key,
                                            "implicit_detach_margin")) {
                                    const char *v =
                                        ogs_yaml_iter_value(&idle_iter);
                                    if (v)
                                        self.time.idle.implicit_detach_margin =
                                            atoll(v);
                                } else
                                    ogs_warn("unknown key `%s`", idle_key);
                            }
                        } else if (!strcmp(time_key, "t3346")) {
                            ogs_yaml_iter_t t3346_iter;
                            ogs_yaml_iter_recurse(&time_iter, &t3346_iter);

                            while (ogs_yaml_iter_next(&t3346_iter)) {
                                const char *t3346_key =
                                    ogs_yaml_iter_key(&t3346_iter);
                                ogs_assert(t3346_key);

                                if (!strcmp(t3346_key, "value")) {
                                    const char *v =
                                        ogs_yaml_iter_value(&t3346_iter);
                                    if (v)
                                        self.time.t3346.value = atoll(v);
                                } else if (!strcmp(t3346_key,
                                            "include_any_reject")) {
                                    self.time.t3346.include_any_reject =
                                        ogs_yaml_iter_bool(&t3346_iter);
                                } else
                                    ogs_warn("unknown key `%s`", t3346_key);
                            }
                        } else if (!strcmp(time_key, "t3413")) {
                            mme_timer_parse_yaml(&time_iter, MME_TIMER_T3413);
                        } else if (!strcmp(time_key, "t3422")) {
                            mme_timer_parse_yaml(&time_iter, MME_TIMER_T3422);
                        } else if (!strcmp(time_key, "t3450")) {
                            mme_timer_parse_yaml(&time_iter, MME_TIMER_T3450);
                        } else if (!strcmp(time_key, "bearer_setup") ||
                                !strcmp(time_key, "sae_bearer_setup")) {
                            mme_bearer_setup_time_parse_yaml(&time_iter);
                        } else if (!strcmp(time_key, "t3460")) {
                            mme_timer_parse_yaml(&time_iter, MME_TIMER_T3460);
                        } else if (!strcmp(time_key, "t3470")) {
                            mme_timer_parse_yaml(&time_iter, MME_TIMER_T3470);
                        } else if (!strcmp(time_key, "t3489")) {
                            mme_timer_parse_yaml(&time_iter, MME_TIMER_T3489);
                        } else if (!strcmp(time_key, "t3495") ||
                                !strcmp(time_key, "nas_deactivate_bearer")) {
                            mme_timer_parse_yaml(&time_iter,
                                    MME_TIMER_NAS_DEACTIVATE_BEARER);
                        } else if (!strcmp(time_key, "sgs_ts6_1") ||
                                !strcmp(time_key, "ts6_1")) {
                            mme_timer_parse_yaml(&time_iter,
                                    MME_TIMER_SGS_TS6_1);
                        } else if (!strcmp(time_key, "s6a") ||
                                !strcmp(time_key, "s6a_timeout")) {
                            mme_timer_parse_yaml(&time_iter, MME_TIMER_S6A);
                        } else if (!strcmp(time_key, "t3512")) {
                            /* handle config in amf */
                        } else if (!strcmp(time_key, "nf_instance")) {
                            /* handle config in app library */
                        } else if (!strcmp(time_key, "subscription")) {
                            /* handle config in app library */
                        } else if (!strcmp(time_key, "message")) {
                            /* handle config in app library */
                        } else if (!strcmp(time_key, "handover")) {
                            /* handle config in app library */
                        } else
                            ogs_warn("unknown key `%s`", time_key);
                    }
                } else if (!strcmp(mme_key, "metrics")) {
                    /* handle config in metrics library */
                } else if (!strcmp(mme_key, "emergency")) {
                    ogs_yaml_iter_t emerg_iter;
                    ogs_yaml_iter_recurse(&mme_iter, &emerg_iter);
                    while (ogs_yaml_iter_next(&emerg_iter)) {
                        const char *emerg_key = ogs_yaml_iter_key(&emerg_iter);
                        ogs_assert(emerg_key);
                        if (!strcmp(emerg_key, "dnn")) {
                                const char *dnn = ogs_yaml_iter_value(&emerg_iter);
                                ogs_assert(dnn);
                                self.emergency.dnn = dnn;
                        } else if (!strcmp(emerg_key, "number")) {
                            ogs_yaml_iter_t number_array, number_iter;
                            ogs_yaml_iter_recurse(&emerg_iter, &number_array);
                            do {
                                const char *digits = NULL;
                                uint8_t categories = 0;

                                if (ogs_yaml_iter_type(&number_array) ==
                                        YAML_MAPPING_NODE) {
                                    memcpy(&number_iter, &number_array,
                                            sizeof(ogs_yaml_iter_t));
                                } else if (ogs_yaml_iter_type(&number_array) ==
                                        YAML_SEQUENCE_NODE) {
                                    if (!ogs_yaml_iter_next(&number_array))
                                        break;
                                    ogs_yaml_iter_recurse(&number_array, &number_iter);
                                } else if (ogs_yaml_iter_type(&number_array) ==
                                        YAML_SCALAR_NODE) {
                                    break;
                                } else
                                    ogs_assert_if_reached();

                                while (ogs_yaml_iter_next(&number_iter)) {
                                    const char *number_key =
                                        ogs_yaml_iter_key(&number_iter);
                                    ogs_assert(number_key);
                                    if (!strcmp(number_key, "digits")) {
                                        digits = ogs_yaml_iter_value(&number_iter);
                                    } else if (!strcmp(number_key, "categories")) {
                                        ogs_yaml_iter_t categories_iter;
                                        ogs_yaml_iter_recurse(&number_iter,
                                                &categories_iter);
                                        ogs_assert(ogs_yaml_iter_type(
                                                &categories_iter) != YAML_MAPPING_NODE);

                                        do {
                                            const char *v = NULL;

                                            if (ogs_yaml_iter_type(&categories_iter) ==
                                                    YAML_SEQUENCE_NODE) {
                                                if (!ogs_yaml_iter_next(
                                                            &categories_iter))
                                                    break;
                                            }

                                            v = ogs_yaml_iter_value(&categories_iter);
                                            if (v) {
                                                if (strstr(v, "police")) {
                                                    categories |=
                                                        OGS_NAS_SERVICE_CATEGORY_POLICE;
                                                } else if (strstr(v, "ambulance")) {
                                                    categories |=
                                                        OGS_NAS_SERVICE_CATEGORY_AMBULANCE;
                                                } else if (strstr(v, "fire")) {
                                                    categories |=
                                                        OGS_NAS_SERVICE_CATEGORY_FIRE_BRIGADE;
                                                } else if (strstr(v, "marine")) {
                                                    categories |=
                                                        OGS_NAS_SERVICE_CATEGORY_MARINE_GUARD;
                                                } else if (strstr(v, "mountain")) {
                                                    categories |=
                                                        OGS_NAS_SERVICE_CATEGORY_MOUNTAIN_RESCUE;
                                                } else {
                                                    categories = strtol(v, NULL, 0);
                                                    if (categories < 1 || categories > 0x1f)
                                                        ogs_warn("invalid categories `%s`", v);
                                                }
                                            }
                                        } while (
                                            ogs_yaml_iter_type(&categories_iter) ==
                                                YAML_SEQUENCE_NODE);
                                    } else
                                        ogs_warn("unknown key `%s`", number_key);
                                }
                                if (digits && categories > 0 && categories <= 0x1f)
                                    mme_emerg_add(categories, digits);
                            } while (ogs_yaml_iter_type(&number_array) ==
                                YAML_SEQUENCE_NODE);
                        } else
                            ogs_warn("unknown key `%s`", emerg_key);
                    }
                } else if (!strcmp(mme_key, "require_hss_map")) {
                    self.require_hss_map_explicit = true;
                    self.require_hss_map = ogs_yaml_iter_bool(&mme_iter);
                } else if (!strcmp(mme_key, "imsi_acl")) {
                    ogs_yaml_iter_t acl_array, acl_iter;

                    self.num_of_imsi_acl = 0;
                    ogs_yaml_iter_recurse(&mme_iter, &acl_array);
                    do {
                        if (ogs_yaml_iter_type(&acl_array) ==
                                YAML_MAPPING_NODE) {
                            break;
                        } else if (ogs_yaml_iter_type(&acl_array) ==
                                YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&acl_array))
                                break;
                            ogs_yaml_iter_recurse(&acl_array, &acl_iter);
                        } else if (ogs_yaml_iter_type(&acl_array) ==
                                YAML_SCALAR_NODE) {
                            ogs_yaml_iter_recurse(&mme_iter, &acl_iter);
                        } else
                            ogs_assert_if_reached();

                        while (ogs_yaml_iter_next(&acl_iter)) {
                            const char *v = ogs_yaml_iter_value(&acl_iter);

                            if (!v || !v[0])
                                continue;
                            if (self.num_of_imsi_acl >= MME_MAX_IMSI_ACL) {
                                ogs_warn("imsi_acl: list full (max %d)",
                                        MME_MAX_IMSI_ACL);
                                break;
                            }
                            ogs_cpystrn(self.imsi_acl[self.num_of_imsi_acl].prefix,
                                    v, OGS_MAX_IMSI_BCD_LEN + 1);
                            self.num_of_imsi_acl++;
                        }
                    } while (ogs_yaml_iter_type(&acl_array) ==
                            YAML_SEQUENCE_NODE &&
                            ogs_yaml_iter_next(&acl_array));

                    ogs_info("imsi_acl: %d prefix(es) loaded",
                            self.num_of_imsi_acl);
                } else if (!strcmp(mme_key, "trace_imsi")) {
                    ogs_yaml_iter_t trace_array, trace_iter;

                    ogs_trace_filter_clear();
                    ogs_yaml_iter_recurse(&mme_iter, &trace_array);
                    do {
                        if (ogs_yaml_iter_type(&trace_array) ==
                                YAML_MAPPING_NODE) {
                            break;
                        } else if (ogs_yaml_iter_type(&trace_array) ==
                                YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&trace_array))
                                break;
                            ogs_yaml_iter_recurse(&trace_array, &trace_iter);
                        } else if (ogs_yaml_iter_type(&trace_array) ==
                                YAML_SCALAR_NODE) {
                            ogs_yaml_iter_recurse(&mme_iter, &trace_iter);
                        } else
                            ogs_assert_if_reached();

                        while (ogs_yaml_iter_next(&trace_iter)) {
                            const char *v = ogs_yaml_iter_value(&trace_iter);

                            if (v && ogs_trace_filter_add(v) != OGS_OK)
                                ogs_warn("trace_imsi: could not add `%s'", v);
                        }
                    } while (ogs_yaml_iter_type(&trace_array) ==
                            YAML_SEQUENCE_NODE &&
                            ogs_yaml_iter_next(&trace_array));

                    ogs_info("trace_imsi: %d prefix(es) loaded",
                            ogs_trace_filter_count());
                } else
                    ogs_warn("unknown key `%s`", mme_key);
            }
        }
    }

    rv = mme_context_validation();
    if (rv != OGS_OK) return rv;

    {
        int loaded = mme_load_recovery_counter(self.recovery_counter_file);
        bool persisted;

        if (loaded < 0) {
            /*
             * No persisted counter (file missing or unreadable). Seed from the
             * wall clock so the advertised Recovery value still differs across
             * restarts; otherwise peers could never detect an MME restart.
             */
            self.gtpc_recovery =
                (uint8_t)ogs_time_to_sec(ogs_time_now());
        } else {
            self.gtpc_recovery = (uint8_t)loaded;
        }
        self.gtpc_recovery++;
        if (self.gtpc_recovery == 0)
            self.gtpc_recovery = 1;

        persisted = mme_save_recovery_counter(
                self.recovery_counter_file, self.gtpc_recovery);
        ogs_info("MME GTP-C recovery counter: %u (file: %s, %s)",
                 self.gtpc_recovery, self.recovery_counter_file,
                 persisted ? "persisted" :
                    (loaded < 0 ? "NOT persisted - time-seeded" :
                                  "NOT persisted"));
    }

    ogs_reload_audit_record_startup("MME");

    return OGS_OK;
}

mme_sgsn_t *mme_sgsn_add(ogs_sockaddr_t *addr)
{
    mme_sgsn_t *sgsn = NULL;

    ogs_assert(addr);

    ogs_pool_alloc(&mme_sgsn_pool, &sgsn);
    ogs_assert(sgsn);
    memset(sgsn, 0, sizeof *sgsn);

    sgsn->gnode.sa_list = addr;

    ogs_list_init(&sgsn->gnode.local_list);
    ogs_list_init(&sgsn->gnode.remote_list);

    ogs_list_init(&sgsn->route_list);
    //ogs_list_init(&sgsn->sgsn_ue_list);

    ogs_list_add(&self.sgsn_list, sgsn);

    return sgsn;
}

void mme_sgsn_remove(mme_sgsn_t *sgsn)
{
    mme_sgsn_route_t *rt = NULL, *next_rt = NULL;
    ogs_assert(sgsn);

    ogs_list_remove(&self.sgsn_list, sgsn);

    ogs_gtp_xact_delete_all(&sgsn->gnode);
    ogs_freeaddrinfo(sgsn->gnode.sa_list);

     /* Free routes in list */
    ogs_list_for_each_safe(&sgsn->route_list, next_rt, rt) {
        ogs_list_remove(&sgsn->route_list, rt);
        ogs_pool_free(&mme_sgsn_route_pool, rt);
    }

    ogs_pool_free(&mme_sgsn_pool, sgsn);
}

void mme_sgsn_remove_all(void)
{
    mme_sgsn_t *sgsn = NULL, *next_sgsn = NULL;

    ogs_list_for_each_safe(&self.sgsn_list, next_sgsn, sgsn)
        mme_sgsn_remove(sgsn);
}

mme_sgsn_t *mme_sgsn_find_by_addr(const ogs_sockaddr_t *addr)
{
    mme_sgsn_t *sgsn = NULL;

    ogs_assert(addr);

    ogs_list_for_each(&self.sgsn_list, sgsn) {
        if (ogs_sockaddr_is_equal(&sgsn->gnode.addr, addr) == true)
            break;
    }

    return sgsn;
}

/* Find SGSN holding route provided in params. Return SGSN configured as default
 * routing if no matching route found. */
mme_sgsn_t *mme_sgsn_find_by_routing_address(const ogs_nas_rai_t *rai, uint16_t cell_id)
{
    mme_sgsn_t *sgsn = NULL;
    ogs_list_for_each(&self.sgsn_list, sgsn) {
        mme_sgsn_route_t *rt = NULL;
        ogs_list_for_each(&sgsn->route_list, rt) {
            if (rt->cell_id == cell_id &&
                memcmp(&rt->rai, rai, sizeof(ogs_nas_rai_t)) == 0)
                return sgsn;
        }
    }

    /* If no exact match found, try using any with same RAI: */
    ogs_list_for_each(&self.sgsn_list, sgsn) {
        mme_sgsn_route_t *rt = NULL;
        ogs_list_for_each(&sgsn->route_list, rt) {
            if (memcmp(&rt->rai, rai, sizeof(ogs_nas_rai_t)) == 0)
                return sgsn;
        }
    }

    /* No route found, return default route if available: */
    return mme_sgsn_find_by_default_routing_address();
}

/* Return SGSN configured as default routing */
mme_sgsn_t *mme_sgsn_find_by_default_routing_address(void)
{
    mme_sgsn_t *sgsn = NULL;
    ogs_list_for_each(&self.sgsn_list, sgsn) {
        if (sgsn->default_route)
            return sgsn;
    }
    return NULL;
}

mme_sgw_t *mme_sgw_add(ogs_sockaddr_t *addr)
{
    mme_sgw_t *sgw = NULL;

    ogs_assert(addr);

    ogs_pool_alloc(&mme_sgw_pool, &sgw);
    ogs_assert(sgw);
    memset(sgw, 0, sizeof *sgw);

    sgw->tac = ogs_calloc(ogs_global_conf()->max.tai, sizeof(uint16_t));
    ogs_assert(sgw->tac);

    sgw->gnode.sa_list = addr;

    ogs_list_init(&sgw->gnode.local_list);
    ogs_list_init(&sgw->gnode.remote_list);

    ogs_list_init(&sgw->sgw_ue_list);

    sgw->t_echo = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_sgw_echo, sgw);
    if (!sgw->t_echo) {
        ogs_error("ogs_timer_add() failed for SGW echo");
        ogs_free(sgw->tac);
        ogs_pool_free(&mme_sgw_pool, sgw);
        return NULL;
    }

    ogs_list_add(&self.sgw_list, sgw);

    return sgw;
}

void mme_sgw_remove(mme_sgw_t *sgw)
{
    ogs_assert(sgw);

    ogs_list_remove(&self.sgw_list, sgw);

    if (sgw->t_echo) {
        ogs_timer_delete(sgw->t_echo);
        sgw->t_echo = NULL;
    }

    ogs_gtp_xact_delete_all(&sgw->gnode);
    ogs_freeaddrinfo(sgw->gnode.sa_list);

    ogs_free(sgw->tac);

    ogs_pool_free(&mme_sgw_pool, sgw);
}

void mme_sgw_remove_all(void)
{
    mme_sgw_t *sgw = NULL, *next_sgw = NULL;

    ogs_list_for_each_safe(&self.sgw_list, next_sgw, sgw)
        mme_sgw_remove(sgw);
}

bool mme_sgw_in_use(const mme_sgw_t *sgw)
{
    int i;
    sgw_ue_t *sgw_ue = NULL;

    ogs_assert(sgw);

    for (i = 0; i < sgw_ue_pool.size; i++) {
        sgw_ue = sgw_ue_pool.index[i];
        if (sgw_ue && sgw_ue->sgw == sgw)
            return true;
    }

    return false;
}

mme_sgw_t *mme_sgw_find_by_addr(const ogs_sockaddr_t *addr)
{
    mme_sgw_t *sgw = NULL;

    ogs_assert(addr);

    ogs_list_for_each(&self.sgw_list, sgw) {
        if (ogs_sockaddr_is_equal(&sgw->gnode.addr, addr) == true)
            return sgw;
    }

    /*
     * SGWC inbound roam may reply from inbound_roam.gtpc.source_port (not
     * gtpc.server.port). Match configured SGW by IP as well.
     */
    ogs_list_for_each(&self.sgw_list, sgw) {
        if (sgw->gnode.sa_list &&
                ogs_sockaddr_check_any_match(
                    sgw->gnode.sa_list, NULL, addr, false) == true)
            return sgw;
    }

    return NULL;
}

static bool mme_sgw_recovery_is_restart(uint8_t stored, uint8_t received)
{
    /*
     * 3GPP TS 23.007: the Restart Counter is an 8-bit serial number. A peer
     * restart is indicated ONLY when the received value is STRICTLY NEWER than
     * the stored one in mod-256 serial-number arithmetic (RFC 1982): the
     * forward distance (received - stored) lies in 1..127. The previous check
     * (naive "received > stored") flagged a restart in BOTH directions, so two
     * interleaved values would each look like a restart and purge on every
     * message.
     */
    if (received == stored)
        return false;
    return (uint8_t)(received - stored) < 128;
}

static void mme_sgw_purge_sessions(mme_sgw_t *sgw)
{
    sgw_ue_t *sgw_ue = NULL, *next = NULL;
    mme_ue_t *mme_ue = NULL;
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(sgw);

    ogs_warn("SGW [%s]:%d recovery restart: purging MME sessions",
            OGS_ADDR(&sgw->gnode.addr, buf), OGS_PORT(&sgw->gnode.addr));

    /*
     * The SGW lost all of its bearer state on restart. Any S11 transaction
     * still outstanding toward it (Delete Session, Modify Bearer, ...) will
     * never get a meaningful reply, so drop them up front rather than letting
     * them time out against a context that no longer exists.
     */
    ogs_gtp_xact_delete_all(&sgw->gnode);

    ogs_list_for_each_safe(&sgw->sgw_ue_list, next, sgw_ue) {
        mme_ue = mme_ue_find_by_id(sgw_ue->mme_ue_id);
        if (!mme_ue) {
            ogs_warn("Orphan sgw_ue without mme_ue: remove");
            sgw_ue_remove(sgw_ue);
            continue;
        }

        if (mme_ue->sgw_ue_id != sgw_ue->id)
            continue;

        /*
         * Per 3GPP TS 23.007, on detecting an S-GW restart the MME deletes the
         * affected bearer contexts. Do NOT signal the restarted SGW: sending
         * Delete Session toward it is pointless (it has no context) and used to
         * leave these UEs stuck when the new SGW answered Context Not Found,
         * which is exactly why stale MME UE contexts remained after an SGW-C
         * restart. Tear the UE down locally instead -- this releases the S1
         * context toward the eNB and frees the EPS bearer / sgw_ue / mme_ue
         * contexts without any S11 signalling.
         */
        ogs_warn("[%s] SGW recovery restart: local UE context release",
                mme_ue->imsi_bcd);
        mme_ue_enter_ue_context_will_remove(mme_ue);
    }
}

bool mme_sgw_recovery_update(mme_sgw_t *sgw, uint8_t recovery)
{
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(sgw);

    if (!sgw->peer_recovery_valid) {
        sgw->peer_recovery = recovery;
        sgw->peer_recovery_valid = true;
        ogs_info("SGW [%s]:%d recovery=%u (initial)",
                OGS_ADDR(&sgw->gnode.addr, buf), OGS_PORT(&sgw->gnode.addr),
                recovery);
        return false;
    }

    /* Unchanged: the common case -- keep the stored value, do nothing. */
    if (recovery == sgw->peer_recovery)
        return false;

    if (!mme_sgw_recovery_is_restart(sgw->peer_recovery, recovery)) {
        /*
         * Older / out-of-order value (reordered datagram or a stray Recovery).
         * Do NOT advance the baseline and do NOT purge -- advancing it here is
         * what let the counter ping-pong and purge repeatedly.
         */
        ogs_warn("SGW [%s]:%d ignoring non-newer recovery %u (stored %u)",
                OGS_ADDR(&sgw->gnode.addr, buf), OGS_PORT(&sgw->gnode.addr),
                recovery, sgw->peer_recovery);
        return false;
    }

    ogs_warn("SGW [%s]:%d recovery changed %u -> %u (restart)",
            OGS_ADDR(&sgw->gnode.addr, buf), OGS_PORT(&sgw->gnode.addr),
            sgw->peer_recovery, recovery);
    sgw->peer_recovery = recovery;
    mme_sgw_purge_sessions(sgw);
    return true;
}

void mme_sgw_echo_schedule(mme_sgw_t *sgw)
{
    ogs_time_t interval;

    ogs_assert(sgw);
    ogs_assert(sgw->t_echo);

    interval = mme_self()->gtpc_echo_interval ?
        ogs_time_from_sec(mme_self()->gtpc_echo_interval) :
        ogs_time_from_sec(60);

    ogs_timer_start(sgw->t_echo, interval);
}

void mme_sgw_echo_reschedule_all(void)
{
    mme_sgw_t *sgw = NULL;

    ogs_list_for_each(&self.sgw_list, sgw)
        mme_sgw_echo_schedule(sgw);
}

/*
 * Parse mme.time subtree.  Caller must pass an iterator recursed into the
 * `time:` mapping (see ogs_yaml_iter_recurse); passing the parent `mme:`
 * iterator would advance through every remaining mme key and skip reload.
 */
static void mme_time_config_parse(ogs_yaml_iter_t *time_iter)
{
    ogs_yaml_iter_t t3402_iter, t3396_iter, t3412_iter, t3423_iter;
    ogs_yaml_iter_t idle_iter, t3346_iter;

    ogs_assert(time_iter);

    while (ogs_yaml_iter_next(time_iter)) {
        const char *time_key = ogs_yaml_iter_key(time_iter);
        ogs_assert(time_key);
        if (!strcmp(time_key, "t3402")) {
            ogs_yaml_iter_recurse(time_iter, &t3402_iter);
            while (ogs_yaml_iter_next(&t3402_iter)) {
                const char *key = ogs_yaml_iter_key(&t3402_iter);
                ogs_assert(key);
                if (!strcmp(key, "value")) {
                    const char *v = ogs_yaml_iter_value(&t3402_iter);
                    if (v)
                        self.time.t3402.value = atoll(v);
                } else
                    ogs_warn("unknown key `%s`", key);
            }
        } else if (!strcmp(time_key, "t3396")) {
            ogs_yaml_iter_recurse(time_iter, &t3396_iter);
            while (ogs_yaml_iter_next(&t3396_iter)) {
                const char *key = ogs_yaml_iter_key(&t3396_iter);
                ogs_assert(key);
                if (!strcmp(key, "value")) {
                    const char *v = ogs_yaml_iter_value(&t3396_iter);
                    if (v)
                        self.time.t3396.value = atoll(v);
                } else
                    ogs_warn("unknown key `%s`", key);
            }
        } else if (!strcmp(time_key, "t3412")) {
            ogs_yaml_iter_recurse(time_iter, &t3412_iter);
            while (ogs_yaml_iter_next(&t3412_iter)) {
                const char *key = ogs_yaml_iter_key(&t3412_iter);
                ogs_assert(key);
                if (!strcmp(key, "value")) {
                    const char *v = ogs_yaml_iter_value(&t3412_iter);
                    if (v)
                        self.time.t3412.value = atoll(v);
                } else
                    ogs_warn("unknown key `%s`", key);
            }
        } else if (!strcmp(time_key, "t3423")) {
            ogs_yaml_iter_recurse(time_iter, &t3423_iter);
            while (ogs_yaml_iter_next(&t3423_iter)) {
                const char *key = ogs_yaml_iter_key(&t3423_iter);
                ogs_assert(key);
                if (!strcmp(key, "value")) {
                    const char *v = ogs_yaml_iter_value(&t3423_iter);
                    if (v)
                        self.time.t3423.value = atoll(v);
                } else
                    ogs_warn("unknown key `%s`", key);
            }
        } else if (!strcmp(time_key, "idle")) {
            ogs_yaml_iter_recurse(time_iter, &idle_iter);
            while (ogs_yaml_iter_next(&idle_iter)) {
                const char *key = ogs_yaml_iter_key(&idle_iter);
                ogs_assert(key);
                if (!strcmp(key, "mobile_reachable_margin")) {
                    const char *v = ogs_yaml_iter_value(&idle_iter);
                    if (v)
                        self.time.idle.mobile_reachable_margin = atoll(v);
                } else if (!strcmp(key, "implicit_detach_margin")) {
                    const char *v = ogs_yaml_iter_value(&idle_iter);
                    if (v)
                        self.time.idle.implicit_detach_margin = atoll(v);
                } else
                    ogs_warn("unknown key `%s`", key);
            }
        } else if (!strcmp(time_key, "t3346")) {
            ogs_yaml_iter_recurse(time_iter, &t3346_iter);
            while (ogs_yaml_iter_next(&t3346_iter)) {
                const char *key = ogs_yaml_iter_key(&t3346_iter);
                ogs_assert(key);
                if (!strcmp(key, "value")) {
                    const char *v = ogs_yaml_iter_value(&t3346_iter);
                    if (v)
                        self.time.t3346.value = atoll(v);
                } else if (!strcmp(key, "include_any_reject")) {
                    self.time.t3346.include_any_reject =
                        ogs_yaml_iter_bool(&t3346_iter);
                } else
                    ogs_warn("unknown key `%s`", key);
            }
        } else if (!strcmp(time_key, "bearer_setup") ||
                !strcmp(time_key, "sae_bearer_setup")) {
            mme_bearer_setup_time_parse_yaml(time_iter);
        } else if (!strcmp(time_key, "t3413")) {
            mme_timer_parse_yaml(time_iter, MME_TIMER_T3413);
        } else if (!strcmp(time_key, "t3422")) {
            mme_timer_parse_yaml(time_iter, MME_TIMER_T3422);
        } else if (!strcmp(time_key, "t3450")) {
            mme_timer_parse_yaml(time_iter, MME_TIMER_T3450);
        } else if (!strcmp(time_key, "t3460")) {
            mme_timer_parse_yaml(time_iter, MME_TIMER_T3460);
        } else if (!strcmp(time_key, "t3470")) {
            mme_timer_parse_yaml(time_iter, MME_TIMER_T3470);
        } else if (!strcmp(time_key, "t3489")) {
            mme_timer_parse_yaml(time_iter, MME_TIMER_T3489);
        } else if (!strcmp(time_key, "t3495") ||
                !strcmp(time_key, "nas_deactivate_bearer")) {
            mme_timer_parse_yaml(time_iter, MME_TIMER_NAS_DEACTIVATE_BEARER);
        } else if (!strcmp(time_key, "sgs_ts6_1") ||
                !strcmp(time_key, "ts6_1")) {
            mme_timer_parse_yaml(time_iter, MME_TIMER_SGS_TS6_1);
        } else if (!strcmp(time_key, "s6a") ||
                !strcmp(time_key, "s6a_timeout")) {
            mme_timer_parse_yaml(time_iter, MME_TIMER_S6A);
        } else if (!strcmp(time_key, "s11_holding")) {
            mme_timer_parse_yaml(time_iter, MME_TIMER_S11_HOLDING);
        } else
            ogs_warn("unknown key `%s` in mme.time (runtime reload)", time_key);
    }
}

void mme_context_reload_runtime(void)
{
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;
    bool found = false;
    int lists_added = 0;
    bool yaml_ok = false;

    ogs_reload_audit_begin();
    mme_reload_lists_changed = 0;

    if (ogs_app_config_reload() != OGS_OK) {
        ogs_warn("Configuration reload failed; keeping previous config");
        ogs_reload_audit_warn("YAML parse failed; previous config kept");
        ogs_reload_audit_finish("MME", false);
        ogs_log_cycle();
        return;
    }

    yaml_ok = true;

    document = ogs_app()->document;
    if (!document) {
        ogs_warn("No configuration document for runtime reload");
        ogs_reload_audit_warn("no configuration document after reload");
        ogs_reload_audit_finish("MME", false);
        ogs_log_cycle();
        return;
    }

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "mme")) {
            ogs_yaml_iter_t mme_iter;
            ogs_yaml_iter_recurse(&root_iter, &mme_iter);
            while (ogs_yaml_iter_next(&mme_iter)) {
                const char *mme_key = ogs_yaml_iter_key(&mme_iter);
                ogs_assert(mme_key);
                if (!strcmp(mme_key, "time")) {
                    ogs_yaml_iter_t time_iter;

                    ogs_yaml_iter_recurse(&mme_iter, &time_iter);
                    mme_time_config_parse(&time_iter);
                    ogs_reload_audit_note("mme.time timers reloaded");
                    found = true;
                } else if (!strcmp(mme_key, "gtpc")) {
                    ogs_yaml_iter_t gtpc_scan;

                    ogs_yaml_iter_recurse(&mme_iter, &gtpc_scan);
                    while (ogs_yaml_iter_next(&gtpc_scan)) {
                        const char *gtpc_key = ogs_yaml_iter_key(&gtpc_scan);
                        ogs_assert(gtpc_key);
                        if (!strcmp(gtpc_key, "echo_interval")) {
                            const char *v = ogs_yaml_iter_value(&gtpc_scan);
                            if (v) {
                                self.gtpc_echo_interval = atoi(v);
                                ogs_reload_audit_note(
                                        "mme.gtpc.echo_interval=%u",
                                        self.gtpc_echo_interval);
                            }
                            found = true;
                        } else if (!strcmp(gtpc_key, "recovery")) {
                            ogs_reload_audit_warn(
                                    "mme.gtpc.recovery ignored "
                                    "(daemon restart required)");
                        } else if (!strcmp(gtpc_key,
                                "recovery_counter_file")) {
                            ogs_reload_audit_warn(
                                    "mme.gtpc.recovery_counter_file ignored "
                                    "(daemon restart required)");
                        }
                    }
                    lists_added += mme_reload_gtpc_client_add_only(&mme_iter);
                } else {
                    lists_added += mme_reload_lists_key_add_only(
                            mme_key, &mme_iter);
                }
            }
        }
    }

    if (!self.require_hss_map_explicit &&
            ogs_list_first(&self.hssmap_list) != NULL) {
        self.require_hss_map = true;
    }

    if (found || lists_added > 0 || mme_reload_lists_changed > 0) {
        mme_sgw_echo_reschedule_all();
    }

    ogs_reload_audit_finish("MME", yaml_ok);
    ogs_log_cycle();
}

mme_pgw_t *mme_pgw_add(ogs_sockaddr_t *addr)
{
    mme_pgw_t *pgw = NULL;

    ogs_assert(addr);

    ogs_pool_alloc(&mme_pgw_pool, &pgw);
    ogs_assert(pgw);
    memset(pgw, 0, sizeof *pgw);

    pgw->tac = ogs_calloc(ogs_global_conf()->max.tai, sizeof(uint16_t));
    ogs_assert(pgw->tac);

    pgw->sa_list = addr;

    ogs_list_add(&self.pgw_list, pgw);

    return pgw;
}

void mme_pgw_remove(mme_pgw_t *pgw)
{
    ogs_assert(pgw);

    ogs_list_remove(&self.pgw_list, pgw);

    ogs_freeaddrinfo(pgw->sa_list);
    ogs_free(pgw->tac);

    ogs_pool_free(&mme_pgw_pool, pgw);
}

void mme_pgw_remove_all(void)
{
    mme_pgw_t *pgw = NULL, *next_pgw = NULL;

    ogs_list_for_each_safe(&self.pgw_list, next_pgw, pgw)
        mme_pgw_remove(pgw);
}

static bool mme_ue_inbound_roam_on_tai(
        mme_ue_t *mme_ue, const ogs_eps_tai_t *tai)
{
    if (!mme_ue || !MME_UE_HAVE_IMSI(mme_ue) || !tai)
        return false;

    /* Home iff the IMSI starts with the serving TAI PLMN digits; the
     * TAI PLMN carries its true MNC length, unlike a PLMN derived from
     * the IMSI (see ogs_plmn_id_imsi_prefix_match). */
    return !ogs_plmn_id_imsi_prefix_match(mme_ue->imsi_bcd, &tai->plmn_id);
}

static int mme_gtpc_entry_selection_order(int yaml_index, const char *order_v)
{
    if (order_v && order_v[0])
        return atoi(order_v);
    return yaml_index * OGS_SELECTION_ORDER_STEP;
}

static void mme_gtpc_client_parse_plmn_id_key(
        ogs_yaml_iter_t *iter, const char *key,
        bool *serving_plmn_parsed, ogs_plmn_id_t *serving_plmn,
        bool *imsi_plmn_parsed, ogs_plmn_id_t *imsi_plmn)
{
    ogs_plmn_id_t plmn_id;

    ogs_assert(iter);
    ogs_assert(key);
    ogs_assert(serving_plmn_parsed);
    ogs_assert(serving_plmn);
    ogs_assert(imsi_plmn_parsed);
    ogs_assert(imsi_plmn);

    if (parse_plmn_id(iter, &plmn_id) != OGS_OK)
        return;

    if (!strcmp(key, "imsi_plmn_id")) {
        *imsi_plmn_parsed = true;
        memcpy(imsi_plmn, &plmn_id, sizeof(plmn_id));
        return;
    }

    if (!strcmp(key, "serving_plmn_id")) {
        *serving_plmn_parsed = true;
        memcpy(serving_plmn, &plmn_id, sizeof(plmn_id));
        return;
    }

    if (!strcmp(key, "plmn_id")) {
        if (mme_self()->inbound_roam_gtpc_plmn_id_is_imsi_plmn) {
            *imsi_plmn_parsed = true;
            memcpy(imsi_plmn, &plmn_id, sizeof(plmn_id));
        } else {
            *serving_plmn_parsed = true;
            memcpy(serving_plmn, &plmn_id, sizeof(plmn_id));
        }
    }
}

static bool mme_pgw_is_default(const mme_pgw_t *pgw)
{
    ogs_assert(pgw);

    return pgw->num_of_apn == 0 &&
            pgw->num_of_tac == 0 &&
            pgw->num_of_e_cell_id == 0 &&
            !pgw->serving_plmn_present &&
            !pgw->imsi_plmn_present &&
            !pgw->imsi_prefix[0];
}

ogs_sockaddr_t *mme_pgw_sockaddr_by_family(
        mme_pgw_t *pgw, int family)
{
    ogs_sockaddr_t *addr = NULL;

    ogs_assert(pgw);

    for (addr = pgw->sa_list; addr; addr = addr->next) {
        if (addr->ogs_sa_family == family)
            return addr;
    }

    return NULL;
}

static bool compare_pgw_info(
        const mme_pgw_t *pgw, const mme_sess_t *sess)
{
    mme_ue_t *mme_ue = NULL;
    int i;

    ogs_assert(pgw);
    ogs_assert(sess);
    ogs_assert(!mme_pgw_is_default(pgw));

    mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
    ogs_assert(mme_ue);

    if (sess->session && sess->session->name) {
        for (i = 0; i < pgw->num_of_apn; i++)
            if (!ogs_strcasecmp(pgw->apn[i], sess->session->name))
                return true;
    }

    for (i = 0; i < pgw->num_of_e_cell_id; i++)
        if (pgw->e_cell_id[i] == mme_ue->e_cgi.cell_id)
            return true;

    for (i = 0; i < pgw->num_of_tac; i++)
        if (pgw->tac[i] == mme_ue->tai.tac)
            return true;

    if (pgw->imsi_plmn_present && MME_UE_HAVE_IMSI(mme_ue) &&
            ogs_plmn_id_imsi_prefix_match(
                mme_ue->imsi_bcd, &pgw->imsi_plmn_id))
        return true;

    if (pgw->imsi_prefix[0] && MME_UE_HAVE_IMSI(mme_ue)) {
        size_t len = strlen(pgw->imsi_prefix);

        if (len > 0 && strncmp(mme_ue->imsi_bcd, pgw->imsi_prefix, len) == 0)
            return true;
    }

    if (!mme_ue_inbound_roam_on_tai(mme_ue, &mme_ue->tai) &&
            pgw->serving_plmn_present &&
            memcmp(&pgw->serving_plmn_id, &mme_ue->tai.plmn_id,
                OGS_PLMN_ID_LEN) == 0)
        return true;

    return false;
}

static void mme_pgw_format_rule(
        const mme_pgw_t *pgw, char *buf, int buflen)
{
    char plmn[OGS_PLMNIDSTRLEN];
    int len = 0;

    ogs_assert(pgw);
    ogs_assert(buf);
    ogs_assert(buflen > 0);

    buf[0] = '\0';

    if (mme_pgw_is_default(pgw)) {
        ogs_cpystrn(buf, "default", buflen);
        return;
    }

    if (pgw->imsi_plmn_present) {
        ogs_plmn_id_to_string(&pgw->imsi_plmn_id, plmn);
        len = ogs_snprintf(buf, buflen, "imsi_plmn:%s", plmn);
    }
    if (pgw->imsi_prefix[0]) {
        if (len > 0)
            len += ogs_snprintf(buf + len, buflen - len, "+");
        len += ogs_snprintf(buf + len, buflen - len, "imsi_prefix:%s",
                pgw->imsi_prefix);
    }
    if (pgw->serving_plmn_present) {
        ogs_plmn_id_to_string(&pgw->serving_plmn_id, plmn);
        if (len > 0)
            len += ogs_snprintf(buf + len, buflen - len, "+");
        len += ogs_snprintf(buf + len, buflen - len, "serving_plmn:%s", plmn);
    }
    if (pgw->num_of_apn > 0) {
        if (len > 0)
            len += ogs_snprintf(buf + len, buflen - len, "+");
        len += ogs_snprintf(buf + len, buflen - len, "apn");
    }
    if (pgw->num_of_tac > 0) {
        if (len > 0)
            len += ogs_snprintf(buf + len, buflen - len, "+");
        ogs_snprintf(buf + len, buflen - len, "tac");
    }
    if (pgw->num_of_e_cell_id > 0) {
        if (len > 0)
            len += ogs_snprintf(buf + len, buflen - len, "+");
        ogs_snprintf(buf + len, buflen - len, "e_cell_id");
    }

    if (len == 0)
        ogs_cpystrn(buf, "filtered", buflen);
    else
        ogs_snprintf(buf + len, buflen - len, " order:%d", pgw->selection_order);
}

void mme_pgw_log_pick(mme_ue_t *mme_ue, const mme_pgw_t *pgw, const char *apn)
{
    char addr[OGS_ADDRSTRLEN];
    char rule[128];
    const char *imsi = "-";

    ogs_assert(pgw);

    if (!pgw->sa_list)
        return;

    if (mme_ue && MME_UE_HAVE_IMSI(mme_ue))
        imsi = mme_ue->imsi_bcd;

    mme_pgw_format_rule(pgw, rule, sizeof(rule));
    OGS_ADDR(pgw->sa_list, addr);

    ogs_info("[%s] PGW/SMF selected DNN:%s %s [%s]",
            imsi, apn ? apn : "-", addr, rule);
}

mme_pgw_t *mme_pgw_find_for_sess(
        ogs_list_t *list, const mme_sess_t *sess)
{
    mme_pgw_t *pgw = NULL;
    mme_pgw_t *default_pgw = NULL;
    mme_pgw_t *best = NULL;
    int best_order = INT_MAX;

    ogs_assert(list);

    ogs_list_for_each(list, pgw) {
        if (mme_pgw_is_default(pgw)) {
            if (!default_pgw)
                default_pgw = pgw;
            continue;
        }

        if (!sess || !compare_pgw_info(pgw, sess))
            continue;

        if (pgw->selection_order < best_order) {
            best_order = pgw->selection_order;
            best = pgw;
        }
    }

    if (best)
        return best;

    return default_pgw;
}

ogs_sockaddr_t *mme_pgw_addr_find_by_apn_enb(
    ogs_list_t *list, int family, const mme_sess_t *sess)
{
    mme_pgw_t *pgw = NULL;

    ogs_assert(list);

    if (!sess) {
        ogs_list_for_each(list, pgw) {
            ogs_sockaddr_t *addr = NULL;

            if (!mme_pgw_is_default(pgw))
                continue;

            addr = mme_pgw_sockaddr_by_family(pgw, family);
            if (addr)
                return addr;
        }
        return NULL;
    }

    pgw = mme_pgw_find_for_sess(list, sess);
    if (!pgw)
        return NULL;

    return mme_pgw_sockaddr_by_family(pgw, family);
}

mme_vlr_t *mme_vlr_add(
        ogs_sockaddr_t *sa_list,
        ogs_sockaddr_t *local_sa_list,
        ogs_sockopt_t *option)
{
    mme_vlr_t *vlr = NULL;

    ogs_assert(sa_list);

    ogs_pool_alloc(&mme_vlr_pool, &vlr);
    ogs_assert(vlr);
    memset(vlr, 0, sizeof *vlr);

    vlr->max_num_of_ostreams = OGS_DEFAULT_SCTP_MAX_NUM_OF_OSTREAMS;
    vlr->ostream_id = 0;

    vlr->sa_list = sa_list;
    vlr->local_sa_list = local_sa_list;
    if (option) {
        vlr->max_num_of_ostreams = option->sctp.sinit_num_ostreams;
        vlr->option = ogs_memdup(option, sizeof *option);
    }

    ogs_list_add(&self.vlr_list, vlr);

    return vlr;
}

void mme_vlr_remove(mme_vlr_t *vlr)
{
    ogs_assert(vlr);

    ogs_list_remove(&self.vlr_list, vlr);

    mme_vlr_close(vlr);

    if (vlr->t_conn)
        ogs_timer_delete(vlr->t_conn);

    ogs_freeaddrinfo(vlr->sa_list);
    ogs_freeaddrinfo(vlr->local_sa_list);
    if (vlr->option)
        ogs_free(vlr->option);

    ogs_pool_free(&mme_vlr_pool, vlr);
}

void mme_vlr_remove_all(void)
{
    mme_vlr_t *vlr = NULL, *next_vlr = NULL;

    ogs_list_for_each_safe(&self.vlr_list, next_vlr, vlr)
        mme_vlr_remove(vlr);
}

void mme_vlr_close(mme_vlr_t *vlr)
{
    ogs_assert(vlr);

    if (vlr->poll) {
        ogs_pollset_remove(vlr->poll);
        vlr->poll = NULL;
    }
    if (vlr->sock) {
        ogs_sctp_destroy(vlr->sock);
        vlr->sock = NULL;
    }
}

mme_vlr_t *mme_vlr_find_by_sock(const ogs_sock_t *sock)
{
    mme_vlr_t *vlr = NULL;
    ogs_assert(sock);

    ogs_list_for_each(&self.vlr_list, vlr) {
        if (vlr->sock == sock)
            return vlr;
    }

    return NULL;
}

static ogs_list_t *mme_csmap_plmn_bucket(const ogs_plmn_id_t *plmn_id, bool create)
{
    char key[OGS_PLMN_ID_LEN];
    ogs_list_t *bucket = NULL;

    ogs_assert(plmn_id);
    ogs_assert(mme_csmap_plmn_hash);

    memcpy(key, plmn_id, OGS_PLMN_ID_LEN);
    bucket = ogs_hash_get(mme_csmap_plmn_hash, key, OGS_PLMN_ID_LEN);
    if (bucket || !create)
        return bucket;

    bucket = ogs_calloc(1, sizeof(*bucket));
    ogs_assert(bucket);
    ogs_list_init(bucket);
    ogs_hash_set(mme_csmap_plmn_hash, ogs_strdup(key), OGS_PLMN_ID_LEN, bucket);
    return bucket;
}

static void mme_csmap_plmn_attach(mme_csmap_t *csmap)
{
    ogs_plmn_id_t plmn_id;
    ogs_list_t *bucket;

    ogs_assert(csmap);
    ogs_nas_to_plmn_id(&plmn_id, &csmap->tai.nas_plmn_id);
    bucket = mme_csmap_plmn_bucket(&plmn_id, true);
    ogs_assert(bucket);
    ogs_list_add(bucket, &csmap->plmn_lnode);
}

static void mme_csmap_plmn_detach(mme_csmap_t *csmap)
{
    ogs_plmn_id_t plmn_id;
    ogs_list_t *bucket;

    ogs_assert(csmap);
    ogs_nas_to_plmn_id(&plmn_id, &csmap->tai.nas_plmn_id);
    bucket = mme_csmap_plmn_bucket(&plmn_id, false);
    if (!bucket)
        return;
    ogs_list_remove(bucket, &csmap->plmn_lnode);
}

mme_csmap_t *mme_csmap_add(mme_vlr_t *vlr)
{
    mme_csmap_t *csmap = NULL;

    ogs_assert(vlr);

    ogs_pool_alloc(&mme_csmap_pool, &csmap);
    ogs_assert(csmap);
    memset(csmap, 0, sizeof *csmap);

    csmap->vlr = vlr;

    ogs_list_add(&self.csmap_list, csmap);

    return csmap;
}

void mme_csmap_remove(mme_csmap_t *csmap)
{
    ogs_assert(csmap);

    mme_csmap_plmn_detach(csmap);
    ogs_list_remove(&self.csmap_list, csmap);

    ogs_pool_free(&mme_csmap_pool, csmap);
}

static void mme_csmap_plmn_hash_clear(void)
{
    ogs_hash_index_t *hi = NULL;

    if (!mme_csmap_plmn_hash)
        return;

    for (hi = ogs_hash_first(mme_csmap_plmn_hash); hi;
            hi = ogs_hash_next(hi)) {
        char *key = (char *)ogs_hash_this_key(hi);
        ogs_list_t *bucket = (ogs_list_t *)ogs_hash_this_val(hi);

        if (bucket)
            ogs_free(bucket);
        if (key)
            ogs_free(key);
    }
    ogs_hash_clear(mme_csmap_plmn_hash);
}

void mme_csmap_remove_all(void)
{
    mme_csmap_t *csmap = NULL, *next_csmap = NULL;

    ogs_list_for_each_safe(&self.csmap_list, next_csmap, csmap)
        mme_csmap_remove(csmap);

    mme_csmap_plmn_hash_clear();
}

static bool mme_csmap_tai_match(
        const mme_csmap_t *csmap, const ogs_eps_tai_t *tai)
{
    ogs_nas_eps_tai_t ogs_nas_tai;
    uint16_t tac_end;

    ogs_assert(csmap);
    ogs_assert(tai);

    ogs_nas_from_plmn_id(&ogs_nas_tai.nas_plmn_id, &tai->plmn_id);
    ogs_nas_tai.tac = tai->tac;

    if (memcmp(&csmap->tai.nas_plmn_id, &ogs_nas_tai.nas_plmn_id,
                sizeof(ogs_nas_plmn_id_t)) != 0)
        return false;

    tac_end = csmap->tac_end ? csmap->tac_end : csmap->tai.tac;
    return ogs_nas_tai.tac >= csmap->tai.tac && ogs_nas_tai.tac <= tac_end;
}

mme_csmap_t *mme_csmap_find_by_tai(const ogs_eps_tai_t *tai)
{
    return mme_csmap_find_by_tai_and_imsi(tai, NULL);
}

mme_csmap_t *mme_csmap_find_by_tai_and_imsi(
        const ogs_eps_tai_t *tai, const char *imsi_bcd)
{
    mme_csmap_t *csmap = NULL;
    mme_csmap_t *fallback = NULL;
    ogs_list_t *bucket = NULL;
    ogs_lnode_t *node = NULL;

    ogs_assert(tai);

    bucket = mme_csmap_plmn_bucket(&tai->plmn_id, false);
    if (bucket) {
        ogs_list_for_each(bucket, node) {
            csmap = ogs_container_of(node, mme_csmap_t, plmn_lnode);
            size_t len;

            if (!mme_csmap_tai_match(csmap, tai))
                continue;

            if (csmap->imsi_prefix[0] == '\0') {
                if (!fallback)
                    fallback = csmap;
                continue;
            }

            if (!imsi_bcd)
                continue;

            len = strlen(csmap->imsi_prefix);
            if (len > 0 && strncmp(imsi_bcd, csmap->imsi_prefix, len) == 0)
                return csmap;
        }
        return fallback;
    }

    ogs_list_for_each(&self.csmap_list, csmap) {
        size_t len;

        if (!mme_csmap_tai_match(csmap, tai))
            continue;

        if (csmap->imsi_prefix[0] == '\0') {
            if (!fallback)
                fallback = csmap;
            continue;
        }

        if (!imsi_bcd)
            continue;

        len = strlen(csmap->imsi_prefix);
        if (len > 0 && strncmp(imsi_bcd, csmap->imsi_prefix, len) == 0)
            return csmap;
    }

    return fallback;
}

mme_csmap_t *mme_csmap_find_by_nas_lai(const ogs_nas_lai_t *lai)
{
    mme_csmap_t *csmap = NULL;
    ogs_assert(lai);

    ogs_list_for_each(&self.csmap_list, csmap) {
        if (memcmp(&csmap->lai, lai, sizeof *lai) == 0)
            return csmap;
    }

    return NULL;
}

mme_hssmap_t *mme_hssmap_add(ogs_plmn_id_t *plmn_id, const char *realm,
                             const char *host, int selection_order)
{
    mme_hssmap_t *hssmap = NULL;

    ogs_assert(plmn_id);

    ogs_pool_alloc(&mme_hssmap_pool, &hssmap);
    ogs_assert(hssmap);
    memset(hssmap, 0, sizeof *hssmap);

    hssmap->plmn_id = *plmn_id;
    hssmap->selection_order = selection_order;
    if (realm)
        hssmap->realm = ogs_strdup(realm);
    else
        hssmap->realm = ogs_epc_domain_from_plmn_id(plmn_id);

    if (host)
        hssmap->host = ogs_strdup(host);
    else
        hssmap->host = NULL;

    ogs_list_add(&self.hssmap_list, hssmap);

    return hssmap;
}

static int mme_hssmap_order_cmp(const void *a, const void *b)
{
    const mme_hssmap_t * const *pa = a;
    const mme_hssmap_t * const *pb = b;

    return (*pa)->selection_order - (*pb)->selection_order;
}

void mme_hssmap_resort_by_order(void)
{
    mme_hssmap_t *hssmap = NULL;
    mme_hssmap_t *nodes[256];
    int i, n = 0;

    ogs_list_for_each(&self.hssmap_list, hssmap) {
        if (n < (int)(sizeof(nodes) / sizeof(nodes[0])))
            nodes[n++] = hssmap;
    }

    if (n <= 1)
        return;

    qsort(nodes, n, sizeof(nodes[0]), mme_hssmap_order_cmp);

    while ((hssmap = ogs_list_first(&self.hssmap_list)) != NULL)
        ogs_list_remove(&self.hssmap_list, hssmap);

    for (i = 0; i < n; i++)
        ogs_list_add(&self.hssmap_list, nodes[i]);
}

void mme_hssmap_remove(mme_hssmap_t *hssmap)
{
    ogs_assert(hssmap);

    ogs_list_remove(&self.hssmap_list, hssmap);

    if (hssmap->realm != NULL)
        ogs_free(hssmap->realm);

    if (hssmap->host != NULL)
        ogs_free(hssmap->host);

    ogs_pool_free(&mme_hssmap_pool, hssmap);
}

void mme_hssmap_remove_all(void)
{
    mme_hssmap_t *hssmap = NULL, *next_hssmap = NULL;

    ogs_list_for_each_safe(&self.hssmap_list, next_hssmap, hssmap)
        mme_hssmap_remove(hssmap);
}

mme_hssmap_t *mme_hssmap_find_by_imsi_bcd(const char *imsi_bcd)
{
    mme_hssmap_t *hssmap = NULL;
    mme_hssmap_t *best = NULL;
    int best_order = INT_MAX;

    ogs_assert(imsi_bcd);

    ogs_list_for_each(&self.hssmap_list, hssmap) {
        char plmn_id_str[OGS_PLMNIDSTRLEN] = "";

        ogs_plmn_id_to_string(&hssmap->plmn_id, plmn_id_str);
        if (strncmp(plmn_id_str, imsi_bcd, strlen(plmn_id_str)) == 0 &&
                hssmap->selection_order < best_order) {
            best_order = hssmap->selection_order;
            best = hssmap;
        }
    }

    return best;
}

/*
 * Resolve the home PLMN of an IMSI, preferring configured PLMNs
 * (which carry their true MNC length) over the digit-6 heuristic in
 * ogs_plmn_id_from_imsi_bcd(). Sources checked: hss_map, gtpc client
 * smf/sgwc imsi_plmn rules, access_control PLMN entries.
 */
void mme_home_plmn_from_imsi_bcd(const char *imsi_bcd, ogs_plmn_id_t *plmn_id)
{
    mme_hssmap_t *hssmap = NULL;
    mme_pgw_t *pgw = NULL;
    mme_sgw_t *sgw = NULL;
    int i;
    bool found = false;
    int best_order = INT_MAX;

    ogs_assert(imsi_bcd);
    ogs_assert(plmn_id);

    if (ogs_plmn_id_pick_imsi_prefix_match(imsi_bcd,
            ogs_local_conf()->serving_plmn_id,
            ogs_local_conf()->num_of_serving_plmn_id,
            plmn_id))
        return;

    for (i = 0; i < self.num_of_served_gummei; i++) {
        served_gummei_t *gummei = &self.served_gummei[i];
        int j;

        for (j = 0; j < gummei->num_of_plmn_id; j++) {
            if (ogs_plmn_id_imsi_prefix_match(
                        imsi_bcd, &gummei->plmn_id[j])) {
                memcpy(plmn_id, &gummei->plmn_id[j], sizeof(*plmn_id));
                return;
            }
        }
    }

    ogs_list_for_each(&self.hssmap_list, hssmap) {
        if (ogs_plmn_id_imsi_prefix_match(imsi_bcd, &hssmap->plmn_id)) {
            if (!found || hssmap->selection_order < best_order) {
                memcpy(plmn_id, &hssmap->plmn_id, sizeof(*plmn_id));
                best_order = hssmap->selection_order;
                found = true;
            }
        }
    }

    if (found)
        return;

    ogs_list_for_each(&self.pgw_list, pgw) {
        if (pgw->imsi_plmn_present &&
                ogs_plmn_id_imsi_prefix_match(
                    imsi_bcd, &pgw->imsi_plmn_id)) {
            memcpy(plmn_id, &pgw->imsi_plmn_id, sizeof(*plmn_id));
            return;
        }
    }

    ogs_list_for_each(&self.sgw_list, sgw) {
        if (sgw->imsi_plmn_present &&
                ogs_plmn_id_imsi_prefix_match(
                    imsi_bcd, &sgw->imsi_plmn_id)) {
            memcpy(plmn_id, &sgw->imsi_plmn_id, sizeof(*plmn_id));
            return;
        }
    }

    for (i = 0; i < self.num_of_access_control; i++) {
        if (self.access_control[i].plmn_id_configured &&
                ogs_plmn_id_imsi_prefix_match(
                    imsi_bcd, &self.access_control[i].plmn_id)) {
            memcpy(plmn_id, &self.access_control[i].plmn_id,
                    sizeof(*plmn_id));
            return;
        }
    }

    ogs_plmn_id_from_imsi_bcd_with_config_fallback(imsi_bcd, plmn_id);
}

static bool mme_imsi_acl_match(const char *imsi_bcd)
{
    int i;

    ogs_assert(imsi_bcd);

    for (i = 0; i < self.num_of_imsi_acl; i++) {
        const char *prefix = self.imsi_acl[i].prefix;
        size_t len = strlen(prefix);

        if (len > 0 && strncmp(imsi_bcd, prefix, len) == 0)
            return true;
    }

    return false;
}

static bool mme_access_control_imsi_prefix_match(const char *imsi_bcd)
{
    int i;

    ogs_assert(imsi_bcd);

    for (i = 0; i < self.num_of_access_control; i++) {
        mme_access_control_t *entry = &self.access_control[i];
        size_t len;

        if (!entry->imsi_prefix[0])
            continue;

        len = strlen(entry->imsi_prefix);
        if (len > 0 && strncmp(imsi_bcd, entry->imsi_prefix, len) == 0)
            return true;
    }

    return false;
}

uint8_t mme_emm_cause_from_access_control_imsi_bcd(const char *imsi_bcd)
{
    mme_access_control_t *ac = NULL;
    int i, best = -1, best_order = INT_MAX;
    bool has_plmn_acl = false;

    ogs_assert(imsi_bcd);

    for (i = 0; i < self.num_of_access_control; i++) {
        mme_access_control_t *entry = &self.access_control[i];

        if (entry->imsi_prefix[0])
            continue;

        if (!entry->plmn_id_configured)
            continue;

        has_plmn_acl = true;

        if (ogs_plmn_id_imsi_prefix_match(imsi_bcd, &entry->plmn_id) &&
                entry->selection_order < best_order) {
            best_order = entry->selection_order;
            best = i;
        }
    }

    if (!has_plmn_acl)
        return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;

    if (best < 0) {
        /*
         * IMSIs covered by imsi_prefix entries are checked on the inbound-roam
         * path (prefix + optional TAC/eNB). Their home PLMN (e.g. 999-70) is
         * intentionally not listed in plmn_id home ACL (999-70/432-46).
         */
        if (mme_access_control_imsi_prefix_match(imsi_bcd))
            return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;

        if (self.default_reject_cause)
            return self.default_reject_cause;
        return OGS_NAS_EMM_CAUSE_PLMN_NOT_ALLOWED;
    }

    ac = &self.access_control[best];
    if (ac->reject_cause)
        return ac->reject_cause;

    return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;
}

bool mme_imsi_hss_allowed(mme_ue_t *mme_ue)
{
    const char *imsi;

    ogs_assert(mme_ue);

    if (!MME_UE_HAVE_IMSI(mme_ue))
        return true;

    imsi = mme_ue->imsi_bcd;

    if (self.num_of_imsi_acl > 0 && !mme_imsi_acl_match(imsi))
        return false;

    if (self.require_hss_map && ogs_list_first(&self.hssmap_list) != NULL) {
        if (!mme_ue->hssmap)
            mme_ue->hssmap = mme_hssmap_find_by_imsi_bcd(imsi);
        if (!mme_ue->hssmap)
            return false;
    }

    if (self.num_of_access_control > 0) {
        uint8_t emm_cause =
            mme_emm_cause_from_access_control_imsi_bcd(imsi);
        if (emm_cause != OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED)
            return false;
    }

    return true;
}

mme_enb_t *mme_enb_add(ogs_sock_t *sock, ogs_sockaddr_t *addr)
{
    mme_enb_t *enb = NULL;
    mme_event_t e;

    ogs_assert(sock);
    ogs_assert(addr);

    ogs_pool_id_calloc(&mme_enb_pool, &enb);
    if (!enb) {
        /*
         * mme_enb_pool is sized to global.max.peer * 2 in
         * mme_context_init(). When this fires the operator must
         * raise global.max.peer in the YAML (e.g.
         *   global:
         *     max:
         *       peer: 16384
         * for ~8k eNBs with headroom for reconnects). Otherwise
         * the affected eNB will retry forever and the MME burns
         * CPU on SCTP accept/reject cycles, which in turn
         * starves the /metrics HTTP worker.
         */
        ogs_error("Cannot allocate mme_enb (pool exhausted, "
                "cap=%u, current=%d) - raise "
                "'global.max.peer' in YAML config",
                (unsigned)ogs_global_conf()->max.peer * 2,
                self.num_of_enbs);
        return NULL;
    }

    enb->sctp.sock = sock;
    enb->sctp.addr = addr;
    enb->sctp.type = mme_enb_sock_type(enb->sctp.sock);

    if (enb->sctp.type == SOCK_STREAM) {
        enb->sctp.poll.read = ogs_pollset_add(ogs_app()->pollset,
            OGS_POLLIN, sock->fd, s1ap_recv_upcall, sock);
        ogs_assert(enb->sctp.poll.read);

        ogs_list_init(&enb->sctp.write_queue);
    }

    enb->max_num_of_ostreams = 0;
    enb->ostream_id = 0;

    ogs_list_init(&enb->enb_ue_list);
    enb->context_created = ogs_time_now();
    enb->enb_ue_hash = ogs_hash_make();
    ogs_assert(enb->enb_ue_hash);

    ogs_hash_set(self.enb_addr_hash,
            enb->sctp.addr, sizeof(ogs_sockaddr_t), enb);

    memset(&e, 0, sizeof(e));
    e.enb_id = enb->id;
    ogs_fsm_init(&enb->sm, s1ap_state_initial, s1ap_state_final, &e);

    /*
     * The /enb-info dumper iterates self.enb_list on the MHD
     * thread. Take the metrics dump lock around the list mutation
     * so the reader either sees the old or the new list head, never
     * a partial pointer write.
     */
    ogs_metrics_dump_lock();
    ogs_list_add(&self.enb_list, enb);
    self.num_of_enbs++;
    ogs_metrics_dump_unlock();
    mme_metrics_inst_global_inc(MME_METR_GLOB_GAUGE_ENB);

    ogs_info("[Added] Number of eNBs is now %d", self.num_of_enbs);

    return enb;
}

int mme_enb_remove(mme_enb_t *enb)
{
    mme_event_t e;

    ogs_assert(enb);
    ogs_assert(enb->sctp.sock);

    /*
     * Hold the metrics dump lock for the full destruction path -
     * not just the list_remove - because the /enb-info dumper
     * accesses enb_ue_list, sctp.addr, etc. and we are about to
     * free them.
     */
    ogs_metrics_dump_lock();
    ogs_list_remove(&self.enb_list, enb);
    if (self.num_of_enbs > 0)
        self.num_of_enbs--;

    memset(&e, 0, sizeof(e));
    e.enb_id = enb->id;
    ogs_fsm_fini(&enb->sm, &e);

    ogs_hash_set(self.enb_addr_hash,
            enb->sctp.addr, sizeof(ogs_sockaddr_t), NULL);
    if (enb->enb_id_presence == true)
        ogs_hash_set(self.enb_id_hash, &enb->enb_id, sizeof(enb->enb_id), NULL);

    /*
     * CHECK:
     *
     * S1-Reset Ack buffer is not cleared at this point.
     * ogs_sctp_flush_and_destroy will clear this buffer
     */

    ogs_sctp_flush_and_destroy(&enb->sctp);

    if (enb->enb_ue_hash) {
        ogs_hash_destroy(enb->enb_ue_hash);
        enb->enb_ue_hash = NULL;
    }

    ogs_pool_id_free(&mme_enb_pool, enb);
    ogs_metrics_dump_unlock();
    mme_metrics_inst_global_dec(MME_METR_GLOB_GAUGE_ENB);
    ogs_info("[Removed] Number of eNBs is now %d", self.num_of_enbs);

    return OGS_OK;
}

int mme_enb_remove_all(void)
{
    mme_enb_t *enb = NULL, *next_enb = NULL;

    ogs_list_for_each_safe(&self.enb_list, next_enb, enb)
        mme_enb_remove(enb);

    return OGS_OK;
}

mme_enb_t *mme_enb_find_by_addr(const ogs_sockaddr_t *addr)
{
    ogs_assert(addr);
    return (mme_enb_t *)ogs_hash_get(self.enb_addr_hash,
            addr, sizeof(ogs_sockaddr_t));

    return NULL;
}

mme_enb_t *mme_enb_find_by_enb_id(uint32_t enb_id)
{
    return (mme_enb_t *)ogs_hash_get(self.enb_id_hash, &enb_id, sizeof(enb_id));
}

int mme_enb_set_enb_id(mme_enb_t *enb, uint32_t enb_id)
{
    ogs_assert(enb);

    if (enb->enb_id_presence == true)
        ogs_hash_set(self.enb_id_hash, &enb->enb_id, sizeof(enb->enb_id), NULL);

    enb->enb_id = enb_id;
    ogs_hash_set(self.enb_id_hash, &enb->enb_id, sizeof(enb->enb_id), enb);

    enb->enb_id_presence = true;

    return OGS_OK;
}

int mme_enb_sock_type(ogs_sock_t *sock)
{
    ogs_socknode_t *snode = NULL;

    ogs_assert(sock);

    ogs_list_for_each(&mme_self()->s1ap_list, snode)
        if (snode->sock == sock) return SOCK_SEQPACKET;

    ogs_list_for_each(&mme_self()->s1ap_list6, snode)
        if (snode->sock == sock) return SOCK_SEQPACKET;

    return SOCK_STREAM;
}

mme_enb_t *mme_enb_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&mme_enb_pool, id);
}

/** enb_ue_context handling function */
enb_ue_t *enb_ue_add(mme_enb_t *enb, uint32_t enb_ue_s1ap_id)
{
    enb_ue_t *enb_ue = NULL;

    ogs_assert(enb);

    if ((enb->max_num_of_ostreams - 1) < 1) {
        ogs_error("enb->max_num_of_ostreams too small (%d)",
                enb->max_num_of_ostreams);
        return NULL;
    }

    ogs_pool_id_calloc(&enb_ue_pool, &enb_ue);
    if (enb_ue == NULL) {
        static ogs_time_t last_pool_err = 0;
        ogs_time_t now = ogs_time_now();
        if (last_pool_err == 0 ||
                now - last_pool_err > ogs_time_from_sec(1)) {
            last_pool_err = now;
            ogs_error("Could not allocate enb_ue context from pool "
                    "(enb_ue_pool size=%d avail=%d). "
                    "Raise global.max.ue.",
                    ogs_pool_size(&enb_ue_pool),
                    ogs_pool_avail(&enb_ue_pool));
        }
        return NULL;
    }

    enb_ue->t_s1_holding = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_s1_holding_timer_expire,
            OGS_UINT_TO_POINTER(enb_ue->id));
    if (!enb_ue->t_s1_holding) {
        ogs_error("ogs_timer_add() failed");
        ogs_pool_id_free(&enb_ue_pool, enb_ue);
        return NULL;
    }

    enb_ue->index = ogs_pool_index(&enb_ue_pool, enb_ue);
    ogs_assert(enb_ue->index > 0 && enb_ue->index <= ogs_global_conf()->max.ue);

    enb_ue->enb_ue_s1ap_id = enb_ue_s1ap_id;
    enb_ue->mme_ue_s1ap_id = enb_ue->index;
    enb_ue->context_created = ogs_time_now();

    /*
     * SCTP output stream identification
     * Default ogs_global_conf()->parameter.sctp_streams : 30
     *   0 : Non UE signalling
     *   1-29 : UE specific association
     */
    enb_ue->enb_ostream_id =
        OGS_NEXT_ID(enb->ostream_id, 1, enb->max_num_of_ostreams-1);

    enb_ue->enb_id = enb->id;

    ogs_list_add(&enb->enb_ue_list, enb_ue);
    enb->num_enb_ues++;
    if (enb->enb_ue_hash)
        ogs_hash_set(enb->enb_ue_hash,
                &enb_ue->enb_ue_s1ap_id,
                sizeof(enb_ue->enb_ue_s1ap_id),
                enb_ue);

    stats_add_enb_ue();

    return enb_ue;
}

void enb_ue_remove(enb_ue_t *enb_ue)
{
    mme_enb_t *enb = NULL;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(enb_ue);

    /*
     * Mark the owning mme_ue as IDLE for the LRU eviction path. If the
     * mme_ue is also being torn down (detach / implicit detach), its
     * mme_ue_remove() runs immediately after this and the field is
     * never observed. Stamp unconditionally — branch-free.
     */
    mme_ue = mme_ue_find_by_id(enb_ue->mme_ue_id);
    if (mme_ue) {
        mme_ue->idle_since = ogs_time_now();
        if (mme_ue->enb_ue_id == enb_ue->id)
            mme_metrics_ue_connected_clear(mme_ue);
    }

    enb = mme_enb_find_by_id(enb_ue->enb_id);

    if (enb) {
        ogs_list_remove(&enb->enb_ue_list, enb_ue);
        if (enb->num_enb_ues > 0) enb->num_enb_ues--;
        if (enb->enb_ue_hash) {
            /*
             * Fast path: the current field value still matches the key
             * that was inserted (true for the vast majority of removes).
             * Fall back to a hash sweep if the id was rewritten by an
             * S1 procedure (e.g. handover/path-switch) between insert
             * and remove.
             */
            enb_ue_t *hit = (enb_ue_t *)ogs_hash_get(enb->enb_ue_hash,
                    &enb_ue->enb_ue_s1ap_id,
                    sizeof(enb_ue->enb_ue_s1ap_id));
            if (hit == enb_ue) {
                ogs_hash_set(enb->enb_ue_hash,
                        &enb_ue->enb_ue_s1ap_id,
                        sizeof(enb_ue->enb_ue_s1ap_id),
                        NULL);
            } else {
                ogs_hash_index_t *hi;
                for (hi = ogs_hash_first(enb->enb_ue_hash);
                        hi; hi = ogs_hash_next(hi)) {
                    if (ogs_hash_this_val(hi) == enb_ue) {
                        const void *k = ogs_hash_this_key(hi);
                        int klen = ogs_hash_this_key_len(hi);
                        ogs_hash_set(enb->enb_ue_hash, k, klen, NULL);
                        break;
                    }
                }
            }
        }
    }

    ogs_assert(enb_ue->t_s1_holding);
    ogs_timer_delete(enb_ue->t_s1_holding);

    ogs_pool_id_free(&enb_ue_pool, enb_ue);

    stats_remove_enb_ue();
}

void enb_ue_switch_to_enb(enb_ue_t *enb_ue, mme_enb_t *new_enb)
{
    mme_enb_t *enb = NULL;
    ogs_assert(enb_ue);
    ogs_assert(new_enb);

    enb = mme_enb_find_by_id(enb_ue->enb_id);

    /*
     * Path-switch (S1AP) may rewrite enb_ue->enb_ue_s1ap_id BEFORE
     * calling us. We can't trust the current field value to remove the
     * old hash entry safely, so we sweep every slot whose value points
     * back to this enb_ue. This is rare (one collision per UE handover)
     * and bounded by the small per-eNB UE count.
     */
    if (enb && enb->enb_ue_hash) {
        ogs_hash_index_t *hi;
        for (hi = ogs_hash_first(enb->enb_ue_hash);
                hi; hi = ogs_hash_next(hi)) {
            if (ogs_hash_this_val(hi) == enb_ue) {
                const void *k = ogs_hash_this_key(hi);
                int klen = ogs_hash_this_key_len(hi);
                ogs_hash_set(enb->enb_ue_hash, k, klen, NULL);
                break;
            }
        }
    }

    if (enb) {
        ogs_list_remove(&enb->enb_ue_list, enb_ue);
        if (enb->num_enb_ues > 0) enb->num_enb_ues--;
    }

    ogs_list_add(&new_enb->enb_ue_list, enb_ue);
    new_enb->num_enb_ues++;
    if (new_enb->enb_ue_hash)
        ogs_hash_set(new_enb->enb_ue_hash,
                &enb_ue->enb_ue_s1ap_id,
                sizeof(enb_ue->enb_ue_s1ap_id),
                enb_ue);

    enb_ue->enb_id = new_enb->id;

    if (new_enb->max_num_of_ostreams < 2) {
        ogs_error("Target eNB has no UE-associated SCTP stream "
                "[MAX:%d]; UE-associated signalling cannot be delivered",
                new_enb->max_num_of_ostreams);
        return;
    }

    if (enb_ue->enb_ostream_id >= new_enb->max_num_of_ostreams) {
        uint16_t old_ostream_id = enb_ue->enb_ostream_id;

        enb_ue->enb_ostream_id =
            OGS_NEXT_ID(new_enb->ostream_id, 1,
                    new_enb->max_num_of_ostreams-1);

        ogs_warn("SCTP output stream re-bound to the target eNB "
                "[OLD:%d NEW:%d MAX:%d] "
                "ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
                old_ostream_id, enb_ue->enb_ostream_id,
                new_enb->max_num_of_ostreams,
                enb_ue->enb_ue_s1ap_id, enb_ue->mme_ue_s1ap_id);
    }
}

enb_ue_t *enb_ue_find_by_enb_ue_s1ap_id(
        const mme_enb_t *enb, uint32_t enb_ue_s1ap_id)
{
    ogs_assert(enb);

    /*
     * Fast path: per-eNB hash maintained by enb_ue_add / _remove /
     * _switch_to_enb. Falls back to the linear scan only if the hash
     * was somehow not created (defensive; mme_enb_add always builds it).
     */
    if (enb->enb_ue_hash)
        return (enb_ue_t *)ogs_hash_get(enb->enb_ue_hash,
                &enb_ue_s1ap_id, sizeof(enb_ue_s1ap_id));

    {
        enb_ue_t *enb_ue = NULL;
        ogs_list_for_each(&enb->enb_ue_list, enb_ue) {
            if (enb_ue_s1ap_id == enb_ue->enb_ue_s1ap_id)
                return enb_ue;
        }
        return NULL;
    }
}

enb_ue_t *enb_ue_find(uint32_t index)
{
    return ogs_pool_find(&enb_ue_pool, index);
}

enb_ue_t *enb_ue_find_by_mme_ue_s1ap_id(uint32_t mme_ue_s1ap_id)
{
    return enb_ue_find(mme_ue_s1ap_id);
}

enb_ue_t *enb_ue_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&enb_ue_pool, id);
}

/** sgw_ue_context handling function */
sgw_ue_t *sgw_ue_add(mme_sgw_t *sgw)
{
    sgw_ue_t *sgw_ue = NULL;

    ogs_assert(sgw);

    ogs_pool_id_calloc(&sgw_ue_pool, &sgw_ue);
    ogs_assert(sgw_ue);

    sgw_ue->t_s11_holding = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_s11_holding_timer_expire,
            OGS_UINT_TO_POINTER(sgw_ue->id));
    if (!sgw_ue->t_s11_holding) {
        ogs_error("ogs_timer_add() failed");
        ogs_pool_id_free(&sgw_ue_pool, sgw_ue);
        return NULL;
    }

    sgw_ue->sgw = sgw;

    ogs_list_add(&sgw->sgw_ue_list, sgw_ue);

    return sgw_ue;
}

void sgw_ue_remove(sgw_ue_t *sgw_ue)
{
    mme_sgw_t *sgw = NULL;

    ogs_assert(sgw_ue);
    sgw = sgw_ue->sgw;
    ogs_assert(sgw);

    ogs_list_remove(&sgw->sgw_ue_list, sgw_ue);

    ogs_assert(sgw_ue->t_s11_holding);
    ogs_timer_delete(sgw_ue->t_s11_holding);

    ogs_pool_id_free(&sgw_ue_pool, sgw_ue);
}

void sgw_ue_switch_to_sgw(sgw_ue_t *sgw_ue, mme_sgw_t *new_sgw)
{
    ogs_assert(sgw_ue);
    ogs_assert(sgw_ue->sgw);
    ogs_assert(new_sgw);

    /* Remove from the old sgw */
    ogs_list_remove(&sgw_ue->sgw->sgw_ue_list, sgw_ue);

    /* Add to the new sgw */
    ogs_list_add(&new_sgw->sgw_ue_list, sgw_ue);

    /* Switch to sgw */
    sgw_ue->sgw = new_sgw;
}

sgw_ue_t *sgw_ue_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&sgw_ue_pool, id);
}

sgw_relocation_e sgw_ue_check_if_relocated(mme_ue_t *mme_ue)
{
    enb_ue_t *enb_ue = NULL;
    sgw_ue_t *old_source_ue = NULL, *source_ue = NULL, *target_ue = NULL;
    mme_sgw_t *current = NULL, *changed = NULL;

    ogs_assert(mme_ue);
    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    ogs_assert(enb_ue);
    source_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    ogs_assert(source_ue);

    current = source_ue->sgw;
    ogs_assert(current);

    changed = changed_sgw_node(current, enb_ue, mme_ue);
    if (!changed) return SGW_WITHOUT_RELOCATION;

    /* Check if Old Source UE */
    old_source_ue = sgw_ue_find_by_id(source_ue->source_ue_id);
    if (old_source_ue) {
        sgw_ue_source_deassociate_target(old_source_ue);
        sgw_ue_remove(old_source_ue);
    }

    target_ue = sgw_ue_find_by_id(source_ue->target_ue_id);
    if (target_ue) {
        ogs_error("SGW-UE source has already been associated with target");
        return SGW_HAS_ALREADY_BEEN_RELOCATED;
    }

    target_ue = sgw_ue_add(changed);
    ogs_assert(target_ue);

    sgw_ue_source_associate_target(source_ue, target_ue);

    return SGW_WITH_RELOCATION;
}

void mme_ue_new_guti(mme_ue_t *mme_ue)
{
    served_gummei_t *served_gummei = NULL;

    ogs_assert(mme_ue);
    ogs_assert(mme_self()->num_of_served_gummei > 0);

    served_gummei = &mme_self()->served_gummei[0];

    ogs_assert(served_gummei->num_of_plmn_id > 0);
    ogs_assert(served_gummei->num_of_mme_gid > 0);
    ogs_assert(served_gummei->num_of_mme_code > 0);

    if (MME_NEXT_GUTI_IS_AVAILABLE(mme_ue)) {
        ogs_warn("GUTI has already been allocated");
        return;
    }

    memset(&mme_ue->next.guti, 0, sizeof(ogs_nas_eps_guti_t));

    /* Use the first configured plmn_id and mme group id */
    ogs_nas_from_plmn_id(
            &mme_ue->next.guti.nas_plmn_id, &served_gummei->plmn_id[0]);
    mme_ue->next.guti.mme_gid = served_gummei->mme_gid[0];
    mme_ue->next.guti.mme_code = served_gummei->mme_code[0];

    mme_ue->next.m_tmsi = mme_m_tmsi_alloc();
    ogs_assert(mme_ue->next.m_tmsi);
    mme_ue->next.guti.m_tmsi = *(mme_ue->next.m_tmsi);
}

void mme_ue_confirm_guti(mme_ue_t *mme_ue)
{
    ogs_assert(MME_NEXT_GUTI_IS_AVAILABLE(mme_ue));

    if (MME_CURRENT_GUTI_IS_AVAILABLE(mme_ue)) {
        /* MME has a VALID GUTI
         * As such, we need to remove previous GUTI in hash table */
        ogs_hash_unset_if_owner(self.guti_ue_hash,
                &mme_ue->current.guti, sizeof(ogs_nas_eps_guti_t), mme_ue);
        ogs_assert(mme_m_tmsi_free(mme_ue->current.m_tmsi) == OGS_OK);
    }

    /* Copying from Next to Current Guti */
    mme_ue->current.m_tmsi = mme_ue->next.m_tmsi;
    memcpy(&mme_ue->current.guti,
            &mme_ue->next.guti, sizeof(ogs_nas_eps_guti_t));

    /* Hashing Current GUTI */
    ogs_hash_set(self.guti_ue_hash,
            &mme_ue->current.guti, sizeof(ogs_nas_eps_guti_t), mme_ue);

    /* Clear Next GUTI */
    mme_ue->next.m_tmsi = NULL;

    ogs_debug("Confirm GUTI[G:%d,C:%d,M_TMSI:0x%x]",
              mme_ue->current.guti.mme_gid,
              mme_ue->current.guti.mme_code,
              mme_ue->current.guti.m_tmsi);
}

void mme_ue_set_p_tmsi(
        mme_ue_t *mme_ue,
        ogs_nas_mobile_identity_tmsi_t *nas_mobile_identity_tmsi)
{
    ogs_assert(mme_ue);
    ogs_assert(nas_mobile_identity_tmsi);

    /*
     * If the P-TMSI received from MSC/VLR is different from the current P-TMSI
     * known by the MME, store this new P-TMSI as 'Next P-TMSI'. This value will
     * be sent to the UE through the Attach Accept or TAU Accept message.
     *
     * When the UE sends an Attach Complete or TAU Complete message,
     * the MME updates the 'Current P-TMSI' with the value in 'Next P-TMSI',
     * thereby confirming and saving the new P-TMSI.
     */
    mme_ue->next.p_tmsi = be32toh(nas_mobile_identity_tmsi->tmsi);
    if (mme_ue->next.p_tmsi != INVALID_P_TMSI) {
        if (mme_ue->current.p_tmsi == mme_ue->next.p_tmsi)
            mme_ue->next.p_tmsi = INVALID_P_TMSI;
    }
}
void mme_ue_confirm_p_tmsi(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);
    ogs_assert(mme_ue->next.p_tmsi);

    mme_ue->current.p_tmsi = mme_ue->next.p_tmsi;
    mme_ue->next.p_tmsi = INVALID_P_TMSI;
}

static bool mme_sgw_is_default(const mme_sgw_t *sgw)
{
    ogs_assert(sgw);

    return sgw->num_of_tac == 0 &&
            sgw->num_of_e_cell_id == 0 &&
            !sgw->serving_plmn_present &&
            !sgw->imsi_plmn_present &&
            !sgw->imsi_prefix[0];
}

static bool compare_sgw_info(
        mme_sgw_t *node, enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    int i;

    ogs_assert(node);
    ogs_assert(enb_ue);

    if (mme_sgw_is_default(node))
        return false;

    for (i = 0; i < node->num_of_tac; i++)
        if (node->tac[i] == enb_ue->saved.tai.tac)
            return true;

    for (i = 0; i < node->num_of_e_cell_id; i++)
        if (node->e_cell_id[i] == enb_ue->saved.e_cgi.cell_id)
            return true;

    if (node->imsi_plmn_present && mme_ue && MME_UE_HAVE_IMSI(mme_ue) &&
            ogs_plmn_id_imsi_prefix_match(
                mme_ue->imsi_bcd, &node->imsi_plmn_id))
        return true;

    if (node->imsi_prefix[0] && mme_ue && MME_UE_HAVE_IMSI(mme_ue)) {
        size_t len = strlen(node->imsi_prefix);

        if (len > 0 && strncmp(mme_ue->imsi_bcd, node->imsi_prefix, len) == 0)
            return true;
    }

    if (!mme_ue_inbound_roam_on_tai(mme_ue, &enb_ue->saved.tai) &&
            node->serving_plmn_present &&
            memcmp(&node->serving_plmn_id, &enb_ue->saved.tai.plmn_id,
                OGS_PLMN_ID_LEN) == 0)
        return true;

    return false;
}

static bool mme_sgw_list_has_filters(void)
{
    mme_sgw_t *sgw = NULL;

    ogs_list_for_each(&mme_self()->sgw_list, sgw) {
        if (!mme_sgw_is_default(sgw))
            return true;
    }

    return false;
}

static mme_sgw_t *mme_sgw_select_for_ue(enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    mme_sgw_t *sgw = NULL;
    mme_sgw_t *default_sgw = NULL;
    mme_sgw_t *best = NULL;
    int best_order = INT_MAX;

    ogs_assert(enb_ue);

    ogs_list_for_each(&mme_self()->sgw_list, sgw) {
        if (mme_sgw_is_default(sgw)) {
            if (!default_sgw)
                default_sgw = sgw;
            continue;
        }

        if (!compare_sgw_info(sgw, enb_ue, mme_ue))
            continue;

        if (sgw->selection_order < best_order) {
            best_order = sgw->selection_order;
            best = sgw;
        }
    }

    if (best)
        return best;

    if (default_sgw)
        return default_sgw;

    return ogs_list_first(&mme_self()->sgw_list);
}

static void mme_sgw_format_rule(
        const mme_sgw_t *sgw, char *buf, int buflen)
{
    char plmn[OGS_PLMNIDSTRLEN];
    int len = 0;

    ogs_assert(sgw);
    ogs_assert(buf);
    ogs_assert(buflen > 0);

    buf[0] = '\0';

    if (mme_sgw_is_default(sgw)) {
        ogs_cpystrn(buf, "default", buflen);
        return;
    }

    if (sgw->imsi_plmn_present) {
        ogs_plmn_id_to_string(&sgw->imsi_plmn_id, plmn);
        len = ogs_snprintf(buf, buflen, "imsi_plmn:%s", plmn);
    }
    if (sgw->imsi_prefix[0]) {
        if (len > 0)
            len += ogs_snprintf(buf + len, buflen - len, "+");
        len += ogs_snprintf(buf + len, buflen - len, "imsi_prefix:%s",
                sgw->imsi_prefix);
    }
    if (sgw->serving_plmn_present) {
        ogs_plmn_id_to_string(&sgw->serving_plmn_id, plmn);
        if (len > 0)
            len += ogs_snprintf(buf + len, buflen - len, "+");
        len += ogs_snprintf(buf + len, buflen - len, "serving_plmn:%s", plmn);
    }
    if (sgw->num_of_tac > 0) {
        if (len > 0)
            len += ogs_snprintf(buf + len, buflen - len, "+");
        ogs_snprintf(buf + len, buflen - len, "tac");
    }
    if (sgw->num_of_e_cell_id > 0) {
        if (len > 0)
            len += ogs_snprintf(buf + len, buflen - len, "+");
        ogs_snprintf(buf + len, buflen - len, "e_cell_id");
    }

    if (len == 0)
        ogs_cpystrn(buf, "filtered", buflen);
    else
        ogs_snprintf(buf + len, buflen - len, " order:%d", sgw->selection_order);
}

static void mme_sgw_log_pick(
        mme_ue_t *mme_ue, const mme_sgw_t *sgw, const char *when,
        const mme_sgw_t *from_sgw)
{
    char addr[OGS_ADDRSTRLEN];
    char from_addr[OGS_ADDRSTRLEN];
    char rule[128];
    const char *imsi = "-";

    ogs_assert(sgw);
    ogs_assert(when);

    if (!sgw->gnode.sa_list)
        return;

    if (mme_ue && MME_UE_HAVE_IMSI(mme_ue))
        imsi = mme_ue->imsi_bcd;

    mme_sgw_format_rule(sgw, rule, sizeof(rule));
    OGS_ADDR(sgw->gnode.sa_list, addr);

    if (from_sgw && from_sgw->gnode.sa_list) {
        OGS_ADDR(from_sgw->gnode.sa_list, from_addr);
        ogs_info("[%s] SGW %s: %s -> %s [%s]",
                imsi, when, from_addr, addr, rule);
    } else {
        ogs_info("[%s] SGW %s: %s [%s]", imsi, when, addr, rule);
    }

    if (mme_ue && strcmp(imsi, "-") != 0) {
        char step[128];

        ogs_snprintf(step, sizeof(step), "sgw_%s %s", when, addr);
        mme_ue_progress(mme_ue, step);
    }
}

static mme_sgw_t *selected_sgw_node(
        mme_sgw_t *current, enb_ue_t *enb_ue)
{
    mme_sgw_t *next, *node;

    ogs_assert(current);
    ogs_assert(enb_ue);

    next = ogs_list_next(current);
    for (node = next; node; node = ogs_list_next(node)) {
        if (compare_sgw_info(node, enb_ue, NULL) == true)
            return node;
    }

    for (node = ogs_list_first(&mme_self()->sgw_list);
            node != next; node = ogs_list_next(node)) {
        if (compare_sgw_info(node, enb_ue, NULL) == true)
            return node;
    }

    return next ? next : ogs_list_first(&mme_self()->sgw_list);
}

static mme_sgw_t *changed_sgw_node(
        mme_sgw_t *current, enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    mme_sgw_t *changed = NULL;

    ogs_assert(current);
    ogs_assert(enb_ue);

    if (mme_sgw_list_has_filters()) {
        changed = mme_sgw_select_for_ue(enb_ue, mme_ue);
        if (changed && changed != current)
            return changed;
        return NULL;
    }

    changed = selected_sgw_node(current, enb_ue);
    if (changed && changed != current &&
            compare_sgw_info(changed, enb_ue, mme_ue) == true)
        return changed;

    return NULL;
}

void mme_sgw_reselect_for_ue_if_needed(mme_ue_t *mme_ue)
{
    enb_ue_t *enb_ue = NULL;
    sgw_ue_t *sgw_ue = NULL;
    mme_sgw_t *new_sgw = NULL;
    mme_sgw_t *current = NULL;

    ogs_assert(mme_ue);

    if (!mme_sgw_list_has_filters())
        return;

    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (!enb_ue)
        return;

    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    if (!sgw_ue)
        return;

    /* S11 context already established on this SGW */
    if (sgw_ue->sgw_s11_teid != 0)
        return;

    current = sgw_ue->sgw;
    ogs_assert(current);

    new_sgw = mme_sgw_select_for_ue(enb_ue, mme_ue);
    if (!new_sgw)
        return;

    if (new_sgw == current) {
        if (MME_UE_HAVE_IMSI(mme_ue))
            mme_sgw_log_pick(mme_ue, new_sgw, "confirmed", NULL);
        else
            ogs_debug("[%s] SGW unchanged after PLMN/TAC check", "-");
        return;
    }

    sgw_ue_switch_to_sgw(sgw_ue, new_sgw);
    mme_sgw_log_pick(mme_ue, new_sgw, "reselected", current);

    if (ECM_CONNECTED(mme_ue))
        mme_metrics_ue_connected_update(mme_ue);
}

mme_ue_t *mme_ue_add(enb_ue_t *enb_ue)
{
    mme_enb_t *enb = NULL;
    mme_ue_t *mme_ue = NULL;
    sgw_ue_t *sgw_ue = NULL;

    char buf[OGS_ADDRSTRLEN];

    ogs_assert(enb_ue);

    enb = mme_enb_find_by_id(enb_ue->enb_id);
    if (!enb) {
        ogs_error("[%d] eNB has already been removed", enb_ue->enb_id);
        return NULL;
    }

    ogs_pool_id_calloc(&mme_ue_pool, &mme_ue);
    if (mme_ue == NULL) {
        /*
         * Pool exhausted: sweep idle UEs once, then retry. Do not call the
         * evictor on every attach — under load that is O(N) per Initial UE
         * and can stall the main loop (looks like a hang, log stops).
         */
        mme_context_evict_idle_ues(0);
        ogs_pool_id_calloc(&mme_ue_pool, &mme_ue);
    }
    if (mme_ue == NULL) {
        static ogs_time_t last_pool_err = 0;
        ogs_time_t now = ogs_time_now();
        if (last_pool_err == 0 ||
                now - last_pool_err > ogs_time_from_sec(1)) {
            last_pool_err = now;
            ogs_error("Could not allocate mme_ue context from pool "
                    "(mme_ue_pool size=%d avail=%d list=%d, "
                    "enb_ue_pool size=%d avail=%d). "
                    "Raise global.max.ue or shorten mme.time.t3412.value "
                    "to free idle UE contexts sooner.",
                    ogs_pool_size(&mme_ue_pool),
                    ogs_pool_avail(&mme_ue_pool),
                    ogs_list_count(&self.mme_ue_list),
                    ogs_pool_size(&enb_ue_pool),
                    ogs_pool_avail(&enb_ue_pool));
        }
        return NULL;
    }

    /* Add All Timers */
    mme_ue->t3413.timer = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_t3413_expire,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!mme_ue->t3413.timer) {
        ogs_error("ogs_timer_add() failed");
        mme_ue_add_abort(mme_ue);
        return NULL;
    }
    mme_ue->t3413.pkbuf = NULL;
    mme_ue->t3422.timer = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_t3422_expire,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!mme_ue->t3422.timer) {
        ogs_error("ogs_timer_add() failed");
        mme_ue_add_abort(mme_ue);
        return NULL;
    }
    mme_ue->t3422.pkbuf = NULL;
    mme_ue->t3450.timer = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_t3450_expire,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!mme_ue->t3450.timer) {
        ogs_error("ogs_timer_add() failed");
        mme_ue_add_abort(mme_ue);
        return NULL;
    }
    mme_ue->t3450.pkbuf = NULL;
    mme_ue->t3460.timer = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_t3460_expire,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!mme_ue->t3460.timer) {
        ogs_error("ogs_timer_add() failed");
        mme_ue_add_abort(mme_ue);
        return NULL;
    }
    mme_ue->t3460.pkbuf = NULL;
    mme_ue->t3470.timer = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_t3470_expire,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!mme_ue->t3470.timer) {
        ogs_error("ogs_timer_add() failed");
        mme_ue_add_abort(mme_ue);
        return NULL;
    }
    mme_ue->t3470.pkbuf = NULL;
    mme_ue->t_mobile_reachable.timer = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_mobile_reachable_expire,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!mme_ue->t_mobile_reachable.timer) {
        ogs_error("ogs_timer_add() failed");
        mme_ue_add_abort(mme_ue);
        return NULL;
    }
    mme_ue->t_mobile_reachable.pkbuf = NULL;
    mme_ue->t_implicit_detach.timer = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_implicit_detach_expire,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!mme_ue->t_implicit_detach.timer) {
        ogs_error("ogs_timer_add() failed");
        mme_ue_add_abort(mme_ue);
        return NULL;
    }
    mme_ue->t_implicit_detach.pkbuf = NULL;

    mme_ue->gn.t_gn_holding = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_gn_holding_timer_expire,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (! mme_ue->gn.t_gn_holding) {
        ogs_error("ogs_timer_add() failed");
        mme_ue_add_abort(mme_ue);
        return NULL;
    }
    mme_ue->gn.gtp_xact_id = OGS_INVALID_POOL_ID;

    mme_ue->t_sgs_ts6_1 = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_sgs_ts6_1_expire,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!mme_ue->t_sgs_ts6_1) {
        ogs_error("ogs_timer_add() failed");
        mme_ue_add_abort(mme_ue);
        return NULL;
    }

    mme_ue->t_s6a = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_s6a_expire,
            OGS_UINT_TO_POINTER(mme_ue->id));
    if (!mme_ue->t_s6a) {
        ogs_error("ogs_timer_add() failed");
        mme_ue_add_abort(mme_ue);
        return NULL;
    }

    ogs_list_init(&mme_ue->sess_list);

    /*
     * Seed the EBI -> bearer-id table with OGS_INVALID_POOL_ID so
     * mme_bearer_find_by_ue_ebi() correctly reports "no bearer" for
     * slots that have not been allocated yet (calloc gave us zero,
     * which is a valid pool id on some configurations).
     */
    {
        int i;
        for (i = 0; i <= MAX_EPS_BEARER_ID; i++)
            mme_ue->ebi_to_bearer_id[i] = OGS_INVALID_POOL_ID;
    }

    /* Set MME-S11-TEID */
    ogs_pool_alloc(&mme_s11_teid_pool, &mme_ue->mme_s11_teid_node);
    if (!mme_ue->mme_s11_teid_node) {
        ogs_error("Could not allocate MME-S11-TEID");
        mme_ue_add_abort(mme_ue);
        return NULL;
    }
    mme_ue->mme_s11_teid = *(mme_ue->mme_s11_teid_node);
    ogs_hash_set(self.mme_s11_teid_hash,
            &mme_ue->mme_s11_teid, sizeof(mme_ue->mme_s11_teid), mme_ue);

    /* Set MME-Gn-TEID */
    ogs_pool_alloc(&mme_gn_teid_pool, &mme_ue->gn.mme_gn_teid_node);
    if (!mme_ue->gn.mme_gn_teid_node) {
        ogs_error("Could not allocate MME-Gn-TEID");
        mme_ue_add_abort(mme_ue);
        return NULL;
    }
    mme_ue->gn.mme_gn_teid = *(mme_ue->gn.mme_gn_teid_node);
    ogs_hash_set(self.mme_gn_teid_hash,
            &mme_ue->gn.mme_gn_teid, sizeof(mme_ue->gn.mme_gn_teid), mme_ue);

    /*
     * When used for the first time, if last node is set,
     * the search is performed from the first SGW in a round-robin manner.
     */
    if (mme_sgw_list_has_filters()) {
        mme_self()->sgw = mme_sgw_select_for_ue(enb_ue, mme_ue);
    } else {
        if (mme_self()->sgw == NULL)
            mme_self()->sgw = ogs_list_last(&mme_self()->sgw_list);
        mme_self()->sgw = selected_sgw_node(mme_self()->sgw, enb_ue);
    }
    if (!mme_self()->sgw) {
        uint16_t tac = 0;
        uint32_t cell_id = 0, enb_id = 0;

        mme_log_radio(NULL, enb_ue, &tac, &cell_id, &enb_id);
        ogs_error("No SGW configured TAC[0x%04x] eNB_ID[0x%x] cell[0x%x]",
                tac, enb_id, cell_id);
        mme_ue_add_abort(mme_ue);
        return NULL;
    }

    sgw_ue = sgw_ue_add(mme_self()->sgw);
    if (!sgw_ue) {
        char sgw_peer[OGS_ADDRSTRLEN];

        ogs_error("[%s] Could not allocate sgw_ue SGW[%s]:%d",
                mme_log_imsi(mme_ue),
                OGS_ADDR(mme_self()->sgw->gnode.sa_list, sgw_peer),
                mme_self()->sgw->gnode.sa_list ?
                    OGS_PORT(mme_self()->sgw->gnode.sa_list) : 0);
        mme_ue_add_abort(mme_ue);
        return NULL;
    }
    if (!sgw_ue->gnode) {
        ogs_error("[%s] SGW has no gnode after pick", mme_log_imsi(mme_ue));
        sgw_ue_remove(sgw_ue);
        mme_ue_add_abort(mme_ue);
        return NULL;
    }

    sgw_ue_associate_mme_ue(sgw_ue, mme_ue);

    if (mme_sgw_list_has_filters())
        mme_sgw_log_pick(mme_ue, mme_self()->sgw, "initial", NULL);
    else
        ogs_debug("UE using SGW on IP[%s]",
                OGS_ADDR(sgw_ue->gnode->sa_list, buf));

    /* Clear VLR */
    mme_ue->csmap = NULL;
    mme_ue->vlr_ostream_id = 0;

    /* Initialization */
    mme_ue->nas_eps.mme.ksi = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    mme_ue->context_created = ogs_time_now();

    mme_ue_fsm_init(mme_ue);

    /*
     * /ue-info iterates self.mme_ue_list on the MHD thread. Guard
     * the link insertion so the reader sees a fully-initialized
     * mme_ue or no mme_ue at all.
     */
    ogs_metrics_dump_lock();
    ogs_list_add(&self.mme_ue_list, mme_ue);
    ogs_metrics_dump_unlock();

    ogs_info("[Added] Number of MME-UEs is now %d",
            ogs_list_count(&self.mme_ue_list));

    return mme_ue;
}

void mme_ue_remove(mme_ue_t *mme_ue)
{
    sgw_ue_t *sgw_ue = NULL;
    ogs_assert(mme_ue);

    /*
     * Take the metrics dump lock for the duration of teardown.
     * The /ue-info dumper may be walking mme_ue_list right now, and
     * we are about to free this mme_ue plus its session/bearer
     * sublists - racing the reader could segfault. The lock is
     * released only after pool_id_free() so by the time the MHD
     * thread re-acquires it, this mme_ue is gone from the list.
     */
    ogs_metrics_dump_lock();
    mme_metrics_on_ue_remove(mme_ue);
    ogs_list_remove(&self.mme_ue_list, mme_ue);

    mme_ue_fsm_fini(mme_ue);

    /* Stop timers first, then drop any already-queued events for this UE. */
    CLEAR_MME_UE_ALL_TIMERS(mme_ue);
    mme_event_purge_mme_ue(mme_ue->id);

    ogs_hash_set(self.mme_s11_teid_hash,
            &mme_ue->mme_s11_teid, sizeof(mme_ue->mme_s11_teid), NULL);
    ogs_hash_set(self.mme_gn_teid_hash,
            &mme_ue->gn.mme_gn_teid, sizeof(mme_ue->gn.mme_gn_teid), NULL);

    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    if (sgw_ue) sgw_ue_remove(sgw_ue);

    if (mme_ue->imsi_len != 0)
        ogs_hash_unset_if_owner(mme_self()->imsi_ue_hash,
                mme_ue->imsi, mme_ue->imsi_len, mme_ue);

    if (MME_CURRENT_GUTI_IS_AVAILABLE(mme_ue)) {
        ogs_hash_unset_if_owner(self.guti_ue_hash,
                &mme_ue->current.guti, sizeof(ogs_nas_eps_guti_t), mme_ue);
        ogs_assert(mme_m_tmsi_free(mme_ue->current.m_tmsi) == OGS_OK);
    }

    if (MME_NEXT_GUTI_IS_AVAILABLE(mme_ue)) {
        ogs_assert(mme_m_tmsi_free(mme_ue->next.m_tmsi) == OGS_OK);
    }

    /* Clear the saved PDN Connectivity Request */
    OGS_NAS_CLEAR_DATA(&mme_ue->pdn_connectivity_request);

    /* Clear Service Indicator */
    CLEAR_SERVICE_INDICATOR(mme_ue);

    /* Free UeRadioCapability */
    OGS_ASN_CLEAR_DATA(&mme_ue->ueRadioCapability);

    /* Clear Transparent Container */
    OGS_ASN_CLEAR_DATA(&mme_ue->container);

    ogs_timer_delete(mme_ue->t3413.timer);
    ogs_timer_delete(mme_ue->t3422.timer);
    ogs_timer_delete(mme_ue->t3450.timer);
    ogs_timer_delete(mme_ue->t3460.timer);
    ogs_timer_delete(mme_ue->t3470.timer);
    ogs_timer_delete(mme_ue->t_mobile_reachable.timer);
    ogs_timer_delete(mme_ue->t_implicit_detach.timer);
    ogs_timer_delete(mme_ue->gn.t_gn_holding);
    ogs_timer_delete(mme_ue->t_sgs_ts6_1);
    ogs_timer_delete(mme_ue->t_s6a);

    mme_ue->enb_ue_id = OGS_INVALID_POOL_ID;

    mme_sess_remove_all(mme_ue);
    mme_session_remove_all(mme_ue);

    ogs_pool_free(&mme_s11_teid_pool, mme_ue->mme_s11_teid_node);
    ogs_pool_free(&mme_gn_teid_pool, mme_ue->gn.mme_gn_teid_node);
    ogs_pool_id_free(&mme_ue_pool, mme_ue);
    ogs_metrics_dump_unlock();

    ogs_info("[Removed] Number of MME-UEs is now %d",
            ogs_list_count(&self.mme_ue_list));
}

void mme_ue_remove_all(void)
{
    mme_ue_t *mme_ue = NULL, *next = NULL;;

    ogs_list_for_each_safe(&self.mme_ue_list, next, mme_ue) {
        enb_ue_t *enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);

        if (enb_ue) enb_ue_remove(enb_ue);

        mme_ue_remove(mme_ue);
    }
}

mme_ue_t *mme_ue_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&mme_ue_pool, id);
}

bool mme_ue_is_valid_for_s1(mme_ue_t *mme_ue)
{
    mme_ue_t *found = NULL;

    if (!mme_ue)
        return false;

    found = mme_ue_find_by_id(mme_ue->id);
    if (found != mme_ue)
        return false;

    if (mme_ue->ue_context_will_remove)
        return false;

    if (!OGS_FSM_STATE(&mme_ue->sm))
        return false;

    if (OGS_FSM_CHECK(&mme_ue->sm, emm_state_ue_context_will_remove))
        return false;

    if (OGS_FSM_CHECK(&mme_ue->sm, emm_state_final))
        return false;

    return true;
}

void mme_ue_fsm_init(mme_ue_t *mme_ue)
{
    mme_event_t e;

    ogs_assert(mme_ue);

    memset(&e, 0, sizeof(e));
    e.mme_ue_id = mme_ue->id;
    ogs_fsm_init(&mme_ue->sm, emm_state_initial, emm_state_final, &e);
}

void mme_ue_fsm_fini(mme_ue_t *mme_ue)
{
    mme_event_t e;

    ogs_assert(mme_ue);

    memset(&e, 0, sizeof(e));
    e.mme_ue_id = mme_ue->id;
    ogs_fsm_fini(&mme_ue->sm, &e);
}

mme_ue_t *mme_ue_find_by_imsi_bcd(const char *imsi_bcd)
{
    uint8_t imsi[OGS_MAX_IMSI_LEN];
    int imsi_len = 0;

    ogs_assert(imsi_bcd);

    ogs_bcd_to_buffer(imsi_bcd, imsi, &imsi_len);

    return mme_ue_find_by_imsi(imsi, imsi_len);
}

mme_ue_t *mme_ue_find_by_imsi(const uint8_t *imsi, int imsi_len)
{
    ogs_assert(imsi && imsi_len);

    return (mme_ue_t *)ogs_hash_get(self.imsi_ue_hash, imsi, imsi_len);
}

mme_ue_t *mme_ue_find_by_guti(const ogs_nas_eps_guti_t *guti)
{
    ogs_assert(guti);

    return (mme_ue_t *)ogs_hash_get(
            self.guti_ue_hash, guti, sizeof(ogs_nas_eps_guti_t));
}

mme_ue_t *mme_ue_find_by_s11_local_teid(uint32_t teid)
{
    return ogs_hash_get(self.mme_s11_teid_hash, &teid, sizeof(teid));
}

mme_ue_t *mme_ue_find_by_gn_local_teid(uint32_t teid)
{
    return ogs_hash_get(self.mme_gn_teid_hash, &teid, sizeof(teid));
}

static mme_ue_t *mme_ue_lookup_by_imsi_bcd(const char *imsi_bcd)
{
    mme_ue_t *mme_ue = NULL;

    ogs_assert(imsi_bcd);

    mme_ue = mme_ue_find_by_imsi_bcd(imsi_bcd);
    if (mme_ue) {
        ogs_mme_trace_set(
                enb_ue_find_by_id(mme_ue->enb_ue_id),
                mme_ue, NULL, "lookup");
        OGS_TLOG_INFO("known UE by IMSI");
    } else {
        ogs_trace_ctx_t ctx;

        memset(&ctx, 0, sizeof(ctx));
        ogs_cpystrn(ctx.imsi, imsi_bcd, sizeof(ctx.imsi));
        ogs_cpystrn(ctx.proc, "lookup", sizeof(ctx.proc));
        ogs_trace_set(&ctx);
        OGS_TLOG_INFO("Unknown UE by IMSI");
    }

    return mme_ue;
}

static mme_ue_t *mme_ue_lookup_by_eps_guti(
        const ogs_nas_eps_mobile_identity_guti_t *eps_guti)
{
    mme_ue_t *mme_ue = NULL;
    ogs_nas_eps_guti_t ogs_nas_guti;

    ogs_assert(eps_guti);

    ogs_nas_guti.nas_plmn_id = eps_guti->nas_plmn_id;
    ogs_nas_guti.mme_gid = eps_guti->mme_gid;
    ogs_nas_guti.mme_code = eps_guti->mme_code;
    ogs_nas_guti.m_tmsi = eps_guti->m_tmsi;

    mme_ue = mme_ue_find_by_guti(&ogs_nas_guti);
    if (mme_ue) {
        ogs_info("[%s] Known UE by GUTI[G:%d,C:%d,M_TMSI:0x%x]",
                mme_ue->imsi_bcd,
                ogs_nas_guti.mme_gid,
                ogs_nas_guti.mme_code,
                ogs_nas_guti.m_tmsi);
    } else {
        ogs_info("Unknown UE by GUTI[G:%d,C:%d,M_TMSI:0x%x]",
                ogs_nas_guti.mme_gid,
                ogs_nas_guti.mme_code,
                ogs_nas_guti.m_tmsi);
    }

    return mme_ue;
}

static mme_ue_t *mme_ue_lookup_by_eps_mobile_identity(
        const ogs_nas_eps_mobile_identity_t *eps_mobile_identity,
        const char *proc)
{
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];
    uint8_t type;

    ogs_assert(proc);

    if (!eps_mobile_identity)
        return NULL;

    if (eps_mobile_identity->length == 0) {
        ogs_debug("EPS mobile identity absent (length=0) [%s]", proc);
        return NULL;
    }

    type = eps_mobile_identity->guti.type;

    switch (type) {
    case OGS_NAS_EPS_MOBILE_IDENTITY_IMSI:
        if (sizeof(ogs_nas_mobile_identity_imsi_t) !=
                eps_mobile_identity->length) {
            ogs_error("mobile_identity length (%d != %d) [%s]",
                    (int)sizeof(ogs_nas_mobile_identity_imsi_t),
                    eps_mobile_identity->length, proc);
            return NULL;
        }
        ogs_nas_eps_imsi_to_bcd(
                &eps_mobile_identity->imsi, eps_mobile_identity->length,
                imsi_bcd);
        return mme_ue_lookup_by_imsi_bcd(imsi_bcd);

    case OGS_NAS_EPS_MOBILE_IDENTITY_GUTI:
        if (eps_mobile_identity->length <
                sizeof(ogs_nas_eps_mobile_identity_guti_t)) {
            ogs_error("GUTI mobile_identity length too short (%d) [%s]",
                    eps_mobile_identity->length, proc);
            return NULL;
        }
        return mme_ue_lookup_by_eps_guti(&eps_mobile_identity->guti);

    case OGS_NAS_MOBILE_IDENTITY_NONE:
        ogs_debug("EPS mobile identity type NONE (0) [%s]", proc);
        return NULL;

    case OGS_NAS_MOBILE_IDENTITY_IMEI:
    case OGS_NAS_MOBILE_IDENTITY_IMEISV:
        ogs_debug("EPS mobile identity type %u (IMEI/IMEISV) "
                "not used for UE lookup [%s]", type, proc);
        return NULL;

    default:
        ogs_error("Invalid EPS mobile identity type [%u] [%s]", type, proc);
        ogs_log_hexdump(OGS_LOG_ERROR,
                (unsigned char *)eps_mobile_identity,
                ogs_min(eps_mobile_identity->length + 1,
                    sizeof(ogs_nas_eps_mobile_identity_t)));
        return NULL;
    }
}

mme_ue_t *mme_ue_find_by_message(const ogs_nas_eps_message_t *message)
{
    mme_ue_t *mme_ue = NULL;
    const ogs_nas_eps_attach_request_t *attach_request = NULL;
    const ogs_nas_eps_detach_request_from_ue_t *detach_request = NULL;
    const ogs_nas_eps_tracking_area_update_request_t *tau_request = NULL;
    const ogs_nas_eps_extended_service_request_t *extended_service_request = NULL;
    const ogs_nas_mobile_identity_t *mobile_identity = NULL;

    const ogs_nas_mobile_identity_tmsi_t *mobile_identity_tmsi = NULL;
    const served_gummei_t *served_gummei = NULL;
    ogs_nas_eps_guti_t ogs_nas_guti;

    switch (message->emm.h.message_type) {
    case OGS_NAS_EPS_ATTACH_REQUEST:
        attach_request = &message->emm.attach_request;
        mme_ue = mme_ue_lookup_by_eps_mobile_identity(
                &attach_request->eps_mobile_identity, "attach");
        break;
    case OGS_NAS_EPS_TRACKING_AREA_UPDATE_REQUEST:
        tau_request = &message->emm.tracking_area_update_request;
        mme_ue = mme_ue_lookup_by_eps_mobile_identity(
                &tau_request->old_guti, "tau");
        break;
    case OGS_NAS_EPS_DETACH_REQUEST:
        detach_request = &message->emm.detach_request_from_ue;
        mme_ue = mme_ue_lookup_by_eps_mobile_identity(
                &detach_request->eps_mobile_identity, "detach");
        break;
    case OGS_NAS_EPS_EXTENDED_SERVICE_REQUEST:
        extended_service_request = &message->emm.extended_service_request;
        mobile_identity = &extended_service_request->m_tmsi;

        if (mobile_identity->length == 0) {
            ogs_debug("Mobile identity absent (length=0) [service-req]");
            break;
        }

        switch (mobile_identity->tmsi.type) {
        case OGS_NAS_MOBILE_IDENTITY_TMSI:
            mobile_identity_tmsi = &mobile_identity->tmsi;
            served_gummei = &mme_self()->served_gummei[0];

            /* Use the first configured plmn_id and mme group id */
            ogs_nas_from_plmn_id(
                    &ogs_nas_guti.nas_plmn_id, &served_gummei->plmn_id[0]);
            ogs_nas_guti.mme_gid = served_gummei->mme_gid[0];
            ogs_nas_guti.mme_code = served_gummei->mme_code[0];
            ogs_nas_guti.m_tmsi = mobile_identity_tmsi->tmsi;

            mme_ue = mme_ue_find_by_guti(&ogs_nas_guti);
            if (mme_ue) {
                ogs_info("[%s] Known UE by GUTI[G:%d,C:%d,M_TMSI:0x%x]",
                        mme_ue->imsi_bcd,
                        ogs_nas_guti.mme_gid,
                        ogs_nas_guti.mme_code,
                        ogs_nas_guti.m_tmsi);
            } else {
                ogs_info("Unknown UE by GUTI[G:%d,C:%d,M_TMSI:0x%x]",
                        ogs_nas_guti.mme_gid,
                        ogs_nas_guti.mme_code,
                        ogs_nas_guti.m_tmsi);
            }
            break;
        case OGS_NAS_MOBILE_IDENTITY_NONE:
            ogs_debug("Mobile identity type NONE (0) [service-req]");
            break;
        default:
            ogs_error("Invalid mobile identity type [%u] [service-req]",
                    mobile_identity->tmsi.type);
            ogs_log_hexdump(OGS_LOG_ERROR,
                    (unsigned char *)mobile_identity,
                    ogs_min(mobile_identity->length + 1,
                        sizeof(ogs_nas_mobile_identity_t)));
            break;
        }
        break;
    default:
        break;
    }

    return mme_ue;
}

int mme_ue_set_imsi(mme_ue_t *mme_ue, char *imsi_bcd)
{
    mme_ue_t *old_mme_ue = NULL;
    mme_sess_t *old_sess = NULL;
    mme_bearer_t *old_bearer = NULL;
    sgw_ue_t *sgw_ue = NULL, *old_sgw_ue = NULL;
    ogs_assert(mme_ue && imsi_bcd);

    /*
     * Issues: #4357
     *
     * Remove the old IMSI hash entry BEFORE overwriting mme_ue->imsi.
     *
     * Previously, the hash removal at the end of this function used
     * mme_ue->imsi AFTER it had already been overwritten with the new IMSI,
     * so the OLD IMSI entry was never actually removed from the hash table.
     *
     * This caused a dangling pointer: the old IMSI key still pointed to
     * this mme_ue_t, and after mme_ue_remove() freed the object (with
     * mme_ue_fsm_fini()), a subsequent lookup by the old IMSI would return
     * a context with an invalid FSM state, leading to ogs_assert_if_reached()
     * in mme_state_operational().
     */
    if (mme_ue->imsi_len != 0)
        ogs_hash_unset_if_owner(mme_self()->imsi_ue_hash,
                mme_ue->imsi, mme_ue->imsi_len, mme_ue);

    ogs_cpystrn(mme_ue->imsi_bcd, imsi_bcd, OGS_MAX_IMSI_BCD_LEN+1);
    ogs_bcd_to_buffer(mme_ue->imsi_bcd, mme_ue->imsi, &mme_ue->imsi_len);

    /* Check if OLD mme_ue_t is existed */
    old_mme_ue = mme_ue_find_by_imsi(mme_ue->imsi, mme_ue->imsi_len);
    if (old_mme_ue) {
        /* Check if OLD mme_ue_t is different with NEW mme_ue_t */
        if (ogs_pool_index(&mme_ue_pool, mme_ue) !=
            ogs_pool_index(&mme_ue_pool, old_mme_ue)) {
            ogs_warn("[%s] OLD UE Context Release", mme_ue->imsi_bcd);
            if (ECM_CONNECTED(old_mme_ue)) {
                enb_ue_t *enb_ue = enb_ue_find_by_id(old_mme_ue->enb_ue_id);
                enb_ue_t *enb_ue_holding = NULL;

                /*
                 * Keep the old S1 context until the new attach/TAU procedure
                 * is authenticated. CLEAR_S1_CONTEXT(mme_ue) will then send
                 * UEContextReleaseCommand to the old E-UTRAN context.
                 *
                 * Do not use HOLDING_S1_CONTEXT(old_mme_ue) here: that macro
                 * stores the holding id in old_mme_ue, but this function
                 * removes old_mme_ue below after moving the session context
                 * to the new mme_ue.
                 */
                ogs_warn("[%s] Holding old S1 context", mme_ue->imsi_bcd);
                if (enb_ue) {
                    int r;

                    enb_ue_holding =
                        enb_ue_find_by_id(mme_ue->enb_ue_holding_id);
                    if (enb_ue_holding) {
                        ogs_error("[%s] Holding S1 context already exists",
                                mme_ue->imsi_bcd);
                        ogs_error("[%s]    ENB_UE_S1AP_ID[%d] "
                                "MME_UE_S1AP_ID[%d]",
                                mme_ue->imsi_bcd,
                                enb_ue_holding->enb_ue_s1ap_id,
                                enb_ue_holding->mme_ue_s1ap_id);
                        r = s1ap_send_ue_context_release_command(
                                enb_ue_holding,
                                S1AP_Cause_PR_nas,
                                S1AP_CauseNas_normal_release,
                                S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE, 0);
                        ogs_expect(r == OGS_OK);
                    } else if (mme_ue->enb_ue_holding_id !=
                            OGS_INVALID_POOL_ID) {
                        ogs_error("[%s] Holding S1 context has already "
                                "been removed", mme_ue->imsi_bcd);
                    }
                    mme_ue->enb_ue_holding_id = OGS_INVALID_POOL_ID;

                    enb_ue->mme_ue_id = OGS_INVALID_POOL_ID;

                    ogs_warn("[%s]    ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d]",
                            old_mme_ue->imsi_bcd,
                            enb_ue->enb_ue_s1ap_id,
                            enb_ue->mme_ue_s1ap_id);

                    enb_ue->ue_ctx_rel_action =
                        S1AP_UE_CTX_REL_S1_CONTEXT_REMOVE;
                    ogs_timer_start(enb_ue->t_s1_holding,
                            mme_timer_cfg(MME_TIMER_S1_HOLDING)->duration);

                    mme_ue->enb_ue_holding_id = old_mme_ue->enb_ue_id;
                    old_mme_ue->enb_ue_id = OGS_INVALID_POOL_ID;
                } else {
                    ogs_error("[%s] S1 Context has already been removed",
                                old_mme_ue->imsi_bcd);
                }
            }

    /*
     * We should delete the MME-Session Context in the MME-UE Context.
     * Otherwise, all unnecessary SESSIONs remain in SMF/UPF.
     *
     * In order to do this, MME-Session Context should be moved
     * from OLD MME-UE Context to NEW MME-UE Context.
     *
     * If needed, The Session deletion process in NEW-MME UE context will work.
     *
     * Note that we should not send Session-Release to the SGW-C at this point.
     * Another GTPv2-C Transaction can cause fatal errors.
     */
            /* Phase-1 : Change MME-UE Context in Session Context */
            ogs_list_for_each(&old_mme_ue->sess_list, old_sess) {
                ogs_list_for_each(&old_sess->bearer_list, old_bearer) {
                    old_bearer->mme_ue_id = mme_ue->id;

                    if (mme_ebi_reserve(mme_ue, old_bearer->ebi) == OGS_OK)
                        ogs_info("Bearer reserved (EBI=%d IMSI=%s)",
                                old_bearer->ebi, mme_ue->imsi_bcd);
                    else
                        ogs_error("Failed to reserve bearer (EBI=%d IMSI=%s)",
                                old_bearer->ebi, mme_ue->imsi_bcd);

                    /* Carry over the EBI -> bearer-id mapping so
                     * mme_bearer_find_by_ue_ebi() on the NEW UE keeps
                     * working immediately after the migration. */
                    if (old_bearer->ebi >= MIN_EPS_BEARER_ID &&
                            old_bearer->ebi <= MAX_EPS_BEARER_ID) {
                        mme_ue->ebi_to_bearer_id[old_bearer->ebi] =
                                old_bearer->id;
                        old_mme_ue->ebi_to_bearer_id[old_bearer->ebi] =
                                OGS_INVALID_POOL_ID;
                    }
                }
                old_sess->mme_ue_id = mme_ue->id;
            }

            /* Phase-2 : Move Session Context from OLD to NEW MME-UE Context */
            if (!ogs_list_empty(&mme_ue->sess_list)) {
                mme_sess_t *stale_sess = NULL, *stale_next = NULL;

                ogs_warn("[%s] NEW UE has session(s) during OLD context merge; "
                        "dropping incomplete NEW sessions",
                        mme_ue->imsi_bcd);
                ogs_list_for_each_safe(&mme_ue->sess_list, stale_next,
                        stale_sess) {
                    mme_sess_remove(stale_sess);
                }
            }

            memcpy(&mme_ue->sess_list,
                    &old_mme_ue->sess_list, sizeof(mme_ue->sess_list));

            /* Phase-3 : Clear Session Context in OLD MME-UE Context */
            memset(&old_mme_ue->sess_list, 0, sizeof(old_mme_ue->sess_list));

            /* Phase-4 : Move sgw_ue->sgw_s11_teid */
            sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
            ogs_assert(sgw_ue);
            old_sgw_ue = sgw_ue_find_by_id(old_mme_ue->sgw_ue_id);
            ogs_assert(old_sgw_ue);
            sgw_ue->sgw_s11_teid = old_sgw_ue->sgw_s11_teid;

            mme_ue_remove(old_mme_ue);
        }
    }

    /* Register new IMSI in hash.
     * Old IMSI hash entry was already removed at the top of this function. */
    ogs_hash_set(self.imsi_ue_hash, mme_ue->imsi, mme_ue->imsi_len, mme_ue);

    mme_ue->hssmap = mme_hssmap_find_by_imsi_bcd(mme_ue->imsi_bcd);
    if (mme_ue->hssmap) {
        char plmn_id_str[OGS_PLMNIDSTRLEN];
        const char *realm = mme_ue->hssmap->realm ? mme_ue->hssmap->realm : "NULL";
        const char *host = mme_ue->hssmap->host ? mme_ue->hssmap->host : "NULL";

        ogs_plmn_id_to_string(&mme_ue->hssmap->plmn_id, plmn_id_str);
        ogs_debug("[%s]: HSS Map HPLMN[%s] Realm[%s] Host[%s]",
                   mme_ue->imsi_bcd, plmn_id_str, realm, host);

    }

    mme_sgw_reselect_for_ue_if_needed(mme_ue);
    mme_ue_progress(mme_ue, "imsi_known");

    return OGS_OK;
}

bool mme_ue_have_indirect_tunnel(mme_ue_t *mme_ue)
{
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;

    ogs_assert(mme_ue);

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        ogs_list_for_each(&sess->bearer_list, bearer) {
            if (MME_HAVE_ENB_DL_INDIRECT_TUNNEL(bearer) ||
                MME_HAVE_ENB_UL_INDIRECT_TUNNEL(bearer) ||
                MME_HAVE_SGW_DL_INDIRECT_TUNNEL(bearer) ||
                MME_HAVE_SGW_UL_INDIRECT_TUNNEL(bearer)) {
                return true;
            }
        }
    }

    return false;
}

void mme_ue_clear_indirect_tunnel(mme_ue_t *mme_ue)
{
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;

    ogs_assert(mme_ue);

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        ogs_list_for_each(&sess->bearer_list, bearer) {
            CLEAR_INDIRECT_TUNNEL(bearer);
        }
    }
}

bool mme_ue_have_active_eps_bearers(mme_ue_t *mme_ue)
{
    mme_sess_t *sess = NULL;

    ogs_assert(mme_ue);

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        if (mme_sess_have_active_eps_bearers(sess) == true)
            return true;
    }

    return false;
}

bool mme_sess_have_active_eps_bearers(mme_sess_t *sess)
{
    mme_bearer_t *bearer = NULL;
    ogs_assert(sess);

    ogs_list_for_each(&sess->bearer_list, bearer) {
        if (OGS_FSM_CHECK(&bearer->sm, esm_state_active))
            return true;
    }

    return false;
}

bool mme_ue_have_session_release_pending(mme_ue_t *mme_ue)
{
    mme_sess_t *sess = NULL;

    ogs_assert(mme_ue);

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        if (mme_sess_have_session_release_pending(sess) == true)
            return true;
    }

    return false;
}

bool mme_sess_have_session_release_pending(mme_sess_t *sess)
{
    mme_bearer_t *bearer = NULL;
    ogs_assert(sess);

    ogs_list_for_each(&sess->bearer_list, bearer) {
        if (OGS_FSM_CHECK(&bearer->sm, esm_state_pdn_will_disconnect))
            return true;
    }

    return false;
}

int mme_ue_xact_count(mme_ue_t *mme_ue, uint8_t org)
{
    sgw_ue_t *sgw_ue = NULL;
    ogs_gtp_node_t *gnode = NULL;

    ogs_assert(org == OGS_GTP_LOCAL_ORIGINATOR ||
                org == OGS_GTP_REMOTE_ORIGINATOR);

    sgw_ue = sgw_ue_find_by_id(mme_ue->sgw_ue_id);
    if (!sgw_ue) return 0;

    gnode = sgw_ue->gnode;
    if (!gnode) return 0;

    return org == OGS_GTP_LOCAL_ORIGINATOR ?
            ogs_list_count(&gnode->local_list) :
                ogs_list_count(&gnode->remote_list);
}

void enb_ue_associate_mme_ue(enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);
    ogs_assert(enb_ue);

    mme_ue->enb_ue_id = enb_ue->id;
    enb_ue->mme_ue_id = mme_ue->id;

    /* UE is back to ECM-CONNECTED — drop the idle stamp so the LRU
     * evictor only considers UEs that are genuinely idle. */
    mme_ue->idle_since = 0;
    mme_idle_t3346_clear(mme_ue);

    /*
     * T-ADS (3GPP TS 23.272 / TS 29.272): the UE just established a
     * signalling connection (ECM-CONNECTED). If the HSS armed URRP-MME,
     * report reachability now via S6a NOR. This covers both the paged
     * response and an autonomous re-appearance (periodic TAU / Service
     * Request) after paging failed; mme_s6a_report_urrp() is a no-op
     * when URRP-MME is not armed.
     */
    mme_s6a_report_urrp(mme_ue);

    mme_metrics_ue_connected_update(mme_ue);
}

void enb_ue_deassociate_mme_ue(enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);
    ogs_assert(enb_ue);

    if (mme_ue->enb_ue_id == enb_ue->id)
        mme_ue->enb_ue_id = OGS_INVALID_POOL_ID;
    else
        ogs_error("Cannot deassociate mme_ue->enb_ue_id[%d] != enb_ue->id[%d]",
                mme_ue->enb_ue_id, enb_ue->id);

    mme_metrics_ue_connected_clear(mme_ue);
}

void enb_ue_source_associate_target(enb_ue_t *source_ue, enb_ue_t *target_ue)
{
    ogs_assert(source_ue);
    ogs_assert(target_ue);

    target_ue->mme_ue_id = source_ue->mme_ue_id;
    target_ue->source_ue_id = source_ue->id;
    source_ue->target_ue_id = target_ue->id;
}

void enb_ue_source_deassociate_target(enb_ue_t *enb_ue)
{
    enb_ue_t *source_ue = NULL;
    enb_ue_t *target_ue = NULL;
    ogs_assert(enb_ue);

    if (enb_ue->target_ue_id >= OGS_MIN_POOL_ID &&
        enb_ue->target_ue_id <= OGS_MAX_POOL_ID) {
        source_ue = enb_ue;
        target_ue = enb_ue_find_by_id(enb_ue->target_ue_id);

        ogs_assert(source_ue->target_ue_id >= OGS_MIN_POOL_ID &&
                source_ue->target_ue_id <= OGS_MAX_POOL_ID);
        source_ue->target_ue_id = OGS_INVALID_POOL_ID;

        if (target_ue) {
            ogs_assert(target_ue->source_ue_id >= OGS_MIN_POOL_ID &&
                    target_ue->source_ue_id <= OGS_MAX_POOL_ID);
            target_ue->source_ue_id = OGS_INVALID_POOL_ID;
        } else
            mme_ran_error(
                    mme_enb_find_by_id(source_ue->enb_id),
                    source_ue,
                    mme_ue_find_by_id(source_ue->mme_ue_id),
                    "s1ap", NULL,
                    "Target-UE-ID has already been removed");


    } else if (enb_ue->source_ue_id >= OGS_MIN_POOL_ID &&
                enb_ue->source_ue_id <= OGS_MAX_POOL_ID) {
        target_ue = enb_ue;
        source_ue = enb_ue_find_by_id(enb_ue->source_ue_id);

        if (source_ue) {
            ogs_assert(source_ue->target_ue_id >= OGS_MIN_POOL_ID &&
                    source_ue->target_ue_id <= OGS_MAX_POOL_ID);
            source_ue->target_ue_id = OGS_INVALID_POOL_ID;
        } else
            ogs_error("Source-UE-ID [%d] has already been removed "
                    "(ENB_UE_S1AP_ID[%d] MME_UE_S1AP_ID[%d])",
                    target_ue->source_ue_id,
                    target_ue->enb_ue_s1ap_id, target_ue->mme_ue_s1ap_id);

        ogs_assert(target_ue->source_ue_id >= OGS_MIN_POOL_ID &&
                target_ue->source_ue_id <= OGS_MAX_POOL_ID);
        target_ue->source_ue_id = OGS_INVALID_POOL_ID;
    }
}

void sgw_ue_associate_mme_ue(sgw_ue_t *sgw_ue, mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);
    ogs_assert(sgw_ue);

    mme_ue->sgw_ue_id = sgw_ue->id;
    sgw_ue->mme_ue_id = mme_ue->id;
}

void sgw_ue_deassociate_mme_ue(sgw_ue_t *sgw_ue, mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);
    ogs_assert(sgw_ue);

    if (mme_ue->sgw_ue_id == sgw_ue->id)
        mme_ue->sgw_ue_id = OGS_INVALID_POOL_ID;
    else
        ogs_error("Cannot deassociate mme_ue->sgw_ue_id[%d] != sgw_ue->id[%d]",
                mme_ue->sgw_ue_id, sgw_ue->id);
}

void sgw_ue_source_associate_target(sgw_ue_t *source_ue, sgw_ue_t *target_ue)
{
    ogs_assert(source_ue);
    ogs_assert(target_ue);

    target_ue->mme_ue_id = source_ue->mme_ue_id;
    target_ue->source_ue_id = source_ue->id;
    source_ue->target_ue_id = target_ue->id;
}

void sgw_ue_source_deassociate_target(sgw_ue_t *sgw_ue)
{
    sgw_ue_t *source_ue = NULL;
    sgw_ue_t *target_ue = NULL;

    ogs_assert(sgw_ue);

    if (sgw_ue->target_ue_id >= OGS_MIN_POOL_ID &&
        sgw_ue->target_ue_id <= OGS_MAX_POOL_ID) {
        source_ue = sgw_ue;
        target_ue = sgw_ue_find_by_id(sgw_ue->target_ue_id);

        ogs_assert(source_ue->target_ue_id >= OGS_MIN_POOL_ID &&
                source_ue->target_ue_id <= OGS_MAX_POOL_ID);
        source_ue->target_ue_id = OGS_INVALID_POOL_ID;

        if (target_ue) {
            ogs_assert(target_ue->source_ue_id >= OGS_MIN_POOL_ID &&
                    target_ue->source_ue_id <= OGS_MAX_POOL_ID);
            target_ue->source_ue_id = OGS_INVALID_POOL_ID;
        } else
            ogs_error("Target-UE-ID [%d] has already been removed "
                    "(SGW-S11-TEID[%d])",
                    source_ue->target_ue_id, source_ue->sgw_s11_teid);

    } else if (sgw_ue->source_ue_id >= OGS_MIN_POOL_ID &&
                sgw_ue->source_ue_id <= OGS_MAX_POOL_ID) {
        target_ue = sgw_ue;
        source_ue = sgw_ue_find_by_id(sgw_ue->source_ue_id);

        if (source_ue) {
            ogs_assert(source_ue->target_ue_id >= OGS_MIN_POOL_ID &&
                    source_ue->target_ue_id <= OGS_MAX_POOL_ID);
            source_ue->target_ue_id = OGS_INVALID_POOL_ID;
        } else
            ogs_error("Source-UE-ID [%d] has already been removed "
                    "(SGW-S11-TEID[%d])",
                    target_ue->source_ue_id, target_ue->sgw_s11_teid);

        ogs_assert(target_ue->source_ue_id >= OGS_MIN_POOL_ID &&
                target_ue->source_ue_id <= OGS_MAX_POOL_ID);
        target_ue->source_ue_id = OGS_INVALID_POOL_ID;
    }
}

mme_sess_t *mme_sess_add(mme_ue_t *mme_ue, uint8_t pti)
{
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;

    ogs_assert(mme_ue);
    ogs_assert(pti != OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED);

    ogs_pool_id_calloc(&mme_sess_pool, &sess);
    ogs_assert(sess);

    ogs_list_init(&sess->bearer_list);

    sess->mme_ue_id = mme_ue->id;
    sess->pti = pti;

    bearer = mme_bearer_add(sess);
    ogs_assert(bearer);

    /*
     * Guard sess_list mutation against the /ue-info dumper running
     * on the MHD thread. The dump lock is recursive so this is safe
     * even when we are already inside a locked region (e.g. attach
     * processing that holds it for a wider window).
     */
    ogs_metrics_dump_lock();
    ogs_list_add(&mme_ue->sess_list, sess);
    ogs_metrics_dump_unlock();

    stats_add_mme_session();

    return sess;
}

void mme_sess_remove(mme_sess_t *sess)
{
    mme_ue_t *mme_ue = NULL;

    ogs_assert(sess);
    mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
    ogs_assert(mme_ue);

    mme_metrics_on_sess_remove(sess);

    /*
     * Same as mme_sess_add - keep the dumper from observing a
     * half-removed sess or following a freed pointer.
     */
    ogs_metrics_dump_lock();
    ogs_list_remove(&mme_ue->sess_list, sess);

    mme_bearer_remove_all(sess);

    OGS_NAS_CLEAR_DATA(&sess->ue_pco);
    OGS_NAS_CLEAR_DATA(&sess->ue_epco);
    OGS_TLV_CLEAR_DATA(&sess->pgw_pco);
    OGS_TLV_CLEAR_DATA(&sess->pgw_epco);

    ogs_pool_id_free(&mme_sess_pool, sess);
    ogs_metrics_dump_unlock();

    stats_remove_mme_session();
}

void mme_sess_remove_all(mme_ue_t *mme_ue)
{
    mme_sess_t *sess = NULL, *next_sess = NULL;

    sess = mme_sess_first(mme_ue);
    while (sess) {
        next_sess = mme_sess_next(sess);

        mme_sess_remove(sess);

        sess = next_sess;
    }
}

mme_sess_t *mme_sess_find_by_pti(const mme_ue_t *mme_ue, uint8_t pti)
{
    mme_sess_t *sess = NULL;

    sess = mme_sess_first(mme_ue);
    while(sess) {
        if (pti == sess->pti)
            return sess;

        sess = mme_sess_next(sess);
    }

    return NULL;
}

mme_sess_t *mme_sess_find_by_ebi(const mme_ue_t *mme_ue, uint8_t ebi)
{
    mme_bearer_t *bearer = NULL;

    bearer = mme_bearer_find_by_ue_ebi(mme_ue, ebi);
    if (bearer)
        return mme_sess_find_by_id(bearer->sess_id);

    return NULL;
}

mme_sess_t *mme_sess_find_by_apn(const mme_ue_t *mme_ue, const char *apn)
{
    mme_sess_t *sess = NULL;

    sess = mme_sess_first(mme_ue);
    while (sess) {
        if (sess->session) {
            ogs_assert(sess->session->name);
            if (ogs_strcasecmp(sess->session->name, apn) == 0)
                return sess;
        }
        sess = mme_sess_next(sess);
    }

    return NULL;
}

mme_sess_t *mme_sess_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&mme_sess_pool, id);
}

mme_sess_t *mme_sess_first(const mme_ue_t *mme_ue)
{
    return ogs_list_first(&mme_ue->sess_list);
}

mme_sess_t *mme_sess_next(mme_sess_t *sess)
{
    return ogs_list_next(sess);
}

unsigned int mme_sess_count(const mme_ue_t *mme_ue)
{
    unsigned int count = 0;
    mme_sess_t *sess = NULL;

    ogs_list_for_each(&mme_ue->sess_list, sess) {
        count++;
    }

    return count;
}

mme_bearer_t *mme_bearer_add(mme_sess_t *sess)
{
    mme_event_t e;

    mme_bearer_t *bearer = NULL;
    mme_ue_t *mme_ue = NULL;

    ogs_assert(sess);
    mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
    ogs_assert(mme_ue);

    ogs_pool_id_calloc(&mme_bearer_pool, &bearer);
    ogs_assert(bearer);

    ogs_list_init(&bearer->update.xact_list);

    /*
     * Allocate a new EBI from the UE bitmap.
     * If all EBIs are exhausted, reject bearer creation.
     */
    bearer->ebi = mme_ebi_alloc(mme_ue);
    if (bearer->ebi == INVALID_EPS_BEARER_ID) {
        mme_ue_error(mme_ue, NULL, "bearer", NULL,
                "Bearer add failed: EBI pool exhausted");
        ogs_pool_free(&mme_bearer_pool, bearer);
        return NULL;
    }

    mme_bearer_added_log(mme_ue, bearer);

    bearer->mme_ue_id = mme_ue->id;
    bearer->sess_id = sess->id;

    /*
     * Guard bearer_list mutation - the /ue-info dumper walks
     * sess->bearer_list on the MHD worker thread.
     */
    ogs_metrics_dump_lock();
    ogs_list_add(&sess->bearer_list, bearer);
    ogs_metrics_dump_unlock();
    /* Keep the EBI -> bearer-id lookup table in sync so subsequent
     * mme_bearer_find_by_ue_ebi() calls hit O(1). */
    if (bearer->ebi >= MIN_EPS_BEARER_ID && bearer->ebi <= MAX_EPS_BEARER_ID)
        mme_ue->ebi_to_bearer_id[bearer->ebi] = bearer->id;

    bearer->t3489.timer = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_t3489_expire,
            OGS_UINT_TO_POINTER(bearer->id));
    bearer->t3489.pkbuf = NULL;

    bearer->t_bearer_setup.timer = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_bearer_setup_expire,
            OGS_UINT_TO_POINTER(bearer->id));
    bearer->t_bearer_setup.pkbuf = NULL;

    bearer->t_nas_deactivate.timer = ogs_timer_add(
            ogs_app()->timer_mgr, mme_timer_nas_deactivate_bearer_expire,
            OGS_UINT_TO_POINTER(bearer->id));
    bearer->t_nas_deactivate.pkbuf = NULL;

    memset(&e, 0, sizeof(e));
    e.bearer_id = bearer->id;
    ogs_fsm_init(&bearer->sm, esm_state_initial, esm_state_final, &e);

    return bearer;
}

void mme_bearer_remove(mme_bearer_t *bearer)
{
    mme_event_t e;
    mme_ue_t *mme_ue = NULL;
    mme_sess_t *sess = NULL;
    ogs_gtp_xact_t *xact = NULL, *next_xact = NULL;

    ogs_assert(bearer);
    mme_ue = mme_ue_find_by_id(bearer->mme_ue_id);
    ogs_assert(mme_ue);
    sess = mme_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);

    mme_bearer_removed_log(mme_ue, bearer);

    memset(&e, 0, sizeof(e));
    e.bearer_id = bearer->id;
    ogs_fsm_fini(&bearer->sm, &e);

    CLEAR_BEARER_ALL_TIMERS(bearer);
    ogs_timer_delete(bearer->t3489.timer);
    ogs_timer_delete(bearer->t_bearer_setup.timer);
    ogs_timer_delete(bearer->t_nas_deactivate.timer);

    /*
     * Take the dump lock around bearer teardown - the /ue-info
     * dumper drills into sess->bearer_list and dereferences each
     * bearer's ebi/qci fields, and we are about to free this
     * bearer. Lock is recursive (see lib/metrics/context.c) so an
     * outer locked section is OK.
     */
    ogs_metrics_dump_lock();
    ogs_list_remove(&sess->bearer_list, bearer);

    OGS_TLV_CLEAR_DATA(&bearer->tft);

    /* Clear the EBI -> bearer-id slot before the EBI is returned to
     * the bitmap so a racing find_by_ue_ebi() can not pick up a stale
     * bearer that has already been removed from the session list. */
    if (bearer->ebi >= MIN_EPS_BEARER_ID && bearer->ebi <= MAX_EPS_BEARER_ID &&
            mme_ue->ebi_to_bearer_id[bearer->ebi] == bearer->id)
        mme_ue->ebi_to_bearer_id[bearer->ebi] = OGS_INVALID_POOL_ID;

    if (OGS_OK != mme_ebi_free(mme_ue, bearer->ebi))
        ogs_warn("EBI free failed [ebi:%d]", bearer->ebi);

    ogs_list_for_each_entry_safe(&bearer->update.xact_list,
            next_xact, xact, to_update_node) {
        ogs_timer_stop(xact->tm_peer);
        ogs_list_remove(&bearer->update.xact_list, &xact->to_update_node);
    }

    ogs_pool_id_free(&mme_bearer_pool, bearer);
    ogs_metrics_dump_unlock();
}

void mme_bearer_remove_all(mme_sess_t *sess)
{
    mme_bearer_t *bearer = NULL, *next_bearer = NULL;

    ogs_assert(sess);

    bearer = mme_bearer_first(sess);
    while (bearer) {
        next_bearer = mme_bearer_next(bearer);

        mme_bearer_remove(bearer);

        bearer = next_bearer;
    }
}

mme_bearer_t *mme_bearer_find_by_sess_ebi(const mme_sess_t *sess, uint8_t ebi)
{
    mme_bearer_t *bearer = NULL;

    ogs_assert(sess);

    bearer = mme_bearer_first(sess);
    while (bearer) {
        if (ebi == bearer->ebi)
            return bearer;

        bearer = mme_bearer_next(bearer);
    }

    return NULL;
}

mme_bearer_t *mme_bearer_find_by_ue_ebi(const mme_ue_t *mme_ue, uint8_t ebi)
{
    ogs_pool_id_t bearer_id;
    mme_bearer_t *bearer = NULL;

    ogs_assert(mme_ue);

    /*
     * Fast path: the EBI -> bearer-id table is updated by
     * mme_bearer_add / _remove. Most S1AP messages (E-RAB setup,
     * release, modify, NAS over S1AP) end up here, so an O(1) array
     * indexing replaces a per-session, per-bearer walk.
     */
    if (ebi >= MIN_EPS_BEARER_ID && ebi <= MAX_EPS_BEARER_ID) {
        bearer_id = mme_ue->ebi_to_bearer_id[ebi];
        if (bearer_id != OGS_INVALID_POOL_ID) {
            bearer = mme_bearer_find_by_id(bearer_id);
            /* Defensive: validate the bearer still belongs to this UE
             * in case the slot survived a removal we did not see. */
            if (bearer && bearer->mme_ue_id == mme_ue->id)
                return bearer;
        }
        return NULL;
    }

    /* Out-of-range EBI: fall through to a linear walk. Callers that
     * pass MIN-1..0 or > MAX hit the original behaviour, which already
     * returned NULL via the loop. */
    {
        mme_sess_t *sess = mme_sess_first(mme_ue);
        while (sess) {
            bearer = mme_bearer_find_by_sess_ebi(sess, ebi);
            if (bearer)
                return bearer;
            sess = mme_sess_next(sess);
        }
    }

    return NULL;
}

mme_bearer_t *mme_bearer_find_or_add_by_message(
        mme_ue_t *mme_ue, ogs_nas_eps_message_t *message, int create_action)
{
    int r;
    uint8_t pti = OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED;
    uint8_t ebi = OGS_NAS_EPS_BEARER_IDENTITY_UNASSIGNED;

    mme_bearer_t *bearer = NULL;
    mme_sess_t *sess = NULL;
    mme_ue_t *sess_mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;

    ogs_assert(mme_ue);
    ogs_assert(message);

    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);

    pti = message->esm.h.procedure_transaction_identity;
    ebi = message->esm.h.eps_bearer_identity;

    ogs_debug("mme_bearer_find_or_add_by_message() : "
            "ESM message type:%d, PTI:%d, EBI:%d",
            message->esm.h.message_type, pti, ebi);

    if (ebi != OGS_NAS_EPS_BEARER_IDENTITY_UNASSIGNED) {
        bearer = mme_bearer_find_by_ue_ebi(mme_ue, ebi);
        if (!bearer) {
            ogs_error("No Bearer : EBI[%d]", ebi);
            r = nas_eps_send_attach_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                    OGS_NAS_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return NULL;
        }

        return bearer;
    }

    if (pti == OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED) {
        ogs_error("ESM message type: %d, Both PTI[%d] and EBI[%d] are 0",
                message->esm.h.message_type, pti, ebi);
        r = nas_eps_send_attach_reject(enb_ue, mme_ue,
                OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                OGS_NAS_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
        return NULL;
    }

    if (message->esm.h.message_type == OGS_NAS_EPS_PDN_DISCONNECT_REQUEST) {
        ogs_nas_eps_pdn_disconnect_request_t *pdn_disconnect_request =
            &message->esm.pdn_disconnect_request;
        ogs_nas_linked_eps_bearer_identity_t *linked_eps_bearer_identity =
            &pdn_disconnect_request->linked_eps_bearer_identity;

        bearer = mme_bearer_find_by_ue_ebi(mme_ue,
                linked_eps_bearer_identity->eps_bearer_identity);
        if (!bearer) {
            ogs_error("No Bearer : Linked-EBI[%d]",
                    linked_eps_bearer_identity->eps_bearer_identity);
            r = nas_eps_send_attach_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                    OGS_NAS_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return NULL;
        }
    } else if (message->esm.h.message_type ==
            OGS_NAS_EPS_BEARER_RESOURCE_ALLOCATION_REQUEST) {
        ogs_nas_eps_bearer_resource_allocation_request_t
            *bearer_allocation_request =
                &message->esm.bearer_resource_allocation_request;
        ogs_nas_linked_eps_bearer_identity_t *linked_eps_bearer_identity =
            &bearer_allocation_request->linked_eps_bearer_identity;

        bearer = mme_bearer_find_by_ue_ebi(mme_ue,
                linked_eps_bearer_identity->eps_bearer_identity);
        if (!bearer) {
            ogs_error("No Bearer : Linked-EBI[%d]",
                    linked_eps_bearer_identity->eps_bearer_identity);
            r = nas_eps_send_bearer_resource_allocation_reject(
                    mme_ue, pti,
                    OGS_NAS_ESM_CAUSE_INVALID_EPS_BEARER_IDENTITY);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return NULL;
        }

    } else if (message->esm.h.message_type ==
            OGS_NAS_EPS_BEARER_RESOURCE_MODIFICATION_REQUEST) {
        ogs_nas_eps_bearer_resource_modification_request_t
            *bearer_modification_request =
                &message->esm.bearer_resource_modification_request;
        ogs_nas_linked_eps_bearer_identity_t *linked_eps_bearer_identity =
            &bearer_modification_request->eps_bearer_identity_for_packet_filter;

        bearer = mme_bearer_find_by_ue_ebi(mme_ue,
                linked_eps_bearer_identity->eps_bearer_identity);
        if (!bearer) {
            ogs_error("No Bearer : Linked-EBI[%d]",
                    linked_eps_bearer_identity->eps_bearer_identity);
            r = nas_eps_send_bearer_resource_modification_reject(
                    mme_ue, pti,
                    OGS_NAS_ESM_CAUSE_INVALID_EPS_BEARER_IDENTITY);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return NULL;
        }
    }

    if (bearer) {
        sess = mme_sess_find_by_id(bearer->sess_id);
        ogs_assert(sess);
        sess->pti = pti;

        return bearer;
    }

    if (message->esm.h.message_type == OGS_NAS_EPS_PDN_CONNECTIVITY_REQUEST) {
        ogs_nas_eps_pdn_connectivity_request_t *pdn_connectivity_request =
            &message->esm.pdn_connectivity_request;
        if (pdn_connectivity_request->presencemask &
            OGS_NAS_EPS_PDN_CONNECTIVITY_REQUEST_ACCESS_POINT_NAME_PRESENT) {
            sess = mme_sess_find_by_apn(mme_ue,
                    pdn_connectivity_request->access_point_name.apn);
            if (sess && create_action != OGS_GTP_CREATE_IN_ATTACH_REQUEST) {

                sess->pti = pti;

                r = nas_eps_send_pdn_connectivity_reject(
                        sess,
                        OGS_NAS_ESM_CAUSE_MULTIPLE_PDN_CONNECTIONS_FOR_A_GIVEN_APN_NOT_ALLOWED,
                        create_action);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
                ogs_mme_trace_set(
                        enb_ue_find_by_id(mme_ue->enb_ue_id), mme_ue,
                        pdn_connectivity_request->access_point_name.apn,
                        "esm");
                OGS_TLOG_WARN("APN duplicated");
                return NULL;
            }
        } else if (pdn_connectivity_request->request_type.value !=
                OGS_NAS_EPS_REQUEST_TYPE_EMERGENCY) {
            sess = mme_sess_first(mme_ue);
            ogs_debug("[%s:%p]", mme_ue->imsi_bcd, mme_ue);
            if (sess) {
                ogs_debug("[%s:%d:%d:%p]",
                    sess->session ? sess->session->name : "Unknown",
                    sess->pti, pti, sess);

                sess_mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
                ogs_debug("[%s:%p]",
                    sess_mme_ue ? sess_mme_ue->imsi_bcd : "Unknown",
                    sess_mme_ue);
            }
        }

        if (!sess) {
            sess = mme_sess_add(mme_ue, pti);
            ogs_assert(sess);

            ogs_debug("[%s:%p]", mme_ue->imsi_bcd, mme_ue);
            ogs_debug("[%s:%d:%d:%p]",
                sess->session ? sess->session->name : "Unknown",
                sess->pti, pti, sess);

            sess_mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
            ogs_debug("[%s:%p]",
                sess_mme_ue ? sess_mme_ue->imsi_bcd : "Unknown",
                sess_mme_ue);
        } else {
            sess->pti = pti;
            ogs_debug("[%s:%p]", mme_ue->imsi_bcd, mme_ue);
            ogs_debug("[%s:%d:%d:%p]",
                sess->session ? sess->session->name : "Unknown",
                sess->pti, pti, sess);

            sess_mme_ue = mme_ue_find_by_id(sess->mme_ue_id);
            ogs_debug("[%s:%p]",
                sess_mme_ue ? sess_mme_ue->imsi_bcd : "Unknown",
                sess_mme_ue);
        }

    } else {
        sess = mme_sess_find_by_pti(mme_ue, pti);
        if (!sess) {
            ogs_error("No Session : ESM message type[%d], PTI[%d]",
                    message->esm.h.message_type, pti);
            r = nas_eps_send_attach_reject(enb_ue, mme_ue,
                    OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                    OGS_NAS_ESM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            return NULL;
        }
    }

    bearer = mme_default_bearer_in_sess(sess);
    if (!bearer) {
        ogs_error("No Bearer(%d) : ESM message type:%d, PTI:%d, EBI:%d",
                mme_sess_count(mme_ue), message->esm.h.message_type, pti, ebi);
        ogs_assert_if_reached();
    }

    return bearer;
}

mme_bearer_t *mme_default_bearer_in_sess(mme_sess_t *sess)
{
    ogs_assert(sess);
    return mme_bearer_first(sess);
}

mme_bearer_t *mme_linked_bearer(mme_bearer_t *bearer)
{
    mme_sess_t *sess = NULL;

    ogs_assert(bearer);
    sess = mme_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);

    return mme_default_bearer_in_sess(sess);
}

mme_bearer_t *mme_bearer_first(const mme_sess_t *sess)
{
    ogs_assert(sess);

    return ogs_list_first(&sess->bearer_list);
}

mme_bearer_t *mme_bearer_next(mme_bearer_t *bearer)
{
    ogs_assert(bearer);
    return ogs_list_next(bearer);
}

mme_bearer_t *mme_bearer_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&mme_bearer_pool, id);
}

void mme_session_remove_all(mme_ue_t *mme_ue)
{
    int i;

    ogs_assert(mme_ue);

    ogs_assert(mme_ue->num_of_session <= OGS_MAX_NUM_OF_SESS);
    for (i = 0; i < mme_ue->num_of_session; i++) {
        if (mme_ue->session[i].name)
            ogs_free(mme_ue->session[i].name);
    }

    mme_ue->num_of_session = 0;
}

ogs_session_t *mme_session_find_by_apn(mme_ue_t *mme_ue, const char *apn)
{
    ogs_session_t *session = NULL;
    int i = 0;

    ogs_assert(mme_ue);
    ogs_assert(apn);

    ogs_assert(mme_ue->num_of_session <= OGS_MAX_NUM_OF_SESS);
    for (i = 0; i < mme_ue->num_of_session; i++) {
        session = &mme_ue->session[i];
        ogs_assert(session->name);
        if (ogs_strcasecmp(session->name, apn) == 0)
            return session;
    }

    return NULL;
}

ogs_session_t *mme_default_session(mme_ue_t *mme_ue)
{
    ogs_session_t *session = NULL;
    int i = 0;

    ogs_assert(mme_ue);

    ogs_assert(mme_ue->num_of_session <= OGS_MAX_NUM_OF_SESS);
    for (i = 0; i < mme_ue->num_of_session; i++) {
        session = &mme_ue->session[i];
        if (session->context_identifier == mme_ue->context_identifier)
            return session;
    }

    return NULL;
}

int mme_find_served_tai(ogs_eps_tai_t *tai)
{
    int i = 0, j = 0, k = 0;

    ogs_assert(tai);

    for (i = 0; i < self.num_of_served_tai; i++) {
        ogs_eps_tai0_list_t *list0 = self.served_tai[i].list0;
        ogs_eps_tai1_list_t *list1 = &self.served_tai[i].list1;
        ogs_eps_tai2_list_t *list2 = &self.served_tai[i].list2;

        if (!list0)
            continue;

        for (j = 0; j < (int)ogs_app_max_eps_tai0_partial_list() &&
                list0->tai[j].num; j++) {
            ogs_assert(list0->tai[j].type == OGS_TAI0_TYPE);
            ogs_assert(list0->tai[j].num <= OGS_MAX_NUM_OF_TAI);

            for (k = 0; k < list0->tai[j].num; k++) {
                if (memcmp(&list0->tai[j].plmn_id,
                            &tai->plmn_id, OGS_PLMN_ID_LEN) == 0 &&
                    list0->tai[j].tac[k] == tai->tac) {
                    return i;
                }
            }
        }

        for (j = 0; list1->tai[j].num; j++) {
            ogs_assert(list1->tai[j].type == OGS_TAI1_TYPE);
            ogs_assert(list1->tai[j].num <= OGS_MAX_NUM_OF_TAI);

            if (memcmp(&list1->tai[j].plmn_id,
                        &tai->plmn_id, OGS_PLMN_ID_LEN) == 0 &&
                    list1->tai[j].tac <= tai->tac &&
                    tai->tac < (list1->tai[j].tac+list1->tai[j].num))
                return i;
        }

        if (list2->num) {
            ogs_assert(list2->type == OGS_TAI2_TYPE);
            ogs_assert(list2->num <= OGS_MAX_NUM_OF_TAI);

            for (j = 0; j < list2->num; j++) {
                if (memcmp(&list2->tai[j].plmn_id,
                            &tai->plmn_id, OGS_PLMN_ID_LEN) == 0 &&
                    list2->tai[j].tac == tai->tac) {
                    return i;
                }
            }
        }
    }

    return -1;
}

#if 0 /* DEPRECATED */
int mme_m_tmsi_pool_generate(void)
{
    int j;
    int index = 0;

    ogs_trace("M-TMSI Pool try to generate...");
    while (index < ogs_global_conf()->max.ue*2) {
        mme_m_tmsi_t *m_tmsi = NULL;
        int conflict = 0;

        m_tmsi = &m_tmsi_pool.array[index];
        ogs_assert(m_tmsi);
        *m_tmsi = ogs_random32();

        /* for mapped-GUTI */
        *m_tmsi |= 0xc0000000;
        *m_tmsi &= 0xff00ffff;

        for (j = 0; j < index; j++) {
            if (*m_tmsi == m_tmsi_pool.array[j]) {
                conflict = 1;
                ogs_trace("[M-TMSI CONFLICT]  %d:0x%x == %d:0x%x",
                        index, *m_tmsi, j, m_tmsi_pool.array[j]);
                break;
            }
        }
        if (conflict == 1) {
            continue;
        }

        index++;
    }
    m_tmsi_pool.size = index;
    ogs_trace("M-TMSI Pool generate...done");

    return OGS_OK;
}
#endif

mme_m_tmsi_t *mme_m_tmsi_alloc(void)
{
    mme_m_tmsi_t *m_tmsi = NULL;

    ogs_pool_alloc(&m_tmsi_pool, &m_tmsi);
    ogs_assert(m_tmsi);

    /* TS23.003
     * 2.8.2.1.2 Mapping in the UE
     *
     * E-UTRAN <M-TMSI> maps as follows:
     * - 6 bits of the E-UTRAN <M-TMSI> starting at bit 29 and down to bit 24
     * are mapped into bit 29 and down to bit 24 of the GERAN/UTRAN <P-TMSI>;
     * - 16 bits of the E-UTRAN <M-TMSI> starting at bit 15 and down to bit 0
     * are mapped into bit 15 and down to bit 0 of the GERAN/UTRAN <P-TMSI>;
     * - and the remaining 8 bits of the E-UTRAN <M-TMSI> are
     * mapped into the 8 Most Significant Bits of the <P-TMSI signature> field.
     *
     * The UE shall fill the remaining 2 octets of the <P-TMSI signature>
     * according to clauses 9.1.1, 9.4.1, 10.2.1, or 10.5.1
     * of 3GPP TS.33.401 [89] , as appropriate, for RAU/Attach procedures
     */

    ogs_assert(*m_tmsi <= 0x003fffff);

    *m_tmsi = ((*m_tmsi & 0xffff) | ((*m_tmsi & 0x003f0000) << 8));
    *m_tmsi |= 0xc0000000;

    return m_tmsi;
}

int mme_m_tmsi_free(mme_m_tmsi_t *m_tmsi)
{
    ogs_assert(m_tmsi);

    /* Restore M-TMSI by Issue #2307 */
    *m_tmsi &= 0x3fffffff;
    *m_tmsi = ((*m_tmsi & 0xffff) | ((*m_tmsi & 0x3f000000) >> 8));
    ogs_pool_free(&m_tmsi_pool, m_tmsi);

    return OGS_OK;
}

/*
 * EPS Bearer ID (EBI) management
 *
 * In EPC, valid EBIs are in range [5..15].
 * Each UE can have at most 11 bearers.
 *
 * We track EBI usage with a bitmap rather than ogs_pool nodes,
 * because bearer contexts may migrate between MME-UE objects
 * during UE context relocation (OLD UE -> NEW UE).
 *
 * Bitmap-based tracking avoids ownership issues with pool-internal
 * pointers (ebi_node) and supports safe EBI reservation.
 */
uint8_t mme_ebi_alloc(mme_ue_t *mme_ue)
{
    uint8_t ebi;

    ogs_assert(mme_ue);

    for (ebi = MIN_EPS_BEARER_ID; ebi <= MAX_EPS_BEARER_ID; ebi++) {

        if (!(mme_ue->ebi_bitmap & (1 << ebi))) {
            mme_ue->ebi_bitmap |= (1 << ebi);
            ogs_debug("EBI allocated [%d]", ebi);
            return ebi;
        }
    }

    ogs_error("No available EBI (range %d-%d)",
            MIN_EPS_BEARER_ID, MAX_EPS_BEARER_ID);

    return INVALID_EPS_BEARER_ID; /* no available EBI */
}

int mme_ebi_free(mme_ue_t *mme_ue, int ebi)
{
    ogs_assert(mme_ue);

    if (ebi < MIN_EPS_BEARER_ID || ebi > MAX_EPS_BEARER_ID) {
        ogs_error("Invalid EBI to free [%d]", ebi);
        return OGS_ERROR;
    }

    mme_ue->ebi_bitmap &= ~(1 << ebi);

    ogs_debug("EBI freed [%d]", ebi);

    return OGS_OK;
}

int mme_ebi_reserve(mme_ue_t *mme_ue, int ebi)
{
    ogs_assert(mme_ue);

    if (ebi < MIN_EPS_BEARER_ID || ebi > MAX_EPS_BEARER_ID) {
        ogs_error("Invalid EBI to reserve [%d]", ebi);
        return OGS_ERROR;
    }

    if (mme_ue->ebi_bitmap & (1 << ebi)) {
        ogs_error("EBI [%d] already reserved", ebi);
        return OGS_ERROR;
    }

    mme_ue->ebi_bitmap |= (1 << ebi);
    ogs_debug("EBI reserved [%d]", ebi);
    return OGS_OK;
}

uint8_t mme_selected_int_algorithm(mme_ue_t *mme_ue)
{
    int i;

    ogs_assert(mme_ue);

    for (i = 0; i < mme_self()->num_of_integrity_order; i++) {
        if (mme_ue->ue_network_capability.eia &
                (0x80 >> mme_self()->integrity_order[i])) {
            return mme_self()->integrity_order[i];
        }
    }

    return 0;
}

uint8_t mme_selected_enc_algorithm(mme_ue_t *mme_ue)
{
    int i;

    ogs_assert(mme_ue);

    for (i = 0; i < mme_self()->num_of_ciphering_order; i++) {
        if (mme_ue->ue_network_capability.eea &
                (0x80 >> mme_self()->ciphering_order[i])) {
            return mme_self()->ciphering_order[i];
        }
    }

    return 0;
}

/*
 * Save the sensitive (partial) context fields
 * from the UE context into the memento
 */
void mme_ue_save_memento(mme_ue_t *mme_ue, mme_ue_memento_t *memento)
{
    ogs_assert(mme_ue);
    ogs_assert(memento);

    memcpy(&memento->ue_network_capability,
            &mme_ue->ue_network_capability,
            sizeof(memento->ue_network_capability));
    memcpy(&memento->ms_network_capability,
            &mme_ue->ms_network_capability,
            sizeof(memento->ms_network_capability));
    memcpy(&memento->ue_additional_security_capability,
            &mme_ue->ue_additional_security_capability,
            sizeof(memento->ue_additional_security_capability));
    memcpy(memento->xres, mme_ue->xres, OGS_MAX_RES_LEN);
    memento->xres_len = mme_ue->xres_len;
    memcpy(memento->kasme, mme_ue->kasme, OGS_SHA256_DIGEST_SIZE);
    memcpy(memento->rand, mme_ue->rand, OGS_RAND_LEN);
    memcpy(memento->autn, mme_ue->autn, OGS_AUTN_LEN);
    memcpy(memento->knas_int, mme_ue->knas_int,
           OGS_SHA256_DIGEST_SIZE / 2);
    memcpy(memento->knas_enc, mme_ue->knas_enc,
           OGS_SHA256_DIGEST_SIZE / 2);
    memento->dl_count = mme_ue->dl_count;
    memento->ul_count = mme_ue->ul_count.i32;
    memcpy(memento->kenb, mme_ue->kenb, OGS_SHA256_DIGEST_SIZE);
    memcpy(memento->hash_mme, mme_ue->hash_mme, OGS_HASH_MME_LEN);
    memento->nonceue = mme_ue->nonceue;
    memento->noncemme = mme_ue->noncemme;
    memento->gprs_ciphering_key_sequence_number =
        mme_ue->gprs_ciphering_key_sequence_number;
    memcpy(memento->nh, mme_ue->nh, OGS_SHA256_DIGEST_SIZE);
    memento->selected_enc_algorithm = mme_ue->selected_enc_algorithm;
    memento->selected_int_algorithm = mme_ue->selected_int_algorithm;
}

/* Restore the sensitive context fields into the UE context */
void mme_ue_restore_memento(mme_ue_t *mme_ue, const mme_ue_memento_t *memento)
{
    ogs_assert(mme_ue);
    ogs_assert(memento);

    memcpy(&mme_ue->ue_network_capability,
            &memento->ue_network_capability,
            sizeof(mme_ue->ue_network_capability));
    memcpy(&mme_ue->ms_network_capability,
            &memento->ms_network_capability,
            sizeof(mme_ue->ms_network_capability));
    memcpy(&mme_ue->ue_additional_security_capability,
            &memento->ue_additional_security_capability,
            sizeof(mme_ue->ue_additional_security_capability));
    memcpy(mme_ue->xres, memento->xres, OGS_MAX_RES_LEN);
    mme_ue->xres_len = memento->xres_len;
    memcpy(mme_ue->kasme, memento->kasme, OGS_SHA256_DIGEST_SIZE);
    memcpy(mme_ue->rand, memento->rand, OGS_RAND_LEN);
    memcpy(mme_ue->autn, memento->autn, OGS_AUTN_LEN);
    memcpy(mme_ue->knas_int, memento->knas_int,
           OGS_SHA256_DIGEST_SIZE / 2);
    memcpy(mme_ue->knas_enc, memento->knas_enc,
           OGS_SHA256_DIGEST_SIZE / 2);
    mme_ue->dl_count = memento->dl_count;
    mme_ue->ul_count.i32 = memento->ul_count;
    memcpy(mme_ue->kenb, memento->kenb, OGS_SHA256_DIGEST_SIZE);
    memcpy(mme_ue->hash_mme, memento->hash_mme, OGS_HASH_MME_LEN);
    mme_ue->nonceue = memento->nonceue;
    mme_ue->noncemme = memento->noncemme;
    mme_ue->gprs_ciphering_key_sequence_number =
        memento->gprs_ciphering_key_sequence_number;
    memcpy(mme_ue->nh, memento->nh, OGS_SHA256_DIGEST_SIZE);
    mme_ue->selected_enc_algorithm = memento->selected_enc_algorithm;
    mme_ue->selected_int_algorithm = memento->selected_int_algorithm;
}

static void stats_add_enb_ue(void)
{
    mme_metrics_inst_global_inc(MME_METR_GLOB_GAUGE_ENB_UE);
    num_of_enb_ue = num_of_enb_ue + 1;
    ogs_info("[Added] Number of eNB-UEs is now %d", num_of_enb_ue);
}

static void stats_remove_enb_ue(void)
{
    mme_metrics_inst_global_dec(MME_METR_GLOB_GAUGE_ENB_UE);
    num_of_enb_ue = num_of_enb_ue - 1;
    ogs_info("[Removed] Number of eNB-UEs is now %d", num_of_enb_ue);
}

static void stats_add_mme_session(void)
{
    mme_metrics_inst_global_inc(MME_METR_GLOB_GAUGE_MME_SESS);
    num_of_mme_sess = num_of_mme_sess + 1;
    ogs_info("[Added] Number of MME-Sessions is now %d", num_of_mme_sess);
}

static void stats_remove_mme_session(void)
{
    mme_metrics_inst_global_dec(MME_METR_GLOB_GAUGE_MME_SESS);
    num_of_mme_sess = num_of_mme_sess - 1;
    ogs_info("[Removed] Number of MME-Sessions is now %d", num_of_mme_sess);
}

/*--------------------------------------------------------------
 *  Emergency Number (EMERG) Management Functions
 *-------------------------------------------------------------*/
mme_emerg_t *mme_emerg_add(uint8_t categories, const char *digits)
{
    mme_emerg_t *emerg = NULL;

    ogs_pool_id_calloc(&mme_emerg_pool, &emerg);

    /* Try to allocate an emergency entry from the pool */
    if (!emerg) {
        ogs_error("Failed to allocate mme_emerg_t from mme_emerg_pool");
        return NULL;
    }

    /* Set attributes */
    emerg->categories = categories;
    emerg->digits = digits;

    /* Add to the golbal emergency list */
    ogs_list_add(&self.emerg_list, emerg);

    ogs_debug("Added Emergency Number %s (categories 0x%02x)",
            digits, categories);

    return emerg;
}

void mme_emerg_remove(mme_emerg_t *emerg)
{
    if (!emerg)
        return;

    /* Remove from the list */
    ogs_list_remove(&self.emerg_list, emerg);

    /* Release object back to the pool */
    ogs_pool_id_free(&mme_emerg_pool, emerg);

    ogs_debug("Emergency number entry removed");
}

void mme_emerg_remove_all(void)
{
    mme_emerg_t *emerg, *tmp;

    /* Iterate safely and free all entries */
    ogs_list_for_each_safe(&self.emerg_list, tmp, emerg)
        ogs_pool_id_free(&mme_emerg_pool, emerg);

    ogs_debug("All emergency number entries removed");
}
