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

#include <yaml.h>
#include <stdio.h>
#include <inttypes.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#define sgwc_recovery_mkdir(p) _mkdir(p)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define sgwc_recovery_mkdir(p) mkdir((p), 0755)
#endif

#include "context.h"
#include "event.h"
#include "gtp-path.h"
#include "pfcp-path.h"
#include "ga-writer.h"
#include "metrics.h"
#include "ogs-metrics.h"

#define SGWC_RECOVERY_COUNTER_FILE "/var/lib/open5gs/sgwc_recovery_counter"

/* Returns the persisted counter (0..255), or -1 if the file is missing
 * or unreadable so the caller can fall back to a time-based seed. */
static int
sgwc_load_recovery_counter(const char *path)
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
sgwc_recovery_mkdir_p(const char *dir)
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
            if (sgwc_recovery_mkdir(tmp) != 0 && errno != EEXIST)
                ogs_warn("mkdir(%s) failed: %s", tmp, strerror(errno));
            *p = '/';
        }
    }
    if (sgwc_recovery_mkdir(tmp) != 0 && errno != EEXIST)
        ogs_warn("mkdir(%s) failed: %s", tmp, strerror(errno));
}

/* Returns true if the counter was persisted to disk. */
static bool
sgwc_save_recovery_counter(const char *path, uint8_t val)
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
        sgwc_recovery_mkdir_p(dir);
    }

    f = fopen(path, "wb");
    if (!f) {
        ogs_error("failed to persist GTP-C recovery counter to %s: %s -- "
                "SGW-C restart detection by MME/SMF will be degraded; "
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

static sgwc_context_t self;

int __sgwc_log_domain;

static OGS_POOL(sgwc_bearer_pool, sgwc_bearer_t);
static OGS_POOL(sgwc_tunnel_pool, sgwc_tunnel_t);

static OGS_POOL(sgwc_ue_pool, sgwc_ue_t);
static OGS_POOL(sgwc_s11_teid_pool, ogs_pool_id_t);

static OGS_POOL(sgwc_sess_pool, sgwc_sess_t);
static OGS_POOL(sgwc_sxa_seid_pool, ogs_pool_id_t);

static int context_initialized = 0;

static int num_of_sgwc_sess = 0;

static void stats_add_sgwc_session(void);
static void stats_remove_sgwc_session(void);

static bool sgwc_wildcard_match_ci(const char *pattern, const char *s)
{
    const char *p = NULL;
    const char *str = NULL;
    const char *star_p = NULL;
    const char *star_s = NULL;

    ogs_assert(pattern);
    ogs_assert(s);

    if (!strchr(pattern, '*'))
        return ogs_strcasecmp(s, pattern) == 0;

    p = pattern;
    str = s;

    while (*str) {
        if (*p == '*') {
            star_p = ++p;
            star_s = str;
            continue;
        }
        if (*p && tolower((unsigned char)*p) == tolower((unsigned char)*str)) {
            p++;
            str++;
            continue;
        }
        if (star_p) {
            p = star_p;
            str = ++star_s;
            continue;
        }
        return false;
    }

    while (*p == '*')
        p++;
    return *p == '\0';
}

void sgwc_sgwu_nwi_rewrite_clear(void)
{
    sgwc_sgwu_nwi_rewrite_rule_t *rule = NULL, *next_rule = NULL;

    ogs_list_for_each_safe(&self.sgwu_nwi_rewrite_list, next_rule, rule) {
        ogs_list_remove(&self.sgwu_nwi_rewrite_list, rule);
        if (rule->match)
            ogs_free(rule->match);
        if (rule->replace)
            ogs_free(rule->replace);
        ogs_free(rule);
    }
}

void sgwc_gn_pgw_clear_list(ogs_list_t *list)
{
    sgwc_gn_pgw_t *pgw = NULL, *next_pgw = NULL;

    ogs_assert(list);

    ogs_list_for_each_safe(list, next_pgw, pgw) {
        ogs_list_remove(list, pgw);
        ogs_free(pgw);
    }
}

static void sgwc_gn_pgw_clear(void)
{
    sgwc_gn_pgw_clear_list(&self.gn_pgw_list);
}

static void sgwc_sgwu_nwi_rewrite_add(
        const char *match, const char *replace, int selection_order)
{
    sgwc_sgwu_nwi_rewrite_rule_t *rule = NULL;

    ogs_assert(match);
    ogs_assert(replace);

    if (!match[0] || !replace[0]) {
        ogs_warn("sgwu_nwi_rewrite: empty match or replace ignored");
        return;
    }

    rule = ogs_calloc(1, sizeof(*rule));
    ogs_assert(rule);
    rule->match = ogs_strdup(match);
    ogs_assert(rule->match);
    rule->replace = ogs_strdup(replace);
    ogs_assert(rule->replace);
    rule->selection_order = selection_order;
    ogs_list_add(&self.sgwu_nwi_rewrite_list, rule);

    ogs_info("SGW-U NWI rewrite: [%s] -> [%s] order:%d "
            "(case-insensitive, * wildcard)",
            rule->match, rule->replace, rule->selection_order);
}

static int sgwc_sgwu_nwi_rewrite_order_cmp(const void *a, const void *b)
{
    const sgwc_sgwu_nwi_rewrite_rule_t * const *pa = a;
    const sgwc_sgwu_nwi_rewrite_rule_t * const *pb = b;

    return (*pa)->selection_order - (*pb)->selection_order;
}

void sgwc_sgwu_nwi_rewrite_resort(void)
{
    sgwc_sgwu_nwi_rewrite_rule_t *rule = NULL;
    sgwc_sgwu_nwi_rewrite_rule_t *rules[256];
    int i, n = 0;

    ogs_list_for_each(&self.sgwu_nwi_rewrite_list, rule) {
        if (n < (int)(sizeof(rules) / sizeof(rules[0])))
            rules[n++] = rule;
    }

    if (n <= 1)
        return;

    qsort(rules, n, sizeof(rules[0]), sgwc_sgwu_nwi_rewrite_order_cmp);

    while ((rule = ogs_list_first(&self.sgwu_nwi_rewrite_list)) != NULL)
        ogs_list_remove(&self.sgwu_nwi_rewrite_list, rule);

    for (i = 0; i < n; i++)
        ogs_list_add(&self.sgwu_nwi_rewrite_list, rules[i]);
}

static void sgwc_sgwu_nwi_rewrite_parse(ogs_yaml_iter_t *parent_iter)
{
    ogs_yaml_iter_t rule_array, rule_iter;
    int rule_entry_idx = 0;

    ogs_assert(parent_iter);

    ogs_yaml_iter_recurse(parent_iter, &rule_array);
    do {
        const char *match = NULL;
        const char *replace = NULL;
        const char *order_v = NULL;

        if (ogs_yaml_iter_type(&rule_array) == YAML_MAPPING_NODE) {
            memcpy(&rule_iter, &rule_array, sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(&rule_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&rule_array))
                break;
            ogs_yaml_iter_recurse(&rule_array, &rule_iter);
        } else if (ogs_yaml_iter_type(&rule_array) == YAML_SCALAR_NODE) {
            break;
        } else
            ogs_assert_if_reached();

        while (ogs_yaml_iter_next(&rule_iter)) {
            const char *key = ogs_yaml_iter_key(&rule_iter);
            ogs_assert(key);
            if (!strcmp(key, "match") || !strcmp(key, "from"))
                match = ogs_yaml_iter_value(&rule_iter);
            else if (!strcmp(key, "replace") || !strcmp(key, "to"))
                replace = ogs_yaml_iter_value(&rule_iter);
            else if (!strcmp(key, "order"))
                order_v = ogs_yaml_iter_value(&rule_iter);
            else
                ogs_warn("unknown key `%s` in sgwu_nwi_rewrite rule", key);
        }

        if (match && replace) {
            sgwc_sgwu_nwi_rewrite_add(match, replace,
                    ogs_pfcp_entry_selection_order(rule_entry_idx, order_v));
            rule_entry_idx++;
        } else if (match || replace)
            ogs_warn("sgwu_nwi_rewrite rule needs both match and replace");
    } while (ogs_yaml_iter_type(&rule_array) == YAML_SEQUENCE_NODE);

    sgwc_sgwu_nwi_rewrite_resort();
}

static bool sgwc_sgwu_nwi_rewrite_key(const char *key)
{
    return !strcmp(key, "sgwu_nwi_rewrite") ||
           !strcmp(key, "nwi_rewrite") ||
           !strcmp(key, "pfcp_nwi_rewrite");
}

static bool sgwc_sgwu_nwi_rewrite_apply(
        sgwc_sess_t *sess, char *nwi, int buflen)
{
    sgwc_sgwu_nwi_rewrite_rule_t *rule = NULL;
    const char *candidates[2];
    int i;

    ogs_assert(sess);
    ogs_assert(nwi);
    ogs_assert(buflen > OGS_MAX_APN_LEN);

    if (ogs_list_empty(&self.sgwu_nwi_rewrite_list))
        return false;

    candidates[0] = nwi;
    candidates[1] = sess->session.name;

    for (i = 0; i < 2; i++) {
        const char *candidate = candidates[i];

        if (!candidate || !candidate[0])
            continue;

        ogs_list_for_each(&self.sgwu_nwi_rewrite_list, rule) {
            if (sgwc_wildcard_match_ci(rule->match, candidate)) {
                ogs_debug("SGW-U NWI rewrite: %s -> %s (pattern %s)",
                        candidate, rule->replace, rule->match);
                ogs_cpystrn(nwi, rule->replace, buflen);
                return true;
            }
        }
    }

    return false;
}

static void sgwc_gtpu_teid_conf_apply_key(
        const char *key, ogs_yaml_iter_t *iter,
        bool *force_cp_teid,
        uint32_t *teid_offset,
        uint8_t *teid_range_indication,
        uint8_t *teid_range)
{
    const char *value = NULL;

    ogs_assert(key);
    ogs_assert(iter);

    if (!strcmp(key, "force_cp_teid") || !strcmp(key, "cp_teid")) {
        *force_cp_teid = ogs_yaml_iter_bool(iter);
    } else if (!strcmp(key, "teid_offset")) {
        value = ogs_yaml_iter_value(iter);
        if (value)
            *teid_offset = (uint32_t)strtoul(value, NULL, 0);
    } else if (!strcmp(key, "teid_range_indication")) {
        value = ogs_yaml_iter_value(iter);
        if (value) {
            int teidri = atoi(value);

            if (teidri < 1 || teidri > 7)
                ogs_warn("teid_range_indication %d out of range (1..7)",
                        teidri);
            else
                *teid_range_indication = (uint8_t)teidri;
        }
    } else if (!strcmp(key, "teid_range")) {
        value = ogs_yaml_iter_value(iter);
        if (value)
            *teid_range = (uint8_t)strtoul(value, NULL, 0);
    }
}

static bool sgwc_gtpu_use_cp_teid(sgwc_sess_t *sess)
{
    ogs_assert(sess);

    if (sgwc_self()->gtpu_force_cp_teid)
        return true;
    if (sgwc_sess_is_inbound_roam(sess) &&
            sgwc_self()->inbound_roam_gtpu_force_cp_teid)
        return true;
    return false;
}

static bool sgwc_gtpu_has_teid_encoding(sgwc_sess_t *sess)
{
    ogs_assert(sess);

    if (sgwc_sess_is_inbound_roam(sess)) {
        if (sgwc_self()->inbound_roam_gtpu_teid_offset ||
                sgwc_self()->inbound_roam_gtpu_teid_range_indication)
            return true;
    } else if (sgwc_self()->gtpu_teid_offset ||
            sgwc_self()->gtpu_teid_range_indication) {
        return true;
    }
    return false;
}

static uint32_t sgwc_gtpu_teid_from_index(sgwc_sess_t *sess, uint32_t index)
{
    uint8_t teidri = 0;
    uint8_t teid_range = 0;
    uint32_t offset = 0;

    ogs_assert(sess);

    if (sgwc_sess_is_inbound_roam(sess)) {
        teidri = sgwc_self()->inbound_roam_gtpu_teid_range_indication;
        teid_range = sgwc_self()->inbound_roam_gtpu_teid_range;
        offset = sgwc_self()->inbound_roam_gtpu_teid_offset;
    } else {
        teidri = sgwc_self()->gtpu_teid_range_indication;
        teid_range = sgwc_self()->gtpu_teid_range;
        offset = sgwc_self()->gtpu_teid_offset;
    }

    if (teidri)
        index = OGS_PFCP_GTPU_INDEX_TO_TEID(index, teidri, teid_range);
    if (offset)
        index += offset;

    return index;
}

void sgwc_context_init(void)
{
    ogs_assert(context_initialized == 0);

    memset(&self, 0, sizeof(sgwc_context_t));

    ogs_log_install_domain(&__sgwc_log_domain, "sgwc", ogs_core()->log.level);

    ogs_pool_init(&sgwc_bearer_pool, ogs_app()->pool.bearer);
    ogs_pool_init(&sgwc_tunnel_pool, ogs_app()->pool.tunnel);

    ogs_pool_init(&sgwc_ue_pool, ogs_global_conf()->max.ue);
    ogs_pool_init(&sgwc_s11_teid_pool, ogs_global_conf()->max.ue);
    ogs_pool_random_id_generate(&sgwc_s11_teid_pool);

    ogs_pool_init(&sgwc_sess_pool, ogs_app()->pool.sess);
    ogs_pool_init(&sgwc_sxa_seid_pool, ogs_app()->pool.sess);
    ogs_pool_random_id_generate(&sgwc_sxa_seid_pool);

    self.imsi_ue_hash = ogs_hash_make();
    ogs_assert(self.imsi_ue_hash);
    self.sgw_s11_teid_hash = ogs_hash_make();
    ogs_assert(self.sgw_s11_teid_hash);
    self.sgwc_sxa_seid_hash = ogs_hash_make();
    ogs_assert(self.sgwc_sxa_seid_hash);

    ogs_list_init(&self.sgw_ue_list);
    ogs_list_init(&self.sgwu_nwi_rewrite_list);
    ogs_list_init(&self.sgsn_gn_list);
    ogs_list_init(&self.gn_server_list);
    ogs_list_init(&self.gn_server_list6);
    ogs_list_init(&self.gn_pgw_list);

    self.cdr.enabled = false;
    self.cdr.interim_interval_s = 300;
    self.cdr.rotate_max_records = 100;
    self.cdr.rotate_max_bytes = 65536;
    self.cdr.rotate_max_seconds = 30;
    self.cdr.triggers = SGWC_CDR_TRIG_START | SGWC_CDR_TRIG_INTERIM |
            SGWC_CDR_TRIG_STOP;
    self.cdr_local_seq = 0;

    self.orphan.enabled = true;
    self.orphan.purge = true;
    self.orphan.interval_s = 60;
    self.orphan.grace_s = 30;
    self.orphan.t_sweep = NULL;

    self.gtpc_recovery = 0;
    self.gtpc_echo_interval = 0;
    self.gn_gtpc_recovery = 0;
    self.recovery_counter_file = SGWC_RECOVERY_COUNTER_FILE;
    self.pfcp_send_user_id = true;

    context_initialized = 1;
}

void sgwc_context_final(void)
{
    ogs_gtp_node_t *gnode = NULL, *next_gnode = NULL;

    ogs_assert(context_initialized == 1);

    sgwc_ue_remove_all();

    ogs_list_for_each_safe(&self.mme_s11_list, next_gnode, gnode)
        sgwc_mme_peer_detach(gnode);

    ogs_list_for_each_safe(&self.pgw_s5c_list, next_gnode, gnode)
        sgwc_pgw_peer_detach(gnode);

    ogs_assert(self.imsi_ue_hash);
    ogs_hash_destroy(self.imsi_ue_hash);
    ogs_assert(self.sgw_s11_teid_hash);
    ogs_hash_destroy(self.sgw_s11_teid_hash);
    ogs_assert(self.sgwc_sxa_seid_hash);
    ogs_hash_destroy(self.sgwc_sxa_seid_hash);

    ogs_pool_final(&sgwc_tunnel_pool);
    ogs_pool_final(&sgwc_bearer_pool);

    ogs_pool_final(&sgwc_ue_pool);
    ogs_pool_final(&sgwc_s11_teid_pool);

    ogs_pool_final(&sgwc_sess_pool);
    ogs_pool_final(&sgwc_sxa_seid_pool);

    ogs_gtp_node_remove_all(&self.mme_s11_list);
    ogs_gtp_node_remove_all(&self.pgw_s5c_list);

    sgwc_sgwu_nwi_rewrite_clear();
    sgwc_gn_pgw_clear();

    context_initialized = 0;
}

sgwc_context_t *sgwc_self(void)
{
    return &self;
}

static bool sgwc_mme_recovery_is_restart(uint8_t stored, uint8_t received)
{
    /*
     * 3GPP TS 23.007: the 8-bit Restart Counter is a serial number (RFC 1982).
     * A restart is indicated ONLY when the received value is STRICTLY NEWER
     * than the stored one (forward distance received - stored in 1..127). The
     * old "received > stored" test flagged both directions and let two
     * interleaved values purge on every message.
     */
    if (received == stored)
        return false;
    return (uint8_t)(received - stored) < 128;
}

static void sgwc_mme_purge_sessions(ogs_gtp_node_t *gnode)
{
    sgwc_ue_t *sgwc_ue = NULL, *next_ue = NULL;
    sgwc_sess_t *sess = NULL, *next_sess = NULL;
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(gnode);

    ogs_warn("MME [%s]:%d recovery restart: purging SGWC sessions",
            OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));

    ogs_list_for_each_safe(&self.sgw_ue_list, next_ue, sgwc_ue) {
        if (sgwc_ue->gnode != gnode)
            continue;

        ogs_list_for_each_safe(&sgwc_ue->sess_list, next_sess, sess) {
            ogs_warn("[%s] MME recovery restart: delete session toward PGW/SMF",
                    sgwc_ue->imsi_bcd);

            /* Remove data-plane bearer on SGW-U */
            if (sess->pfcp_node && sess->sgwu_sxa_seid)
                sgwc_pfcp_send_session_deletion_request(
                        sess, OGS_INVALID_POOL_ID, NULL);

            /* Delete PDN connection on PGW/SMF (S5C) */
            if (sess->gnode)
                sgwc_gtp_send_s5c_delete_session_request(sess);

            sgwc_sess_remove(sess);
        }

        if (ogs_list_empty(&sgwc_ue->sess_list))
            sgwc_ue_remove(sgwc_ue);
    }
}

sgwc_mme_peer_t *sgwc_mme_peer_get(ogs_gtp_node_t *gnode)
{
    ogs_assert(gnode);
    return gnode->data_ptr;
}

void sgwc_mme_peer_attach(ogs_gtp_node_t *gnode)
{
    sgwc_mme_peer_t *peer = NULL;

    ogs_assert(gnode);

    if (gnode->data_ptr)
        return;

    peer = ogs_calloc(1, sizeof(*peer));
    ogs_assert(peer);
    peer->gnode = gnode;
    gnode->data_ptr = peer;
}

void sgwc_mme_peer_detach(ogs_gtp_node_t *gnode)
{
    sgwc_mme_peer_t *peer = NULL;

    ogs_assert(gnode);

    peer = gnode->data_ptr;
    if (!peer)
        return;

    if (peer->t_echo) {
        ogs_timer_delete(peer->t_echo);
        peer->t_echo = NULL;
    }

    gnode->data_ptr = NULL;
    ogs_free(peer);
}

bool sgwc_mme_recovery_update(sgwc_mme_peer_t *peer, uint8_t recovery)
{
    ogs_gtp_node_t *gnode = NULL;
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(peer);
    gnode = peer->gnode;
    ogs_assert(gnode);

    if (!peer->peer_recovery_valid) {
        peer->peer_recovery = recovery;
        peer->peer_recovery_valid = true;
        ogs_info("MME [%s]:%d recovery=%u (initial)",
                OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr),
                recovery);
        return false;
    }

    /* Unchanged: keep the stored value, do nothing. */
    if (recovery == peer->peer_recovery)
        return false;

    if (!sgwc_mme_recovery_is_restart(peer->peer_recovery, recovery)) {
        /* Older / out-of-order: do NOT advance the baseline and do NOT purge. */
        ogs_warn("MME [%s]:%d ignoring non-newer recovery %u (stored %u)",
                OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr),
                recovery, peer->peer_recovery);
        return false;
    }

    ogs_warn("MME [%s]:%d recovery changed %u -> %u (restart)",
            OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr),
            peer->peer_recovery, recovery);
    peer->peer_recovery = recovery;
    sgwc_mme_purge_sessions(gnode);
    return true;
}

void sgwc_mme_echo_schedule(sgwc_mme_peer_t *peer)
{
    ogs_time_t interval;

    ogs_assert(peer);
    ogs_assert(peer->t_echo);

    interval = sgwc_self()->gtpc_echo_interval ?
        ogs_time_from_sec(sgwc_self()->gtpc_echo_interval) :
        ogs_time_from_sec(60);

    ogs_timer_start(peer->t_echo, interval);
}

void sgwc_mme_echo_reschedule_all(void)
{
    ogs_gtp_node_t *gnode = NULL;
    sgwc_mme_peer_t *peer = NULL;

    ogs_list_for_each(&self.mme_s11_list, gnode) {
        peer = sgwc_mme_peer_get(gnode);
        if (peer && peer->t_echo)
            sgwc_mme_echo_schedule(peer);
    }
}

static bool sgwc_pgw_recovery_is_restart(uint8_t stored, uint8_t received)
{
    /*
     * 3GPP TS 23.007: the 8-bit Restart Counter is a serial number (RFC 1982).
     * A restart is indicated ONLY when the received value is STRICTLY NEWER
     * than the stored one (forward distance received - stored in 1..127). The
     * old "received > stored" test flagged both directions and let two
     * interleaved values purge on every message.
     */
    if (received == stored)
        return false;
    return (uint8_t)(received - stored) < 128;
}

static void sgwc_pgw_purge_sessions(ogs_gtp_node_t *gnode)
{
    sgwc_ue_t *sgwc_ue = NULL, *next_ue = NULL;
    sgwc_sess_t *sess = NULL, *next_sess = NULL;
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(gnode);

    ogs_warn("PGW [%s]:%d recovery restart: purging SGWC sessions",
            OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));

    ogs_list_for_each_safe(&self.sgw_ue_list, next_ue, sgwc_ue) {
        ogs_list_for_each_safe(&sgwc_ue->sess_list, next_sess, sess) {
            if (sess->gnode != gnode)
                continue;

            ogs_warn("[%s] PGW recovery restart: delete session",
                    sgwc_ue->imsi_bcd);
            /*
             * Notify the MME so it releases the UE/bearer contexts. This MUST
             * be a Delete Bearer Request (network-initiated, carrying the
             * default-bearer EBI): the MME has no handler for a received Delete
             * Session Request and silently drops it ("Not implemented"), which
             * left stale UE contexts on the MME after a PGW/SMF restart.
             * Fire-and-forget with the same per-bearer timeout fallback used by
             * the admin detach path; sgwc_sess_remove() below frees the local
             * context (and the SGW-U PFCP session) immediately afterward.
             */
            sgwc_gtp_send_delete_bearer_request_to_mme(
                    sgwc_ue, sess, OGS_INVALID_POOL_ID);
            sgwc_sess_remove(sess);
        }

        if (ogs_list_empty(&sgwc_ue->sess_list))
            sgwc_ue_remove(sgwc_ue);
    }
}

sgwc_pgw_peer_t *sgwc_pgw_peer_get(ogs_gtp_node_t *gnode)
{
    ogs_assert(gnode);
    return gnode->data_ptr;
}

void sgwc_pgw_peer_attach(ogs_gtp_node_t *gnode)
{
    sgwc_pgw_peer_t *peer = NULL;

    ogs_assert(gnode);

    if (gnode->data_ptr)
        return;

    peer = ogs_calloc(1, sizeof(*peer));
    ogs_assert(peer);
    peer->gnode = gnode;
    gnode->data_ptr = peer;
}

void sgwc_pgw_peer_detach(ogs_gtp_node_t *gnode)
{
    sgwc_pgw_peer_t *peer = NULL;

    ogs_assert(gnode);

    peer = gnode->data_ptr;
    if (!peer)
        return;

    if (peer->t_echo) {
        ogs_timer_delete(peer->t_echo);
        peer->t_echo = NULL;
    }

    gnode->data_ptr = NULL;
    ogs_free(peer);
}

bool sgwc_pgw_recovery_update(sgwc_pgw_peer_t *peer, uint8_t recovery)
{
    ogs_gtp_node_t *gnode = NULL;
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(peer);
    gnode = peer->gnode;
    ogs_assert(gnode);

    if (!peer->peer_recovery_valid) {
        peer->peer_recovery = recovery;
        peer->peer_recovery_valid = true;
        ogs_info("PGW [%s]:%d recovery=%u (initial)",
                OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr),
                recovery);
        return false;
    }

    /* Unchanged: keep the stored value, do nothing. */
    if (recovery == peer->peer_recovery)
        return false;

    if (!sgwc_pgw_recovery_is_restart(peer->peer_recovery, recovery)) {
        /* Older / out-of-order: do NOT advance the baseline and do NOT purge. */
        ogs_warn("PGW [%s]:%d ignoring non-newer recovery %u (stored %u)",
                OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr),
                recovery, peer->peer_recovery);
        return false;
    }

    ogs_warn("PGW [%s]:%d recovery changed %u -> %u (restart)",
            OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr),
            peer->peer_recovery, recovery);
    peer->peer_recovery = recovery;
    sgwc_pgw_purge_sessions(gnode);
    return true;
}

void sgwc_pgw_echo_schedule(sgwc_pgw_peer_t *peer)
{
    ogs_time_t interval;

    ogs_assert(peer);
    ogs_assert(peer->t_echo);

    interval = sgwc_self()->gtpc_echo_interval ?
        ogs_time_from_sec(sgwc_self()->gtpc_echo_interval) :
        ogs_time_from_sec(60);

    ogs_timer_start(peer->t_echo, interval);
}

void sgwc_pgw_echo_reschedule_all(void)
{
    ogs_gtp_node_t *gnode = NULL;
    sgwc_pgw_peer_t *peer = NULL;

    ogs_list_for_each(&self.pgw_s5c_list, gnode) {
        peer = sgwc_pgw_peer_get(gnode);
        if (peer && peer->t_echo)
            sgwc_pgw_echo_schedule(peer);
    }
}

sgwc_sgsn_peer_t *sgwc_sgsn_peer_get(ogs_gtp_node_t *gnode)
{
    ogs_assert(gnode);
    return gnode->data_ptr;
}

void sgwc_sgsn_peer_attach(ogs_gtp_node_t *gnode)
{
    sgwc_sgsn_peer_t *peer = NULL;

    ogs_assert(gnode);

    if (gnode->data_ptr)
        return;

    peer = ogs_calloc(1, sizeof(*peer));
    ogs_assert(peer);
    peer->gnode = gnode;
    gnode->data_ptr = peer;
}

void sgwc_sgsn_peer_detach(ogs_gtp_node_t *gnode)
{
    sgwc_sgsn_peer_t *peer = NULL;

    ogs_assert(gnode);

    peer = gnode->data_ptr;
    if (!peer)
        return;

    if (peer->t_echo) {
        ogs_timer_delete(peer->t_echo);
        peer->t_echo = NULL;
    }

    gnode->data_ptr = NULL;
    ogs_free(peer);
}

void sgwc_sgsn_peer_setup(ogs_gtp_node_t *gnode)
{
    ogs_gtp_node_t *mme_gnode = NULL;
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(gnode);

    mme_gnode = ogs_gtp_node_find_by_addr(
            &sgwc_self()->mme_s11_list, &gnode->addr);
    if (mme_gnode) {
        ogs_info("Remove [%s]:%d from S11 (Gn SGSN peer)",
                OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));
        sgwc_mme_peer_detach(mme_gnode);
        ogs_gtp_node_remove(&sgwc_self()->mme_s11_list, mme_gnode);
    }

    sgwc_sgsn_peer_attach(gnode);
    ogs_info("SGWC Gn SGSN peer: [%s]:%d",
            OGS_ADDR(&gnode->addr, buf), OGS_PORT(&gnode->addr));

    sgwc_sgsn_peer_start_echo(gnode);
}

void sgwc_sgsn_echo_schedule(sgwc_sgsn_peer_t *peer)
{
    ogs_time_t interval;

    ogs_assert(peer);
    ogs_assert(peer->t_echo);

    interval = sgwc_self()->gtpc_echo_interval ?
        ogs_time_from_sec(sgwc_self()->gtpc_echo_interval) :
        ogs_time_from_sec(60);

    ogs_timer_start(peer->t_echo, interval);
}

static int sgwc_context_prepare(void)
{
    return OGS_OK;
}

static int sgwc_gn_yaml_add_server(ogs_yaml_iter_t *parent, const char *key,
        ogs_list_t *list, ogs_list_t *list6)
{
    ogs_yaml_iter_t array, iter;
    const char *iter_key = NULL;

    ogs_yaml_iter_recurse(parent, &array);
    do {
        const char *v = NULL;
        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
        uint16_t port = 0;
        int i, num = 0;
        int rv;
        ogs_sockaddr_t *addr = NULL;

        if (ogs_yaml_iter_type(&array) == YAML_MAPPING_NODE)
            break;
        if (ogs_yaml_iter_type(&array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&array))
                break;
            ogs_yaml_iter_recurse(&array, &iter);
        } else if (ogs_yaml_iter_type(&array) == YAML_SCALAR_NODE) {
            ogs_yaml_iter_recurse(parent, &iter);
        } else
            ogs_assert_if_reached();

        while (ogs_yaml_iter_next(&iter)) {
            iter_key = ogs_yaml_iter_key(&iter);
            ogs_assert(iter_key);
            if (!strcmp(iter_key, key) || !strcmp(iter_key, "addr") ||
                    !strcmp(iter_key, "name")) {
                v = ogs_yaml_iter_value(&iter);
                if (v) {
                    hostname[num] = v;
                    num++;
                }
            } else if (!strcmp(iter_key, "port")) {
                v = ogs_yaml_iter_value(&iter);
                if (v)
                    port = (uint16_t)atoi(v);
            }
        }

        if (!port)
            port = ogs_gtp_self()->gtpc_port ? ogs_gtp_self()->gtpc_port : 2123;

        for (i = 0; i < num; i++) {
            rv = ogs_addaddrinfo(&addr, AF_UNSPEC, hostname[i], port, 0);
            ogs_assert(rv == OGS_OK);
        }

        if (addr) {
            ogs_sockaddr_t *current = addr;
            while (current) {
                if (current->ogs_sa_family == AF_INET &&
                        ogs_global_conf()->parameter.no_ipv4 == 0)
                    ogs_socknode_add(list, AF_INET, current, NULL);
                if (current->ogs_sa_family == AF_INET6 &&
                        ogs_global_conf()->parameter.no_ipv6 == 0)
                    ogs_socknode_add(list6, AF_INET6, current, NULL);
                current = current->next;
            }
            ogs_freeaddrinfo(addr);
        }
    } while (ogs_yaml_iter_type(&array) == YAML_SEQUENCE_NODE &&
            ogs_yaml_iter_next(&array));

    return OGS_OK;
}

static int sgwc_gn_pgw_apply_addr(
        sgwc_gn_pgw_t *pgw, ogs_sockaddr_t *addr, uint16_t port)
{
    int rv;
    ogs_sockaddr_t *v4 = NULL, *v6 = NULL;

    ogs_assert(pgw);
    ogs_assert(addr);

    rv = ogs_copyaddrinfo(&v4, addr);
    ogs_assert(rv == OGS_OK);
    rv = ogs_copyaddrinfo(&v6, addr);
    ogs_assert(rv == OGS_OK);
    rv = ogs_filteraddrinfo(&v4, AF_INET);
    ogs_assert(rv == OGS_OK);
    rv = ogs_filteraddrinfo(&v6, AF_INET6);
    ogs_assert(rv == OGS_OK);

    memset(&pgw->f_teid, 0, sizeof(pgw->f_teid));
    pgw->f_teid.interface_type = OGS_GTP2_F_TEID_S5_S8_PGW_GTP_C;
    pgw->f_teid.teid = 0;
    rv = ogs_gtp2_sockaddr_to_f_teid(v4, v6, &pgw->f_teid, &pgw->f_teid_len);
    ogs_freeaddrinfo(v4);
    ogs_freeaddrinfo(v6);

    if (port && port != ogs_gtp_self()->gtpc_port) {
        ogs_warn("gn.pgw.port ignored; PGW destination uses gtpc port %u",
                ogs_gtp_self()->gtpc_port);
    }

    return rv;
}

static sgwc_gn_pgw_t *sgwc_gn_pgw_add(ogs_list_t *list,
        const char *hostname, uint16_t port, const char *imsi_prefix,
        int selection_order)
{
    int rv;
    ogs_sockaddr_t *addr = NULL;
    sgwc_gn_pgw_t *pgw = NULL;

    ogs_assert(list);
    ogs_assert(hostname);

    if (!port)
        port = ogs_gtp_self()->gtpc_port;

    rv = ogs_addaddrinfo(&addr, AF_UNSPEC, hostname, port, 0);
    if (rv != OGS_OK || !addr) {
        ogs_error("gn.pgw address resolution failed [%s]", hostname);
        return NULL;
    }

    pgw = ogs_calloc(1, sizeof(*pgw));
    if (!pgw) {
        ogs_error("gn.pgw alloc failed");
        ogs_freeaddrinfo(addr);
        return NULL;
    }

    if (imsi_prefix && imsi_prefix[0]) {
        ogs_cpystrn(pgw->imsi_prefix, imsi_prefix, sizeof(pgw->imsi_prefix));
    }

    pgw->selection_order = selection_order;

    rv = sgwc_gn_pgw_apply_addr(pgw, addr, port);
    ogs_freeaddrinfo(addr);
    if (rv != OGS_OK) {
        ogs_error("gn.pgw F-TEID build failed [%s]", hostname);
        ogs_free(pgw);
        return NULL;
    }

    ogs_list_add(list, pgw);
    return pgw;
}

void sgwc_gn_pgw_yaml_add(ogs_list_t *list, ogs_yaml_iter_t *parent_iter)
{
    ogs_yaml_iter_t pgw_array, pgw_item;
    int pgw_entry_idx = 0;

    ogs_assert(list);
    ogs_assert(parent_iter);

    ogs_yaml_iter_recurse(parent_iter, &pgw_array);
    do {
        const char *hostname = NULL;
        const char *imsi_prefix = NULL;
        const char *order_v = NULL;
        uint16_t port = 0;

        if (ogs_yaml_iter_type(&pgw_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&pgw_array))
                break;
            ogs_yaml_iter_recurse(&pgw_array, &pgw_item);
        } else {
            ogs_yaml_iter_recurse(parent_iter, &pgw_item);
        }

        while (ogs_yaml_iter_next(&pgw_item)) {
            const char *pk = ogs_yaml_iter_key(&pgw_item);
            const char *pv = ogs_yaml_iter_value(&pgw_item);
            ogs_assert(pk);
            if (!strcmp(pk, "address") || !strcmp(pk, "addr") ||
                    !strcmp(pk, "name"))
                hostname = pv;
            else if (!strcmp(pk, "port") && pv)
                port = (uint16_t)atoi(pv);
            else if (!strcmp(pk, "imsi_prefix") && pv)
                imsi_prefix = pv;
            else if (!strcmp(pk, "order") && pv)
                order_v = pv;
        }

        if (hostname) {
            if (!sgwc_gn_pgw_add(list, hostname, port, imsi_prefix,
                        ogs_pfcp_entry_selection_order(pgw_entry_idx,
                            order_v))) {
                ogs_error("Failed to add gn.pgw [%s]", hostname);
            } else {
                pgw_entry_idx++;
            }
        }

        if (ogs_yaml_iter_type(&pgw_array) != YAML_SEQUENCE_NODE)
            break;
    } while (ogs_yaml_iter_type(&pgw_array) == YAML_SEQUENCE_NODE);
}

sgwc_gn_pgw_t *sgwc_gn_pgw_find_for_ue(sgwc_ue_t *sgwc_ue)
{
    sgwc_gn_pgw_t *pgw = NULL;
    sgwc_gn_pgw_t *best = NULL;
    sgwc_gn_pgw_t *default_pgw = NULL;
    int best_prefix_len = -1;
    int best_order = INT_MAX;

    ogs_list_for_each(&self.gn_pgw_list, pgw) {
        if (!pgw->imsi_prefix[0]) {
            if (!default_pgw ||
                    pgw->selection_order < default_pgw->selection_order)
                default_pgw = pgw;
            continue;
        }

        if (!sgwc_ue || !sgwc_ue->imsi_bcd[0])
            continue;

        if (strncmp(sgwc_ue->imsi_bcd, pgw->imsi_prefix,
                    strlen(pgw->imsi_prefix)) == 0) {
            int plen = (int)strlen(pgw->imsi_prefix);

            if (plen > best_prefix_len ||
                    (plen == best_prefix_len &&
                     pgw->selection_order < best_order)) {
                best_prefix_len = plen;
                best_order = pgw->selection_order;
                best = pgw;
            }
        }
    }

    if (best) {
        ogs_debug("Gn PGW selected imsi_prefix:%s IMSI:%s order:%d",
                best->imsi_prefix, sgwc_ue->imsi_bcd, best->selection_order);
        return best;
    }

    if (default_pgw) {
        ogs_debug("Gn PGW selected default IMSI:%s order:%d",
                sgwc_ue && sgwc_ue->imsi_bcd[0] ? sgwc_ue->imsi_bcd : "-",
                default_pgw->selection_order);
    }

    return default_pgw;
}

static int sgwc_context_validation(void)
{
    if (ogs_list_empty(&ogs_gtp_self()->gtpc_list) &&
        ogs_list_empty(&ogs_gtp_self()->gtpc_list6)) {
        ogs_error("No sgwc.gtpc in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }
    if (self.gn_enabled && ogs_list_empty(&self.gn_pgw_list)) {
        ogs_error("sgwc.gn requires pgw/smf address in '%s'", ogs_app()->file);
        return OGS_ERROR;
    }
    return OGS_OK;
}

int sgwc_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_app()->document;
    ogs_assert(document);

    rv = sgwc_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "sgwc")) {
            ogs_yaml_iter_t sgwc_iter;
            ogs_yaml_iter_recurse(&root_iter, &sgwc_iter);
            while (ogs_yaml_iter_next(&sgwc_iter)) {
                const char *sgwc_key = ogs_yaml_iter_key(&sgwc_iter);
                ogs_assert(sgwc_key);
                if (!strcmp(sgwc_key, "gtpc")) {
                    ogs_yaml_iter_t gtpc_iter;
                    ogs_yaml_iter_recurse(&sgwc_iter, &gtpc_iter);
                    while (ogs_yaml_iter_next(&gtpc_iter)) {
                        const char *gtpc_key = ogs_yaml_iter_key(&gtpc_iter);
                        ogs_assert(gtpc_key);
                        if (!strcmp(gtpc_key, "echo_interval")) {
                            const char *v = ogs_yaml_iter_value(&gtpc_iter);
                            if (v)
                                self.gtpc_echo_interval = atoi(v);
                        } else if (!strcmp(gtpc_key,
                                "recovery_counter_file")) {
                            const char *v = ogs_yaml_iter_value(&gtpc_iter);
                            if (v) self.recovery_counter_file = v;
                        }
                    }
                } else if (!strcmp(sgwc_key, "gtpu")) {
                    ogs_yaml_iter_t gtpu_iter;
                    ogs_yaml_iter_recurse(&sgwc_iter, &gtpu_iter);
                    while (ogs_yaml_iter_next(&gtpu_iter)) {
                        const char *gk = ogs_yaml_iter_key(&gtpu_iter);
                        ogs_assert(gk);
                        sgwc_gtpu_teid_conf_apply_key(gk, &gtpu_iter,
                                &self.gtpu_force_cp_teid,
                                &self.gtpu_teid_offset,
                                &self.gtpu_teid_range_indication,
                                &self.gtpu_teid_range);
                    }
                    if (self.gtpu_force_cp_teid)
                        ogs_info("GTP-U: SGWC assigns F-TEID (gtpu.force_cp_teid)");
                    if (self.gtpu_teid_offset ||
                            self.gtpu_teid_range_indication)
                        ogs_info("GTP-U TEID offset=0x%x "
                                "teid_range_indication=%u teid_range=%u",
                                self.gtpu_teid_offset,
                                self.gtpu_teid_range_indication,
                                self.gtpu_teid_range);
                } else if (sgwc_sgwu_nwi_rewrite_key(sgwc_key)) {
                    sgwc_sgwu_nwi_rewrite_parse(&sgwc_iter);
                } else if (!strcmp(sgwc_key, "pfcp")) {
                    ogs_yaml_iter_t pfcp_iter;
                    ogs_yaml_iter_recurse(&sgwc_iter, &pfcp_iter);
                    while (ogs_yaml_iter_next(&pfcp_iter)) {
                        const char *pfcp_key = ogs_yaml_iter_key(&pfcp_iter);
                        ogs_assert(pfcp_key);
                        if (!strcmp(pfcp_key, "send_user_id") ||
                                !strcmp(pfcp_key, "send_user_id_to_sgwu")) {
                            self.pfcp_send_user_id =
                                ogs_yaml_iter_bool(&pfcp_iter);
                        }
                    }
                } else if (!strcmp(sgwc_key, "sgwu")) {
                    /* handle config in pfcp library */
                } else if (!strcmp(sgwc_key, "trace_imsi")) {
                    ogs_yaml_iter_t trace_array, trace_iter;

                    ogs_yaml_iter_recurse(&sgwc_iter, &trace_array);
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
                            ogs_yaml_iter_recurse(&sgwc_iter, &trace_iter);
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
                } else if (!strcmp(sgwc_key, "inbound_roam")) {
                    ogs_yaml_iter_t roam_iter;
                    ogs_yaml_iter_recurse(&sgwc_iter, &roam_iter);
                    while (ogs_yaml_iter_next(&roam_iter)) {
                        const char *rk = ogs_yaml_iter_key(&roam_iter);
                        ogs_assert(rk);
                        if (!strcmp(rk, "gtpc")) {
                            ogs_yaml_iter_t gtpc_iter;
                            ogs_yaml_iter_recurse(&roam_iter, &gtpc_iter);
                            while (ogs_yaml_iter_next(&gtpc_iter)) {
                                const char *gk =
                                    ogs_yaml_iter_key(&gtpc_iter);
                                const char *gv =
                                    ogs_yaml_iter_value(&gtpc_iter);
                                ogs_assert(gk);
                                if (!strcmp(gk, "source_port") ||
                                        !strcmp(gk, "send_port") ||
                                        !strcmp(gk, "port")) {
                                    if (gv)
                                        self.inbound_roam_gtpc_source_port =
                                            (uint16_t)atoi(gv);
                                } else if (!strcmp(gk, "teid_offset")) {
                                    if (gv)
                                        self.inbound_roam_teid_offset =
                                            (uint32_t)strtoul(gv, NULL, 0);
                                } else if (!strcmp(gk,
                                            "send_recovery_on_s5_csr") ||
                                        !strcmp(gk, "recovery_on_s5_csr")) {
                                    self.inbound_roam_gtpc_send_recovery_on_s5_csr =
                                        ogs_yaml_iter_bool(&gtpc_iter);
                                } else if (!strcmp(gk, "recv_port") ||
                                        !strcmp(gk, "dest_port") ||
                                        !strcmp(gk, "destination_port")) {
                                    ogs_warn("sgwc.inbound_roam.gtpc.%s "
                                            "ignored — PGW destination is "
                                            "always gtpc.server.port (%u)",
                                            gk, ogs_gtp_self()->gtpc_port);
                                } else
                                    ogs_warn("unknown key `%s` in "
                                            "sgwc.inbound_roam.gtpc", gk);
                            }
                        } else if (!strcmp(rk, "gtpu")) {
                            ogs_yaml_iter_t gtpu_iter;
                            ogs_yaml_iter_recurse(&roam_iter, &gtpu_iter);
                            while (ogs_yaml_iter_next(&gtpu_iter)) {
                                const char *gk = ogs_yaml_iter_key(&gtpu_iter);
                                ogs_assert(gk);
                                sgwc_gtpu_teid_conf_apply_key(gk, &gtpu_iter,
                                        &self.inbound_roam_gtpu_force_cp_teid,
                                        &self.inbound_roam_gtpu_teid_offset,
                                        &self.inbound_roam_gtpu_teid_range_indication,
                                        &self.inbound_roam_gtpu_teid_range);
                            }
                        } else if (!strcmp(rk, "teid_offset")) {
                            const char *rv =
                                ogs_yaml_iter_value(&roam_iter);
                            if (rv)
                                self.inbound_roam_teid_offset =
                                    (uint32_t)strtoul(rv, NULL, 0);
                        } else if (sgwc_sgwu_nwi_rewrite_key(rk)) {
                            sgwc_sgwu_nwi_rewrite_parse(&roam_iter);
                        } else
                            ogs_warn("unknown key `%s` in sgwc.inbound_roam",
                                    rk);
                    }
                    if (self.inbound_roam_gtpc_source_port)
                        ogs_info("Inbound roam GTP-C S5 source_port=%u "
                                "(PGW dest=%u, S11 on gtpc.server)",
                                self.inbound_roam_gtpc_source_port,
                                ogs_gtp_self()->gtpc_port);
                    if (self.inbound_roam_gtpc_send_recovery_on_s5_csr)
                        ogs_info("Inbound roam GTP-C S5 CSR: Recovery IE on");
                    if (self.inbound_roam_teid_offset)
                        ogs_info("Inbound roam GTP-C TEID offset=0x%x",
                                self.inbound_roam_teid_offset);
                    if (self.inbound_roam_gtpu_force_cp_teid)
                        ogs_info("Inbound roam GTP-U: SGWC assigns F-TEID "
                                "(force_cp_teid)");
                    if (self.inbound_roam_gtpu_teid_offset ||
                            self.inbound_roam_gtpu_teid_range_indication) {
                        ogs_info("Inbound roam GTP-U TEID offset=0x%x "
                                "teid_range_indication=%u teid_range=%u",
                                self.inbound_roam_gtpu_teid_offset,
                                self.inbound_roam_gtpu_teid_range_indication,
                                self.inbound_roam_gtpu_teid_range);
                        if (!self.inbound_roam_gtpu_force_cp_teid)
                            ogs_warn("inbound_roam.gtpu teid_offset/range "
                                    "needs force_cp_teid:true when SGW-U "
                                    "advertises FTUP");
                    }
                } else if (!strcmp(sgwc_key, "gn")) {
                    ogs_yaml_iter_t gn_iter;
                    ogs_yaml_iter_recurse(&sgwc_iter, &gn_iter);
                    self.gn_enabled = true;
                    sgwc_gn_pgw_clear();
                    while (ogs_yaml_iter_next(&gn_iter)) {
                        const char *gn_key = ogs_yaml_iter_key(&gn_iter);
                        ogs_assert(gn_key);
                        if (!strcmp(gn_key, "server")) {
                            sgwc_gn_yaml_add_server(&gn_iter, "address",
                                    &self.gn_server_list,
                                    &self.gn_server_list6);
                        } else if (!strcmp(gn_key, "pgw") ||
                                !strcmp(gn_key, "smf")) {
                            sgwc_gn_pgw_yaml_add(&self.gn_pgw_list, &gn_iter);
                        } else
                            ogs_warn("unknown key `%s` in sgwc.gn", gn_key);
                    }
                    if (ogs_list_empty(&self.gn_pgw_list))
                        ogs_error("sgwc.gn enabled but no pgw/smf address");
                    else
                        ogs_info("Gn interface enabled (%d PGW/SMF entries)",
                                ogs_list_count(&self.gn_pgw_list));
                } else if (!strcmp(sgwc_key, "cdr")) {
                    ogs_yaml_iter_t c_iter;
                    ogs_yaml_iter_recurse(&sgwc_iter, &c_iter);
                    while (ogs_yaml_iter_next(&c_iter)) {
                        const char *ck = ogs_yaml_iter_key(&c_iter);
                        const char *cv = ogs_yaml_iter_value(&c_iter);
                        ogs_assert(ck);
                        if (!strcmp(ck, "enabled")) {
                            self.cdr.enabled = ogs_yaml_iter_bool(&c_iter);
                        } else if (!strcmp(ck, "spool_dir") ||
                                !strcmp(ck, "directory")) {
                            self.cdr.spool_dir = cv;
                        } else if (!strcmp(ck, "node_id") ||
                                !strcmp(ck, "nodeid")) {
                            self.cdr.node_id = cv;
                        } else if (!strcmp(ck, "local_address") ||
                                !strcmp(ck, "sgw_address")) {
                            self.cdr.local_address = cv;
                        } else if (!strcmp(ck, "interim_interval_s") ||
                                !strcmp(ck, "interim_interval")) {
                            if (cv) self.cdr.interim_interval_s =
                                (uint32_t)atoi(cv);
                        } else if (!strcmp(ck, "max_records")) {
                            if (cv) self.cdr.rotate_max_records =
                                (uint32_t)atoi(cv);
                        } else if (!strcmp(ck, "max_bytes")) {
                            if (cv) self.cdr.rotate_max_bytes =
                                (uint32_t)atoi(cv);
                        } else if (!strcmp(ck, "max_seconds")) {
                            if (cv) self.cdr.rotate_max_seconds =
                                (uint32_t)atoi(cv);
                        } else if (!strcmp(ck, "triggers")) {
                            uint32_t t = 0;
                            if (cv) {
                                const char *p = cv;
                                while (*p) {
                                    while (*p == ' ' || *p == ',') p++;
                                    if (!strncmp(p, "start", 5)) {
                                        t |= SGWC_CDR_TRIG_START; p += 5;
                                    } else if (!strncmp(p, "interim", 7)) {
                                        t |= SGWC_CDR_TRIG_INTERIM; p += 7;
                                    } else if (!strncmp(p, "stop", 4)) {
                                        t |= SGWC_CDR_TRIG_STOP; p += 4;
                                    } else {
                                        while (*p && *p != ',') p++;
                                    }
                                }
                            }
                            if (t) self.cdr.triggers = t;
                        } else
                            ogs_warn("unknown key `%s` in sgwc.cdr", ck);
                    }
                } else if (!strcmp(sgwc_key, "orphan")) {
                    ogs_yaml_iter_t o_iter;
                    ogs_yaml_iter_recurse(&sgwc_iter, &o_iter);
                    while (ogs_yaml_iter_next(&o_iter)) {
                        const char *ok = ogs_yaml_iter_key(&o_iter);
                        const char *ov = ogs_yaml_iter_value(&o_iter);
                        ogs_assert(ok);
                        if (!strcmp(ok, "enabled")) {
                            self.orphan.enabled = ogs_yaml_iter_bool(&o_iter);
                        } else if (!strcmp(ok, "purge")) {
                            self.orphan.purge = ogs_yaml_iter_bool(&o_iter);
                        } else if (!strcmp(ok, "interval") ||
                                !strcmp(ok, "interval_s")) {
                            if (ov) self.orphan.interval_s =
                                (uint32_t)atoi(ov);
                        } else if (!strcmp(ok, "grace") ||
                                !strcmp(ok, "grace_s")) {
                            if (ov) self.orphan.grace_s =
                                (uint32_t)atoi(ov);
                        } else
                            ogs_warn("unknown key `%s` in sgwc.orphan", ok);
                    }
                } else
                    ogs_warn("unknown key `%s`", sgwc_key);
            }
        }
    }

    rv = sgwc_context_validation();
    if (rv != OGS_OK) return rv;

    {
        int loaded = sgwc_load_recovery_counter(self.recovery_counter_file);
        bool persisted;

        if (loaded < 0) {
            /*
             * No persisted counter (file missing or unreadable). Seed from the
             * wall clock so the advertised Recovery value still differs across
             * restarts. Without this the SGW-C would announce the same value on
             * every boot and peers (MME/SMF) could never detect an SGW-C
             * restart -- which is exactly what stops their stale sessions from
             * being purged.
             */
            self.gtpc_recovery =
                (uint8_t)ogs_time_to_sec(ogs_time_now());
        } else {
            self.gtpc_recovery = (uint8_t)loaded;
        }
        self.gtpc_recovery++;
        if (self.gtpc_recovery == 0)
            self.gtpc_recovery = 1;
        self.gn_gtpc_recovery = self.gtpc_recovery;

        persisted = sgwc_save_recovery_counter(
                self.recovery_counter_file, self.gtpc_recovery);
        ogs_info("SGWC GTP-C recovery counter: %u (file: %s, %s)",
                 self.gtpc_recovery, self.recovery_counter_file,
                 persisted ? "persisted" :
                    (loaded < 0 ? "NOT persisted - time-seeded" :
                                  "NOT persisted"));
    }

    ogs_reload_audit_record_startup("SGWC");

    return OGS_OK;
}

sgwc_ue_t *sgwc_ue_add_by_message(ogs_gtp2_message_t *message)
{
    sgwc_ue_t *sgwc_ue = NULL;
    /* Clang scan-build SA: Dead initialization: Don't set req before message is checked for NULL. */
    ogs_gtp2_create_session_request_t *req;

    ogs_assert(message);

    req = &message->create_session_request;
    if (req->imsi.presence == 0) {
        ogs_error("No IMSI");
        return NULL;
    }

    ogs_trace("sgwc_ue_add_by_message() - IMSI ");
    ogs_log_hexdump(OGS_LOG_TRACE, req->imsi.data, req->imsi.len);

    /*
     * 7.2.1 in 3GPP TS 29.274 Release 15
     *
     * If the new Create Session Request received by the SGW collides with
     * an existing active PDN connection context (the existing PDN connection
     * context is identified with the tuple [IMSI, EPS Bearer ID], where IMSI
     * shall be replaced by TAC and SNR part of ME Identity for emergency
     * attached UE without UICC or authenticated IMSI), this Create Session
     * Request shall be treated as a request for a new session. Before creating
     * the new session, the SGW should delete:
     *
     * - the existing PDN connection context locally, if the Create Session
     *   Request is received with the TEID set to zero in the header, or
     *   if it is received with a TEID not set to zero in the header and
     *   it collides with the default bearer of an existing PDN connection
     *   context;
     * - the existing dedicated bearer context locally, if the Create Session
     *   Request collides with an existing dedicated bearer context and
     *   the message is received with a TEID not set to zero in the header.
     */
    sgwc_ue = sgwc_ue_find_by_imsi(req->imsi.data, req->imsi.len);
    if (sgwc_ue)
        sgwc_ue_remove(sgwc_ue);
    sgwc_ue = sgwc_ue_add(req->imsi.data, req->imsi.len);
    if (!sgwc_ue) {
        ogs_error("sgwc_ue_add() failed");
        return NULL;
    }

    return sgwc_ue;
}

sgwc_ue_t *sgwc_ue_add(uint8_t *imsi, int imsi_len)
{
    sgwc_ue_t *sgwc_ue = NULL;

    ogs_assert(imsi);
    ogs_assert(imsi_len);

    ogs_pool_id_calloc(&sgwc_ue_pool, &sgwc_ue);
    if (!sgwc_ue) {
        ogs_error("Maximum number of sgwc_ue[%lld] reached",
                    (long long)ogs_global_conf()->max.ue);
        return NULL;
    }

    /* Set SGW-S11-TEID */
    ogs_pool_alloc(&sgwc_s11_teid_pool, &sgwc_ue->sgw_s11_teid_node);
    if (!sgwc_ue->sgw_s11_teid_node) {
        ogs_error("SGW-S11-TEID pool exhausted");
        ogs_pool_id_free(&sgwc_ue_pool, sgwc_ue);
        return NULL;
    }

    sgwc_ue->sgw_s11_teid = *(sgwc_ue->sgw_s11_teid_node);

    ogs_hash_set(self.sgw_s11_teid_hash,
            &sgwc_ue->sgw_s11_teid, sizeof(sgwc_ue->sgw_s11_teid), sgwc_ue);

    /* Set IMSI */
    sgwc_ue->imsi_len = ogs_min(imsi_len, OGS_MAX_IMSI_LEN);
    memcpy(sgwc_ue->imsi, imsi, sgwc_ue->imsi_len);
    ogs_buffer_to_bcd(sgwc_ue->imsi, sgwc_ue->imsi_len, sgwc_ue->imsi_bcd);

    ogs_list_init(&sgwc_ue->sess_list);

    sgwc_ue->csr_replace_s11_xact_id = OGS_INVALID_POOL_ID;
    sgwc_ue->csr_replace_gtpbuf = NULL;
    sgwc_ue->csr_replace_sess_id = OGS_INVALID_POOL_ID;
    sgwc_ue->csr_replace_t0 = 0;

    ogs_hash_set(self.imsi_ue_hash, sgwc_ue->imsi, sgwc_ue->imsi_len, sgwc_ue);

    ogs_metrics_dump_lock();
    ogs_list_add(&self.sgw_ue_list, sgwc_ue);
    ogs_metrics_dump_unlock();

    sgwc_metrics_ue_active_inc(sgwc_ue);

    ogs_debug("[Added] Number of SGWC-UEs is now %d",
            ogs_list_count(&self.sgw_ue_list));

    return sgwc_ue;
}

int sgwc_ue_remove(sgwc_ue_t *sgwc_ue)
{
    ogs_assert(sgwc_ue);

    sgwc_metrics_ue_active_dec(sgwc_ue);

    ogs_metrics_dump_lock();
    ogs_list_remove(&self.sgw_ue_list, sgwc_ue);
    ogs_metrics_dump_unlock();

    ogs_hash_set(self.sgw_s11_teid_hash,
            &sgwc_ue->sgw_s11_teid, sizeof(sgwc_ue->sgw_s11_teid), NULL);
    ogs_hash_unset_if_owner(self.imsi_ue_hash,
            sgwc_ue->imsi, sgwc_ue->imsi_len, sgwc_ue);

    if (sgwc_ue->uli_pkbuf) {
        ogs_pkbuf_free(sgwc_ue->uli_pkbuf);
        sgwc_ue->uli_pkbuf = NULL;
    }

    if (sgwc_ue->csr_replace_gtpbuf) {
        ogs_pkbuf_free(sgwc_ue->csr_replace_gtpbuf);
        sgwc_ue->csr_replace_gtpbuf = NULL;
    }
    sgwc_ue->csr_replace_s11_xact_id = OGS_INVALID_POOL_ID;
    sgwc_ue->csr_replace_sess_id = OGS_INVALID_POOL_ID;
    sgwc_ue->csr_replace_t0 = 0;

    sgwc_sess_remove_all(sgwc_ue);

    ogs_pool_free(&sgwc_s11_teid_pool, sgwc_ue->sgw_s11_teid_node);
    ogs_pool_id_free(&sgwc_ue_pool, sgwc_ue);

    ogs_debug("[Removed] Number of SGWC-UEs is now %d",
            ogs_list_count(&self.sgw_ue_list));

    return OGS_OK;
}

void sgwc_ue_remove_all(void)
{
    sgwc_ue_t *sgwc_ue = NULL, *next = NULL;;

    ogs_list_for_each_safe(&self.sgw_ue_list, next, sgwc_ue)
        sgwc_ue_remove(sgwc_ue);
}

void sgwc_ue_remove_if_empty(sgwc_ue_t *sgwc_ue)
{
    if (!sgwc_ue)
        return;

    /*
     * Keep the UE while a Create Session Request collision replace is
     * pending: that flow re-establishes a session on the same UE and
     * still needs the context.
     */
    if (sgwc_ue->csr_replace_s11_xact_id != OGS_INVALID_POOL_ID ||
            sgwc_ue->csr_replace_sess_id != OGS_INVALID_POOL_ID)
        return;

    /*
     * Once the last PDN connection is gone, the SGWC-UE context (its S11
     * TEID, IMSI hash entry and the sgwc_ue_active gauge) must be released.
     * Otherwise UE contexts accumulate indefinitely on normal detach, since
     * the MME and SGW-U release their state but the SGW-C never does.
     */
    if (ogs_list_empty(&sgwc_ue->sess_list))
        sgwc_ue_remove(sgwc_ue);
}

sgwc_ue_t *sgwc_ue_find_by_imsi_bcd(const char *imsi_bcd)
{
    uint8_t imsi[OGS_MAX_IMSI_LEN];
    int imsi_len = 0;

    if (!imsi_bcd || !imsi_bcd[0])
        return NULL;

    ogs_bcd_to_buffer(imsi_bcd, imsi, &imsi_len);
    if (!imsi_len)
        return NULL;

    return sgwc_ue_find_by_imsi(imsi, imsi_len);
}

sgwc_ue_t *sgwc_ue_find_by_imsi(uint8_t *imsi, int imsi_len)
{
    if (!imsi || imsi_len <= 0)
        return NULL;

    return ogs_hash_get(self.imsi_ue_hash, imsi, imsi_len);
}

sgwc_ue_t *sgwc_ue_find_by_teid(uint32_t teid)
{
    return ogs_hash_get(self.sgw_s11_teid_hash, &teid, sizeof(teid));
}

sgwc_ue_t *sgwc_ue_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&sgwc_ue_pool, id);
}

/*
 * IMSI-prefix matching against configured/serving PLMNs (which carry
 * their true MNC length) instead of deriving a PLMN from the IMSI:
 * ogs_plmn_id_from_imsi_bcd() misreads any IMSI whose MSIN begins with
 * '0' (digit-6 heuristic), misclassifying home subscribers as roamers.
 */
static bool sgwc_imsi_is_operator_home(const char *imsi_bcd)
{
    int i;

    ogs_assert(imsi_bcd);

    for (i = 0; i < ogs_local_conf()->num_of_serving_plmn_id; i++) {
        if (ogs_plmn_id_imsi_prefix_match(imsi_bcd,
                    &ogs_local_conf()->serving_plmn_id[i]))
            return true;
    }

    return false;
}

void sgwc_home_plmn_from_imsi_bcd(const char *imsi_bcd, ogs_plmn_id_t *plmn_id)
{
    sgwc_gn_pgw_t *pgw = NULL;
    sgwc_gn_pgw_t *best = NULL;
    int best_len = 0;

    ogs_assert(imsi_bcd);
    ogs_assert(plmn_id);

    if (ogs_plmn_id_pick_imsi_prefix_match(imsi_bcd,
            ogs_local_conf()->serving_plmn_id,
            ogs_local_conf()->num_of_serving_plmn_id,
            plmn_id))
        return;

    /*
     * For inbound roamers whose home PLMN is not in serving_plmn_id, use the
     * longest matching gn.pgw imsi_prefix (operator-configured PLMN digits).
     */
    ogs_list_for_each(&self.gn_pgw_list, pgw) {
        int plen;

        if (!pgw->imsi_prefix[0])
            continue;

        plen = (int)strlen(pgw->imsi_prefix);
        if (plen < 5)
            continue;

        if (strncmp(imsi_bcd, pgw->imsi_prefix, plen) == 0 && plen > best_len) {
            best = pgw;
            best_len = plen;
        }
    }

    if (best) {
        char mcc_buf[4];
        const char *pfx = best->imsi_prefix;
        int mnc_len;
        uint16_t mcc, mnc;

        /*
         * Do not derive MNC length from imsi_prefix digit count alone
         * (432110... + prefix "432110" -> 432-110). Try 2- then 3-digit
         * MNC and keep the first that prefix-matches the IMSI.
         */
        for (mnc_len = 2; mnc_len <= 3; mnc_len++) {
            if (best_len < 3 + mnc_len)
                continue;

            memcpy(mcc_buf, pfx, 3);
            mcc_buf[3] = '\0';
            mcc = (uint16_t)atoi(mcc_buf);
            mnc = (uint16_t)atoi(pfx + 3);
            ogs_plmn_id_build(plmn_id, mcc, mnc, (uint16_t)mnc_len);
            if (ogs_plmn_id_imsi_prefix_match(imsi_bcd, plmn_id))
                return;
        }
    }

    ogs_plmn_id_from_imsi_bcd_with_config_fallback(imsi_bcd, plmn_id);
}

bool sgwc_sess_is_inbound_roam(sgwc_sess_t *sess)
{
    sgwc_ue_t *sgwc_ue = NULL;
    ogs_plmn_id_t zero_plmn_id;

    ogs_assert(sess);

    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    if (!sgwc_ue)
        return true;

    if (sgwc_imsi_is_operator_home(sgwc_ue->imsi_bcd))
        return false;

    memset(&zero_plmn_id, 0, sizeof(zero_plmn_id));
    if (memcmp(&sess->serving_plmn_id, &zero_plmn_id, OGS_PLMN_ID_LEN) == 0)
        return true;

    return !ogs_plmn_id_imsi_prefix_match(
            sgwc_ue->imsi_bcd, &sess->serving_plmn_id);
}

static uint32_t sgwc_inbound_roam_teid(uint32_t raw)
{
    uint32_t offset = sgwc_self()->inbound_roam_teid_offset;

    if (!offset)
        return raw;
    return raw + offset;
}

void sgwc_inbound_roam_teid_offset_apply(sgwc_ue_t *sgwc_ue, sgwc_sess_t *sess)
{
    uint32_t raw_teid;
    uint64_t seid;

    ogs_assert(sgwc_ue);
    ogs_assert(sess);

    if (!sgwc_self()->inbound_roam_teid_offset)
        return;
    if (!sgwc_sess_is_inbound_roam(sess))
        return;

    raw_teid = *(sess->sgwc_sxa_seid_node);
    ogs_hash_set(self.sgwc_sxa_seid_hash, &sess->sgwc_sxa_seid,
            sizeof(sess->sgwc_sxa_seid), NULL);

    sess->sgw_s5c_teid = sgwc_inbound_roam_teid(raw_teid);
    seid = (uint64_t)sess->sgw_s5c_teid;
    sess->sgwc_sxa_seid = seid;
    ogs_hash_set(self.sgwc_sxa_seid_hash, &sess->sgwc_sxa_seid,
            sizeof(sess->sgwc_sxa_seid), sess);

    raw_teid = *(sgwc_ue->sgw_s11_teid_node);
    ogs_hash_set(self.sgw_s11_teid_hash, &sgwc_ue->sgw_s11_teid,
            sizeof(sgwc_ue->sgw_s11_teid), NULL);
    sgwc_ue->sgw_s11_teid = sgwc_inbound_roam_teid(raw_teid);
    ogs_hash_set(self.sgw_s11_teid_hash, &sgwc_ue->sgw_s11_teid,
            sizeof(sgwc_ue->sgw_s11_teid), sgwc_ue);

    ogs_debug("Inbound roam TEID offset 0x%x: SGW-S11=0x%x SGW-S5C=0x%x",
            sgwc_self()->inbound_roam_teid_offset,
            sgwc_ue->sgw_s11_teid, sess->sgw_s5c_teid);
}

static void sgwc_sess_pfcp_nwi_base(sgwc_sess_t *sess, char *nwi, int buflen)
{
    char apn_full[OGS_MAX_APN_LEN+1];

    ogs_assert(sess);
    ogs_assert(nwi);
    ogs_assert(buflen > OGS_MAX_APN_LEN);
    ogs_assert(sess->session.name);

    /*
     * Inbound roam: MME sends APN FQDN on S11 (home PLMN OI) and VPP/UPG
     * expects that FQDN as the PFCP Network Instance.  session.name holds
     * APN-NI only (for pfcp.client apn matching and Gn-handover safety).
     *
     * Home / Gn-handover: keep APN-NI for PFCP NWI even when S11 carried
     * a full APN (3G->4G mobility); the home SGW-U has no FQDN NWI.
     */
    if (sess->apn_fqdn_len > 0 &&
            ogs_fqdn_parse(apn_full, (const char *)sess->apn_fqdn,
                ogs_min(sess->apn_fqdn_len, (int)sizeof(sess->apn_fqdn))) > 0 &&
            ogs_dnn_oi_from_fqdn(apn_full) &&
            sgwc_sess_is_inbound_roam(sess)) {
        ogs_cpystrn(nwi, apn_full, buflen);
        return;
    }

    ogs_cpystrn(nwi, sess->session.name, buflen);
}

void sgwc_sess_sync_pfcp_pdr_nwi(sgwc_sess_t *sess)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    char nwi[OGS_MAX_APN_LEN+1];
    bool rewritten;

    ogs_assert(sess);

    if (!sess->session.name || !sess->session.name[0])
        return;

    sgwc_sess_pfcp_nwi_base(sess, nwi, sizeof(nwi));
    rewritten = sgwc_sgwu_nwi_rewrite_apply(sess, nwi, sizeof(nwi));

    /*
     * UPG-VPP looks up Network Instance names case-sensitively.  When no
     * rewrite rule remapped the APN to an explicit NWI name, lowercase the
     * raw APN string so "Hiweb"/"HIWEB" becomes "hiweb" and matches the NWI
     * as configured in VPP.
     */
    if (!rewritten) {
        char *p;
        for (p = nwi; *p; p++)
            *p = (char)tolower((unsigned char)*p);
    }

    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        if (pdr->apn)
            ogs_free(pdr->apn);
        pdr->apn = ogs_strdup(nwi);
        ogs_assert(pdr->apn);
    }

    ogs_list_for_each(&sess->pfcp.far_list, far) {
        if (far->apn)
            ogs_free(far->apn);
        far->apn = ogs_strdup(nwi);
        ogs_assert(far->apn);
    }
}

sgwc_sess_t *sgwc_sess_add(sgwc_ue_t *sgwc_ue, char *apn)
{
    sgwc_sess_t *sess = NULL;

    ogs_assert(sgwc_ue);

    ogs_pool_id_calloc(&sgwc_sess_pool, &sess);
    if (!sess) {
        ogs_error("Maximum number of session[%lld] reached",
                    (long long)ogs_app()->pool.sess);
        return NULL;
    }

    ogs_pfcp_pool_init(&sess->pfcp);

    /* Set TEID & SEID */
    ogs_pool_alloc(&sgwc_sxa_seid_pool, &sess->sgwc_sxa_seid_node);
    if (!sess->sgwc_sxa_seid_node) {
        ogs_error("SGW-SXA-SEID pool exhausted");
        ogs_pfcp_pool_final(&sess->pfcp);
        ogs_pool_id_free(&sgwc_sess_pool, sess);
        return NULL;
    }

    sess->sgw_s5c_teid = *(sess->sgwc_sxa_seid_node);
    sess->sgwc_sxa_seid = *(sess->sgwc_sxa_seid_node);

    ogs_hash_set(self.sgwc_sxa_seid_hash,
            &sess->sgwc_sxa_seid, sizeof(sess->sgwc_sxa_seid), sess);

    /* Create BAR in PFCP Session */
    ogs_pfcp_bar_new(&sess->pfcp);

    /* Set APN */
    sess->session.name = ogs_strdup(apn);
    ogs_assert(sess->session.name);

    sess->sgwc_ue_id = sgwc_ue->id;

    ogs_metrics_dump_lock();
    ogs_list_add(&sgwc_ue->sess_list, sess);
    ogs_metrics_dump_unlock();

    stats_add_sgwc_session();

    return sess;
}

static bool compare_ue_info(ogs_pfcp_node_t *node, sgwc_sess_t *sess)
{
    sgwc_ue_t *sgwc_ue = NULL;
    int i;

    ogs_assert(node);
    ogs_assert(sess);
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    ogs_assert(sgwc_ue);

    ogs_assert(sess->session.name);
    for (i = 0; i < node->num_of_dnn; i++)
        if (ogs_strcasecmp(node->dnn[i], sess->session.name) == 0) return true;

    for (i = 0; i < node->num_of_e_cell_id; i++)
        if (sgwc_ue->uli_presence == true &&
            node->e_cell_id[i] == sgwc_ue->e_cgi.cell_id) return true;

    for (i = 0; i < node->num_of_tac; i++)
        if (sgwc_ue->uli_presence == true &&
            node->tac[i] == sgwc_ue->e_tai.tac) return true;

    return false;
}

static ogs_pfcp_node_t *selected_sgwu_node(
        ogs_pfcp_node_t *current, sgwc_sess_t *sess)
{
    ogs_pfcp_node_t *next, *node;
    ogs_pfcp_node_t *best = NULL;
    int best_order = INT_MAX;

    ogs_assert(current);
    ogs_assert(sess);

    ogs_list_for_each(&ogs_pfcp_self()->pfcp_peer_list, node) {
        if (!OGS_FSM_CHECK(&node->sm, sgwc_pfcp_state_associated))
            continue;
        if (compare_ue_info(node, sess) &&
                node->selection_order < best_order) {
            best_order = node->selection_order;
            best = node;
        }
    }

    if (best)
        return best;

    if (ogs_global_conf()->parameter.no_pfcp_rr_select == 0) {
        /* continue search from current position */
        next = ogs_list_next(current);
        for (node = next; node; node = ogs_list_next(node)) {
            if (OGS_FSM_CHECK(&node->sm, sgwc_pfcp_state_associated))
                return node;
        }
        /* cyclic search from top to current position */
        for (node = ogs_list_first(&ogs_pfcp_self()->pfcp_peer_list);
                node != next; node = ogs_list_next(node)) {
            if (OGS_FSM_CHECK(&node->sm, sgwc_pfcp_state_associated))
                return node;
        }
    }

    ogs_error("No SGWUs are PFCP associated that are suited to RR "
            "[PLMN:%d/%d APN:%s]",
            ogs_plmn_id_mcc(&sess->serving_plmn_id),
            ogs_plmn_id_mnc(&sess->serving_plmn_id),
            sess->session.name ? sess->session.name : "-");
    return NULL;
}

void sgwc_sess_select_sgwu(sgwc_sess_t *sess)
{
    ogs_pfcp_node_t *node = NULL;

    ogs_assert(sess);

    /*
     * When used for the first time, if last node is set,
     * the search is performed from the first SGW-U in a round-robin manner.
     */
    if (ogs_pfcp_self()->pfcp_node == NULL)
        ogs_pfcp_self()->pfcp_node =
            ogs_list_last(&ogs_pfcp_self()->pfcp_peer_list);

    if (ogs_pfcp_self()->pfcp_node) {
        /* setup GTP session with selected SGW-U */
        node = selected_sgwu_node(ogs_pfcp_self()->pfcp_node, sess);
        if (node) {
            ogs_pfcp_self()->pfcp_node = node;
            OGS_SETUP_PFCP_NODE(sess, node);
            ogs_debug("UE using SGW-U on IP %s",
                    ogs_sockaddr_to_string_static(node->addr_list));
        } else {
            sgwc_ue_t *sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
            ogs_error("No PFCP-associated SGW-U for session "
                    "[IMSI:%s PLMN:%d/%d TAC:%d APN:%s]",
                    sgwc_ue ? sgwc_ue->imsi_bcd : "-",
                    ogs_plmn_id_mcc(&sess->serving_plmn_id),
                    ogs_plmn_id_mnc(&sess->serving_plmn_id),
                    (sgwc_ue && sgwc_ue->uli_presence) ? sgwc_ue->e_tai.tac : 0,
                    sess->session.name ? sess->session.name : "-");
            sess->pfcp_node = NULL;
        }
    } else {
        sgwc_ue_t *sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        ogs_error("No SGW-U configured in sgwc.pfcp "
                "[IMSI:%s PLMN:%d/%d APN:%s]",
                sgwc_ue ? sgwc_ue->imsi_bcd : "-",
                ogs_plmn_id_mcc(&sess->serving_plmn_id),
                ogs_plmn_id_mnc(&sess->serving_plmn_id),
                sess->session.name ? sess->session.name : "-");
        sess->pfcp_node = NULL;
    }
}

void sgwc_sess_abort_create(sgwc_sess_t *sess)
{
    if (!sess)
        return;

    /*
     * Roll back a partially established PDN during Create Session.  The PGW/SMF
     * S5 session exists only after Create Session Response (see
     * sgwc_metrics_session_active_inc).  sgwc_sess_remove() purges SGW-U (PFCP).
     */
    if (sess->metrics_session_counted && sess->gnode && !sess->gn) {
        if (sgwc_gtp_send_s5c_delete_session_request(sess) != OGS_OK) {
            ogs_warn("S5 Delete Session failed during create abort "
                    "[sess_id=%d]", sess->id);
        }
    }

    sgwc_sess_remove(sess);
}

int sgwc_orphan_sweep(bool do_purge, ogs_time_t grace, int *out_purged)
{
    sgwc_ue_t *ue = NULL, *next_ue = NULL;
    sgwc_sess_t *sess = NULL, *next_sess = NULL;
    ogs_time_t now = ogs_time_now();
    int remaining = 0, purged = 0, empty_ue_lingering = 0;

    /*
     * Main-thread only: this walks and mutates sgw_ue_list / sess_list and may
     * send S5/PFCP teardown messages. sgwc_sess_remove() takes the metrics dump
     * lock internally for the list removal, which is what the admin HTTP reader
     * (sgwc_admin_list_sessions) also holds while iterating, so the two never
     * corrupt the list. The _safe iterators tolerate removal of the current
     * node; the outer iterator pre-captures next_ue so removing an emptied UE
     * is safe too.
     */
    ogs_list_for_each_safe(&self.sgw_ue_list, next_ue, ue) {
        ogs_list_for_each_safe(&ue->sess_list, next_sess, sess) {
            /*
             * Three ways a session is dead weight:
             *  - never completed establishment (not counted),
             *  - lost its SGW-U user plane (sxa_seid == 0),
             *  - lost ALL bearers but was kept alive (bearer-less stub).
             * The last one is produced by a default-bearer Delete Bearer
             * procedure that got routed down the dedicated-bearer path
             * (see sgwc_s11_handle_delete_bearer_response); the PGW/SMF
             * freed its side, so the stub (and its SGW-U twin) can never
             * become usable again.
             */
            bool no_bearer = ogs_list_empty(&sess->bearer_list);
            bool is_orphan = (!sess->metrics_session_counted ||
                              sess->sgwu_sxa_seid == 0 || no_bearer);
            bool aged_out;

            if (!is_orphan)
                continue;

            aged_out = (sess->create_session_t0 == 0) ||
                    ((now - sess->create_session_t0) > grace);

            if (do_purge && aged_out) {
                ogs_info("orphan sweep: purge imsi=%s apn=%s "
                         "(counted=%d sxa_seid=0x%" PRIx64 " bearers=%s)",
                         ue->imsi_bcd,
                         sess->session.name ? sess->session.name : "-",
                         sess->metrics_session_counted, sess->sgwu_sxa_seid,
                         no_bearer ? "none" : "yes");
                sgwc_sess_abort_create(sess);
                purged++;
                continue; /* sess is freed; do not count as remaining */
            }

            /* Orphan that survives this sweep (in grace, or purge disabled). */
            remaining++;
        }

        /*
         * Reclaim empty UE contexts. sgwc_ue_remove_if_empty() refuses to free
         * a UE while a CSR-replace is still pinned. A pin that never cleared
         * (the deferred Create Session was lost, e.g. the PFCP Session Deletion
         * response from SGW-U never arrived) would otherwise keep an empty UE
         * alive forever -- the root cause of sgwc_ue_active drifting far above
         * the active session count. Once the pin ages past the grace window,
         * drop it so the empty UE is released on this pass.
         */
        if (ogs_list_empty(&ue->sess_list) &&
                (ue->csr_replace_s11_xact_id != OGS_INVALID_POOL_ID ||
                 ue->csr_replace_sess_id != OGS_INVALID_POOL_ID)) {
            bool pin_stale = (ue->csr_replace_t0 == 0) ||
                    ((now - ue->csr_replace_t0) > grace);

            if (pin_stale) {
                ogs_warn("orphan sweep: clearing stale CSR-replace pin on "
                         "empty UE imsi=%s (age=%lldms)",
                         ue->imsi_bcd,
                         ue->csr_replace_t0 ?
                            (long long)ogs_time_to_msec(now - ue->csr_replace_t0)
                            : -1);
                if (ue->csr_replace_gtpbuf) {
                    ogs_pkbuf_free(ue->csr_replace_gtpbuf);
                    ue->csr_replace_gtpbuf = NULL;
                }
                ue->csr_replace_s11_xact_id = OGS_INVALID_POOL_ID;
                ue->csr_replace_sess_id = OGS_INVALID_POOL_ID;
                ue->csr_replace_t0 = 0;
            } else {
                /* Pin still within grace; a real CSR-replace may complete. */
                empty_ue_lingering++;
            }
        }

        sgwc_ue_remove_if_empty(ue);
    }

    sgwc_metrics_global_set(
            SGWC_METR_GLOB_GAUGE_UE_ORPHAN, empty_ue_lingering);

    if (out_purged)
        *out_purged = purged;

    return remaining;
}

static void orphan_sweep_timer_cb(void *data)
{
    sgwc_event_t *e = NULL;
    int rv;

    e = sgwc_event_new(SGWC_EVT_ORPHAN_SWEEP);
    ogs_assert(e);
    e->timer_id = SGWC_TIMER_ORPHAN_SWEEP;

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed [%d] for orphan sweep", (int)rv);
        sgwc_event_free(e);
    }
}

void sgwc_orphan_timer_start(void)
{
    uint32_t interval_s;

    if (!self.orphan.enabled) {
        ogs_info("SGWC orphan sweep disabled by config");
        return;
    }

    /* Clamp to a sane floor so a misconfigured 0/1s never busy-loops. */
    interval_s = self.orphan.interval_s;
    if (interval_s < 5) {
        ogs_warn("sgwc.orphan.interval %u too low; using 5s", interval_s);
        interval_s = 5;
        self.orphan.interval_s = interval_s;
    }

    if (!self.orphan.t_sweep) {
        self.orphan.t_sweep = ogs_timer_add(
                ogs_app()->timer_mgr, orphan_sweep_timer_cb, NULL);
        ogs_assert(self.orphan.t_sweep);
    }

    ogs_timer_start(self.orphan.t_sweep, ogs_time_from_sec(interval_s));

    ogs_info("SGWC orphan sweep started: interval=%us grace=%us purge=%s",
             interval_s, self.orphan.grace_s,
             self.orphan.purge ? "on" : "off");
}

void sgwc_orphan_timer_stop(void)
{
    if (self.orphan.t_sweep) {
        ogs_timer_delete(self.orphan.t_sweep);
        self.orphan.t_sweep = NULL;
    }
}

int sgwc_sess_remove(sgwc_sess_t *sess)
{
    sgwc_ue_t *sgwc_ue = NULL;

    ogs_assert(sess);

    sgwc_metrics_session_active_dec(sess);

    sgwc_sess_purge_upf(sess);

    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    ogs_assert(sgwc_ue);

    sgwc_ga_cdr_session_stop(sess);
    sgwc_ga_sess_clear(sess);

    ogs_metrics_dump_lock();
    ogs_list_remove(&sgwc_ue->sess_list, sess);
    ogs_metrics_dump_unlock();

    ogs_hash_set(self.sgwc_sxa_seid_hash, &sess->sgwc_sxa_seid,
            sizeof(sess->sgwc_sxa_seid), NULL);

    sgwc_bearer_remove_all(sess);

    ogs_pfcp_sess_clear(&sess->pfcp);

    ogs_pfcp_pool_final(&sess->pfcp);

    ogs_assert(sess->session.name);
    ogs_free(sess->session.name);

    ogs_pool_free(&sgwc_sxa_seid_pool, sess->sgwc_sxa_seid_node);
    ogs_pool_id_free(&sgwc_sess_pool, sess);

    stats_remove_sgwc_session();

    return OGS_OK;
}

void sgwc_sess_remove_all(sgwc_ue_t *sgwc_ue)
{
    sgwc_sess_t *sess = NULL, *next_sess = NULL;

    ogs_assert(sgwc_ue);
    ogs_list_for_each_safe(&sgwc_ue->sess_list, next_sess, sess)
        sgwc_sess_remove(sess);
}

bool sgwc_sess_s5c_teid_matches(sgwc_sess_t *sess, uint32_t teid)
{
    uint32_t offset, raw, low;

    ogs_assert(sess);

    if (!teid)
        return false;

    if (sess->sgw_s5c_teid == teid)
        return true;

    offset = sgwc_self()->inbound_roam_teid_offset;
    if (!offset)
        return false;

    raw = sess->sgw_s5c_teid - offset;
    if (raw == teid)
        return true;

    low = teid & 0xFFFFFFu;
    if ((sess->sgw_s5c_teid & 0xFFFFFFu) == low)
        return true;
    if ((raw & 0xFFFFFFu) == low)
        return true;

    return false;
}

sgwc_sess_t* sgwc_sess_find_by_teid(uint32_t teid)
{
    sgwc_sess_t *sess = NULL;
    uint32_t offset = 0;
    uint32_t alt = 0;

    if (!teid)
        return NULL;

    sess = sgwc_sess_find_by_seid((uint64_t)teid);
    if (sess) {
        if (sgwc_sess_s5c_teid_matches(sess, teid))
            return sess;
        return NULL;
    }

    /*
     * Inbound roam PGW interop: we advertise sgw_s5c_teid = raw + teid_offset,
     * but some PGWs (e.g. Huawei) send back only the low 24 bits in S5 GTP-C
     * headers (Update Bearer Request, etc.). Retry with offset variants only
     * when the candidate session's SGW-S5C-TEID matches the header TEID.
     */
    offset = sgwc_self()->inbound_roam_teid_offset;
    if (!offset)
        return NULL;

    alt = teid + offset;
    if (alt != teid) {
        sess = sgwc_sess_find_by_seid((uint64_t)alt);
        if (sess && sgwc_sess_s5c_teid_matches(sess, teid))
            return sess;
    }

    alt = teid | offset;
    if (alt != teid) {
        sess = sgwc_sess_find_by_seid((uint64_t)alt);
        if (sess && sgwc_sess_s5c_teid_matches(sess, teid))
            return sess;
    }

    return NULL;
}

sgwc_sess_t *sgwc_sess_find_by_seid(uint64_t seid)
{
    return ogs_hash_get(self.sgwc_sxa_seid_hash, &seid, sizeof(seid));
}

sgwc_sess_t* sgwc_sess_find_by_apn(sgwc_ue_t *sgwc_ue, char *apn)
{
    sgwc_sess_t *sess = NULL;

    ogs_assert(sgwc_ue);
    ogs_assert(apn);

    ogs_list_for_each(&sgwc_ue->sess_list, sess) {
        if (!ogs_strcasecmp(sess->session.name, apn))
            return sess;
    }

    return NULL;
}

sgwc_sess_t *sgwc_sess_find_by_ebi(sgwc_ue_t *sgwc_ue, uint8_t ebi)
{
    sgwc_bearer_t *bearer = NULL;
    ogs_assert(sgwc_ue);

    bearer = sgwc_bearer_find_by_ue_ebi(sgwc_ue, ebi);
    if (bearer)
        return sgwc_sess_find_by_id(bearer->sess_id);

    return NULL;
}

sgwc_sess_t *sgwc_sess_find_by_nsapi(sgwc_ue_t *sgwc_ue, uint8_t nsapi)
{
    sgwc_sess_t *sess = NULL;

    ogs_assert(sgwc_ue);

    ogs_list_for_each(&sgwc_ue->sess_list, sess) {
        if (sess->gn && sess->gn_nsapi == nsapi)
            return sess;
    }

    return sgwc_sess_find_by_ebi(sgwc_ue, nsapi);
}

sgwc_sess_t *sgwc_sess_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&sgwc_sess_pool, id);
}

bool sgwc_pfcp_peer_in_use(const ogs_pfcp_node_t *node)
{
    int i;
    sgwc_sess_t *sess = NULL;

    ogs_assert(node);

    for (i = 0; i < sgwc_sess_pool.size; i++) {
        sess = sgwc_sess_pool.index[i];
        if (sess && sess->pfcp_node == node)
            return true;
    }

    return false;
}

int sgwc_sess_pfcp_xact_count(
        sgwc_ue_t *sgwc_ue, uint8_t pfcp_type, uint64_t modify_flags)
{
    sgwc_sess_t *sess = NULL;
    int xact_count = 0;

    ogs_assert(sgwc_ue);

    ogs_list_for_each(&sgwc_ue->sess_list, sess) {
        ogs_pfcp_node_t *pfcp_node = sess->pfcp_node;
        ogs_pfcp_xact_t *pfcp_xact = NULL;

        if (!pfcp_node)
            continue;
        ogs_list_for_each(&pfcp_node->local_list, pfcp_xact) {
            ogs_pool_id_t sess_id = OGS_INVALID_POOL_ID;

            if (pfcp_type && pfcp_type != pfcp_xact->seq[0].type)
                continue;
            if (!(pfcp_xact->modify_flags & OGS_PFCP_MODIFY_SESSION))
                continue;
            if (modify_flags && modify_flags != pfcp_xact->modify_flags)
                continue;

            sess_id = OGS_POINTER_TO_UINT(pfcp_xact->data);
            ogs_assert(sess_id >= OGS_MIN_POOL_ID &&
                    sess_id <= OGS_MAX_POOL_ID);
            if (sess->id != sess_id)
                continue;

            xact_count++;
        }
    }

    return xact_count;
}

ogs_pfcp_xact_t *sgwc_pfcp_find_session_modify_xact(
        sgwc_sess_t *sess, uint64_t modify_flags)
{
    ogs_pfcp_xact_t *pfcp_xact = NULL;
    ogs_pool_id_t sess_id = OGS_INVALID_POOL_ID;

    ogs_assert(sess);
    ogs_assert(sess->pfcp_node);

    ogs_list_for_each(&sess->pfcp_node->local_list, pfcp_xact) {
        if (pfcp_xact->seq[0].type !=
                OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE)
            continue;
        if (!(pfcp_xact->modify_flags & OGS_PFCP_MODIFY_SESSION))
            continue;
        if (modify_flags && modify_flags != pfcp_xact->modify_flags)
            continue;

        sess_id = OGS_POINTER_TO_UINT(pfcp_xact->data);
        ogs_assert(sess_id >= OGS_MIN_POOL_ID && sess_id <= OGS_MAX_POOL_ID);
        if (sess->id != sess_id)
            continue;

        return pfcp_xact;
    }

    return NULL;
}

sgwc_bearer_t *sgwc_bearer_add(sgwc_sess_t *sess)
{
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *tunnel = NULL;
    sgwc_ue_t *sgwc_ue = NULL;

    ogs_assert(sess);
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    ogs_assert(sgwc_ue);

    ogs_pool_id_calloc(&sgwc_bearer_pool, &bearer);
    if (!bearer) {
        ogs_error("ogs_pool_id_calloc() failed");
        return NULL;
    }

    ogs_list_add(&sess->bearer_list, bearer);

    bearer->sgwc_ue_id = sgwc_ue->id;
    bearer->sess_id = sess->id;

    /* Downlink */
    tunnel = sgwc_tunnel_add(bearer, OGS_GTP2_F_TEID_S5_S8_SGW_GTP_U);
    if (!tunnel) {
        ogs_error("sgwc_tunnel_add() failed");
        sgwc_bearer_remove(bearer);
        return NULL;
    }

    /* Uplink */
    tunnel = sgwc_tunnel_add(bearer, OGS_GTP2_F_TEID_S1_U_SGW_GTP_U);
    if (!tunnel) {
        ogs_error("sgwc_tunnel_add() failed");
        sgwc_bearer_remove(bearer);
        return NULL;
    }

    sgwc_bearer_urr_setup(bearer);

    return bearer;
}

void sgwc_ue_store_uli_raw(sgwc_ue_t *sgwc_ue, void *data, uint16_t len)
{
    ogs_assert(sgwc_ue);
    if (sgwc_ue->uli_pkbuf) {
        ogs_pkbuf_free(sgwc_ue->uli_pkbuf);
        sgwc_ue->uli_pkbuf = NULL;
    }
    if (!data || !len) return;
    sgwc_ue->uli_pkbuf = ogs_pkbuf_alloc(NULL, len);
    if (sgwc_ue->uli_pkbuf)
        ogs_pkbuf_put_data(sgwc_ue->uli_pkbuf, data, len);
}

void sgwc_bearer_urr_setup(sgwc_bearer_t *bearer)
{
    sgwc_sess_t *sess = NULL;
    sgwc_cdr_config_t *cfg = &sgwc_self()->cdr;
    ogs_pfcp_urr_t *urr = NULL;
    sgwc_tunnel_t *dl_tunnel = NULL;
    sgwc_tunnel_t *ul_tunnel = NULL;

    ogs_assert(bearer);
    if (!cfg->enabled) return;

    sess = sgwc_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);
    if (bearer->urr) return;

    urr = ogs_pfcp_urr_add(&sess->pfcp);
    ogs_assert(urr);
    bearer->urr = urr;

    urr->meas_method = OGS_PFCP_MEASUREMENT_METHOD_VOLUME |
                       OGS_PFCP_MEASUREMENT_METHOD_DURATION;

    if (cfg->interim_interval_s) {
        urr->rep_triggers.time_threshold = 1;
        urr->time_threshold = cfg->interim_interval_s;
        urr->meas_info.istm = 1;
    }

    dl_tunnel = sgwc_dl_tunnel_in_bearer(bearer);
    ul_tunnel = sgwc_ul_tunnel_in_bearer(bearer);
    ogs_assert(dl_tunnel && dl_tunnel->pdr);
    ogs_assert(ul_tunnel && ul_tunnel->pdr);

    ogs_pfcp_pdr_associate_urr(dl_tunnel->pdr, urr);
    ogs_pfcp_pdr_associate_urr(ul_tunnel->pdr, urr);
}

int sgwc_bearer_remove(sgwc_bearer_t *bearer)
{
    sgwc_sess_t *sess = NULL;

    ogs_assert(bearer);
    sess = sgwc_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);

    ogs_list_remove(&sess->bearer_list, bearer);

    sgwc_tunnel_remove_all(bearer);

    ogs_pool_id_free(&sgwc_bearer_pool, bearer);

    return OGS_OK;
}

void sgwc_bearer_remove_all(sgwc_sess_t *sess)
{
    sgwc_bearer_t *bearer = NULL, *next_bearer = NULL;

    ogs_assert(sess);
    ogs_list_for_each_safe(&sess->bearer_list, next_bearer, bearer)
        sgwc_bearer_remove(bearer);
}

sgwc_bearer_t *sgwc_bearer_find_by_sess_ebi(sgwc_sess_t *sess, uint8_t ebi)
{
    sgwc_bearer_t *bearer = NULL;

    ogs_assert(sess);
    ogs_list_for_each(&sess->bearer_list, bearer)
        if (ebi == bearer->ebi) return bearer;

    return NULL;
}

sgwc_bearer_t *sgwc_bearer_find_by_ue_ebi(sgwc_ue_t *sgwc_ue, uint8_t ebi)
{
    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;

    ogs_assert(sgwc_ue);
    ogs_list_for_each(&sgwc_ue->sess_list, sess) {
        ogs_list_for_each(&sess->bearer_list, bearer) {
            if (ebi == bearer->ebi) return bearer;
        }
    }

    return NULL;
}

sgwc_bearer_t *sgwc_default_bearer_in_sess(sgwc_sess_t *sess)
{
    ogs_assert(sess);
    return ogs_list_first(&sess->bearer_list);
}

sgwc_bearer_t *sgwc_bearer_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&sgwc_bearer_pool, id);
}

sgwc_tunnel_t *sgwc_tunnel_add(
        sgwc_bearer_t *bearer, uint8_t interface_type)
{
    sgwc_sess_t *sess = NULL;
    sgwc_tunnel_t *tunnel = NULL;

    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    sgwc_ue_t *sgwc_ue = NULL;

    ogs_pfcp_interface_t src_if = OGS_PFCP_INTERFACE_UNKNOWN;
    ogs_pfcp_interface_t dst_if = OGS_PFCP_INTERFACE_UNKNOWN;
    ogs_pfcp_3gpp_interface_type_t src_if_type =
        OGS_PFCP_3GPP_INTERFACE_TYPE_UNKNOWN;
    ogs_pfcp_3gpp_interface_type_t dst_if_type =
        OGS_PFCP_3GPP_INTERFACE_TYPE_UNKNOWN;

    ogs_assert(bearer);
    sess = sgwc_sess_find_by_id(bearer->sess_id);
    ogs_assert(sess);

    switch (interface_type) {
    /* Downlink */
    case OGS_GTP2_F_TEID_S5_S8_SGW_GTP_U:
        src_if = OGS_PFCP_INTERFACE_CORE;
        src_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_S5_S8_U;
        dst_if = OGS_PFCP_INTERFACE_ACCESS;
        dst_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_S1_U;
        break;

    /* Uplink */
    case OGS_GTP2_F_TEID_S1_U_SGW_GTP_U:
        src_if = OGS_PFCP_INTERFACE_ACCESS;
        src_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_S1_U;
        dst_if = OGS_PFCP_INTERFACE_CORE;
        dst_if_type = OGS_PFCP_3GPP_INTERFACE_TYPE_S5_S8_U;
        break;

    /* Indirect */
    case OGS_GTP2_F_TEID_SGW_GTP_U_FOR_DL_DATA_FORWARDING:
    case OGS_GTP2_F_TEID_SGW_GTP_U_FOR_UL_DATA_FORWARDING:
        src_if = OGS_PFCP_INTERFACE_ACCESS;
        src_if_type =
            OGS_PFCP_3GPP_INTERFACE_TYPE_SGW_UPF_GTP_U_FOR_UL_DATA_FORWARDING;
        dst_if = OGS_PFCP_INTERFACE_ACCESS;
        dst_if_type =
            OGS_PFCP_3GPP_INTERFACE_TYPE_SGW_UPF_GTP_U_FOR_DL_DATA_FORWARDING;
        break;
    default:
        ogs_fatal("Invalid interface type = %d", interface_type);
        ogs_assert_if_reached();
    }

    ogs_pool_id_calloc(&sgwc_tunnel_pool, &tunnel);
    if (!tunnel) {
        ogs_error("ogs_pool_id_calloc() failed");
        return NULL;
    }

    ogs_list_add(&bearer->tunnel_list, tunnel);

    tunnel->interface_type = interface_type;
    tunnel->bearer_id = bearer->id;

    pdr = ogs_pfcp_pdr_add(&sess->pfcp);
    if (!pdr) {
        sgwc_ue = sgwc_ue_find_by_id(bearer->sgwc_ue_id);
        ogs_error("Cannot add PDR [IMSI:%s] [APN:%s] [EBI:%u] "
                "[interface-type:%u] [PDR:%d/%d]",
                sgwc_ue ? sgwc_ue->imsi_bcd : "unknown",
                sess->session.name ? sess->session.name : "unknown",
                (unsigned)bearer->ebi, (unsigned)interface_type,
                ogs_list_count(&sess->pfcp.pdr_list), OGS_MAX_NUM_OF_PDR);
        sgwc_tunnel_remove(tunnel);
        return NULL;
    }
    tunnel->pdr = pdr;

    ogs_assert(sess->session.name);
    pdr->apn = ogs_strdup(sess->session.name);
    ogs_assert(pdr->apn);

    pdr->src_if = src_if;

    pdr->src_if_type_presence = true;
    pdr->src_if_type = src_if_type;

    far = ogs_pfcp_far_add(&sess->pfcp);
    if (!far) {
        ogs_error("ogs_pfcp_far_add() failed");
        sgwc_tunnel_remove(tunnel);
        return NULL;
    }
    tunnel->far = far;

    ogs_assert(sess->session.name);
    far->apn = ogs_strdup(sess->session.name);
    ogs_assert(far->apn);

    far->dst_if = dst_if;

    far->dst_if_type_presence = true;
    far->dst_if_type = dst_if_type;

    ogs_pfcp_pdr_associate_far(pdr, far);

    far->apply_action =
        OGS_PFCP_APPLY_ACTION_BUFF| OGS_PFCP_APPLY_ACTION_NOCP;
    ogs_assert(sess->pfcp.bar);

    ogs_assert(sess->pfcp_node);
    if (sess->pfcp_node->up_function_features.ftup &&
            !sgwc_gtpu_use_cp_teid(sess)) {

       /* TS 129 244 V16.5.0 8.2.3
        *
        * At least one of the V4 and V6 flags shall be set to "1",
        * and both may be set to "1" for both scenarios:
        *
        * - when the CP function is providing F-TEID, i.e.
        *   both IPv4 address field and IPv6 address field may be present;
        *   or
        * - when the UP function is requested to allocate the F-TEID,
        *   i.e. when CHOOSE bit is set to "1",
        *   and the IPv4 address and IPv6 address fields are not present.
        */

        pdr->f_teid.ipv4 = 1;
        pdr->f_teid.ipv6 = 1;
        pdr->f_teid.ch = 1;
        pdr->f_teid_len = 1;
    } else {
        ogs_gtpu_resource_t *resource = NULL;
        resource = ogs_pfcp_find_gtpu_resource(
                &sess->pfcp_node->gtpu_resource_list,
                sess->session.name, pdr->src_if);
        if (resource) {
            ogs_user_plane_ip_resource_info_to_sockaddr(&resource->info,
                &tunnel->local_addr, &tunnel->local_addr6);
            if (sgwc_gtpu_has_teid_encoding(sess))
                tunnel->local_teid =
                    sgwc_gtpu_teid_from_index(sess, pdr->teid);
            else if (resource->info.teidri)
                tunnel->local_teid = OGS_PFCP_GTPU_INDEX_TO_TEID(
                        pdr->teid, resource->info.teidri,
                        resource->info.teid_range);
            else
                tunnel->local_teid = pdr->teid;
        } else {
            ogs_assert(sess->pfcp_node->addr_list);
            if (sess->pfcp_node->addr_list->ogs_sa_family == AF_INET)
                ogs_assert(OGS_OK ==
                    ogs_copyaddrinfo(
                        &tunnel->local_addr, sess->pfcp_node->addr_list));
            else if (sess->pfcp_node->addr_list->ogs_sa_family == AF_INET6)
                ogs_assert(OGS_OK ==
                    ogs_copyaddrinfo(
                        &tunnel->local_addr6, sess->pfcp_node->addr_list));
            else
                ogs_assert_if_reached();

            tunnel->local_teid = sgwc_gtpu_has_teid_encoding(sess) ?
                sgwc_gtpu_teid_from_index(sess, pdr->teid) : pdr->teid;
        }

        ogs_assert(OGS_OK ==
            ogs_pfcp_sockaddr_to_f_teid(
                tunnel->local_addr, tunnel->local_addr6,
                &pdr->f_teid, &pdr->f_teid_len));
        pdr->f_teid.teid = tunnel->local_teid;
        pdr->f_teid.ch = 0;
    }

    return tunnel;
}

int sgwc_tunnel_remove(sgwc_tunnel_t *tunnel)
{
    sgwc_bearer_t *bearer = NULL;

    ogs_assert(tunnel);
    bearer = sgwc_bearer_find_by_id(tunnel->bearer_id);
    ogs_assert(bearer);

    ogs_list_remove(&bearer->tunnel_list, tunnel);

    if (tunnel->pdr)
        ogs_pfcp_pdr_remove(tunnel->pdr);
    if (tunnel->far)
        ogs_pfcp_far_remove(tunnel->far);

    if (tunnel->local_addr)
        ogs_freeaddrinfo(tunnel->local_addr);
    if (tunnel->local_addr6)
        ogs_freeaddrinfo(tunnel->local_addr6);

    ogs_pool_id_free(&sgwc_tunnel_pool, tunnel);

    return OGS_OK;
}

void sgwc_tunnel_remove_all(sgwc_bearer_t *bearer)
{
    sgwc_tunnel_t *tunnel = NULL, *next_tunnel = NULL;

    ogs_assert(bearer);
    ogs_list_for_each_safe(&bearer->tunnel_list, next_tunnel, tunnel)
        sgwc_tunnel_remove(tunnel);
}

sgwc_tunnel_t *sgwc_tunnel_find_by_teid(sgwc_ue_t *sgwc_ue, uint32_t teid)
{
    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *tunnel = NULL;

    ogs_assert(sgwc_ue);

    ogs_list_for_each(&sgwc_ue->sess_list, sess) {
        ogs_list_for_each(&sess->bearer_list, bearer) {
            ogs_list_for_each(&bearer->tunnel_list, tunnel) {
                if (tunnel->local_teid == teid) return tunnel;
            }
        }
    }

    return NULL;
}

sgwc_tunnel_t *sgwc_tunnel_find_by_interface_type(
        sgwc_bearer_t *bearer, uint8_t interface_type)
{
    sgwc_tunnel_t *tunnel = NULL;

    ogs_assert(bearer);

    ogs_list_for_each(&bearer->tunnel_list, tunnel)
        if (tunnel->interface_type == interface_type) return tunnel;

    return NULL;
}

sgwc_tunnel_t *sgwc_tunnel_find_by_pdr_id(
        sgwc_sess_t *sess, ogs_pfcp_pdr_id_t pdr_id)
{
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *tunnel = NULL;

    ogs_pfcp_pdr_t *pdr = NULL;

    ogs_assert(sess);

    ogs_list_for_each(&sess->bearer_list, bearer) {
        ogs_list_for_each(&bearer->tunnel_list, tunnel) {
            pdr = tunnel->pdr;
            ogs_assert(pdr);

            if (pdr->id == pdr_id) return tunnel;
        }
    }

    return NULL;
}

sgwc_tunnel_t *sgwc_tunnel_find_by_far_id(
        sgwc_sess_t *sess, ogs_pfcp_far_id_t far_id)
{
    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *tunnel = NULL;

    ogs_pfcp_far_t *far = NULL;

    ogs_assert(sess);

    ogs_list_for_each(&sess->bearer_list, bearer) {
        ogs_list_for_each(&bearer->tunnel_list, tunnel) {
            far = tunnel->far;
            ogs_assert(far);

            if (far->id == far_id) return tunnel;
        }
    }

    return NULL;
}

sgwc_tunnel_t *sgwc_tunnel_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&sgwc_tunnel_pool, id);
}

sgwc_tunnel_t *sgwc_dl_tunnel_in_bearer(sgwc_bearer_t *bearer)
{
    ogs_assert(bearer);
    return sgwc_tunnel_find_by_interface_type(bearer,
            OGS_GTP2_F_TEID_S5_S8_SGW_GTP_U);
}
sgwc_tunnel_t *sgwc_ul_tunnel_in_bearer(sgwc_bearer_t *bearer)
{
    ogs_assert(bearer);
    return sgwc_tunnel_find_by_interface_type(bearer,
            OGS_GTP2_F_TEID_S1_U_SGW_GTP_U);
}

static void stats_add_sgwc_session(void)
{
    num_of_sgwc_sess = num_of_sgwc_sess + 1;
    ogs_info("[Added] Number of SGWC-Sessions is now %d", num_of_sgwc_sess);
}

static void stats_remove_sgwc_session(void)
{
    num_of_sgwc_sess = num_of_sgwc_sess - 1;
    ogs_debug("[Removed] Number of SGWC-Sessions is now %d", num_of_sgwc_sess);
}
