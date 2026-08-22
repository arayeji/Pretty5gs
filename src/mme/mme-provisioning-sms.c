/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "mme-provisioning-sms.h"
#include "nas-path.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

#ifndef _WIN32
#include <sys/stat.h>
#endif

#define MME_PROV_SMS_DEFAULT_TRACKER \
    "/var/lib/open5gs/mme-imei-tracker.txt"

typedef struct mme_imei_track_entry_s {
    char imsi[OGS_MAX_IMSI_BCD_LEN + 1];
    char imei[MME_PROV_SMS_IMEI_LEN + 1];
} mme_imei_track_entry_t;

static ogs_list_t g_rules;
static uint8_t g_rp_msg_ref;

static ogs_hash_t *g_imei_hash = NULL;
static ogs_thread_mutex_t g_imei_lock;
static char g_tracker_path[512];
static bool g_tracker_dirty;

static void tracker_mkdir_p(const char *dir)
{
    char tmp[512];
    char *p;
    size_t len;

    if (!dir || !dir[0])
        return;

    ogs_cpystrn(tmp, dir, sizeof(tmp));
    len = strlen(tmp);
    if (len && tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

#ifndef _WIN32
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                ogs_warn("mkdir(%s): %s", tmp, strerror(errno));
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        ogs_warn("mkdir(%s): %s", tmp, strerror(errno));
#else
    (void)p;
#endif
}

static void tracker_clear_hash(void)
{
    ogs_hash_index_t *hi;

    if (!g_imei_hash)
        return;

    for (hi = ogs_hash_first(g_imei_hash); hi; ) {
        mme_imei_track_entry_t *e =
            (mme_imei_track_entry_t *)ogs_hash_this_val(hi);
        hi = ogs_hash_next(hi);
        if (e) {
            ogs_hash_set(g_imei_hash, e->imsi, strlen(e->imsi) + 1, NULL);
            ogs_free(e);
        }
    }
}

static void tracker_load(void)
{
    FILE *f;
    char line[128];
    int loaded = 0;

    if (!g_tracker_path[0] || !g_imei_hash)
        return;

    f = fopen(g_tracker_path, "r");
    if (!f)
        return;

    while (fgets(line, sizeof(line), f)) {
        char imsi[OGS_MAX_IMSI_BCD_LEN + 1];
        char imei[MME_PROV_SMS_IMEI_LEN + 1];
        mme_imei_track_entry_t *e, *old;
        char *comma, *nl;
        size_t imsi_len, imei_len;

        nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        if (line[0] == '#' || line[0] == '\0')
            continue;

        comma = strchr(line, ',');
        if (!comma)
            continue;
        *comma = '\0';

        imsi_len = strlen(line);
        imei_len = strlen(comma + 1);
        if (imsi_len < 6 || imsi_len > OGS_MAX_IMSI_BCD_LEN)
            continue;
        if (imei_len < MME_PROV_SMS_IMEI_LEN)
            continue;

        ogs_cpystrn(imsi, line, sizeof(imsi));
        ogs_cpystrn(imei, comma + 1, sizeof(imei));
        imei[MME_PROV_SMS_IMEI_LEN] = '\0';

        e = ogs_calloc(1, sizeof(*e));
        if (!e)
            continue;
        ogs_cpystrn(e->imsi, imsi, sizeof(e->imsi));
        ogs_cpystrn(e->imei, imei, sizeof(e->imei));

        old = ogs_hash_get(g_imei_hash, e->imsi, strlen(e->imsi) + 1);
        if (old) {
            ogs_hash_set(g_imei_hash, old->imsi, strlen(old->imsi) + 1, NULL);
            ogs_free(old);
        }
        ogs_hash_set(g_imei_hash, e->imsi, strlen(e->imsi) + 1, e);
        loaded++;
    }

    fclose(f);
    ogs_info("provisioning_sms: loaded %d IMEI tracker entries from %s",
            loaded, g_tracker_path);
}

static void tracker_save(void)
{
    FILE *f;
    ogs_hash_index_t *hi;
    char dir[512];
    char *slash;
    int n = 0;

    if (!g_tracker_dirty || !g_tracker_path[0] || !g_imei_hash)
        return;

    ogs_cpystrn(dir, g_tracker_path, sizeof(dir));
    slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        tracker_mkdir_p(dir);
    }

    f = fopen(g_tracker_path, "w");
    if (!f) {
        ogs_error("provisioning_sms: cannot write tracker %s: %s",
                g_tracker_path, strerror(errno));
        return;
    }

    fprintf(f, "# imsi,imei (15 digits) — local provisioning tracker\n");
    for (hi = ogs_hash_first(g_imei_hash); hi; hi = ogs_hash_next(hi)) {
        mme_imei_track_entry_t *e =
            (mme_imei_track_entry_t *)ogs_hash_this_val(hi);
        if (!e)
            continue;
        fprintf(f, "%s,%s\n", e->imsi, e->imei);
        n++;
    }
    fclose(f);
    g_tracker_dirty = false;
    ogs_debug("provisioning_sms: saved %d IMEI tracker entries to %s",
            n, g_tracker_path);
}

/* Returns true if IMEI is new or changed for this IMSI (needs SMS). */
static bool tracker_imei_is_new(const char *imsi, const char *imei)
{
    mme_imei_track_entry_t *e;
    bool is_new;

    ogs_assert(imsi);
    ogs_assert(imei);

    ogs_thread_mutex_lock(&g_imei_lock);
    e = g_imei_hash ?
        ogs_hash_get(g_imei_hash, imsi, strlen(imsi) + 1) : NULL;
    is_new = (!e || strcmp(e->imei, imei) != 0);
    ogs_thread_mutex_unlock(&g_imei_lock);
    return is_new;
}

static void tracker_remember(const char *imsi, const char *imei)
{
    mme_imei_track_entry_t *e, *old;

    ogs_assert(imsi);
    ogs_assert(imei);
    if (!g_imei_hash)
        return;

    ogs_thread_mutex_lock(&g_imei_lock);

    old = ogs_hash_get(g_imei_hash, imsi, strlen(imsi) + 1);
    if (old && strcmp(old->imei, imei) == 0) {
        ogs_thread_mutex_unlock(&g_imei_lock);
        return;
    }

    if (old) {
        ogs_hash_set(g_imei_hash, old->imsi, strlen(old->imsi) + 1, NULL);
        ogs_free(old);
    }

    e = ogs_calloc(1, sizeof(*e));
    ogs_assert(e);
    ogs_cpystrn(e->imsi, imsi, sizeof(e->imsi));
    ogs_cpystrn(e->imei, imei, sizeof(e->imei));
    ogs_hash_set(g_imei_hash, e->imsi, strlen(e->imsi) + 1, e);
    g_tracker_dirty = true;
    tracker_save();

    ogs_thread_mutex_unlock(&g_imei_lock);
}

static void extract_imei15(const char *imeisv_bcd, char *imei, size_t imei_sz)
{
    size_t n, i;

    ogs_assert(imei);
    ogs_assert(imei_sz > MME_PROV_SMS_IMEI_LEN);
    imei[0] = '\0';
    if (!imeisv_bcd || !imeisv_bcd[0])
        return;

    n = 0;
    for (i = 0; imeisv_bcd[i] && n < MME_PROV_SMS_IMEI_LEN; i++) {
        if (isdigit((unsigned char)imeisv_bcd[i]))
            imei[n++] = imeisv_bcd[i];
    }
    imei[n] = '\0';
    if (n != MME_PROV_SMS_IMEI_LEN)
        imei[0] = '\0';
}

void mme_provisioning_sms_init(void)
{
    ogs_list_init(&g_rules);
    g_rp_msg_ref = 0;
    g_imei_hash = ogs_hash_make();
    ogs_assert(g_imei_hash);
    ogs_thread_mutex_init(&g_imei_lock);
    ogs_cpystrn(g_tracker_path, MME_PROV_SMS_DEFAULT_TRACKER,
            sizeof(g_tracker_path));
    g_tracker_dirty = false;
}

void mme_provisioning_sms_remove_all(void)
{
    mme_provisioning_sms_rule_t *rule, *next;

    ogs_list_for_each_safe(&g_rules, next, rule) {
        ogs_list_remove(&g_rules, rule);
        ogs_free(rule);
    }
}

void mme_provisioning_sms_final(void)
{
    mme_provisioning_sms_remove_all();

    ogs_thread_mutex_lock(&g_imei_lock);
    if (g_tracker_dirty)
        tracker_save();
    tracker_clear_hash();
    if (g_imei_hash) {
        ogs_hash_destroy(g_imei_hash);
        g_imei_hash = NULL;
    }
    ogs_thread_mutex_unlock(&g_imei_lock);
    ogs_thread_mutex_destroy(&g_imei_lock);
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t parse_hex(const char *hex, uint8_t *out, size_t out_max)
{
    size_t n = 0;
    int hi, lo;

    if (!hex || !out || !out_max)
        return 0;

    while (*hex) {
        while (*hex && isspace((unsigned char)*hex))
            hex++;
        if (!*hex)
            break;
        if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
            hex += 2;
            continue;
        }
        hi = hex_nibble(*hex++);
        if (hi < 0 || !*hex)
            return 0;
        lo = hex_nibble(*hex++);
        if (lo < 0)
            return 0;
        if (n >= out_max)
            return 0;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

static void encode_tbcd_digits(const char *digits, uint8_t *out, size_t *out_len,
        size_t out_max)
{
    size_t nd = 0, i;
    char buf[MME_PROV_SMS_MAX_OA_DIGITS + 2];

    *out_len = 0;
    if (!digits || !digits[0])
        digits = "0";

    for (i = 0; digits[i] && nd < MME_PROV_SMS_MAX_OA_DIGITS; i++) {
        if (isdigit((unsigned char)digits[i]))
            buf[nd++] = digits[i];
    }
    if (!nd)
        buf[nd++] = '0';
    buf[nd] = '\0';
    if (nd & 1)
        buf[nd++] = 'F';

    for (i = 0; i + 1 < nd && *out_len < out_max; i += 2) {
        int d1 = buf[i] == 'F' ? 0xF : (buf[i] - '0');
        int d2 = buf[i + 1] == 'F' ? 0xF : (buf[i + 1] - '0');
        out[(*out_len)++] = (uint8_t)((d2 << 4) | d1);
    }
}

static void fill_scts(uint8_t scts[7])
{
    time_t now = time(NULL);
    struct tm tm_buf, *tm;

    memset(scts, 0, 7);
#if defined(_WIN32)
    tm = gmtime_s(&tm_buf, &now) == 0 ? &tm_buf : NULL;
#else
    tm = gmtime_r(&now, &tm_buf);
#endif
    if (!tm)
        return;

    scts[0] = (uint8_t)(((tm->tm_year % 10) << 4) | ((tm->tm_year / 10) % 10));
    scts[1] = (uint8_t)((((tm->tm_mon + 1) % 10) << 4) |
            (((tm->tm_mon + 1) / 10) % 10));
    scts[2] = (uint8_t)(((tm->tm_mday % 10) << 4) | ((tm->tm_mday / 10) % 10));
    scts[3] = (uint8_t)(((tm->tm_hour % 10) << 4) | ((tm->tm_hour / 10) % 10));
    scts[4] = (uint8_t)(((tm->tm_min % 10) << 4) | ((tm->tm_min / 10) % 10));
    scts[5] = (uint8_t)(((tm->tm_sec % 10) << 4) | ((tm->tm_sec / 10) % 10));
    scts[6] = 0x00;
}

static size_t build_mt_binary_sms(const mme_provisioning_sms_rule_t *rule,
        uint8_t *out, size_t out_max)
{
    uint8_t tpdu[OGS_NAS_MAX_MESSAGE_CONTAINER_LEN];
    uint8_t rp[OGS_NAS_MAX_MESSAGE_CONTAINER_LEN];
    uint8_t oa_tbcd[12];
    size_t oa_tbcd_len = 0, tpdu_len = 0, rp_len = 0, ud_off;
    size_t udhl = 0;
    uint8_t first;
    size_t i;
    size_t ndigits = 0;

    if (!rule || !rule->userdata_len || !out || out_max < 16)
        return 0;

    encode_tbcd_digits(rule->oa, oa_tbcd, &oa_tbcd_len, sizeof(oa_tbcd));
    for (i = 0; rule->oa[i]; i++)
        if (isdigit((unsigned char)rule->oa[i]))
            ndigits++;
    if (!ndigits)
        ndigits = 1;

    first = 0x04; /* MTI=DELIVER, MMS=1 */
    if (rule->dest_port || rule->orig_port)
        first |= 0x40; /* UDHI */

    tpdu[tpdu_len++] = first;
    tpdu[tpdu_len++] = (uint8_t)ndigits;
    tpdu[tpdu_len++] = 0x91;
    if (ndigits <= 3)
        tpdu[tpdu_len - 1] = 0x81;
    for (i = 0; i < oa_tbcd_len; i++)
        tpdu[tpdu_len++] = oa_tbcd[i];
    tpdu[tpdu_len++] = 0x00;
    tpdu[tpdu_len++] = rule->dcs ? rule->dcs : 0x04;

    {
        uint8_t scts[7];
        fill_scts(scts);
        memcpy(tpdu + tpdu_len, scts, 7);
        tpdu_len += 7;
    }

    ud_off = tpdu_len;
    tpdu[tpdu_len++] = 0;

    if (rule->dest_port || rule->orig_port) {
        tpdu[tpdu_len++] = 0x06;
        tpdu[tpdu_len++] = 0x05;
        tpdu[tpdu_len++] = 0x04;
        tpdu[tpdu_len++] = (uint8_t)((rule->dest_port >> 8) & 0xff);
        tpdu[tpdu_len++] = (uint8_t)(rule->dest_port & 0xff);
        tpdu[tpdu_len++] = (uint8_t)((rule->orig_port >> 8) & 0xff);
        tpdu[tpdu_len++] = (uint8_t)(rule->orig_port & 0xff);
        udhl = 7;
    }

    if (tpdu_len + rule->userdata_len > sizeof(tpdu))
        return 0;
    memcpy(tpdu + tpdu_len, rule->userdata, rule->userdata_len);
    tpdu_len += rule->userdata_len;
    tpdu[ud_off] = (uint8_t)(udhl + rule->userdata_len);

    rp[rp_len++] = 0x01;
    rp[rp_len++] = ++g_rp_msg_ref ? g_rp_msg_ref : (g_rp_msg_ref = 1);
    {
        size_t sc_len = 0;
        uint8_t sc[12];
        encode_tbcd_digits(rule->oa, sc, &sc_len, sizeof(sc));
        rp[rp_len++] = (uint8_t)(1 + sc_len);
        rp[rp_len++] = 0x91;
        for (i = 0; i < sc_len; i++)
            rp[rp_len++] = sc[i];
    }
    rp[rp_len++] = 0x00;
    rp[rp_len++] = (uint8_t)tpdu_len;
    if (rp_len + tpdu_len > sizeof(rp))
        return 0;
    memcpy(rp + rp_len, tpdu, tpdu_len);
    rp_len += tpdu_len;

    if (3 + rp_len > out_max)
        return 0;
    out[0] = 0x89;
    out[1] = 0x01;
    out[2] = (uint8_t)rp_len;
    memcpy(out + 3, rp, rp_len);
    return 3 + rp_len;
}

static mme_provisioning_sms_rule_t *find_rule_for_imsi(const char *imsi_bcd)
{
    mme_provisioning_sms_rule_t *rule;
    ogs_plmn_id_t home;

    if (!imsi_bcd || !imsi_bcd[0])
        return NULL;

    mme_home_plmn_from_imsi_bcd(imsi_bcd, &home);

    ogs_list_for_each(&g_rules, rule) {
        if (!rule->plmn_present)
            continue;
        if (memcmp(&rule->imsi_plmn_id, &home, OGS_PLMN_ID_LEN) == 0)
            return rule;
    }
    return NULL;
}

static int parse_one_rule(ogs_yaml_iter_t *entry)
{
    mme_provisioning_sms_rule_t *rule;
    const char *hex = NULL;
    int count_before = 0;
    mme_provisioning_sms_rule_t *r;

    ogs_list_for_each(&g_rules, r)
        count_before++;

    rule = ogs_calloc(1, sizeof(*rule));
    ogs_assert(rule);
    rule->dcs = 0x04;
    ogs_cpystrn(rule->oa, "0", sizeof(rule->oa));

    while (ogs_yaml_iter_next(entry)) {
        const char *k = ogs_yaml_iter_key(entry);
        if (!k)
            continue;

        if (!strcmp(k, "imsi_plmn_id") || !strcmp(k, "plmn_id")) {
            ogs_yaml_iter_t plmn_iter;
            const char *mcc = NULL, *mnc = NULL;

            ogs_yaml_iter_recurse(entry, &plmn_iter);
            while (ogs_yaml_iter_next(&plmn_iter)) {
                const char *pk = ogs_yaml_iter_key(&plmn_iter);
                const char *pv = ogs_yaml_iter_value(&plmn_iter);
                if (!pk || !pv)
                    continue;
                if (!strcmp(pk, "mcc"))
                    mcc = pv;
                else if (!strcmp(pk, "mnc"))
                    mnc = pv;
            }
            if (mcc && mnc) {
                ogs_plmn_id_build(&rule->imsi_plmn_id,
                        atoi(mcc), atoi(mnc), strlen(mnc));
                rule->plmn_present = true;
            }
        } else if (!strcmp(k, "userdata_hex") || !strcmp(k, "payload_hex")) {
            hex = ogs_yaml_iter_value(entry);
        } else if (!strcmp(k, "oa") || !strcmp(k, "originator")) {
            const char *v = ogs_yaml_iter_value(entry);
            if (v)
                ogs_cpystrn(rule->oa, v, sizeof(rule->oa));
        } else if (!strcmp(k, "dcs")) {
            const char *v = ogs_yaml_iter_value(entry);
            if (v) {
                if (v[0] == '0' && (v[1] == 'x' || v[1] == 'X'))
                    rule->dcs = (uint8_t)strtoul(v, NULL, 16);
                else
                    rule->dcs = (uint8_t)atoi(v);
            }
        } else if (!strcmp(k, "dest_port")) {
            const char *v = ogs_yaml_iter_value(entry);
            if (v)
                rule->dest_port = (uint16_t)atoi(v);
        } else if (!strcmp(k, "orig_port")) {
            const char *v = ogs_yaml_iter_value(entry);
            if (v)
                rule->orig_port = (uint16_t)atoi(v);
        } else {
            ogs_warn("mme.provisioning_sms: unknown key `%s'", k);
        }
    }

    if (hex) {
        rule->userdata_len = parse_hex(hex, rule->userdata,
                sizeof(rule->userdata));
        if (!rule->userdata_len && hex[0])
            ogs_warn("mme.provisioning_sms: bad userdata_hex");
    }

    if (!rule->plmn_present || !rule->userdata_len) {
        ogs_warn("mme.provisioning_sms: skip rule "
                "(need imsi_plmn_id + userdata_hex)");
        ogs_free(rule);
        return 0;
    }
    if (count_before >= MME_PROV_SMS_MAX_RULES) {
        ogs_warn("mme.provisioning_sms: max %d rules",
                MME_PROV_SMS_MAX_RULES);
        ogs_free(rule);
        return 0;
    }

    ogs_list_add(&g_rules, rule);
    ogs_info("provisioning_sms: IMSI-PLMN mcc=%d mnc=%0*d "
            "userdata=%zu octets dcs=0x%02x ports=%u/%u",
            ogs_plmn_id_mcc(&rule->imsi_plmn_id),
            ogs_plmn_id_mnc_len(&rule->imsi_plmn_id),
            ogs_plmn_id_mnc(&rule->imsi_plmn_id),
            rule->userdata_len, rule->dcs,
            rule->dest_port, rule->orig_port);
    return 1;
}

static int parse_rules_sequence(ogs_yaml_iter_t *array)
{
    int count = 0;

    while (1) {
        ogs_yaml_iter_t entry;

        if (ogs_yaml_iter_type(array) == YAML_SCALAR_NODE)
            break;
        if (ogs_yaml_iter_type(array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(array))
                break;
            ogs_yaml_iter_recurse(array, &entry);
        } else if (ogs_yaml_iter_type(array) == YAML_MAPPING_NODE) {
            ogs_yaml_iter_recurse(array, &entry);
        } else {
            break;
        }

        count += parse_one_rule(&entry);

        if (ogs_yaml_iter_type(array) != YAML_SEQUENCE_NODE)
            break;
    }

    return count;
}

int mme_provisioning_sms_parse(ogs_yaml_iter_t *parent)
{
    ogs_yaml_iter_t root;
    int count = 0;
    char new_path[512];
    bool reload_tracker = false;

    ogs_assert(parent);
    mme_provisioning_sms_remove_all();

    ogs_cpystrn(new_path, g_tracker_path, sizeof(new_path));
    ogs_yaml_iter_recurse(parent, &root);

    if (ogs_yaml_iter_type(&root) == YAML_SEQUENCE_NODE) {
        count = parse_rules_sequence(&root);
    } else if (ogs_yaml_iter_type(&root) == YAML_MAPPING_NODE) {
        ogs_yaml_iter_t probe;
        bool has_rules_key = false;
        bool has_tracker_key = false;

        ogs_yaml_iter_recurse(parent, &probe);
        while (ogs_yaml_iter_next(&probe)) {
            const char *k = ogs_yaml_iter_key(&probe);
            if (!k)
                continue;
            if (!strcmp(k, "rules"))
                has_rules_key = true;
            else if (!strcmp(k, "tracker_file"))
                has_tracker_key = true;
        }

        if (has_rules_key || has_tracker_key) {
            ogs_yaml_iter_t map;
            ogs_yaml_iter_recurse(parent, &map);
            while (ogs_yaml_iter_next(&map)) {
                const char *k = ogs_yaml_iter_key(&map);
                if (!k)
                    continue;
                if (!strcmp(k, "tracker_file")) {
                    const char *v = ogs_yaml_iter_value(&map);
                    if (v && v[0]) {
                        ogs_cpystrn(new_path, v, sizeof(new_path));
                        reload_tracker = true;
                    }
                } else if (!strcmp(k, "rules")) {
                    ogs_yaml_iter_t rules;
                    ogs_yaml_iter_recurse(&map, &rules);
                    count = parse_rules_sequence(&rules);
                } else {
                    ogs_warn("mme.provisioning_sms: unknown key `%s'", k);
                }
            }
        } else {
            ogs_yaml_iter_t entry;
            ogs_yaml_iter_recurse(parent, &entry);
            count = parse_one_rule(&entry);
        }
    }

    ogs_thread_mutex_lock(&g_imei_lock);
    if (reload_tracker && strcmp(g_tracker_path, new_path) != 0) {
        tracker_clear_hash();
        ogs_cpystrn(g_tracker_path, new_path, sizeof(g_tracker_path));
        tracker_load();
    } else if (g_imei_hash && ogs_hash_count(g_imei_hash) == 0) {
        tracker_load();
    } else if (reload_tracker) {
        ogs_cpystrn(g_tracker_path, new_path, sizeof(g_tracker_path));
    }
    ogs_thread_mutex_unlock(&g_imei_lock);

    if (count > 0)
        ogs_info("provisioning_sms: tracker_file=%s", g_tracker_path);

    return count;
}

void mme_provisioning_sms_on_attach_complete(mme_ue_t *mme_ue)
{
    mme_provisioning_sms_rule_t *rule;
    uint8_t nas[OGS_NAS_MAX_MESSAGE_CONTAINER_LEN];
    size_t nas_len;
    char imei[MME_PROV_SMS_IMEI_LEN + 1];
    int r;

    if (!mme_ue || !MME_UE_HAVE_IMSI(mme_ue))
        return;
    if (ogs_list_empty(&g_rules))
        return;

    rule = find_rule_for_imsi(mme_ue->imsi_bcd);
    if (!rule)
        return;

    extract_imei15(mme_ue->imeisv_bcd, imei, sizeof(imei));
    if (!imei[0]) {
        ogs_debug("[%s] provisioning_sms: no IMEI yet; skip",
                mme_ue->imsi_bcd);
        return;
    }

    if (!tracker_imei_is_new(mme_ue->imsi_bcd, imei)) {
        ogs_debug("[%s] provisioning_sms: IMEI %s already tracked; skip",
                mme_ue->imsi_bcd, imei);
        return;
    }

    nas_len = build_mt_binary_sms(rule, nas, sizeof(nas));
    if (!nas_len) {
        ogs_error("[%s] provisioning_sms: failed to build MT SMS",
                mme_ue->imsi_bcd);
        return;
    }

    r = nas_eps_send_downlink_nas_transport(mme_ue, nas, (uint8_t)nas_len);
    if (r != OGS_OK) {
        ogs_warn("[%s] provisioning_sms: Downlink NAS transport failed "
                "(S1 gone?) — IMEI not recorded, will retry next attach",
                mme_ue->imsi_bcd);
        return;
    }

    tracker_remember(mme_ue->imsi_bcd, imei);
    ogs_info("[%s] provisioning_sms: sent binary MT SMS "
            "(%zu userdata octets) for new/changed IMEI %s",
            mme_ue->imsi_bcd, rule->userdata_len, imei);
}
