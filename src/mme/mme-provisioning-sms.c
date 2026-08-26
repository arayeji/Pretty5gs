/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "mme-provisioning-sms.h"
#include "nas-path.h"
#include "ogs-dbi.h"

#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/un.h>
#include <sys/socket.h>

static ogs_list_t g_rules;
static uint8_t g_rp_msg_ref;
static ogs_thread_mutex_t g_db_lock;
static bool g_db_lock_ok;

void mme_provisioning_sms_init(void)
{
    ogs_list_init(&g_rules);
    g_rp_msg_ref = 0;
    ogs_thread_mutex_init(&g_db_lock);
    g_db_lock_ok = true;
}

void mme_provisioning_sms_remove_all(void)
{
    mme_provisioning_sms_rule_t *rule, *next;

    ogs_list_for_each_safe(&g_rules, next, rule) {
        ogs_list_remove(&g_rules, rule);
        if (rule->event_fd >= 0)
            close(rule->event_fd);
        ogs_free(rule);
    }
}

/*
 * Resolve the delivery=event datagram target from config. event_socket is a
 * UNIX-domain path; event_addr is "host:port" (UDP, IPv4/IPv6). Called once at
 * parse time; the client socket itself is created lazily on first send.
 */
static int event_target_setup(mme_provisioning_sms_rule_t *rule)
{
    rule->event_fd = -1;
    rule->event_family = 0;

    if (rule->event_socket[0]) {
        struct sockaddr_un *un = (struct sockaddr_un *)&rule->event_sa;
        memset(un, 0, sizeof(*un));
        un->sun_family = AF_UNIX;
        ogs_cpystrn(un->sun_path, rule->event_socket, sizeof(un->sun_path));
        rule->event_salen = (socklen_t)sizeof(*un);
        rule->event_family = AF_UNIX;
        return OGS_OK;
    }

    if (rule->event_addr[0]) {
        char host[64], *colon;
        const char *port;
        struct addrinfo hints, *res = NULL;

        ogs_cpystrn(host, rule->event_addr, sizeof(host));
        colon = strrchr(host, ':');
        if (!colon) {
            ogs_error("provisioning_sms: event_addr needs host:port [%s]",
                    rule->event_addr);
            return OGS_ERROR;
        }
        *colon = '\0';
        port = colon + 1;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_NUMERICSERV;
        if (getaddrinfo(host, port, &hints, &res) != 0 || !res) {
            ogs_error("provisioning_sms: cannot resolve event_addr [%s]",
                    rule->event_addr);
            return OGS_ERROR;
        }
        memcpy(&rule->event_sa, res->ai_addr, res->ai_addrlen);
        rule->event_salen = (socklen_t)res->ai_addrlen;
        rule->event_family = res->ai_family;
        freeaddrinfo(res);
        return OGS_OK;
    }

    return OGS_ERROR;  /* neither configured */
}

/*
 * One fire-and-forget datagram. Non-blocking: if the external provisioner is
 * down or its socket buffer is full, the send is dropped (EAGAIN/ENOENT) and
 * the next attach re-fires. This never blocks the MME worker.
 */
static void event_send(mme_provisioning_sms_rule_t *rule,
        const char *buf, size_t len)
{
    ssize_t n;

    if (rule->event_family == 0)
        return;

    if (rule->event_fd < 0) {
        rule->event_fd = socket(rule->event_family, SOCK_DGRAM, 0);
        if (rule->event_fd < 0)
            return;
        (void)fcntl(rule->event_fd, F_SETFD, FD_CLOEXEC);
        (void)fcntl(rule->event_fd, F_SETFL,
                fcntl(rule->event_fd, F_GETFL, 0) | O_NONBLOCK);
    }

    n = sendto(rule->event_fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL,
            (struct sockaddr *)&rule->event_sa, rule->event_salen);
    (void)n;  /* fire-and-forget; drops are acceptable */
}

void mme_provisioning_sms_final(void)
{
    mme_provisioning_sms_remove_all();
    if (g_db_lock_ok) {
        ogs_thread_mutex_destroy(&g_db_lock);
        g_db_lock_ok = false;
    }
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
    tm = gmtime_r(&now, &tm_buf);
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

    first = 0x04;
    if (rule->dest_port || rule->orig_port)
        first |= 0x40;

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

static void extract_imei15(const char *imeisv_bcd, char *imei, size_t imei_sz)
{
    size_t n = 0, i;

    ogs_assert(imei);
    ogs_assert(imei_sz > MME_PROV_SMS_IMEI_LEN);
    imei[0] = '\0';
    if (!imeisv_bcd || !imeisv_bcd[0])
        return;

    for (i = 0; imeisv_bcd[i] && n < MME_PROV_SMS_IMEI_LEN; i++) {
        if (isdigit((unsigned char)imeisv_bcd[i]))
            imei[n++] = imeisv_bcd[i];
    }
    imei[n] = '\0';
    if (n != MME_PROV_SMS_IMEI_LEN)
        imei[0] = '\0';
}

static bool tracker_imei_is_new(const char *imsi, const char *imei)
{
    char stored[MME_PROV_SMS_IMEI_LEN + 1];
    int rv;

    if (!ogs_mongoc()->initialized || !ogs_mongoc()->collection.imei_tracker)
        return false;

    ogs_thread_mutex_lock(&g_db_lock);
    rv = ogs_dbi_imei_tracker_get(imsi, stored, sizeof(stored));
    ogs_thread_mutex_unlock(&g_db_lock);

    if (rv != OGS_OK)
        return true;
    return strcmp(stored, imei) != 0;
}

static void tracker_remember(const char *imsi, const char *imei)
{
    int rv;

    if (!ogs_mongoc()->initialized || !ogs_mongoc()->collection.imei_tracker)
        return;

    ogs_thread_mutex_lock(&g_db_lock);
    rv = ogs_dbi_imei_tracker_set(imsi, imei);
    ogs_thread_mutex_unlock(&g_db_lock);

    if (rv != OGS_OK)
        ogs_error("[%s] provisioning_sms: failed to persist IMEI %s in DB",
                imsi, imei);
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
    rule->delivery = MME_PROV_SMS_DELIVERY_S1;
    rule->require_no_apn = true;    /* only UEs without an APN IE, by default */
    rule->event_fd = -1;
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
        } else if (!strcmp(k, "delivery")) {
            const char *v = ogs_yaml_iter_value(entry);
            if (v && (!strcmp(v, "event") || !strcmp(v, "external") ||
                    !strcmp(v, "emit")))
                rule->delivery = MME_PROV_SMS_DELIVERY_EVENT;
            else
                rule->delivery = MME_PROV_SMS_DELIVERY_S1;
        } else if (!strcmp(k, "require_no_apn") ||
                !strcmp(k, "only_default_apn")) {
            const char *v = ogs_yaml_iter_value(entry);
            rule->require_no_apn =
                    !(v && (!strcmp(v, "false") || !strcmp(v, "0") ||
                            !strcmp(v, "no")));
        } else if (!strcmp(k, "event_socket")) {
            const char *v = ogs_yaml_iter_value(entry);
            if (v)
                ogs_cpystrn(rule->event_socket, v, sizeof(rule->event_socket));
        } else if (!strcmp(k, "event_addr")) {
            const char *v = ogs_yaml_iter_value(entry);
            if (v)
                ogs_cpystrn(rule->event_addr, v, sizeof(rule->event_addr));
        } else if (!strcmp(k, "tracker_file")) {
            ogs_warn("mme.provisioning_sms: tracker_file ignored "
                    "(IMEI tracker is MongoDB collection imei_tracker)");
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

    /* S1 delivery needs the CP payload (userdata_hex); EVENT delivery needs a
     * datagram target (event_socket or event_addr) -- the external provisioner
     * builds the CP itself. */
    if (!rule->plmn_present) {
        ogs_warn("mme.provisioning_sms: skip rule (need imsi_plmn_id)");
        ogs_free(rule);
        return 0;
    }
    if (rule->delivery == MME_PROV_SMS_DELIVERY_S1 && !rule->userdata_len) {
        ogs_warn("mme.provisioning_sms: skip rule (delivery=s1 needs "
                "userdata_hex)");
        ogs_free(rule);
        return 0;
    }
    if (rule->delivery == MME_PROV_SMS_DELIVERY_EVENT &&
            event_target_setup(rule) != OGS_OK) {
        ogs_warn("mme.provisioning_sms: skip rule (delivery=event needs a "
                "valid event_socket or event_addr)");
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
    if (rule->delivery == MME_PROV_SMS_DELIVERY_EVENT)
        ogs_info("provisioning_sms: IMSI-PLMN mcc=%d mnc=%0*d delivery=event "
                "target=%s require_no_apn=%s",
                ogs_plmn_id_mcc(&rule->imsi_plmn_id),
                ogs_plmn_id_mnc_len(&rule->imsi_plmn_id),
                ogs_plmn_id_mnc(&rule->imsi_plmn_id),
                rule->event_socket[0] ? rule->event_socket : rule->event_addr,
                rule->require_no_apn ? "true" : "false");
    else
        ogs_info("provisioning_sms: IMSI-PLMN mcc=%d mnc=%0*d delivery=s1 "
                "require_no_apn=%s userdata=%zu octets dcs=0x%02x ports=%u/%u",
                ogs_plmn_id_mcc(&rule->imsi_plmn_id),
                ogs_plmn_id_mnc_len(&rule->imsi_plmn_id),
                ogs_plmn_id_mnc(&rule->imsi_plmn_id),
                rule->require_no_apn ? "true" : "false",
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

    ogs_assert(parent);
    mme_provisioning_sms_remove_all();

    ogs_yaml_iter_recurse(parent, &root);

    if (ogs_yaml_iter_type(&root) == YAML_SEQUENCE_NODE) {
        count = parse_rules_sequence(&root);
    } else if (ogs_yaml_iter_type(&root) == YAML_MAPPING_NODE) {
        ogs_yaml_iter_t probe;
        bool has_rules_key = false;

        ogs_yaml_iter_recurse(parent, &probe);
        while (ogs_yaml_iter_next(&probe)) {
            const char *k = ogs_yaml_iter_key(&probe);
            if (k && !strcmp(k, "rules"))
                has_rules_key = true;
        }

        if (has_rules_key) {
            ogs_yaml_iter_t map;
            ogs_yaml_iter_recurse(parent, &map);
            while (ogs_yaml_iter_next(&map)) {
                const char *k = ogs_yaml_iter_key(&map);
                if (!k)
                    continue;
                if (!strcmp(k, "rules")) {
                    ogs_yaml_iter_t rules;
                    ogs_yaml_iter_recurse(&map, &rules);
                    count = parse_rules_sequence(&rules);
                } else if (!strcmp(k, "tracker_file")) {
                    ogs_warn("mme.provisioning_sms: tracker_file ignored "
                            "(use MongoDB imei_tracker; set db_uri)");
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

    if (count > 0 &&
            (!ogs_mongoc()->initialized ||
             !ogs_mongoc()->collection.imei_tracker)) {
        ogs_warn("provisioning_sms: %d rule(s) loaded but MongoDB not ready "
                "(set top-level db_uri in mme.yaml) — SMS tracker disabled",
                count);
    }

    return count;
}

/*
 * Did this UE rely on the default APN (no APN IE in its Attach Request)?
 * sess->ue_provided_apn is set by esm_handle_pdn_connectivity_request:
 * false when the APN IE was absent/empty. The initial default bearer is the
 * first session. If we cannot tell (no session yet), be conservative and do
 * NOT treat it as "no APN" -- we never provision on uncertainty.
 */
static bool ue_sent_no_apn(mme_ue_t *mme_ue)
{
    mme_sess_t *sess = mme_sess_first(mme_ue);
    if (!sess)
        return false;
    return !sess->ue_provided_apn;
}

/*
 * Hand the qualifying attach to an external provisioner (osmo-msc SMPP) as a
 * single fire-and-forget datagram -- NOT a log line. Rare (default-APN UEs of
 * the configured PLMN), non-blocking, so it does not load the MME. The external
 * service owns change-detection, rate limiting and the actual send.
 *
 * Payload (one line, space-separated key=val; NUL-free):
 *   event=attach imsi=.. msisdn=.. imei=.. imeisv=.. mcc=.. mnc=.. apn_absent=1
 */
static void emit_apnprov_event(mme_provisioning_sms_rule_t *rule,
        mme_ue_t *mme_ue, const char *imei)
{
    ogs_plmn_id_t home;
    char buf[256];
    int n;

    mme_home_plmn_from_imsi_bcd(mme_ue->imsi_bcd, &home);

    n = snprintf(buf, sizeof(buf),
            "event=attach imsi=%s msisdn=%s imei=%s imeisv=%s "
            "mcc=%d mnc=%0*d apn_absent=1\n",
            mme_ue->imsi_bcd,
            mme_ue->msisdn_bcd[0] ? mme_ue->msisdn_bcd : "-",
            imei[0] ? imei : "-",
            mme_ue->imeisv_bcd[0] ? mme_ue->imeisv_bcd : "-",
            ogs_plmn_id_mcc(&home),
            ogs_plmn_id_mnc_len(&home), ogs_plmn_id_mnc(&home));
    if (n <= 0)
        return;
    if (n > (int)sizeof(buf))
        n = (int)sizeof(buf);

    event_send(rule, buf, (size_t)n);
    ogs_debug("[%s] provisioning_sms: APNPROV event -> %s",
            mme_ue->imsi_bcd,
            rule->event_socket[0] ? rule->event_socket : rule->event_addr);
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

    /* Core eligibility: only UEs that sent no APN IE (default APN). */
    if (rule->require_no_apn && !ue_sent_no_apn(mme_ue)) {
        ogs_debug("[%s] provisioning_sms: UE supplied an APN; skip",
                mme_ue->imsi_bcd);
        return;
    }

    extract_imei15(mme_ue->imeisv_bcd, imei, sizeof(imei));

    /*
     * EVENT delivery: emit for the external provisioner and return. No
     * MongoDB, no S1 SMS, no tracker -- the external service dedups/sends.
     * IMEI may be empty (no IMEISV yet); the external side handles that.
     */
    if (rule->delivery == MME_PROV_SMS_DELIVERY_EVENT) {
        emit_apnprov_event(rule, mme_ue, imei);
        return;
    }

    /* S1 delivery (in-MME sender): needs MongoDB tracker + an IMEI. */
    if (!ogs_mongoc()->initialized || !ogs_mongoc()->collection.imei_tracker) {
        ogs_debug("[%s] provisioning_sms: no MongoDB; skip",
                mme_ue->imsi_bcd);
        return;
    }
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
