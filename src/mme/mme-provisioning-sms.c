/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "mme-provisioning-sms.h"
#include "nas-path.h"

#include <ctype.h>
#include <time.h>

static ogs_list_t g_rules;
static uint8_t g_rp_msg_ref;

void mme_provisioning_sms_init(void)
{
    ogs_list_init(&g_rules);
    g_rp_msg_ref = 0;
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
    if (!nd) {
        buf[nd++] = '0';
    }
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

    /* Semi-octet BCD YY MM DD hh mm ss + timezone 0 (UTC) */
    scts[0] = (uint8_t)(((tm->tm_year % 10) << 4) | ((tm->tm_year / 10) % 10));
    scts[1] = (uint8_t)((((tm->tm_mon + 1) % 10) << 4) |
            (((tm->tm_mon + 1) / 10) % 10));
    scts[2] = (uint8_t)(((tm->tm_mday % 10) << 4) | ((tm->tm_mday / 10) % 10));
    scts[3] = (uint8_t)(((tm->tm_hour % 10) << 4) | ((tm->tm_hour / 10) % 10));
    scts[4] = (uint8_t)(((tm->tm_min % 10) << 4) | ((tm->tm_min / 10) % 10));
    scts[5] = (uint8_t)(((tm->tm_sec % 10) << 4) | ((tm->tm_sec / 10) % 10));
    scts[6] = 0x00;
}

/*
 * Build CP-DATA(RP-DATA(SMS-DELIVER)) into out[].
 * Returns length or 0 on failure.
 */
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

    /* SMS-DELIVER */
    tpdu[tpdu_len++] = first;
    tpdu[tpdu_len++] = (uint8_t)ndigits;          /* OA length (digits) */
    tpdu[tpdu_len++] = 0x91;                      /* international/ISDN; use 0x81 unknown if short */
    if (ndigits <= 3)
        tpdu[tpdu_len - 1] = 0x81;                /* unknown / national-ish */
    for (i = 0; i < oa_tbcd_len; i++)
        tpdu[tpdu_len++] = oa_tbcd[i];
    tpdu[tpdu_len++] = 0x00;                      /* PID */
    tpdu[tpdu_len++] = rule->dcs ? rule->dcs : 0x04;

    {
        uint8_t scts[7];
        fill_scts(scts);
        memcpy(tpdu + tpdu_len, scts, 7);
        tpdu_len += 7;
    }

    ud_off = tpdu_len;
    tpdu[tpdu_len++] = 0; /* UDL placeholder */

    if (rule->dest_port || rule->orig_port) {
        /* UDHL + app-port 16-bit (IEI 0x05) */
        tpdu[tpdu_len++] = 0x06; /* UDHL */
        tpdu[tpdu_len++] = 0x05; /* IEI */
        tpdu[tpdu_len++] = 0x04; /* IEDL */
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

    /* RP-DATA (Network → MS): type=0x01 */
    rp[rp_len++] = 0x01;
    rp[rp_len++] = ++g_rp_msg_ref ? g_rp_msg_ref : (g_rp_msg_ref = 1);
    /* RP-OA = SC address (use same OA digits) */
    {
        size_t sc_len = 0;
        uint8_t sc[12];
        encode_tbcd_digits(rule->oa, sc, &sc_len, sizeof(sc));
        rp[rp_len++] = (uint8_t)(1 + sc_len); /* length of toa+tbcd */
        rp[rp_len++] = 0x91;
        for (i = 0; i < sc_len; i++)
            rp[rp_len++] = sc[i];
    }
    rp[rp_len++] = 0x00; /* empty RP-DA */
    rp[rp_len++] = (uint8_t)tpdu_len;
    if (rp_len + tpdu_len > sizeof(rp))
        return 0;
    memcpy(rp + rp_len, tpdu, tpdu_len);
    rp_len += tpdu_len;

    /* CP-DATA: PD=SMS(9), network-allocated TI (flag=1,tio=0) → 0x89,
     * message type CP-DATA(0x01), then LV RP-DATA */
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

int mme_provisioning_sms_parse(ogs_yaml_iter_t *parent)
{
    ogs_yaml_iter_t array, entry;
    int count = 0;

    ogs_assert(parent);
    mme_provisioning_sms_remove_all();

    ogs_yaml_iter_recurse(parent, &array);
    while (1) {
        mme_provisioning_sms_rule_t *rule;
        const char *hex = NULL;

        if (ogs_yaml_iter_type(&array) == YAML_SCALAR_NODE)
            break;
        if (ogs_yaml_iter_type(&array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&array))
                break;
            ogs_yaml_iter_recurse(&array, &entry);
        } else if (ogs_yaml_iter_type(&array) == YAML_MAPPING_NODE) {
            ogs_yaml_iter_recurse(&array, &entry);
        } else {
            break;
        }

        rule = ogs_calloc(1, sizeof(*rule));
        ogs_assert(rule);
        rule->dcs = 0x04;
        ogs_cpystrn(rule->oa, "0", sizeof(rule->oa));

        while (ogs_yaml_iter_next(&entry)) {
            const char *k = ogs_yaml_iter_key(&entry);
            if (!k)
                continue;

            if (!strcmp(k, "imsi_plmn_id") || !strcmp(k, "plmn_id")) {
                ogs_yaml_iter_t plmn_iter;
                const char *mcc = NULL, *mnc = NULL;

                ogs_yaml_iter_recurse(&entry, &plmn_iter);
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
                hex = ogs_yaml_iter_value(&entry);
            } else if (!strcmp(k, "oa") || !strcmp(k, "originator")) {
                const char *v = ogs_yaml_iter_value(&entry);
                if (v)
                    ogs_cpystrn(rule->oa, v, sizeof(rule->oa));
            } else if (!strcmp(k, "dcs")) {
                const char *v = ogs_yaml_iter_value(&entry);
                if (v) {
                    if (v[0] == '0' && (v[1] == 'x' || v[1] == 'X'))
                        rule->dcs = (uint8_t)strtoul(v, NULL, 16);
                    else
                        rule->dcs = (uint8_t)atoi(v);
                }
            } else if (!strcmp(k, "dest_port")) {
                const char *v = ogs_yaml_iter_value(&entry);
                if (v)
                    rule->dest_port = (uint16_t)atoi(v);
            } else if (!strcmp(k, "orig_port")) {
                const char *v = ogs_yaml_iter_value(&entry);
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
        } else if (count >= MME_PROV_SMS_MAX_RULES) {
            ogs_warn("mme.provisioning_sms: max %d rules",
                    MME_PROV_SMS_MAX_RULES);
            ogs_free(rule);
            break;
        } else {
            ogs_list_add(&g_rules, rule);
            count++;
            ogs_info("provisioning_sms: IMSI-PLMN mcc=%d mnc=%0*d "
                    "userdata=%zu octets dcs=0x%02x ports=%u/%u",
                    ogs_plmn_id_mcc(&rule->imsi_plmn_id),
                    ogs_plmn_id_mnc_len(&rule->imsi_plmn_id),
                    ogs_plmn_id_mnc(&rule->imsi_plmn_id),
                    rule->userdata_len, rule->dcs,
                    rule->dest_port, rule->orig_port);
        }

        if (ogs_yaml_iter_type(&array) != YAML_SEQUENCE_NODE)
            break;
    }

    return count;
}

void mme_provisioning_sms_on_attach_complete(mme_ue_t *mme_ue)
{
    mme_provisioning_sms_rule_t *rule;
    uint8_t nas[OGS_NAS_MAX_MESSAGE_CONTAINER_LEN];
    size_t nas_len;
    int r;

    if (!mme_ue || !MME_UE_HAVE_IMSI(mme_ue))
        return;
    if (!mme_ue->attach_pdn_apn_ie_missing)
        return;
    if (ogs_list_empty(&g_rules)) {
        mme_ue->attach_pdn_apn_ie_missing = false;
        return;
    }

    rule = find_rule_for_imsi(mme_ue->imsi_bcd);
    if (!rule) {
        mme_ue->attach_pdn_apn_ie_missing = false;
        return;
    }

    nas_len = build_mt_binary_sms(rule, nas, sizeof(nas));
    if (!nas_len) {
        ogs_error("[%s] provisioning_sms: failed to build MT SMS",
                mme_ue->imsi_bcd);
        mme_ue->attach_pdn_apn_ie_missing = false;
        return;
    }

    r = nas_eps_send_downlink_nas_transport(mme_ue, nas, (uint8_t)nas_len);
    if (r != OGS_OK) {
        ogs_warn("[%s] provisioning_sms: Downlink NAS transport failed "
                "(S1 gone?)", mme_ue->imsi_bcd);
    } else {
        ogs_info("[%s] provisioning_sms: sent binary MT SMS "
                "(%zu userdata octets) after Attach Complete "
                "(APN IE was missing on attach PDN)",
                mme_ue->imsi_bcd, rule->userdata_len);
    }

    /* One shot per attach procedure */
    mme_ue->attach_pdn_apn_ie_missing = false;
}
