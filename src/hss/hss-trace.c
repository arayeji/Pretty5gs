/*
 * Copyright (C) 2026 Open5GS contributors
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

#include "hss-trace.h"
#include "ogs-diameter-common.h"
#include "ogs-metrics.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static struct fd_hook_hdl *hss_diam_trace_hook_hdl = NULL;
static struct fd_hook_hdl *hss_diam_rewrite_hook_hdl = NULL;

static void hss_diam_copy_os_avp(
        struct msg *msg, struct dict_object *obj, char *buf, size_t buflen);
static bool hss_diam_user_name_to_imsi_bcd(
        struct msg *msg, char *imsi_bcd, size_t imsi_bcd_len);

static void hss_diam_copy_os_avp(
        struct msg *msg, struct dict_object *obj, char *buf, size_t buflen)
{
    int ret;
    struct avp *avp = NULL;
    struct avp_hdr *hdr = NULL;

    if (!buf || buflen == 0)
        return;
    buf[0] = '\0';
    if (!msg || !obj)
        return;

    ret = fd_msg_search_avp(msg, obj, &avp);
    if (ret != 0 || !avp)
        return;
    ret = fd_msg_avp_hdr(avp, &hdr);
    if (ret != 0 || !hdr || !hdr->avp_value || !hdr->avp_value->os.data ||
            hdr->avp_value->os.len == 0)
        return;

    ogs_cpystrn(buf, (char *)hdr->avp_value->os.data,
            ogs_min(hdr->avp_value->os.len + 1, buflen));
}

/*
 * Accept alias Destination-Realms (e.g. MME auto epc…mcc999…) when the
 * message was already delivered to this HSS peer and is not addressed to a
 * different Destination-Host. Rewrites Dest-Realm to local Realm so
 * freeDiameter does not answer UNABLE_TO_DELIVER / "another realm/host"
 * before S6a runs. MME/DRA unchanged.
 */
static void hss_diam_rewrite_dest_realm_alias(struct msg *msg)
{
    int ret;
    struct msg_hdr *msg_hdr = NULL;
    struct avp *avp = NULL;
    union avp_value val;
    char dest_realm[OGS_MAX_FQDN_LEN + 1];
    char dest_host[OGS_MAX_FQDN_LEN + 1];
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN + 1];
    const char *local_realm;
    const char *local_host;

    if (!msg || !fd_g_config || !fd_g_config->cnf_diamrlm)
        return;

    ret = fd_msg_hdr(msg, &msg_hdr);
    if (ret != 0 || !msg_hdr)
        return;
    if (msg_hdr->msg_flags & CMD_ANSWER)
        return;

    local_realm = (const char *)fd_g_config->cnf_diamrlm;
    local_host = fd_g_config->cnf_diamid ?
        (const char *)fd_g_config->cnf_diamid : NULL;

    hss_diam_copy_os_avp(msg, ogs_diam_destination_realm,
            dest_realm, sizeof(dest_realm));
    if (!dest_realm[0] || !strcmp(dest_realm, local_realm))
        return;

    hss_diam_copy_os_avp(msg, ogs_diam_destination_host,
            dest_host, sizeof(dest_host));
    if (dest_host[0] && local_host && strcmp(dest_host, local_host) != 0)
        return;

    ret = fd_msg_search_avp(msg, ogs_diam_destination_realm, &avp);
    if (ret != 0 || !avp)
        return;

    memset(&val, 0, sizeof(val));
    val.os.data = (uint8_t *)local_realm;
    val.os.len = strlen(local_realm);
    ret = fd_msg_avp_setvalue(avp, &val);
    if (ret != 0) {
        ogs_error("HSS Dest-Realm alias rewrite failed (%d) from=%s",
                ret, dest_realm);
        return;
    }

    imsi_bcd[0] = '\0';
    (void)hss_diam_user_name_to_imsi_bcd(msg, imsi_bcd, sizeof(imsi_bcd));
    if (imsi_bcd[0] && ogs_trace_filter_match(imsi_bcd)) {
        hss_imsi_warn(imsi_bcd, "diameter",
                "rewrote Dest-Realm %s -> %s (local alias accept)",
                dest_realm, local_realm);
    } else {
        ogs_info("HSS Dest-Realm alias: %s -> %s", dest_realm, local_realm);
    }
}

static bool hss_diam_user_name_to_imsi_bcd(
        struct msg *msg, char *imsi_bcd, size_t imsi_bcd_len)
{
    char user_name[OGS_MAX_IMSI_BCD_LEN + 8];
    size_t i, j = 0;

    if (!imsi_bcd || imsi_bcd_len == 0)
        return false;
    imsi_bcd[0] = '\0';

    hss_diam_copy_os_avp(msg, ogs_diam_user_name, user_name, sizeof(user_name));
    if (!user_name[0])
        return false;

    for (i = 0; user_name[i]; i++) {
        if (user_name[i] >= '0' && user_name[i] <= '9') {
            if (j + 1 >= imsi_bcd_len)
                return false;
            imsi_bcd[j++] = user_name[i];
        }
    }
    imsi_bcd[j] = '\0';
    return ogs_imsi_bcd_is_valid(imsi_bcd);
}

static void hss_diam_rewrite_hook_cb(
        enum fd_hook_type type, struct msg *msg, struct peer_hdr *peer,
        void *other, struct fd_hook_permsgdata *pmd, void *regdata)
{
    (void)type;
    (void)peer;
    (void)other;
    (void)pmd;
    (void)regdata;

    if (msg)
        hss_diam_rewrite_dest_realm_alias(msg);
}

static const char *hss_diam_hook_name(enum fd_hook_type type)
{
    switch (type) {
    case HOOK_MESSAGE_ROUTING_ERROR:
        return "ROUTING_ERROR";
    case HOOK_MESSAGE_DROPPED:
        return "DROPPED";
    case HOOK_MESSAGE_ROUTING_FORWARD:
        return "ROUTING_FORWARD";
    default:
        return "HOOK";
    }
}

static void hss_diam_trace_hook_cb(
        enum fd_hook_type type, struct msg *msg, struct peer_hdr *peer,
        void *other, struct fd_hook_permsgdata *pmd, void *regdata)
{
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN + 1];
    char dest_realm[OGS_MAX_FQDN_LEN + 1];
    char dest_host[OGS_MAX_FQDN_LEN + 1];
    const char *err = (other && (type == HOOK_MESSAGE_ROUTING_ERROR ||
                type == HOOK_MESSAGE_DROPPED)) ? (const char *)other : NULL;

    (void)peer;
    (void)pmd;
    (void)regdata;

    if (!msg || ogs_trace_filter_count() == 0)
        return;
    if (!hss_diam_user_name_to_imsi_bcd(msg, imsi_bcd, sizeof(imsi_bcd)))
        return;
    if (!ogs_trace_filter_match(imsi_bcd))
        return;

    hss_diam_copy_os_avp(msg, ogs_diam_destination_realm,
            dest_realm, sizeof(dest_realm));
    hss_diam_copy_os_avp(msg, ogs_diam_destination_host,
            dest_host, sizeof(dest_host));

    hss_imsi_warn(imsi_bcd, "diameter",
            "%s before S6a (local Identity=%s Realm=%s) "
            "Dest-Realm=%s Dest-Host=%s detail=%s",
            hss_diam_hook_name(type),
            fd_g_config && fd_g_config->cnf_diamid ?
                (char *)fd_g_config->cnf_diamid : "-",
            fd_g_config && fd_g_config->cnf_diamrlm ?
                (char *)fd_g_config->cnf_diamrlm : "-",
            dest_realm[0] ? dest_realm : "-",
            dest_host[0] ? dest_host : "-",
            err && err[0] ? err : "-");
}

int hss_diam_trace_hooks_init(void)
{
    uint32_t trace_mask = HOOK_MASK(
            HOOK_MESSAGE_ROUTING_ERROR,
            HOOK_MESSAGE_DROPPED,
            HOOK_MESSAGE_ROUTING_FORWARD);
    uint32_t rewrite_mask = HOOK_MASK(HOOK_MESSAGE_RECEIVED);
    int ret;

    if (!hss_diam_rewrite_hook_hdl) {
        ret = fd_hook_register(rewrite_mask, hss_diam_rewrite_hook_cb,
                NULL, NULL, &hss_diam_rewrite_hook_hdl);
        if (ret != 0)
            return ret;
    }

    if (!hss_diam_trace_hook_hdl) {
        ret = fd_hook_register(trace_mask, hss_diam_trace_hook_cb,
                NULL, NULL, &hss_diam_trace_hook_hdl);
        if (ret != 0)
            return ret;
    }

    return 0;
}

void hss_diam_trace_hooks_final(void)
{
    if (hss_diam_trace_hook_hdl) {
        (void)fd_hook_unregister(hss_diam_trace_hook_hdl);
        hss_diam_trace_hook_hdl = NULL;
    }
    if (hss_diam_rewrite_hook_hdl) {
        (void)fd_hook_unregister(hss_diam_rewrite_hook_hdl);
        hss_diam_rewrite_hook_hdl = NULL;
    }
}

void hss_trace_set(const char *imsi_bcd, const char *proc)
{
    ogs_trace_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));

    if (imsi_bcd && imsi_bcd[0])
        ogs_cpystrn(ctx.imsi, imsi_bcd, sizeof(ctx.imsi));
    if (proc && proc[0])
        ogs_cpystrn(ctx.proc, proc, sizeof(ctx.proc));

    ogs_trace_set(&ctx);
    if (ctx.imsi[0])
        ogs_trace_packet_on_imsi(ctx.imsi);
}

void hss_trace_done(void)
{
    ogs_trace_clear();
}

void hss_imsi_log(
        const char *imsi_bcd, const char *proc, int level,
        const char *fmt, ...)
{
    va_list ap;
    char prefix[OGS_TRACE_PREFIX_BUFSIZE];
    char msg[OGS_HUGE_LEN];
    const char *id = (imsi_bcd && imsi_bcd[0]) ? imsi_bcd : "-";
    bool filter_hit;
    ogs_log_level_e domain_level;

    ogs_assert(fmt);

    /*
     * Opt-in like mme_ue_log / sgwc_ue_log. Use the configured domain level
     * for the "domain at debug" path — do NOT call ogs_log_domain_prints()
     * here, because that helper itself elevates when TLS IMSI matches the
     * filter and would let non-matched IMSIs through while a traced IMSI
     * is still sticky on the freeDiameter worker.
     */
    filter_hit = ogs_trace_filter_match(id);
    domain_level = ogs_log_get_domain_level(OGS_LOG_DOMAIN);

    if (!filter_hit && domain_level < OGS_LOG_DEBUG)
        return;

    /*
     * Filter-matched lines must not share the thread-local ogs_log_guard
     * with unrelated FD-thread INFO/WARN chatter.
     */
    if (!filter_hit && level != OGS_LOG_DEBUG && !ogs_log_guard())
        return;

    /*
     * When elevating past the domain level, cap with the process-wide
     * trace budget (peek; ogs_log_vprintf consumes).
     */
    if (domain_level < (ogs_log_level_e)level &&
            !ogs_log_trace_budget(false))
        return;

    hss_trace_set(id, proc);
    ogs_trace_format_prefix(prefix, sizeof(prefix));

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    ogs_log_printf(level, OGS_LOG_DOMAIN,
            0, __FILE__, __LINE__, OGS_FUNC, 0, "%s %s", prefix, msg);

    /*
     * Do not leave IMSI sticky on freeDiameter workers. Sticky filter match
     * makes ogs_log_domain_prints() elevate every ogs_debug/ogs_info on the
     * thread (unlike MME/SGWC, which overwrite context on the next UE event).
     * HSS_TRACE_SCOPE() is a safety net if a path returns early.
     */
    ogs_trace_clear();
}

void hss_trace_event(
        const char *imsi_bcd, const char *proc,
        const char *fmt, ...)
{
    va_list ap;
    char msg[OGS_HUGE_LEN];
    const char *id = (imsi_bcd && imsi_bcd[0]) ? imsi_bcd : "-";

    ogs_assert(fmt);

    va_start(ap, fmt);
    ogs_vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    hss_imsi_info(id, proc, "%s", msg);
}

void hss_trace_diameter(
        const char *imsi_bcd, const char *dir, struct msg *msg)
{
    static const char b64tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint8_t *buf = NULL;
    size_t len = 0, dump_len, i, o;
    int ret, truncated = 0;
    char b64[((OGS_TRACE_PACKET_MAX + 2) / 3) * 4 + 1];

    if (!imsi_bcd || !imsi_bcd[0] || !msg)
        return;
    if (ogs_trace_filter_count() == 0)
        return;
    if (!ogs_trace_filter_match(imsi_bcd))
        return;

    ret = fd_msg_update_length(msg);
    if (ret != 0) {
        hss_imsi_warn(imsi_bcd, "diameter",
                "PACKET diameter %s: fd_msg_update_length failed (%d)",
                dir && dir[0] ? dir : "-", ret);
        return;
    }

    ret = fd_msg_bufferize(msg, &buf, &len);
    if (ret != 0 || !buf || !len) {
        hss_imsi_warn(imsi_bcd, "diameter",
                "PACKET diameter %s: fd_msg_bufferize failed "
                "(ret=%d len=%zu) — no PACKET line",
                dir && dir[0] ? dir : "-", ret, len);
        if (buf)
            free(buf);
        return;
    }

    dump_len = len;
    if (dump_len > OGS_TRACE_PACKET_MAX) {
        dump_len = OGS_TRACE_PACKET_MAX;
        truncated = 1;
    }

    o = 0;
    for (i = 0; i + 2 < dump_len && o + 4 < sizeof(b64); i += 3) {
        b64[o++] = b64tab[(buf[i] >> 2) & 0x3F];
        b64[o++] = b64tab[((buf[i] & 0x3) << 4) | ((buf[i + 1] & 0xF0) >> 4)];
        b64[o++] = b64tab[((buf[i + 1] & 0xF) << 2) | ((buf[i + 2] & 0xC0) >> 6)];
        b64[o++] = b64tab[buf[i + 2] & 0x3F];
    }
    if (i < dump_len && o + 4 < sizeof(b64)) {
        b64[o++] = b64tab[(buf[i] >> 2) & 0x3F];
        if (i + 1 == dump_len) {
            b64[o++] = b64tab[((buf[i] & 0x3) << 4)];
            b64[o++] = '=';
        } else {
            b64[o++] = b64tab[((buf[i] & 0x3) << 4) |
                    ((buf[i + 1] & 0xF0) >> 4)];
            b64[o++] = b64tab[((buf[i + 1] & 0xF) << 2)];
        }
        b64[o++] = '=';
    }
    b64[o] = '\0';

    /* Emit under [hss] like S6a events so NMS scrapes both RX and TX. */
    hss_imsi_info(imsi_bcd, "diameter",
            "PACKET: proto=diameter dir=%s len=%zu%s b64=%s",
            dir && dir[0] ? dir : "-",
            len,
            truncated ? " trunc=1" : "",
            b64);
    free(buf);
}

int hss_admin_trace_imsi_ep(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len)
{
    ogs_metrics_query_t resolved = { 0 };
    char imsi_buf[OGS_TRACE_IMSI_LEN];
    const ogs_metrics_query_t *use_q = q;

    if (q && q->msisdn && q->msisdn[0] &&
            !q->force && !(q->imsi && strcmp(q->imsi, "list") == 0)) {
        ogs_msisdn_data_t msisdn_data;

        memset(&msisdn_data, 0, sizeof(msisdn_data));
        if (hss_db_msisdn_data((char *)q->msisdn, &msisdn_data) != OGS_OK ||
                !msisdn_data.imsi.bcd[0]) {
            *body_len = (size_t)snprintf(body, body_cap,
                    "{\"ok\":false,\"detail\":\"msisdn %s not found in HSS DB\","
                    "\"trace_imsi\":[]}\n", q->msisdn);
            return 400;
        }

        ogs_cpystrn(imsi_buf, msisdn_data.imsi.bcd, sizeof(imsi_buf));
        if (!q->remove)
            (void)ogs_trace_alias_set(OGS_TRACE_ALIAS_MSISDN, q->msisdn, imsi_buf);

        resolved = *q;
        resolved.imsi = imsi_buf;
        resolved.msisdn = NULL;
        if (!resolved.match)
            resolved.match = "exact";
        use_q = &resolved;
    }

    return ogs_metrics_admin_trace_imsi(use_q, body, body_cap, body_len);
}

