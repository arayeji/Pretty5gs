/*
 * Copyright (C) 2025 Open5GS contributors
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

#include "ogs-core.h"

/* Per-thread: shard workers each carry their own prefix context — a
 * shared global let concurrent dispatches overwrite each other's
 * fields mid-format (trace lines with another UE's IMSI/TEIDs). */
static OGS_THREAD_LOCAL ogs_trace_ctx_t self;

static struct {
    ogs_thread_mutex_t mutex;
    int initialized;
    int count;
    char imsi[OGS_MAX_TRACE_IMSI_FILTERS][OGS_TRACE_IMSI_LEN];
    bool exact[OGS_MAX_TRACE_IMSI_FILTERS];
} trace_filter;

void ogs_trace_filter_init(void)
{
    /* Runs from ogs_core_initialize() while the process is still
     * single-threaded — the only safe place to create the mutex. */
    if (trace_filter.initialized)
        return;
    ogs_thread_mutex_init(&trace_filter.mutex);
    trace_filter.initialized = 1;
}

static void trace_filter_init_once(void)
{
    /*
     * Lazy fallback for callers that never ran ogs_core_initialize()
     * (unit tools). Do NOT rely on this in multithreaded daemons: two
     * threads racing here would both run pthread_mutex_init. The real
     * init happens single-threaded in ogs_trace_filter_init().
     */
    if (trace_filter.initialized)
        return;
    ogs_trace_filter_init();
}

static void trace_copy_str(char *dst, size_t dstlen, const char *src)
{
    ogs_assert(dst);
    ogs_assert(dstlen > 0);

    if (!src || !src[0]) {
        dst[0] = '\0';
        return;
    }

    ogs_cpystrn(dst, src, dstlen);
}

void ogs_trace_clear(void)
{
    memset(&self, 0, sizeof(self));
}

void ogs_trace_set(const ogs_trace_ctx_t *ctx)
{
    ogs_assert(ctx);
    memcpy(&self, ctx, sizeof(self));
}

void ogs_trace_merge(const ogs_trace_ctx_t *ctx)
{
    /*
     * Only overwrites fields that are non-empty/non-zero in ctx. Cleared fields
     * in ctx do not reset self — use ogs_trace_set() for log prefixes.
     */
    ogs_assert(ctx);

    if (ctx->imsi[0])
        trace_copy_str(self.imsi, sizeof(self.imsi), ctx->imsi);
    if (ctx->apn[0])
        trace_copy_str(self.apn, sizeof(self.apn), ctx->apn);
    if (ctx->proc[0])
        trace_copy_str(self.proc, sizeof(self.proc), ctx->proc);

    if (ctx->enb_id)
        self.enb_id = ctx->enb_id;
    if (ctx->enb_ue_s1ap_id)
        self.enb_ue_s1ap_id = ctx->enb_ue_s1ap_id;
    if (ctx->mme_ue_s1ap_id)
        self.mme_ue_s1ap_id = ctx->mme_ue_s1ap_id;

    if (ctx->ebi)
        self.ebi = ctx->ebi;

    if (ctx->pgw_ip[0])
        trace_copy_str(self.pgw_ip, sizeof(self.pgw_ip), ctx->pgw_ip);
    if (ctx->ue_ip[0])
        trace_copy_str(self.ue_ip, sizeof(self.ue_ip), ctx->ue_ip);

    if (ctx->mme_s11_teid)
        self.mme_s11_teid = ctx->mme_s11_teid;
    if (ctx->sgw_s11_teid)
        self.sgw_s11_teid = ctx->sgw_s11_teid;

    if (ctx->sgw_s5c_teid)
        self.sgw_s5c_teid = ctx->sgw_s5c_teid;
    if (ctx->pgw_s5c_teid)
        self.pgw_s5c_teid = ctx->pgw_s5c_teid;
}

const ogs_trace_ctx_t *ogs_trace_get(void)
{
    return &self;
}

bool ogs_trace_should_emit(int domain)
{
    /* Subscriber being traced: always emit. */
    if (ogs_trace_filter_match(self.imsi))
        return true;

    /* Nobody traced (or not this one): per-IMSI trace lines are
     * opt-in — only a debug-enabled domain still emits them. */
    return ogs_log_domain_prints(domain, OGS_LOG_DEBUG);
}

static void trace_fmt_u32(char *buf, size_t buflen, uint32_t value)
{
    if (value)
        ogs_snprintf(buf, buflen, "%u", value);
    else
        ogs_cpystrn(buf, "-", buflen);
}

static void trace_fmt_teid(char *buf, size_t buflen, uint32_t value)
{
    if (value)
        ogs_snprintf(buf, buflen, "0x%x", value);
    else
        ogs_cpystrn(buf, "-", buflen);
}

void ogs_trace_filter_clear(void)
{
    trace_filter_init_once();
    ogs_thread_mutex_lock(&trace_filter.mutex);
    trace_filter.count = 0;
    memset(trace_filter.imsi, 0, sizeof(trace_filter.imsi));
    ogs_thread_mutex_unlock(&trace_filter.mutex);
    ogs_trace_alias_clear();
}

int ogs_trace_filter_add(const char *imsi_prefix)
{
    return ogs_trace_filter_add_ex(imsi_prefix, false);
}

int ogs_trace_filter_add_ex(const char *imsi, bool exact_match)
{
    int i;

    if (!imsi || !imsi[0])
        return OGS_ERROR;

    trace_filter_init_once();
    ogs_thread_mutex_lock(&trace_filter.mutex);

    for (i = 0; i < trace_filter.count; i++) {
        if (strcmp(trace_filter.imsi[i], imsi) == 0) {
            trace_filter.exact[i] = exact_match;
            ogs_thread_mutex_unlock(&trace_filter.mutex);
            return OGS_OK;
        }
    }

    if (trace_filter.count >= OGS_MAX_TRACE_IMSI_FILTERS) {
        ogs_thread_mutex_unlock(&trace_filter.mutex);
        return OGS_ERROR;
    }

    ogs_cpystrn(trace_filter.imsi[trace_filter.count], imsi,
            OGS_TRACE_IMSI_LEN);
    trace_filter.exact[trace_filter.count] = exact_match;
    trace_filter.count++;

    ogs_thread_mutex_unlock(&trace_filter.mutex);
    return OGS_OK;
}

int ogs_trace_filter_replace_ex(const char *imsi, bool exact_match)
{
    ogs_trace_filter_clear();
    return ogs_trace_filter_add_ex(imsi, exact_match);
}

int ogs_trace_filter_remove(const char *imsi_prefix)
{
    int i, j;

    if (!imsi_prefix || !imsi_prefix[0])
        return OGS_ERROR;

    trace_filter_init_once();
    ogs_thread_mutex_lock(&trace_filter.mutex);

    for (i = 0; i < trace_filter.count; i++) {
        if (strcmp(trace_filter.imsi[i], imsi_prefix) != 0)
            continue;

        for (j = i + 1; j < trace_filter.count; j++)
            ogs_cpystrn(trace_filter.imsi[j - 1], trace_filter.imsi[j],
                    OGS_TRACE_IMSI_LEN);
        trace_filter.count--;
        trace_filter.imsi[trace_filter.count][0] = '\0';
        ogs_thread_mutex_unlock(&trace_filter.mutex);
        return OGS_OK;
    }

    ogs_thread_mutex_unlock(&trace_filter.mutex);
    return OGS_ERROR;
}

bool ogs_trace_filter_match(const char *imsi_bcd)
{
    int i;
    bool matched = false;

    if (!imsi_bcd || !imsi_bcd[0])
        return false;

    /* Lock-free fast path for the common case (no tracing active):
     * with the opt-in trace gating this runs on every candidate trace
     * line. A torn read of count is benign — filter edits are rare
     * admin actions and the slow path re-checks under the mutex. */
    if (trace_filter.count == 0)
        return false;

    trace_filter_init_once();
    ogs_thread_mutex_lock(&trace_filter.mutex);

    for (i = 0; i < trace_filter.count; i++) {
        size_t n = strlen(trace_filter.imsi[i]);

        if (n == 0)
            continue;
        if (trace_filter.exact[i]) {
            if (strcmp(imsi_bcd, trace_filter.imsi[i]) == 0) {
                matched = true;
                break;
            }
        } else if (strncmp(imsi_bcd, trace_filter.imsi[i], n) == 0) {
            matched = true;
            break;
        }
    }

    ogs_thread_mutex_unlock(&trace_filter.mutex);
    return matched;
}

int ogs_trace_filter_count(void)
{
    int count;

    trace_filter_init_once();
    ogs_thread_mutex_lock(&trace_filter.mutex);
    count = trace_filter.count;
    ogs_thread_mutex_unlock(&trace_filter.mutex);
    return count;
}

int ogs_trace_filter_get(int index, char *buf, size_t buflen)
{
    if (!buf || buflen == 0)
        return OGS_ERROR;

    trace_filter_init_once();
    ogs_thread_mutex_lock(&trace_filter.mutex);
    if (index < 0 || index >= trace_filter.count) {
        ogs_thread_mutex_unlock(&trace_filter.mutex);
        return OGS_ERROR;
    }
    ogs_cpystrn(buf, trace_filter.imsi[index], buflen);
    ogs_thread_mutex_unlock(&trace_filter.mutex);
    return OGS_OK;
}

bool ogs_trace_filter_get_exact(int index)
{
    bool exact = false;

    trace_filter_init_once();
    ogs_thread_mutex_lock(&trace_filter.mutex);
    if (index >= 0 && index < trace_filter.count)
        exact = trace_filter.exact[index];
    ogs_thread_mutex_unlock(&trace_filter.mutex);
    return exact;
}

size_t ogs_trace_format_prefix(char *buf, size_t buflen)
{
    char enb_id[16];
    char enb_s1ap[16];
    char mme_s1ap[16];
    char mme_s11[16];
    char sgw_s11[16];
    char sgw_s5[16];
    char pgw_s5[16];
    char ebi[8];

    ogs_assert(buf);
    ogs_assert(buflen > 0);

    trace_fmt_u32(enb_id, sizeof(enb_id), self.enb_id);
    trace_fmt_u32(enb_s1ap, sizeof(enb_s1ap), self.enb_ue_s1ap_id);
    trace_fmt_u32(mme_s1ap, sizeof(mme_s1ap), self.mme_ue_s1ap_id);
    trace_fmt_teid(mme_s11, sizeof(mme_s11), self.mme_s11_teid);
    trace_fmt_teid(sgw_s11, sizeof(sgw_s11), self.sgw_s11_teid);
    trace_fmt_teid(sgw_s5, sizeof(sgw_s5), self.sgw_s5c_teid);
    trace_fmt_teid(pgw_s5, sizeof(pgw_s5), self.pgw_s5c_teid);
    if (self.ebi)
        ogs_snprintf(ebi, sizeof(ebi), "%u", self.ebi);
    else
        ogs_cpystrn(ebi, "-", sizeof(ebi));

    return ogs_snprintf(buf, buflen,
            "[IMSI:%s ENB:%s ENB_S1AP:%s MME_S1AP:%s EBI:%s "
            "MME_S11:%s SGW_S11:%s SGW_S5:%s PGW_S5:%s PGW_IP:%s "
            "IP:%s APN:%s PROC:%s]",
            self.imsi[0] ? self.imsi : "-",
            enb_id,
            enb_s1ap,
            mme_s1ap,
            ebi,
            mme_s11,
            sgw_s11,
            sgw_s5,
            pgw_s5,
            self.pgw_ip[0] ? self.pgw_ip : "-",
            self.ue_ip[0] ? self.ue_ip : "-",
            self.apn[0] ? self.apn : "-",
            self.proc[0] ? self.proc : "-");
}

/* ---- PACKET dumps (filter-gated) ----------------------------------- */

static const char trace_b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Owned copy — bind stores a heap buffer so handlers may free the
 * source pkbuf, and steal can move the buffer to another thread. */
static OGS_THREAD_LOCAL struct {
    uint8_t *data;
    size_t len;
    char proto[16];
} packet_rx;

static void packet_rx_clear(void)
{
    if (packet_rx.data) {
        ogs_free(packet_rx.data);
        packet_rx.data = NULL;
    }
    packet_rx.len = 0;
    packet_rx.proto[0] = '\0';
}

static struct {
    ogs_thread_mutex_t mutex;
    int initialized;
    int count;
    ogs_trace_alias_type_e type[OGS_MAX_TRACE_ALIASES];
    char key[OGS_MAX_TRACE_ALIASES][OGS_TRACE_ALIAS_KEY_LEN];
    char imsi[OGS_MAX_TRACE_ALIASES][OGS_TRACE_IMSI_LEN];
} trace_alias;

static void trace_alias_init_once(void)
{
    if (trace_alias.initialized)
        return;
    /* Same single-threaded startup assumption as trace_filter_init. */
    ogs_thread_mutex_init(&trace_alias.mutex);
    trace_alias.initialized = 1;
}

static size_t trace_b64_encode(char *out, size_t out_size,
        const uint8_t *in, size_t in_size)
{
    size_t i, o = 0;

    if (!out || out_size < 1)
        return 0;
    if (!in && in_size)
        return 0;

    for (i = 0; i + 2 < in_size; i += 3) {
        if (o + 4 >= out_size)
            break;
        out[o++] = trace_b64_table[(in[i] >> 2) & 0x3F];
        out[o++] = trace_b64_table[((in[i] & 0x3) << 4) |
                ((in[i + 1] & 0xF0) >> 4)];
        out[o++] = trace_b64_table[((in[i + 1] & 0xF) << 2) |
                ((in[i + 2] & 0xC0) >> 6)];
        out[o++] = trace_b64_table[in[i + 2] & 0x3F];
    }
    if (i < in_size && o + 4 < out_size) {
        out[o++] = trace_b64_table[(in[i] >> 2) & 0x3F];
        if (i + 1 == in_size) {
            out[o++] = trace_b64_table[((in[i] & 0x3) << 4)];
            out[o++] = '=';
        } else {
            out[o++] = trace_b64_table[((in[i] & 0x3) << 4) |
                    ((in[i + 1] & 0xF0) >> 4)];
            out[o++] = trace_b64_table[((in[i + 1] & 0xF) << 2)];
        }
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

void ogs_trace_packet(const char *imsi, const char *proto, const char *dir,
        const void *data, size_t len)
{
    char b64[((OGS_TRACE_PACKET_MAX + 2) / 3) * 4 + 1];
    size_t dump_len;
    int truncated = 0;
    static volatile uint32_t rate_sec;
    static volatile uint32_t rate_count;
    uint32_t now_sec, n;

    /* Lock-free empty-filter fast path — production default. */
    if (trace_filter.count == 0)
        return;
    if (!imsi || !imsi[0] || !data || !len)
        return;
    if (!ogs_trace_filter_match(imsi))
        return;

    /*
     * Cap PACKET log rate. Unbounded ogs_info(base64) after enabling
     * trace saturated the process log lock and starved the MHD metrics
     * thread — the whole admin/metrics API looked dead.
     */
#define OGS_TRACE_PACKET_PER_SEC  200
    now_sec = (uint32_t)ogs_time_sec(ogs_time_now());
    if (now_sec != rate_sec) {
        rate_sec = now_sec;
        rate_count = 0;
    }
    n = __atomic_add_fetch(&rate_count, 1, __ATOMIC_RELAXED);
    if (n > OGS_TRACE_PACKET_PER_SEC)
        return;

    dump_len = len;
    if (dump_len > OGS_TRACE_PACKET_MAX) {
        dump_len = OGS_TRACE_PACKET_MAX;
        truncated = 1;
    }

    if (!trace_b64_encode(b64, sizeof(b64), (const uint8_t *)data, dump_len))
        return;

    /*
     * Install IMSI for the duration of the log line. HSS (and any NF that
     * clears TLS context after each event) would otherwise drop INFO PACKET
     * lines when the *core* domain is below info — ogs_log only elevates on
     * thread-local filter match. MME often keeps IMSI sticky, so it looked
     * fine there while HSS showed events but never PACKET.
     */
    {
        ogs_trace_ctx_t hold = *ogs_trace_get();
        ogs_trace_ctx_t ctx = hold;

        ogs_cpystrn(ctx.imsi, imsi, sizeof(ctx.imsi));
        ogs_trace_set(&ctx);
        ogs_info("[IMSI:%s] PACKET: proto=%s dir=%s len=%zu%s b64=%s",
                imsi,
                proto && proto[0] ? proto : "-",
                dir && dir[0] ? dir : "-",
                len,
                truncated ? " trunc=1" : "",
                b64);
        ogs_trace_set(&hold);
    }
}

void ogs_trace_packet_ctx(const char *proto, const char *dir,
        const void *data, size_t len)
{
    if (!self.imsi[0])
        return;
    ogs_trace_packet(self.imsi, proto, dir, data, len);
}

void ogs_trace_packet_bind_rx(const char *proto, const void *data, size_t len)
{
    size_t copy_len;

    packet_rx_clear();

    if (trace_filter.count == 0)
        return;
    if (!data || !len)
        return;

    /* Cap copy to dump max — enough for NMS PCAP rebuild. */
    copy_len = len;
    if (copy_len > OGS_TRACE_PACKET_MAX)
        copy_len = OGS_TRACE_PACKET_MAX;

    packet_rx.data = ogs_malloc(copy_len);
    if (!packet_rx.data)
        return;
    memcpy(packet_rx.data, data, copy_len);
    packet_rx.len = copy_len;
    if (proto && proto[0])
        ogs_cpystrn(packet_rx.proto, proto, sizeof(packet_rx.proto));
    else
        ogs_cpystrn(packet_rx.proto, "-", sizeof(packet_rx.proto));
}

void ogs_trace_packet_on_imsi(const char *imsi)
{
    if (!packet_rx.data || !packet_rx.len)
        return;
    if (!imsi || !imsi[0])
        return;

    ogs_trace_packet(imsi, packet_rx.proto, "rx",
            packet_rx.data, packet_rx.len);
    packet_rx_clear();
}

bool ogs_trace_filter_active(void)
{
    return trace_filter.count > 0;
}

bool ogs_trace_packet_steal_rx(uint8_t **data, size_t *len,
        char *proto, size_t proto_size)
{
    ogs_assert(data);
    ogs_assert(len);

    *data = NULL;
    *len = 0;
    if (proto && proto_size)
        proto[0] = '\0';

    if (!packet_rx.data || !packet_rx.len)
        return false;

    *data = packet_rx.data;
    *len = packet_rx.len;
    if (proto && proto_size)
        ogs_cpystrn(proto, packet_rx.proto, proto_size);

    packet_rx.data = NULL;
    packet_rx.len = 0;
    packet_rx.proto[0] = '\0';
    return true;
}

void ogs_trace_packet_free_buf(uint8_t *data)
{
    if (data)
        ogs_free(data);
}

static bool trace_alias_imei_match(const char *key, const char *imeisv)
{
    size_t kn, in;

    if (!key || !key[0] || !imeisv || !imeisv[0])
        return false;

    kn = strlen(key);
    in = strlen(imeisv);
    /* IMEI is 14–15 digits; IMEISV adds a spare. Match key as prefix. */
    if (kn < 14 || kn > 16)
        return false;
    if (in < kn)
        return false;
    return strncmp(imeisv, key, kn) == 0;
}

int ogs_trace_alias_set(ogs_trace_alias_type_e type, const char *key,
        const char *imsi_bcd)
{
    int i;

    if ((type != OGS_TRACE_ALIAS_MSISDN && type != OGS_TRACE_ALIAS_IMEI) ||
            !key || !key[0] || !imsi_bcd || !imsi_bcd[0])
        return OGS_ERROR;

    trace_alias_init_once();
    ogs_thread_mutex_lock(&trace_alias.mutex);

    for (i = 0; i < trace_alias.count; i++) {
        if (trace_alias.type[i] == type &&
                strcmp(trace_alias.key[i], key) == 0) {
            ogs_cpystrn(trace_alias.imsi[i], imsi_bcd, OGS_TRACE_IMSI_LEN);
            ogs_thread_mutex_unlock(&trace_alias.mutex);
            return ogs_trace_filter_add_ex(imsi_bcd, true);
        }
    }

    if (trace_alias.count >= OGS_MAX_TRACE_ALIASES) {
        ogs_thread_mutex_unlock(&trace_alias.mutex);
        return OGS_ERROR;
    }

    trace_alias.type[trace_alias.count] = type;
    ogs_cpystrn(trace_alias.key[trace_alias.count], key,
            OGS_TRACE_ALIAS_KEY_LEN);
    ogs_cpystrn(trace_alias.imsi[trace_alias.count], imsi_bcd,
            OGS_TRACE_IMSI_LEN);
    trace_alias.count++;
    ogs_thread_mutex_unlock(&trace_alias.mutex);

    return ogs_trace_filter_add_ex(imsi_bcd, true);
}

void ogs_trace_alias_refresh_imsi(const char *msisdn_bcd,
        const char *imeisv_bcd, const char *imsi_bcd)
{
    int i;
    char old_list[OGS_MAX_TRACE_ALIASES][OGS_TRACE_IMSI_LEN];
    char key_list[OGS_MAX_TRACE_ALIASES][OGS_TRACE_ALIAS_KEY_LEN];
    int type_list[OGS_MAX_TRACE_ALIASES];
    int n_old = 0;
    bool hit = false;

    if (!imsi_bcd || !imsi_bcd[0])
        return;
    if (!trace_alias.initialized || trace_alias.count == 0)
        return;

    memset(old_list, 0, sizeof(old_list));

    ogs_thread_mutex_lock(&trace_alias.mutex);

    for (i = 0; i < trace_alias.count; i++) {
        bool match = false;

        if (trace_alias.type[i] == OGS_TRACE_ALIAS_MSISDN &&
                msisdn_bcd && msisdn_bcd[0] &&
                strcmp(trace_alias.key[i], msisdn_bcd) == 0)
            match = true;
        else if (trace_alias.type[i] == OGS_TRACE_ALIAS_IMEI &&
                trace_alias_imei_match(trace_alias.key[i], imeisv_bcd))
            match = true;

        if (!match)
            continue;

        hit = true;
        if (strcmp(trace_alias.imsi[i], imsi_bcd) != 0) {
            ogs_cpystrn(old_list[n_old], trace_alias.imsi[i],
                    OGS_TRACE_IMSI_LEN);
            ogs_cpystrn(key_list[n_old], trace_alias.key[i],
                    OGS_TRACE_ALIAS_KEY_LEN);
            type_list[n_old] = (int)trace_alias.type[i];
            ogs_cpystrn(trace_alias.imsi[i], imsi_bcd, OGS_TRACE_IMSI_LEN);
            n_old++;
        }
    }

    ogs_thread_mutex_unlock(&trace_alias.mutex);

    if (!hit)
        return;

    for (i = 0; i < n_old; i++) {
        (void)ogs_trace_filter_remove(old_list[i]);
        ogs_info("trace alias refresh type=%d key=%s imsi=%s (was %s)",
                type_list[i], key_list[i], imsi_bcd, old_list[i]);
    }

    (void)ogs_trace_filter_add_ex(imsi_bcd, true);
}

void ogs_trace_alias_clear(void)
{
    if (!trace_alias.initialized)
        return;
    ogs_thread_mutex_lock(&trace_alias.mutex);
    trace_alias.count = 0;
    memset(trace_alias.key, 0, sizeof(trace_alias.key));
    memset(trace_alias.imsi, 0, sizeof(trace_alias.imsi));
    ogs_thread_mutex_unlock(&trace_alias.mutex);
}
