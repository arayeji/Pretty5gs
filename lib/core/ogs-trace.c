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
    if (ctx->sgw_ip[0])
        trace_copy_str(self.sgw_ip, sizeof(self.sgw_ip), ctx->sgw_ip);

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
            "MME_S11:%s SGW_S11:%s SGW_IP:%s SGW_S5:%s PGW_S5:%s "
            "PGW_IP:%s IP:%s APN:%s PROC:%s]",
            self.imsi[0] ? self.imsi : "-",
            enb_id,
            enb_s1ap,
            mme_s1ap,
            ebi,
            mme_s11,
            sgw_s11,
            self.sgw_ip[0] ? self.sgw_ip : "-",
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
    bool link_present;
    ogs_trace_link_t link;
} packet_rx;

static void packet_rx_clear(void)
{
    if (packet_rx.data) {
        ogs_free(packet_rx.data);
        packet_rx.data = NULL;
    }
    packet_rx.len = 0;
    packet_rx.proto[0] = '\0';
    packet_rx.link_present = false;
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

static void trace_endpoint_fmt(char *out, size_t out_size,
        const ogs_sockaddr_t *addr)
{
    char ip[OGS_ADDRSTRLEN];

    out[0] = '\0';
    if (!addr)
        return;
    if (addr->ogs_sa_family != AF_INET && addr->ogs_sa_family != AF_INET6)
        return;
    if (!OGS_ADDR((ogs_sockaddr_t *)addr, ip))
        return;

    if (addr->ogs_sa_family == AF_INET6)
        ogs_snprintf(out, out_size, "[%s]:%u", ip, OGS_PORT(addr));
    else
        ogs_snprintf(out, out_size, "%s:%u", ip, OGS_PORT(addr));
}

void ogs_trace_link_set(ogs_trace_link_t *link, ogs_trace_l4_e l4,
        const ogs_sockaddr_t *local, const ogs_sockaddr_t *remote)
{
    ogs_assert(link);

    memset(link, 0, sizeof(*link));
    if (trace_filter.count == 0)
        return;

    link->l4 = l4;
    trace_endpoint_fmt(link->local, sizeof(link->local), local);
    trace_endpoint_fmt(link->remote, sizeof(link->remote), remote);
    link->ts = ogs_time_now();
}

void ogs_trace_link_set_sock(ogs_trace_link_t *link, ogs_trace_l4_e l4,
        const ogs_sock_t *sock, const ogs_sockaddr_t *remote)
{
    ogs_trace_link_set(link, l4, sock ? &sock->local_addr : NULL, remote);
}

void ogs_trace_link_set_fd(ogs_trace_link_t *link, ogs_trace_l4_e l4, int fd)
{
    ogs_sockaddr_t local, remote;
    socklen_t len;
    bool have_local = false, have_remote = false;

    ogs_assert(link);

    memset(link, 0, sizeof(*link));
    if (trace_filter.count == 0 || fd < 0)
        return;

    memset(&local, 0, sizeof(local));
    memset(&remote, 0, sizeof(remote));
    len = sizeof(local.ss);
    have_local = getsockname(fd, &local.sa, &len) == 0;
    len = sizeof(remote.ss);
    have_remote = getpeername(fd, &remote.sa, &len) == 0;

    ogs_trace_link_set(link, l4, have_local ? &local : NULL,
            have_remote ? &remote : NULL);
}

static const char *trace_l4_name(uint8_t l4)
{
    switch (l4) {
    case OGS_TRACE_L4_UDP:
        return "udp";
    case OGS_TRACE_L4_SCTP:
        return "sctp";
    case OGS_TRACE_L4_TCP:
        return "tcp";
    default:
        return NULL;
    }
}

/* " ts=.. l4=.. src=.. dst=.. [sid=..] [ppid=..]" */
static void trace_link_fmt(char *out, size_t out_size, const char *dir,
        const ogs_trace_link_t *link, ogs_time_t ts)
{
    const char *l4 = link ? trace_l4_name(link->l4) : NULL;
    const char *src = NULL, *dst = NULL;
    size_t o;

    o = ogs_snprintf(out, out_size, " ts=%lld.%06lld",
            (long long)(ts / OGS_USEC_PER_SEC),
            (long long)(ts % OGS_USEC_PER_SEC));
    if (!l4 || o >= out_size)
        return;

    if (dir && !strcmp(dir, "tx")) {
        src = link->local;
        dst = link->remote;
    } else {
        src = link->remote;
        dst = link->local;
    }
    o += ogs_snprintf(out + o, out_size - o, " l4=%s src=%s dst=%s", l4,
            src[0] ? src : "-", dst[0] ? dst : "-");
    if (link->sctp_stream_present && o < out_size)
        o += ogs_snprintf(out + o, out_size - o, " sid=%u",
                link->sctp_stream);
    if (link->sctp_ppid && o < out_size)
        ogs_snprintf(out + o, out_size - o, " ppid=%u", link->sctp_ppid);
}

void ogs_trace_packet_link(const char *imsi, const char *proto,
        const char *dir, const void *data, size_t len,
        const ogs_trace_link_t *link)
{
    char b64[((OGS_TRACE_PACKET_SEG + 2) / 3) * 4 + 1];
    char meta[2 * OGS_TRACE_ENDPOINT_LEN + 96];
    size_t dump_len, off;
    int truncated = 0, seg, nseg;
    ogs_time_t ts;
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
     * Cap PACKET log rate (per packet, not per seg line). Unbounded
     * ogs_info(base64) after enabling trace saturated the process log
     * lock and starved the MHD metrics thread — the whole admin/metrics
     * API looked dead.
     */
#define OGS_TRACE_PACKET_PER_SEC  200
    ts = ogs_time_now();
    now_sec = (uint32_t)ogs_time_sec(ts);
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
    if (link && link->ts)
        ts = link->ts;
    trace_link_fmt(meta, sizeof(meta), dir, link, ts);

    nseg = (int)((dump_len + OGS_TRACE_PACKET_SEG - 1) / OGS_TRACE_PACKET_SEG);

    /*
     * Force-emit so PACKET still appears when the core domain is below
     * info. Do not rely on sticky TLS IMSI to elevate generic logs.
     */
    ogs_log_force_push();
    for (seg = 0, off = 0; seg < nseg; seg++, off += OGS_TRACE_PACKET_SEG) {
        size_t chunk = dump_len - off;
        char segbuf[48] = "";

        if (chunk > OGS_TRACE_PACKET_SEG)
            chunk = OGS_TRACE_PACKET_SEG;
        if (!trace_b64_encode(b64, sizeof(b64),
                    (const uint8_t *)data + off, chunk))
            break;
        if (nseg > 1)
            ogs_snprintf(segbuf, sizeof(segbuf), " seg=%d/%d off=%zu",
                    seg + 1, nseg, off);

        ogs_log_printf(OGS_LOG_INFO, OGS_LOG_DOMAIN, 0,
                __FILE__, __LINE__, OGS_FUNC, 0,
                "[IMSI:%s] PACKET: proto=%s dir=%s len=%zu%s%s%s b64=%s",
                imsi,
                proto && proto[0] ? proto : "-",
                dir && dir[0] ? dir : "-",
                len, meta, segbuf,
                truncated ? " trunc=1" : "",
                b64);
    }
    ogs_log_force_pop();
}

void ogs_trace_packet(const char *imsi, const char *proto, const char *dir,
        const void *data, size_t len)
{
    ogs_trace_packet_link(imsi, proto, dir, data, len, NULL);
}

void ogs_trace_packet_ctx(const char *proto, const char *dir,
        const void *data, size_t len)
{
    if (!self.imsi[0])
        return;
    ogs_trace_packet(self.imsi, proto, dir, data, len);
}

void ogs_trace_packet_bind_rx_link(const char *proto, const void *data,
        size_t len, const ogs_trace_link_t *link)
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

    /* the dump may come later: keep when it was received */
    if (link)
        packet_rx.link = *link;
    else
        memset(&packet_rx.link, 0, sizeof(packet_rx.link));
    if (!packet_rx.link.ts)
        packet_rx.link.ts = ogs_time_now();
    packet_rx.link_present = true;
}

void ogs_trace_packet_bind_rx(const char *proto, const void *data, size_t len)
{
    ogs_trace_packet_bind_rx_link(proto, data, len, NULL);
}

void ogs_trace_packet_on_imsi(const char *imsi)
{
    if (!packet_rx.data || !packet_rx.len)
        return;
    if (!imsi || !imsi[0])
        return;

    ogs_trace_packet_link(imsi, packet_rx.proto, "rx",
            packet_rx.data, packet_rx.len,
            packet_rx.link_present ? &packet_rx.link : NULL);
    packet_rx_clear();
}

bool ogs_trace_filter_active(void)
{
    return trace_filter.count > 0;
}

bool ogs_trace_packet_steal_rx_link(uint8_t **data, size_t *len,
        char *proto, size_t proto_size, ogs_trace_link_t *link)
{
    ogs_assert(data);
    ogs_assert(len);

    *data = NULL;
    *len = 0;
    if (proto && proto_size)
        proto[0] = '\0';
    if (link)
        memset(link, 0, sizeof(*link));

    if (!packet_rx.data || !packet_rx.len)
        return false;

    *data = packet_rx.data;
    *len = packet_rx.len;
    if (proto && proto_size)
        ogs_cpystrn(proto, packet_rx.proto, proto_size);
    if (link && packet_rx.link_present)
        *link = packet_rx.link;

    packet_rx.data = NULL;
    packet_rx.len = 0;
    packet_rx.proto[0] = '\0';
    packet_rx.link_present = false;
    return true;
}

bool ogs_trace_packet_steal_rx(uint8_t **data, size_t *len,
        char *proto, size_t proto_size)
{
    return ogs_trace_packet_steal_rx_link(data, len, proto, proto_size, NULL);
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
