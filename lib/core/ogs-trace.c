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
