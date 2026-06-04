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

static ogs_trace_ctx_t self;

static struct {
    ogs_thread_mutex_t mutex;
    int initialized;
    int count;
    char imsi[OGS_MAX_TRACE_IMSI_FILTERS][OGS_TRACE_IMSI_LEN];
} trace_filter;

static void trace_filter_init_once(void)
{
    if (trace_filter.initialized)
        return;
    ogs_thread_mutex_init(&trace_filter.mutex);
    trace_filter.initialized = 1;
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
    int i;

    if (!imsi_prefix || !imsi_prefix[0])
        return OGS_ERROR;

    trace_filter_init_once();
    ogs_thread_mutex_lock(&trace_filter.mutex);

    for (i = 0; i < trace_filter.count; i++) {
        if (strcmp(trace_filter.imsi[i], imsi_prefix) == 0) {
            ogs_thread_mutex_unlock(&trace_filter.mutex);
            return OGS_OK;
        }
    }

    if (trace_filter.count >= OGS_MAX_TRACE_IMSI_FILTERS) {
        ogs_thread_mutex_unlock(&trace_filter.mutex);
        return OGS_ERROR;
    }

    ogs_cpystrn(trace_filter.imsi[trace_filter.count], imsi_prefix,
            OGS_TRACE_IMSI_LEN);
    trace_filter.count++;

    ogs_thread_mutex_unlock(&trace_filter.mutex);
    return OGS_OK;
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

    trace_filter_init_once();
    ogs_thread_mutex_lock(&trace_filter.mutex);

    for (i = 0; i < trace_filter.count; i++) {
        size_t n = strlen(trace_filter.imsi[i]);

        if (n == 0)
            continue;
        if (strncmp(imsi_bcd, trace_filter.imsi[i], n) == 0) {
            matched = true;
            break;
        }
    }

    ogs_thread_mutex_unlock(&trace_filter.mutex);
    return matched;
}

int ogs_trace_filter_count(void)
{
    trace_filter_init_once();
    return trace_filter.count;
}

const char *ogs_trace_filter_get(int index)
{
    trace_filter_init_once();
    ogs_thread_mutex_lock(&trace_filter.mutex);
    if (index < 0 || index >= trace_filter.count) {
        ogs_thread_mutex_unlock(&trace_filter.mutex);
        return NULL;
    }
    ogs_thread_mutex_unlock(&trace_filter.mutex);
    return trace_filter.imsi[index];
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
            "MME_S11:%s SGW_S11:%s SGW_S5:%s PGW_S5:%s "
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
            self.ue_ip[0] ? self.ue_ip : "-",
            self.apn[0] ? self.apn : "-",
            self.proc[0] ? self.proc : "-");
}
