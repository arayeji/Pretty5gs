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

#if !defined(OGS_CORE_INSIDE) && !defined(OGS_CORE_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_TRACE_H
#define OGS_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

#define OGS_TRACE_IMSI_LEN  16
#define OGS_TRACE_APN_LEN   101
#define OGS_TRACE_PROC_LEN  32
#define OGS_TRACE_IP_LEN    48
#define OGS_TRACE_PREFIX_BUFSIZE 384

typedef struct ogs_trace_ctx_s {
    char imsi[OGS_TRACE_IMSI_LEN];
    char apn[OGS_TRACE_APN_LEN];
    char proc[OGS_TRACE_PROC_LEN];
    char pgw_ip[OGS_TRACE_IP_LEN];
    char ue_ip[OGS_TRACE_IP_LEN];

    uint32_t enb_id;
    uint32_t enb_ue_s1ap_id;
    uint32_t mme_ue_s1ap_id;

    uint8_t ebi;

    uint32_t mme_s11_teid;
    uint32_t sgw_s11_teid;

    uint32_t sgw_s5c_teid;
    uint32_t pgw_s5c_teid;
} ogs_trace_ctx_t;

#define OGS_MAX_TRACE_IMSI_FILTERS 16

/* single-threaded startup init (called by ogs_core_initialize) */
void ogs_trace_filter_init(void);
void ogs_trace_clear(void);
void ogs_trace_set(const ogs_trace_ctx_t *ctx);

/*
 * Runtime IMSI prefix filters: DEBUG/TRACE logs for matching subscribers
 * are emitted even when the log domain level is error/warn. Prefix match
 * (e.g. "99970" matches "001010000000002"). Thread-safe; no restart.
 */
void ogs_trace_filter_clear(void);
int ogs_trace_filter_add(const char *imsi_prefix);
int ogs_trace_filter_add_ex(const char *imsi, bool exact_match);
int ogs_trace_filter_remove(const char *imsi_prefix);
int ogs_trace_filter_replace_ex(const char *imsi, bool exact_match);
bool ogs_trace_filter_match(const char *imsi_bcd);
bool ogs_trace_filter_get_exact(int index);
int ogs_trace_filter_count(void);
int ogs_trace_filter_get(int index, char *buf, size_t buflen);
/* Prefer ogs_trace_set() for OGS_TLOG prefixes (merge keeps stale fields). */
void ogs_trace_merge(const ogs_trace_ctx_t *ctx);
const ogs_trace_ctx_t *ogs_trace_get(void);
size_t ogs_trace_format_prefix(char *buf, size_t buflen);

#define OGS_TLOG(level, fmt, ...) \
    do { \
        char _ogs_tlog_prefix[OGS_TRACE_PREFIX_BUFSIZE]; \
        ogs_trace_format_prefix(_ogs_tlog_prefix, sizeof(_ogs_tlog_prefix)); \
        ogs_log_printf(level, OGS_LOG_DOMAIN, 0, __FILE__, __LINE__, OGS_FUNC, \
                0, "%s " fmt, _ogs_tlog_prefix, ##__VA_ARGS__); \
    } while (0)

#define OGS_TLOG_FATAL(fmt, ...) OGS_TLOG(OGS_LOG_FATAL, fmt, ##__VA_ARGS__)
#define OGS_TLOG_ERROR(fmt, ...) OGS_TLOG(OGS_LOG_ERROR, fmt, ##__VA_ARGS__)
#define OGS_TLOG_WARN(fmt, ...)  OGS_TLOG(OGS_LOG_WARN, fmt, ##__VA_ARGS__)
#define OGS_TLOG_INFO(fmt, ...)  OGS_TLOG(OGS_LOG_INFO, fmt, ##__VA_ARGS__)
#define OGS_TLOG_DEBUG(fmt, ...) OGS_TLOG(OGS_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define OGS_TLOG_TRACE(fmt, ...) OGS_TLOG(OGS_LOG_TRACE, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* OGS_TRACE_H */
