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

/*
 * Per-subscriber trace lines are an ON-DEMAND debugging tool: emit
 * only when the current trace context's IMSI matches a configured
 * filter (or the domain is at debug). With an empty filter list the
 * whole prefix-format + vfprintf path is skipped — it burned ~3.6%
 * of MME CPU during production failure storms. Runtime enable, no
 * restart: POST /admin/trace/imsi with a prefix ("432" = every UE).
 */
bool ogs_trace_should_emit(int domain);

/*
 * PACKET dumps for NMS PCAP rebuild. Zero cost when the IMSI filter is
 * empty; when active, emits one INFO line:
 *   PACKET: proto=<name> dir=<rx|tx> len=<n> b64=<base64>
 * Payload is capped (OGS_TRACE_PACKET_MAX) so a traced flood cannot
 * balloon journald. Never called for untraced subscribers.
 */
#define OGS_TRACE_PACKET_MAX        2048
#define OGS_TRACE_ALIAS_KEY_LEN     20
#define OGS_MAX_TRACE_ALIASES       16

typedef enum {
    OGS_TRACE_ALIAS_MSISDN = 1,
    OGS_TRACE_ALIAS_IMEI = 2,
} ogs_trace_alias_type_e;

void ogs_trace_packet(const char *imsi, const char *proto, const char *dir,
        const void *data, size_t len);
/* Uses thread-local ogs_trace_get()->imsi; no-op if unset/unmatched. */
void ogs_trace_packet_ctx(const char *proto, const char *dir,
        const void *data, size_t len);
/*
 * Bind an RX buffer for the current worker; the next
 * ogs_trace_packet_on_imsi() dumps it once (then clears). Safe if the
 * filter is empty (no-op). Call before handlers that may set IMSI.
 */
void ogs_trace_packet_bind_rx(const char *proto, const void *data, size_t len);
void ogs_trace_packet_on_imsi(const char *imsi);
/*
 * Cross-thread RX PACKET handoff (MME workers): bind copies into TLS
 * owned memory; steal moves that buffer to the caller (e.g. enb_ue) so
 * the UE-owner shard can dump after IMSI is known. No-op / false when
 * the filter is empty or nothing is bound.
 */
bool ogs_trace_filter_active(void);
bool ogs_trace_packet_steal_rx(uint8_t **data, size_t *len,
        char *proto, size_t proto_size);
void ogs_trace_packet_free_buf(uint8_t *data);

/*
 * Trace was requested by MSISDN/IMEI: keep the alias and the resolved
 * IMSI filter entry. On each attach, refresh so SIM/device swaps still
 * hit IMSI-keyed NF logs.
 */
int ogs_trace_alias_set(ogs_trace_alias_type_e type, const char *key,
        const char *imsi_bcd);
void ogs_trace_alias_refresh_imsi(const char *msisdn_bcd,
        const char *imeisv_bcd, const char *imsi_bcd);
void ogs_trace_alias_clear(void);

#define OGS_TLOG(level, fmt, ...) \
    do { \
        char _ogs_tlog_prefix[OGS_TRACE_PREFIX_BUFSIZE]; \
        if (!ogs_trace_should_emit(OGS_LOG_DOMAIN)) break; \
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
