/*
 * Copyright (C) 2026 by the Open5GS contributors.
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

#include "pcrf-mysql.h"
#include "pcrf-context.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_MYSQL

#include <mysql.h>

static MYSQL *pcrf_mysql;

/*
 * PyHSS stores APN-AMBR in apn.apn_ambr_{dl,ul} consistent with 3GPP
 * APN-AMBR (kbit/s in S6a / charging); Open5GS session AMBR is bit/s.
 */
#define PCRF_PYHSS_AMBR_TO_BPS(kbps) ((uint64_t)(kbps) * 1000ULL)

static uint8_t pyhss_ip_version_to_session_type(int v)
{
    switch (v) {
    case 0:
        return OGS_PDU_SESSION_TYPE_IPV4;
    case 1:
        return OGS_PDU_SESSION_TYPE_IPV6;
    case 2:
        return OGS_PDU_SESSION_TYPE_IPV4V6;
    case 3:
    case 4:
        return OGS_PDU_SESSION_TYPE_IPV4V6;
    default:
        return OGS_PDU_SESSION_TYPE_IPV4;
    }
}

/*
 * pcrf.yaml documents ARP pre-emption as 1 = disabled, 2 = enabled.
 * PyHSS uses BOOLEAN (0/1).
 */
static uint8_t pyhss_bool_arp_preemption(const char *s)
{
    if (s && (s[0] == '1' || !ogs_strcasecmp(s, "true")))
        return 2;
    return 1;
}

/*
 * subscriber.apn_list is a comma-separated list of allowed APN short names
 * (PyHSS `apn.apn`).
 */
static int pcrf_mysql_apn_in_list(const char *apn_list, const char *apn)
{
    const char *p;
    size_t apn_len;

    if (!apn_list || !apn)
        return 0;

    apn_len = strlen(apn);
    if (!apn_len)
        return 0;

    p = apn_list;
    for (;;) {
        const char *comma;
        size_t toklen;

        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0')
            break;

        comma = strchr(p, ',');
        toklen = comma ? (size_t)(comma - p) : strlen(p);
        while (toklen > 0 && (p[toklen - 1] == ' ' || p[toklen - 1] == '\t'))
            toklen--;

        if (toklen == apn_len && !ogs_strncasecmp(p, apn, apn_len))
            return 1;

        if (!comma)
            break;
        p = comma + 1;
    }
    return 0;
}

int pcrf_mysql_open(pcrf_context_t *ctx)
{
    ogs_assert(ctx);
    if (!ctx->mysql.enabled)
        return OGS_OK;

    ogs_assert(ctx->mysql.server && ctx->mysql.user && ctx->mysql.database);

    pcrf_mysql = mysql_init(NULL);
    if (!pcrf_mysql) {
        ogs_error("mysql_init() failed");
        return OGS_ERROR;
    }

    if (!mysql_real_connect(pcrf_mysql, ctx->mysql.server, ctx->mysql.user,
            ctx->mysql.password ? ctx->mysql.password : "",
            ctx->mysql.database, ctx->mysql.port, NULL, 0)) {
        ogs_error("mysql_real_connect failed: %s", mysql_error(pcrf_mysql));
        mysql_close(pcrf_mysql);
        pcrf_mysql = NULL;
        return OGS_ERROR;
    }

    ogs_info("PCRF MySQL: connected to %s/%s (PyHSS schema)",
            ctx->mysql.server, ctx->mysql.database);
    return OGS_OK;
}

void pcrf_mysql_close(void)
{
    if (pcrf_mysql) {
        mysql_close(pcrf_mysql);
        pcrf_mysql = NULL;
    }
}

int pcrf_mysql_qos_data(
        const char *imsi_bcd, const char *apn, ogs_session_data_t *session_data)
{
    char query[2048];
    char e_imsi[64];
    char e_apn[OGS_MAX_APN_LEN * 2 + 16];
    MYSQL_RES *res = NULL;
    MYSQL_ROW row;
    long ambr_dl_kbps, ambr_ul_kbps;
    int ip_ver, qci, arp_pri;

    ogs_assert(imsi_bcd && apn && session_data);
    ogs_assert(pcrf_mysql);

    memset(session_data, 0, sizeof(*session_data));

    mysql_real_escape_string(pcrf_mysql, e_imsi, imsi_bcd,
            (unsigned long)strlen(imsi_bcd));
    mysql_real_escape_string(pcrf_mysql, e_apn, apn,
            (unsigned long)strlen(apn));

    snprintf(query, sizeof(query),
            "SELECT s.apn_list, a.ip_version, a.qci, a.arp_priority, "
            "a.arp_preemption_capability, a.arp_preemption_vulnerability, "
            "a.apn_ambr_dl, a.apn_ambr_ul "
            "FROM subscriber s "
            "INNER JOIN apn a ON a.apn = '%s' "
            "WHERE s.imsi = '%s' "
            "AND (s.enabled IS NULL OR s.enabled <> 0) "
            "LIMIT 1",
            e_apn, e_imsi);

    if (mysql_query(pcrf_mysql, query)) {
        ogs_error("mysql_query failed: %s", mysql_error(pcrf_mysql));
        return OGS_ERROR;
    }

    res = mysql_store_result(pcrf_mysql);
    if (!res) {
        ogs_error("mysql_store_result failed: %s", mysql_error(pcrf_mysql));
        return OGS_ERROR;
    }

    row = mysql_fetch_row(res);
    if (!row || !row[0]) {
        ogs_error("No PyHSS subscriber+apn for IMSI[%s] APN[%s]", imsi_bcd, apn);
        mysql_free_result(res);
        return OGS_ERROR;
    }

    if (!pcrf_mysql_apn_in_list(row[0], apn)) {
        ogs_error("APN[%s] not in apn_list for IMSI[%s] (list:[%s])",
                apn, imsi_bcd, row[0]);
        mysql_free_result(res);
        return OGS_ERROR;
    }

    session_data->session.name = ogs_strdup(apn);
    ogs_assert(session_data->session.name);

    ip_ver = row[1] ? atoi(row[1]) : 0;
    session_data->session.session_type = pyhss_ip_version_to_session_type(ip_ver);

    qci = row[2] ? atoi(row[2]) : 9;
    if (qci < 0 || qci > 255)
        qci = 9;
    session_data->session.qos.index = (uint8_t)qci;

    arp_pri = row[3] ? atoi(row[3]) : 4;
    if (arp_pri < 1)
        arp_pri = 1;
    else if (arp_pri > 15)
        arp_pri = 15;
    session_data->session.qos.arp.priority_level = (uint8_t)arp_pri;

    session_data->session.qos.arp.pre_emption_capability =
            pyhss_bool_arp_preemption(row[4]);
    session_data->session.qos.arp.pre_emption_vulnerability =
            pyhss_bool_arp_preemption(row[5]);

    ambr_dl_kbps = row[6] ? strtol(row[6], NULL, 10) : 0;
    ambr_ul_kbps = row[7] ? strtol(row[7], NULL, 10) : 0;
    if (ambr_dl_kbps < 0)
        ambr_dl_kbps = 0;
    if (ambr_ul_kbps < 0)
        ambr_ul_kbps = 0;

    session_data->session.ambr.downlink = PCRF_PYHSS_AMBR_TO_BPS(ambr_dl_kbps);
    session_data->session.ambr.uplink = PCRF_PYHSS_AMBR_TO_BPS(ambr_ul_kbps);

    mysql_free_result(res);
    return OGS_OK;
}

#else /* !HAVE_MYSQL */

int pcrf_mysql_open(pcrf_context_t *ctx)
{
    ogs_assert(ctx);
    if (ctx->mysql.enabled) {
        ogs_error("PCRF MySQL requested in config but Open5GS was built "
                "without -Dmysql_pcrf=true (libmysqlclient)");
        return OGS_ERROR;
    }
    return OGS_OK;
}

void pcrf_mysql_close(void) {}

int pcrf_mysql_qos_data(
        const char *imsi_bcd, const char *apn, ogs_session_data_t *session_data)
{
    ogs_assert(imsi_bcd && apn && session_data);
    ogs_error("PCRF MySQL not compiled in");
    return OGS_ERROR;
}

#endif /* HAVE_MYSQL */
