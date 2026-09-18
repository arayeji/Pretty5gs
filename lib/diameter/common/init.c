/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#include "ogs-diameter-common.h"

#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#ifdef _WIN32
#include <direct.h>
#define diam_mkdir(p) _mkdir(p)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define diam_mkdir(p) mkdir((p), 0755)
#endif

int __ogs_diam_domain;

#define DIAM_OSI_DIR "/var/lib/open5gs"

static void diam_gnutls_log_func(int level, const char *str);
static void diam_log_func(int printlevel, const char *format, va_list ap);

static void diam_mkdir_p(const char *dir)
{
    char tmp[512];
    char *p;
    size_t len;

    if (!dir || !dir[0])
        return;

    ogs_cpystrn(tmp, dir, sizeof(tmp));
    len = strlen(tmp);
    if (len && tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (diam_mkdir(tmp) != 0 && errno != EEXIST)
                ogs_warn("mkdir(%s) failed: %s", tmp, strerror(errno));
            *p = '/';
        }
    }
    if (diam_mkdir(tmp) != 0 && errno != EEXIST)
        ogs_warn("mkdir(%s) failed: %s", tmp, strerror(errno));
}

static void diam_osi_path(char *buf, size_t buflen)
{
    const char *id = fd_g_config && fd_g_config->cnf_diamid ?
            (const char *)fd_g_config->cnf_diamid : "unknown";
    char safe[128];
    size_t i, n = 0;

    for (i = 0; id[i] && n + 1 < sizeof(safe); i++) {
        unsigned char c = (unsigned char)id[i];
        safe[n++] = (isalnum(c) || c == '-' || c == '_') ? (char)c : '_';
    }
    safe[n] = '\0';
    if (!safe[0])
        ogs_cpystrn(safe, "unknown", sizeof(safe));

    ogs_snprintf(buf, buflen, DIAM_OSI_DIR "/diam_osi_%s", safe);
}

static uint32_t diam_load_osi(const char *path)
{
    FILE *f;
    unsigned long val = 0;

    f = fopen(path, "r");
    if (!f)
        return 0;
    if (fscanf(f, "%lu", &val) != 1)
        val = 0;
    fclose(f);
    return (uint32_t)val;
}

static void diam_save_osi(const char *path, uint32_t val)
{
    FILE *f;

    diam_mkdir_p(DIAM_OSI_DIR);
    f = fopen(path, "w");
    if (!f) {
        ogs_error("failed to persist Diameter Origin-State-Id to %s: %s",
                path, strerror(errno));
        return;
    }
    fprintf(f, "%u\n", val);
    fclose(f);
}

static void diam_set_restart_origin_state_id(void)
{
    char path[512];
    uint32_t loaded, now, osi;

    diam_osi_path(path, sizeof(path));
    loaded = diam_load_osi(path);
    now = (uint32_t)ogs_time_to_sec(ogs_time_now());
    if (!now)
        now = 1;

    /*
     * RFC 6733: a strictly greater Origin-State-Id means this peer
     * restarted. time^pid can go backwards and the DRA then keeps the
     * old association and RSTs the new CER.
     */
    osi = now;
    if (loaded && osi <= loaded)
        osi = loaded + 1;
    if (!osi)
        osi = 1;

    fd_g_config->cnf_orstateid = osi;
    diam_save_osi(path, osi);
    ogs_info("Diameter Origin-State-Id %u (restart, prev %u)", osi, loaded);
}

int ogs_diam_init(int mode, const char *conffile, ogs_diam_config_t *fd_config)
{
    int ret;

    ogs_assert(fd_config);

    gnutls_global_set_log_level(0);
    gnutls_global_set_log_function(diam_gnutls_log_func);

    fd_g_debug_lvl = FD_LOG_ERROR;
    ret = fd_log_handler_register(diam_log_func);
    if (ret != 0) {
        ogs_error("fd_log_handler_register() failed");
        return ret;
    }

    ret = fd_core_initialize();
    if (ret != 0) {
        ogs_error("fd_core_initialize() failed");
        return ret;
    }

    /* Parse the configuration file */
    if (conffile) {
        CHECK_FCT_DO( fd_core_parseconf(conffile), goto error );
    } else {
        CHECK_FCT_DO( ogs_diam_config_init(fd_config), goto error );
    }

    /* Initialize FD Message */
    CHECK_FCT( ogs_diam_message_init() );

    /* Initialize FD logger */
    CHECK_FCT_DO( ogs_diam_logger_init(), goto error );

    /* Initialize FD stats */
    CHECK_FCT_DO( ogs_diam_stats_init(mode, &fd_config->stats), goto error );

    diam_set_restart_origin_state_id();

    /*
     * RFC 6733 12: Tc defaults to 30 s, deliberately slow so that a
     * peer which is down does not see a reconnect storm - and a DRA
     * that rate-limits us is exactly what a 5 s retry would trip.
     *
     * The fast retry this replaced was a workaround for the DRA
     * refusing CER after an MME crash; the persistent, monotonic
     * Origin-State-Id set above is the RFC 6733 5.1 fix for that, so
     * the first CER is accepted and no fast retry is needed.
     *
     * freeDiameter already applies the 30 s default in fd_conf_init()
     * and overrides it from "TcTimer" (or a per-peer ConnectPeer Tc) in
     * the conf file, so the right thing here is to touch nothing. The
     * previous code clobbered any conf value above 5 s.
     */
    if (!fd_g_config->cnf_timer_tc)     /* belt and braces; fd sets 30 */
        fd_g_config->cnf_timer_tc = OGS_DIAM_TIMER_TC_DEFAULT;
    ogs_info("Diameter TcTimer %us (RFC 6733 default %ds; set TcTimer or "
            "a per-peer ConnectPeer Tc in the freeDiameter conf to change)",
            fd_g_config->cnf_timer_tc, OGS_DIAM_TIMER_TC_DEFAULT);

    return 0;
error:
    CHECK_FCT_DO( fd_core_shutdown(),  );
    CHECK_FCT_DO( fd_core_wait_shutdown_complete(),  );

    return -1;
}

int ogs_diam_start(void)
{
    /* Start the servers */
    CHECK_FCT_DO( fd_core_start(), goto error );

    CHECK_FCT_DO( fd_core_waitstartcomplete(), goto error );

    /*
     * Do NOT block startup waiting for a peer to reach OPEN. This is
     * shared by every NF that speaks Diameter, so it must not encode
     * one NF's policy.
     *
     * Failing the individual request that needs the peer is both
     * correct and diagnosable, and it keeps the work that does not
     * need Diameter running. (In the MME that means attaches get EMM
     * cause #17 while TAU and Service Request for already-attached UEs
     * still work.) A blocking wait instead added its full timeout to
     * every restart - including restarts done while the DRA is
     * deliberately down.
     *
     * An NF that really must hold off new traffic while its peer is
     * unreachable should do that in its own access layer - for the MME
     * that is S1AP OVERLOAD START (36.413 8.7.6, driven per 23.401
     * 4.3.7.4.2), released with OVERLOAD STOP once a peer is OPEN -
     * not a sleep here.
     */
    if (!ogs_diam_any_peer_open()) {
        ogs_warn("Diameter: no ConnectPeer OPEN yet; continuing startup. "
                "Requests that need a Diameter peer will fail until one "
                "connects");
        ogs_diam_log_peer_states();
    }

    CHECK_FCT( ogs_diam_stats_start() );

    return 0;
error:
    CHECK_FCT_DO( fd_core_shutdown(),  );
    CHECK_FCT_DO( fd_core_wait_shutdown_complete(),  );

    return -1;
}

void ogs_diam_final()
{
    ogs_diam_stats_final();
    ogs_diam_logger_final();

    CHECK_FCT_DO( fd_core_shutdown(), ogs_error("fd_core_shutdown() failed") );
    CHECK_FCT_DO( fd_core_wait_shutdown_complete(),
            ogs_error("fd_core_wait_shutdown_complete() failed"));
}

static void diam_gnutls_log_func(int level, const char *str)
{
    ogs_trace("gnutls[%d]: %s", level, str);
}

static void diam_log_func(int printlevel, const char *format, va_list ap)
{
    char *buffer = NULL;
    int  ret = 0;
    size_t len;

    buffer = ogs_calloc(1, OGS_MAX_SDU_LEN);
    ogs_assert(buffer);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
    ret = ogs_vsnprintf(buffer, OGS_MAX_SDU_LEN, format, ap);
#pragma GCC diagnostic pop
    if (ret < 0 || ret > OGS_MAX_SDU_LEN) {
        ogs_error("vsnprintf() failed[ret=%d]", ret);
        ogs_free(buffer);
        return;
    }

    /* Trim trailing whitespace/newlines; skip empty FD lines that used
     * to show up as bare "((null):0)" in collectors (NULL __FILE__). */
    len = strlen(buffer);
    while (len > 0 &&
            (buffer[len - 1] == '\n' || buffer[len - 1] == '\r' ||
             buffer[len - 1] == ' ' || buffer[len - 1] == '\t'))
        buffer[--len] = '\0';
    if (!len) {
        ogs_free(buffer);
        return;
    }

    /* Pass a real file label — NULL becomes "((null):0)" via %s:%d. */
#define diam_log_printf(level, ...) \
    ogs_log_printf(level, OGS_LOG_DOMAIN, 0, \
            "freeDiameter", 0, NULL, 0, __VA_ARGS__)

    switch(printlevel) {
    case FD_LOG_ANNOYING:
        diam_log_printf(OGS_LOG_TRACE, "[%d] %s", printlevel, buffer);
        break;
    case FD_LOG_DEBUG:
        diam_log_printf(OGS_LOG_TRACE, "[%d] %s", printlevel, buffer);
        break;
    case FD_LOG_INFO:
        diam_log_printf(OGS_LOG_TRACE, "[%d] %s", printlevel, buffer);
        break;
    case FD_LOG_NOTICE:
        diam_log_printf(OGS_LOG_DEBUG, "%s", buffer);
        break;
    case FD_LOG_ERROR:
        diam_log_printf(OGS_LOG_ERROR, "%s", buffer);
        if (!strcmp(buffer, " - The certificate is expired.")) {
            ogs_error("You can renew CERT as follows:");
            ogs_error("./support/freeDiameter/make_certs.sh "
                    "./install/etc/open5gs/freeDiameter");
        }
        break;
    case FD_LOG_FATAL:
        diam_log_printf(OGS_LOG_FATAL, "%s", buffer);
        break;
    default:
        diam_log_printf(OGS_LOG_ERROR, "[%d] %s", printlevel, buffer);
        break;
    }

    ogs_free(buffer);
}
