/*
 * Copyright (C) 2026 by Open5GS contributors
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "ogs-reload-audit.h"

#include "ogs-core.h"
#include "ogs-init.h"

#include <stdarg.h>
#include <string.h>

static char reload_audit_lines[OGS_RELOAD_AUDIT_MAX_LINES]
        [OGS_RELOAD_AUDIT_LINE_LEN];
static int reload_audit_count = 0;

static void reload_audit_push(const char *line, bool warn)
{
    char buf[OGS_RELOAD_AUDIT_LINE_LEN];

    ogs_assert(line);

    ogs_cpystrn(buf, line, sizeof(buf));

    if (warn)
        ogs_warn("SIGHUP: %s", buf);
    else
        ogs_info("SIGHUP: %s", buf);

    if (reload_audit_count < OGS_RELOAD_AUDIT_MAX_LINES) {
        ogs_cpystrn(reload_audit_lines[reload_audit_count], buf,
                sizeof(reload_audit_lines[0]));
        reload_audit_count++;
    } else if (reload_audit_count == OGS_RELOAD_AUDIT_MAX_LINES) {
        ogs_warn("SIGHUP: reload audit line buffer full; further changes "
                "logged only above");
        reload_audit_count++;
    }
}

void ogs_reload_audit_begin(void)
{
    reload_audit_count = 0;
    ogs_info("SIGHUP: config reload starting (file=%s)",
            ogs_app()->file ? ogs_app()->file : "(none)");
}

void ogs_reload_audit_note(const char *fmt, ...)
{
    char buf[OGS_RELOAD_AUDIT_LINE_LEN];
    va_list ap;

    ogs_assert(fmt);

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    reload_audit_push(buf, false);
}

void ogs_reload_audit_warn(const char *fmt, ...)
{
    char buf[OGS_RELOAD_AUDIT_LINE_LEN];
    va_list ap;

    ogs_assert(fmt);

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    reload_audit_push(buf, true);
}

void ogs_reload_audit_finish(const char *nf, bool yaml_ok)
{
    int i;
    int shown = 0;

    ogs_assert(nf);

    ogs_info("%s SIGHUP reload %s (config=%s, %d change(s) logged)",
            nf,
            yaml_ok ? "completed" : "aborted",
            ogs_app()->file ? ogs_app()->file : "(none)",
            reload_audit_count > OGS_RELOAD_AUDIT_MAX_LINES ?
                OGS_RELOAD_AUDIT_MAX_LINES : reload_audit_count);

    if (reload_audit_count == 0) {
        if (yaml_ok)
            ogs_info("%s SIGHUP: no reloadable keys changed "
                    "(runtime config unchanged)", nf);
        reload_audit_count = 0;
        return;
    }

    ogs_info("%s SIGHUP reload summary:", nf);
    for (i = 0; i < reload_audit_count &&
            i < OGS_RELOAD_AUDIT_MAX_LINES; i++) {
        ogs_info("  %d. %s", i + 1, reload_audit_lines[i]);
        shown++;
    }

    if (reload_audit_count > OGS_RELOAD_AUDIT_MAX_LINES)
        ogs_warn("%s SIGHUP: %d additional change(s) not listed "
                "(see earlier SIGHUP lines)",
                nf, reload_audit_count - OGS_RELOAD_AUDIT_MAX_LINES);

    ogs_info("%s SIGHUP: %d change(s) listed above", nf, shown);
    reload_audit_count = 0;
}
