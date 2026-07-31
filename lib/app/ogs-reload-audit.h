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

#ifndef OGS_RELOAD_AUDIT_H
#define OGS_RELOAD_AUDIT_H

#include <stdbool.h>
#include <time.h>

#if defined(__GNUC__)
#define OGS_RELOAD_AUDIT_PRINTF(fmt, arg) \
    __attribute__((format(printf, fmt, arg)))
#else
#define OGS_RELOAD_AUDIT_PRINTF(fmt, arg)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define OGS_RELOAD_AUDIT_MAX_LINES 128
#define OGS_RELOAD_AUDIT_LINE_LEN  384
#define OGS_RELOAD_AUDIT_NF_LEN    16

typedef struct ogs_reload_audit_snapshot_s {
    bool valid;
    time_t finished_at;
    bool ok;
    bool truncated; /* true if change_count exceeded OGS_RELOAD_AUDIT_MAX_LINES */
    char nf[OGS_RELOAD_AUDIT_NF_LEN];
    int change_count;
    int line_count;
    char lines[OGS_RELOAD_AUDIT_MAX_LINES][OGS_RELOAD_AUDIT_LINE_LEN];
} ogs_reload_audit_snapshot_t;

void ogs_reload_audit_begin(void);
void ogs_reload_audit_note(const char *fmt, ...) OGS_RELOAD_AUDIT_PRINTF(1, 2);
void ogs_reload_audit_warn(const char *fmt, ...) OGS_RELOAD_AUDIT_PRINTF(1, 2);
void ogs_reload_audit_finish(const char *nf, bool yaml_ok);
void ogs_reload_audit_record_startup(const char *nf);

const ogs_reload_audit_snapshot_t *ogs_reload_audit_get_last(void);

struct cJSON;
void ogs_reload_audit_snapshot_to_json(struct cJSON *parent);

#ifdef __cplusplus
}
#endif

#endif /* OGS_RELOAD_AUDIT_H */
