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

#include "ogs-compat.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OGS_RELOAD_AUDIT_MAX_LINES 128
#define OGS_RELOAD_AUDIT_LINE_LEN  384

void ogs_reload_audit_begin(void);
void ogs_reload_audit_note(const char *fmt, ...) OGS_GNUC_PRINTF(1, 2);
void ogs_reload_audit_warn(const char *fmt, ...) OGS_GNUC_PRINTF(1, 2);
void ogs_reload_audit_finish(const char *nf, bool yaml_ok);

#ifdef __cplusplus
}
#endif

#endif /* OGS_RELOAD_AUDIT_H */
