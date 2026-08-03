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

/*
 * cJSON helper for ogs_reload_audit_get_last(). Linked from MME/SGWC/SMF
 * only (not libogsapp) to avoid duplicate cJSON objects in libogsapp.
 */

#include "ogs-core.h"
#include "ogs-reload-audit.h"

#include "sbi/openapi/external/cJSON.h"

void ogs_reload_audit_snapshot_to_json(cJSON *parent)
{
    const ogs_reload_audit_snapshot_t *snap;
    cJSON *obj = NULL;
    cJSON *changes = NULL;
    int i;

    ogs_assert(parent);

    snap = ogs_reload_audit_get_last();
    if (!snap)
        return;

    obj = cJSON_CreateObject();
    ogs_assert(obj);

    cJSON_AddNumberToObject(obj, "finished_at", (double)snap->finished_at);
    cJSON_AddBoolToObject(obj, "ok", snap->ok ? 1 : 0);
    cJSON_AddBoolToObject(obj, "truncated", snap->truncated ? 1 : 0);
    cJSON_AddStringToObject(obj, "nf", snap->nf);
    cJSON_AddNumberToObject(obj, "change_count", snap->change_count);
    cJSON_AddNumberToObject(obj, "line_count", snap->line_count);

    changes = cJSON_CreateArray();
    ogs_assert(changes);
    for (i = 0; i < snap->line_count; i++)
        cJSON_AddItemToArray(changes, cJSON_CreateString(snap->lines[i]));
    cJSON_AddItemToObject(obj, "changes", changes);

    cJSON_AddItemToObject(parent, "last_reload", obj);
}
