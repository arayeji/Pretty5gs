/*
 * Copyright (C) 2026 by Open5GS contributors
 *
 * Admin endpoints for the SMF Prometheus HTTP server.
 * See src/mme/admin-api.h for the operational contract.
 */

#pragma once

#include "ogs-metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

void smf_admin_api_register(void);

size_t smf_dump_maintenance_status(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q);

#ifdef __cplusplus
}
#endif
