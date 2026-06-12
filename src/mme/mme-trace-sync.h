/*
 * Copyright (C) 2026 by Open5GS contributors
 */

#ifndef MME_TRACE_SYNC_H
#define MME_TRACE_SYNC_H

#include "ogs-metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

size_t mme_trace_sync_append(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t body_len);

#ifdef __cplusplus
}
#endif

#endif /* MME_TRACE_SYNC_H */
