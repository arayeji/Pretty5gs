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

#ifndef SGWC_RUNTIME_CONFIG_H
#define SGWC_RUNTIME_CONFIG_H

#include "ogs-metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

char *sgwc_runtime_config_dump(void);

size_t sgwc_dump_runtime_config(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_RUNTIME_CONFIG_H */
