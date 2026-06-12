/*
 * Copyright (C) 2025 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef SGWC_PDN_INFO_H
#define SGWC_PDN_INFO_H

#include <stddef.h>

#include "ogs-metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PDN_INFO_PAGE_SIZE_DEFAULT
#define PDN_INFO_PAGE_SIZE_DEFAULT 100U
#endif

typedef struct sgwc_sess_s sgwc_sess_t;

bool sgwc_sess_rat_metric_labels(const sgwc_sess_t *sess,
        const char **rat, const char **gtp_if);

size_t sgwc_dump_pdn_info(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_PDN_INFO_H */
