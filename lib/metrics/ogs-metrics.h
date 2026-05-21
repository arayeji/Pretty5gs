/*
 * Copyright (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#ifndef OGS_METRICS_H
#define OGS_METRICS_H

/* MUST come first to satisfy core headers like ogs-list.h */
#include "core/ogs-core.h"

/* App layer (logging domain, etc.) */
#include "app/ogs-app.h"

/* Expose internal metrics structures to metrics library users */
#define OGS_METRICS_INSIDE
#include "metrics/context.h"
#undef OGS_METRICS_INSIDE


#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

/*
 * Public extern of the metrics log domain symbol. Every other
 * Open5GS library header that redefines OGS_LOG_DOMAIN also
 * publishes the underlying symbol (see ogs-app.h, ogs-s1ap.h,
 * etc.). Without this, TUs that include this header *before*
 * other headers carrying asn1c inline functions
 * (asn_internal.h's ogs_asn_malloc/calloc/realloc) end up baking
 * "__ogs_metrics_domain" into those inlines and the link / compile
 * fails with "__ogs_metrics_domain undeclared".
 */
extern int __ogs_metrics_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __ogs_metrics_domain

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OGS_METRICS_H */

