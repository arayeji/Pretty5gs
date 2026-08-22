/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Local IMSI→IMEI tracker for MME provisioning SMS (MongoDB collection
 * "imei_tracker"). Separate from subscribers.imeisv — this records the
 * IMEI for which provisioning SMS was already sent.
 */

#if !defined(OGS_DBI_INSIDE) && !defined(OGS_DBI_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_DBI_IMEI_TRACKER_H
#define OGS_DBI_IMEI_TRACKER_H

#ifdef __cplusplus
extern "C" {
#endif

#define OGS_DBI_IMEI_TRACKER_IMEI_LEN 15

/*
 * Look up stored IMEI for IMSI.
 * Returns OGS_OK if found (imei_out filled), OGS_ERROR if missing/error.
 */
int ogs_dbi_imei_tracker_get(const char *imsi,
        char *imei_out, size_t imei_out_size);

/*
 * Upsert IMSI→IMEI (last provisioned / tracked equipment).
 */
int ogs_dbi_imei_tracker_set(const char *imsi, const char *imei);

#ifdef __cplusplus
}
#endif

#endif /* OGS_DBI_IMEI_TRACKER_H */
