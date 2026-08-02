/*
 * Copyright (C) 2019-2026 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS / Pretty5GS.
 *
 * PGW selection for S11 Create Session (HSS static, APN DNS, YAML).
 */

#if !defined(MME_PGW_SELECT_H_INCLUDED)
#define MME_PGW_SELECT_H_INCLUDED

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mme_ue_s mme_ue_t;
typedef struct mme_sess_s mme_sess_t;
typedef struct mme_pgw_s mme_pgw_t;

typedef enum mme_pgw_selection_source_e {
    MME_PGW_SOURCE_FORCE_YAML = 0,
    MME_PGW_SOURCE_HSS_STATIC,
    MME_PGW_SOURCE_APN_DNS,
    MME_PGW_SOURCE_YAML_FALLBACK,
} mme_pgw_selection_source_t;

const char *mme_pgw_selection_source_string(mme_pgw_selection_source_t source);

/*
 * Select PGW-C address for a new/restored PDN Create Session.
 *
 * Precedence (mode=standard):
 *   1) HSS static MIP6 (smf_ip and allocation != DYNAMIC)
 *   2) APN DNS (if enabled)
 *   3) YAML gtpc.client.smf
 *
 * mode=force: always YAML (ignores HSS and APN DNS).
 *
 * On success fills *out_ip (and optionally *out_pgw for YAML picks).
 */
int mme_pgw_select_for_sess(
        mme_ue_t *mme_ue, mme_sess_t *sess, ogs_session_t *session,
        ogs_ip_t *out_ip, mme_pgw_t **out_pgw,
        mme_pgw_selection_source_t *out_source);

typedef struct enb_ue_s enb_ue_t;

/*
 * Bind PGW into sess->pgw_s5c_ip for Create Session Request.
 *
 * Returns:
 *   OGS_OK    — bound (sess->pgw_s5c_ip set)
 *   OGS_RETRY — DNS async pending (sess->pgw_dns_pending=true)
 *   OGS_ERROR — failed
 */
int mme_pgw_bind_for_csr(mme_ue_t *mme_ue, mme_sess_t *sess,
        enb_ue_t *enb_ue, int create_action);

#ifdef __cplusplus
}
#endif

#endif /* MME_PGW_SELECT_H_INCLUDED */
