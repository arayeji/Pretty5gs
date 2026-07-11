/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(SMF_LI_H)
#define SMF_LI_H

#include "context.h"
#include "ogs-li.h"

#ifdef __cplusplus
extern "C" {
#endif

void smf_li_init(void);
void smf_li_final(void);
void smf_li_parse_config(ogs_yaml_iter_t *smf_iter);

void smf_li_report_sess(smf_sess_t *sess, ogs_li_event_e event,
        const char *detail);

int smf_admin_li_target(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len);

#ifdef __cplusplus
}
#endif

#endif /* SMF_LI_H */
