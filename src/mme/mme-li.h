/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(MME_LI_H)
#define MME_LI_H

#include "mme-context.h"
#include "ogs-li.h"

#ifdef __cplusplus
extern "C" {
#endif

void mme_li_init(void);
void mme_li_final(void);
void mme_li_parse_config(ogs_yaml_iter_t *mme_iter);

void mme_li_report(mme_ue_t *mme_ue, ogs_li_event_e event,
        const char *detail);

int mme_admin_li_target(const ogs_metrics_query_t *q,
        char *body, size_t body_cap, size_t *body_len);

#ifdef __cplusplus
}
#endif

#endif /* MME_LI_H */
