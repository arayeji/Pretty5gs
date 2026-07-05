/*
 * Copyright (C) 2026 by Open5GS Contributors
 *
 * Ga interface SGW-CDR writer (offline charging via spool + open5gs-cgfd).
 */

#ifndef SGWC_GA_WRITER_H
#define SGWC_GA_WRITER_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

int sgwc_ga_writer_open(void);
void sgwc_ga_writer_close(void);
int sgwc_ga_writer_apply_runtime(const sgwc_cdr_config_t *new_cfg);

void sgwc_ga_cdr_session_start(sgwc_sess_t *sess);
void sgwc_ga_cdr_session_interim(sgwc_sess_t *sess, uint32_t interval_duration_s);
void sgwc_ga_cdr_session_stop(sgwc_sess_t *sess);
void sgwc_ga_sess_clear(sgwc_sess_t *sess);

/* Merge PFCP usage-report volume (interval deltas) into session counters. */
void sgwc_sess_usage_accumulate(sgwc_sess_t *sess,
        uint64_t ul_vol, uint64_t dl_vol, uint32_t duration_s);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_GA_WRITER_H */
