/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(ADMF_X1_H)
#define ADMF_X1_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

int admf_x1_push_target_add(const char *liid, const char *imsi,
        const char *msisdn);
int admf_x1_push_target_remove(const char *liid, const char *imsi);

#ifdef __cplusplus
}
#endif

#endif /* ADMF_X1_H */
