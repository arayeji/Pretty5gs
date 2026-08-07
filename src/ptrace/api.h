/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_API_H)
#define PTRACE_API_H

#include "ptrace.h"

#ifdef __cplusplus
extern "C" {
#endif

int ptrace_api_open(void);
void ptrace_api_close(void);
void ptrace_api_publish(const ptrace_event_t *evt);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_API_H */
