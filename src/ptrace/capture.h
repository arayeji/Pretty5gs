/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_CAPTURE_H)
#define PTRACE_CAPTURE_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

int ptrace_capture_open(void);
void ptrace_capture_close(void);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_CAPTURE_H */
