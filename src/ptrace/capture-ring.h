/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_CAPTURE_RING_H)
#define PTRACE_CAPTURE_RING_H

#include "ptrace.h"

#ifdef __cplusplus
extern "C" {
#endif

int ptrace_ring_open(const char *path, int size_gb);
void ptrace_ring_close(void);
int ptrace_ring_write(const uint8_t *data, uint16_t len, ogs_time_t ts,
        char *ref_out, size_t ref_len);
int ptrace_ring_export(const char *const *refs, int nrefs,
        const char *out_path);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_CAPTURE_RING_H */
