/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#if !defined(PTRACE_DECODE_H)
#define PTRACE_DECODE_H

#include "ptrace.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Decode one packet into 0..PTRACE_MAX_EVENTS_PER_PKT events.
 * Caller owns returned events and must ptrace_event_free() them. */
int ptrace_decode_packet(ptrace_packet_t *pkt,
        ptrace_event_t **out, int *nout);

int ptrace_decode_s1ap(const uint8_t *data, int len,
        ptrace_event_t *base, ptrace_event_t **extra, int *nextra);
int ptrace_decode_nas(const uint8_t *data, int len, ptrace_event_t *evt);
int ptrace_decode_gtpc(const uint8_t *data, int len, ptrace_event_t *evt);
int ptrace_decode_gtpu(const uint8_t *data, int len, ptrace_event_t *evt);
int ptrace_decode_pfcp(const uint8_t *data, int len, ptrace_event_t *evt);
int ptrace_decode_diameter(const uint8_t *data, int len, ptrace_event_t *evt);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_DECODE_H */
