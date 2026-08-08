/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Identity-first extract: cheap NAS / GTP-C / Diameter parse, no S1AP ASN.
 */

#if !defined(PTRACE_IDENTITY_H)
#define PTRACE_IDENTITY_H

#include "ptrace.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Fill id from a raw L2 frame. Returns true if subscriber/session identity
 * is present (IMSI/GUTI/MSISDN/IMEI/Diameter session_id). */
bool ptrace_identity_extract(const uint8_t *data, uint16_t len,
        ogs_time_t ts, ptrace_role_e role, const char *packet_ref,
        ptrace_id_event_t *out);

/* Convert compact id event → full event (stack or pool). */
void ptrace_identity_to_event(const ptrace_id_event_t *id, ptrace_event_t *evt);

#ifdef __cplusplus
}
#endif

#endif /* PTRACE_IDENTITY_H */
