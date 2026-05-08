/*
 * Copyright (C) 2026 by the Open5GS contributors.
 *
 * This file is part of Open5GS.
 */
#ifndef PCRF_MYSQL_H
#define PCRF_MYSQL_H

#include "ogs-proto.h"

struct pcrf_context_s;

#ifdef __cplusplus
extern "C" {
#endif

int pcrf_mysql_open(struct pcrf_context_s *ctx);
void pcrf_mysql_close(void);

int pcrf_mysql_qos_data(
        const char *imsi_bcd, const char *apn, ogs_session_data_t *session_data);

#ifdef __cplusplus
}
#endif

#endif /* PCRF_MYSQL_H */
