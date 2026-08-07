/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "context.h"

int app_initialize(const char *const argv[])
{
    int rv;
    (void)argv;

    rv = ptrace_initialize();
    if (rv != OGS_OK) {
        ogs_error("Failed to initialize Pretty-Trace (ptrace)");
        return rv;
    }
    ogs_info("Pretty-Trace initialize...done");
    return OGS_OK;
}

void app_terminate(void)
{
    ptrace_terminate();
    ogs_info("Pretty-Trace terminate...done");
}
