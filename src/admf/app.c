/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "ogs-app.h"

int admf_initialize(void);
void admf_terminate(void);

int app_initialize(const char *const argv[])
{
    int rv;
    (void)argv;

    rv = admf_initialize();
    if (rv != OGS_OK) {
        ogs_error("Failed to initialize ADMF");
        return rv;
    }

    ogs_info("ADMF initialize...done");
    return OGS_OK;
}

void app_terminate(void)
{
    admf_terminate();
    ogs_info("ADMF terminate...done");
}
