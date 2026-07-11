/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "context.h"
#include "hi1.h"

static ogs_thread_t *thread;
static bool started = false;

static void admf_main(void *data)
{
    (void)data;
    for (;;)
        ogs_msleep(1000);
}

int admf_initialize(void)
{
    int rv;

#define APP_NAME "admf"
    rv = ogs_app_parse_local_conf(APP_NAME);
    if (rv != OGS_OK)
        return rv;

    rv = admf_context_init();
    if (rv != OGS_OK)
        return rv;

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK)
        return rv;

    rv = admf_context_parse_config();
    if (rv != OGS_OK)
        return rv;

    rv = admf_hi1_open();
    if (rv != OGS_OK)
        return rv;

    thread = ogs_thread_create(admf_main, NULL);
    if (!thread)
        return OGS_ERROR;

    started = true;
    return OGS_OK;
}

void admf_terminate(void)
{
    if (!started)
        return;

    admf_hi1_close();
    ogs_thread_destroy(thread);
    admf_context_final();
    started = false;
}
