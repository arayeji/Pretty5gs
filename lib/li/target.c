/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "ogs-li.h"

#include <string.h>

void ogs_li_target_set_init(ogs_li_target_set_t *set, int max_targets)
{
    ogs_assert(set);
    ogs_assert(max_targets > 0);

    memset(set, 0, sizeof(*set));
    ogs_list_init(&set->list);
    ogs_pool_init(&set->pool, max_targets);
    set->next_cin = 1;
}

void ogs_li_target_set_final(ogs_li_target_set_t *set)
{
    ogs_li_target_t *target = NULL, *next = NULL;

    ogs_assert(set);

    ogs_list_for_each_safe(&set->list, next, target) {
        ogs_list_remove(&set->list, target);
        ogs_pool_free(&set->pool, target);
    }

    ogs_pool_final(&set->pool);
    memset(set, 0, sizeof(*set));
}

ogs_li_target_t *ogs_li_target_add(
        ogs_li_target_set_t *set, const char *liid, const char *imsi,
        const char *msisdn)
{
    ogs_li_target_t *target = NULL;
    ogs_li_target_t *existing = NULL;

    ogs_assert(set);
    ogs_assert(liid && liid[0]);
    ogs_assert(imsi && imsi[0]);

    existing = ogs_li_target_find_by_imsi(set, imsi);
    if (existing) {
        ogs_cpystrn(existing->liid, liid, sizeof(existing->liid));
        if (msisdn && msisdn[0])
            ogs_cpystrn(existing->msisdn, msisdn, sizeof(existing->msisdn));
        existing->active = true;
        return existing;
    }

    ogs_pool_alloc(&set->pool, &target);
    if (!target) {
        ogs_error("LI target pool exhausted");
        return NULL;
    }

    memset(target, 0, sizeof(*target));
    ogs_cpystrn(target->liid, liid, sizeof(target->liid));
    ogs_cpystrn(target->imsi, imsi, sizeof(target->imsi));
    if (msisdn && msisdn[0])
        ogs_cpystrn(target->msisdn, msisdn, sizeof(target->msisdn));
    target->cin = ogs_li_target_alloc_cin(set);
    target->active = true;

    ogs_list_add(&set->list, target);
    return target;
}

bool ogs_li_target_remove_by_liid(ogs_li_target_set_t *set, const char *liid)
{
    ogs_li_target_t *target = NULL;

    ogs_assert(set);
    ogs_assert(liid && liid[0]);

    target = ogs_li_target_find_by_liid(set, liid);
    if (!target)
        return false;

    ogs_list_remove(&set->list, target);
    ogs_pool_free(&set->pool, target);
    return true;
}

bool ogs_li_target_remove_by_imsi(ogs_li_target_set_t *set, const char *imsi)
{
    ogs_li_target_t *target = NULL;

    ogs_assert(set);
    ogs_assert(imsi && imsi[0]);

    target = ogs_li_target_find_by_imsi(set, imsi);
    if (!target)
        return false;

    ogs_list_remove(&set->list, target);
    ogs_pool_free(&set->pool, target);
    return true;
}

ogs_li_target_t *ogs_li_target_find_by_imsi(
        const ogs_li_target_set_t *set, const char *imsi)
{
    ogs_li_target_t *target = NULL;

    ogs_assert(set);
    ogs_assert(imsi && imsi[0]);

    ogs_list_for_each(&set->list, target) {
        if (target->active && strcmp(target->imsi, imsi) == 0)
            return target;
    }

    return NULL;
}

ogs_li_target_t *ogs_li_target_find_by_liid(
        const ogs_li_target_set_t *set, const char *liid)
{
    ogs_li_target_t *target = NULL;

    ogs_assert(set);
    ogs_assert(liid && liid[0]);

    ogs_list_for_each(&set->list, target) {
        if (strcmp(target->liid, liid) == 0)
            return target;
    }

    return NULL;
}

uint32_t ogs_li_target_alloc_cin(ogs_li_target_set_t *set)
{
    uint32_t cin;

    ogs_assert(set);

    cin = set->next_cin++;
    if (set->next_cin == 0)
        set->next_cin = 1;

    return cin;
}
