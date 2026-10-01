/*
 * Copyright (C) 2026 by Ahmad Raeiji <ahmad.rayeji@gmail.com>
 *
 * This file is part of Open5GS / Pretty5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "ogs-sbi.h"
#include "core/abts.h"

#define LOCK_THREADS 4
#define LOCK_LOOPS 20000

static int shared_counter;
static int inside;
static int overlap;

static void lock_thread(void *data)
{
    int i;

    /* no app pollset to wake in a unit test */
    ogs_sbi_lock_mark_poller();

    for (i = 0; i < LOCK_LOOPS; i++) {
        ogs_sbi_lock();
        if (++inside != 1)
            overlap++;

        /* nested, as handlers re-enter lib/sbi helpers */
        ogs_sbi_lock();
        shared_counter++;
        ogs_sbi_unlock();

        inside--;
        ogs_sbi_unlock();
    }
}

static void test1_func(abts_case *tc, void *data)
{
    /* disabled (the default): no-ops, always "held" */
    ABTS_TRUE(tc, !ogs_sbi_lock_is_enabled());
    ogs_sbi_lock();
    ogs_sbi_unlock();
    ABTS_TRUE(tc, ogs_sbi_lock_held());
}

static void test2_func(abts_case *tc, void *data)
{
    ogs_sbi_lock_mark_poller();
    ogs_sbi_lock_enable();
    ogs_sbi_lock_enable();
    ABTS_TRUE(tc, ogs_sbi_lock_is_enabled());

    ABTS_TRUE(tc, !ogs_sbi_lock_held());
    ogs_sbi_lock();
    ABTS_TRUE(tc, ogs_sbi_lock_held());
    ogs_sbi_lock();
    ogs_sbi_unlock();
    ABTS_TRUE(tc, ogs_sbi_lock_held());
    ogs_sbi_unlock();
    ABTS_TRUE(tc, !ogs_sbi_lock_held());
}

static void test3_func(abts_case *tc, void *data)
{
    ogs_thread_t *thread[LOCK_THREADS];
    int i;

    ABTS_TRUE(tc, ogs_sbi_lock_is_enabled());

    shared_counter = 0;
    inside = 0;
    overlap = 0;

    for (i = 0; i < LOCK_THREADS; i++) {
        thread[i] = ogs_thread_create(lock_thread, NULL);
        ABTS_PTR_NOTNULL(tc, thread[i]);
    }
    for (i = 0; i < LOCK_THREADS; i++)
        ogs_thread_destroy(thread[i]);

    ABTS_INT_EQUAL(tc, 0, overlap);
    ABTS_INT_EQUAL(tc, LOCK_THREADS * LOCK_LOOPS, shared_counter);
    ABTS_TRUE(tc, !ogs_sbi_lock_held());
}

abts_suite *test_sbi_lock(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, test1_func, NULL);
    abts_run_test(suite, test2_func, NULL);
    abts_run_test(suite, test3_func, NULL);

    return suite;
}
