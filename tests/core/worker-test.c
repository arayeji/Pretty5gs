/*
 * Copyright (C) 2019-2026 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
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

#include "ogs-core.h"
#include "core/abts.h"

/*
 * ogs_worker contract the NF offload threads (MME s1ap-rx/-free,
 * AMF ngap-rx/-free) rely on: FIFO dispatch on the worker thread,
 * non-blocking post that reports a full queue, startup barrier and
 * cross-thread pkbuf frees with per-thread pools.
 */

#define WAIT_MS_MAX 5000

typedef struct worker_state_s {
    ogs_thread_mutex_t mutex;
    ogs_thread_cond_t cond;

    int count;
    int order_errors;
    int identity_errors;
    int last_seq;

    bool block;         /* dispatch parks until cleared */
    bool blocked;       /* dispatch is parked */

    bool init_ran;
    ogs_pkbuf_pool_t *pool;
    ogs_pkbuf_t *pkbuf; /* hand-off slot, worker -> main */
} worker_state_t;

typedef struct worker_event_s {
    int seq;
    ogs_pkbuf_t *pkbuf; /* main -> worker, freed on the worker */
    bool alloc;         /* worker allocates one for main */
} worker_event_t;

static worker_event_t *worker_event_new(int seq)
{
    worker_event_t *e = ogs_calloc(1, sizeof(*e));
    ogs_assert(e);
    e->seq = seq;
    return e;
}

static void state_init(worker_state_t *s)
{
    memset(s, 0, sizeof(*s));
    ogs_thread_mutex_init(&s->mutex);
    ogs_thread_cond_init(&s->cond);
    s->last_seq = -1;
}

static void state_final(worker_state_t *s)
{
    ogs_thread_cond_destroy(&s->cond);
    ogs_thread_mutex_destroy(&s->mutex);
}

static void worker_dispatch(ogs_worker_t *worker, void *event)
{
    worker_state_t *s = worker->data;
    worker_event_t *e = event;

    ogs_thread_mutex_lock(&s->mutex);

    if (ogs_worker_self() != worker ||
            ogs_worker_self_id() != worker->id + 1)
        s->identity_errors++;

    if (e->seq != s->last_seq + 1)
        s->order_errors++;
    s->last_seq = e->seq;

    while (s->block) {
        s->blocked = true;
        ogs_thread_cond_signal(&s->cond);
        ogs_thread_cond_wait(&s->cond, &s->mutex);
    }
    s->blocked = false;

    if (e->alloc) {
        s->pkbuf = ogs_pkbuf_alloc(NULL, 100);
        ogs_assert(s->pkbuf);
    }

    s->count++;
    ogs_thread_cond_signal(&s->cond);
    ogs_thread_mutex_unlock(&s->mutex);

    if (e->pkbuf)
        ogs_pkbuf_free(e->pkbuf);
    ogs_free(e);
}

static void worker_thread_init(ogs_worker_t *worker)
{
    worker_state_t *s = worker->data;

    if (s->pool)
        ogs_pkbuf_thread_pool_set(s->pool);
    s->init_ran = true;
}

static bool state_wait(worker_state_t *s, int count, bool blocked)
{
    int waited = 0;
    bool ok;

    ogs_thread_mutex_lock(&s->mutex);
    while (s->count < count || (blocked && !s->blocked)) {
        ogs_thread_mutex_unlock(&s->mutex);
        if (waited++ >= WAIT_MS_MAX) {
            ogs_thread_mutex_lock(&s->mutex);
            break;
        }
        ogs_msleep(1);
        ogs_thread_mutex_lock(&s->mutex);
    }
    ok = s->count >= count && (!blocked || s->blocked);
    ogs_thread_mutex_unlock(&s->mutex);

    return ok;
}

static ogs_worker_t *worker_new(worker_state_t *s, unsigned int capacity)
{
    ogs_worker_t *worker = ogs_worker_create(
            0, capacity, 16, 16, worker_dispatch, s);
    ogs_assert(worker);
    ogs_worker_hooks(worker, worker_thread_init, NULL);
    ogs_worker_set_name(worker, "worker-test");
    return worker;
}

static void worker_free(ogs_worker_t *worker)
{
    ogs_worker_join(worker);
    ogs_worker_destroy(worker);
}

/* FIFO order, identity on both sides, startup barrier */
static void test1_func(abts_case *tc, void *data)
{
    worker_state_t s;
    ogs_worker_t *worker = NULL;
    int i;

    state_init(&s);
    worker = worker_new(&s, 256);

    ogs_worker_start(worker);
    ABTS_TRUE(tc, s.init_ran);

    ABTS_PTR_EQUAL(tc, NULL, ogs_worker_self());
    ABTS_INT_EQUAL(tc, 0, ogs_worker_self_id());
    ABTS_TRUE(tc, ogs_worker_active());

    for (i = 0; i < 200; i++)
        ABTS_INT_EQUAL(tc, OGS_OK,
                ogs_worker_post(worker, worker_event_new(i)));

    ABTS_TRUE(tc, state_wait(&s, 200, false));
    ABTS_INT_EQUAL(tc, 200, s.count);
    ABTS_INT_EQUAL(tc, 0, s.order_errors);
    ABTS_INT_EQUAL(tc, 0, s.identity_errors);

    worker_free(worker);
    state_final(&s);
}

/* A full queue is reported, never waited on */
static void test2_func(abts_case *tc, void *data)
{
    worker_state_t s;
    ogs_worker_t *worker = NULL;
    worker_event_t *extra = NULL;
    ogs_time_t start;
    int i, capacity = 4, rv;

    state_init(&s);
    worker = worker_new(&s, capacity);
    ogs_worker_start(worker);

    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_worker_post(worker, NULL));

    /* park the worker inside dispatch of event 0 */
    s.block = true;
    ABTS_INT_EQUAL(tc, OGS_OK, ogs_worker_post(worker, worker_event_new(0)));
    ABTS_TRUE(tc, state_wait(&s, 0, true));

    for (i = 1; i <= capacity; i++)
        ABTS_INT_EQUAL(tc, OGS_OK,
                ogs_worker_post(worker, worker_event_new(i)));

    extra = worker_event_new(capacity + 1);
    start = ogs_get_monotonic_time();
    rv = ogs_worker_post(worker, extra);
    ABTS_INT_EQUAL(tc, OGS_RETRY, rv);
    ABTS_TRUE(tc, ogs_get_monotonic_time() - start < ogs_time_from_msec(100));

    /* the caller still owns a refused event */
    if (rv != OGS_OK)
        ogs_free(extra);

    ogs_thread_mutex_lock(&s.mutex);
    s.block = false;
    ogs_thread_cond_broadcast(&s.cond);
    ogs_thread_mutex_unlock(&s.mutex);

    ABTS_TRUE(tc, state_wait(&s, capacity + 1, false));
    ABTS_INT_EQUAL(tc, capacity + 1, s.count);
    ABTS_INT_EQUAL(tc, 0, s.order_errors);

    worker_free(worker);
    state_final(&s);
}

/* pkbufs cross threads in both directions with a per-thread pool */
static void test3_func(abts_case *tc, void *data)
{
    worker_state_t s;
    ogs_worker_t *worker = NULL;
    ogs_pkbuf_config_t config;
    worker_event_t *e = NULL;
    int i;

    memset(&config, 0, sizeof(config));
    config.cluster_128_pool = 64;
    config.cluster_256_pool = 16;
    config.cluster_512_pool = 16;
    config.cluster_1024_pool = 16;
    config.cluster_2048_pool = 16;
    config.cluster_8192_pool = 16;

    state_init(&s);
    /* talloc builds have no pools: only the cross-thread frees remain */
    s.pool = ogs_pkbuf_pool_create(&config);
#if OGS_USE_TALLOC == 0
    ABTS_PTR_NOTNULL(tc, s.pool);
#endif

    worker = worker_new(&s, 64);
    ogs_worker_start(worker);

    for (i = 0; i < 32; i++) {
        /* main-allocated buffer, freed on the worker */
        e = worker_event_new(i);
        e->pkbuf = ogs_pkbuf_alloc(NULL, 100);
        ABTS_PTR_NOTNULL(tc, e->pkbuf);
        e->alloc = true;
        ABTS_INT_EQUAL(tc, OGS_OK, ogs_worker_post(worker, e));

        ABTS_TRUE(tc, state_wait(&s, i + 1, false));

        /* worker-allocated buffer, freed on main */
        ogs_thread_mutex_lock(&s.mutex);
        ABTS_PTR_NOTNULL(tc, s.pkbuf);
#if OGS_USE_TALLOC == 0
        if (s.pkbuf)
            ABTS_PTR_EQUAL(tc, s.pool, s.pkbuf->pool);
#endif
        if (s.pkbuf)
            ogs_pkbuf_free(s.pkbuf);
        s.pkbuf = NULL;
        ogs_thread_mutex_unlock(&s.mutex);
    }

    ABTS_INT_EQUAL(tc, 0, s.order_errors);

    worker_free(worker);

    /* every buffer from the pool is back: it can go now */
    if (s.pool)
        ogs_pkbuf_pool_destroy(s.pool);
    state_final(&s);
}

/* Several producers, one consumer: nothing lost when producers retry */
typedef struct producer_s {
    ogs_worker_t *worker;
    int base;
    int n;
    int retries;
} producer_t;

static int mp_count[4];
static ogs_thread_mutex_t mp_mutex;

static void mp_dispatch(ogs_worker_t *worker, void *event)
{
    worker_event_t *e = event;

    ogs_thread_mutex_lock(&mp_mutex);
    mp_count[e->seq / 10000]++;
    ogs_thread_mutex_unlock(&mp_mutex);
    ogs_free(e);
}

static void producer_main(void *data)
{
    producer_t *p = data;
    int i;

    for (i = 0; i < p->n; i++) {
        worker_event_t *e = worker_event_new(p->base + i);
        while (ogs_worker_post(p->worker, e) == OGS_RETRY) {
            p->retries++;
            ogs_usleep(50);
        }
    }
}

static void test4_func(abts_case *tc, void *data)
{
    ogs_worker_t *worker = NULL;
    ogs_thread_t *thread[4];
    producer_t p[4];
    int i, total, waited = 0;

    memset(mp_count, 0, sizeof(mp_count));
    ogs_thread_mutex_init(&mp_mutex);

    worker = ogs_worker_create(1, 64, 16, 16, mp_dispatch, NULL);
    ABTS_PTR_NOTNULL(tc, worker);
    ogs_worker_start(worker);

    for (i = 0; i < 4; i++) {
        p[i].worker = worker;
        p[i].base = i * 10000;
        p[i].n = 5000;
        p[i].retries = 0;
        thread[i] = ogs_thread_create(producer_main, &p[i]);
        ABTS_PTR_NOTNULL(tc, thread[i]);
    }
    for (i = 0; i < 4; i++)
        ogs_thread_destroy(thread[i]);

    do {
        ogs_thread_mutex_lock(&mp_mutex);
        total = mp_count[0] + mp_count[1] + mp_count[2] + mp_count[3];
        ogs_thread_mutex_unlock(&mp_mutex);
        if (total >= 4 * 5000)
            break;
        ogs_msleep(1);
    } while (waited++ < WAIT_MS_MAX);

    for (i = 0; i < 4; i++)
        ABTS_INT_EQUAL(tc, 5000, mp_count[i]);

    worker_free(worker);
    ogs_thread_mutex_destroy(&mp_mutex);
}

abts_suite *test_worker(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, test1_func, NULL);
    abts_run_test(suite, test2_func, NULL);
    abts_run_test(suite, test3_func, NULL);
    abts_run_test(suite, test4_func, NULL);

    return suite;
}
