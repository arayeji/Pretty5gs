/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (C) 2019-2020 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ogs-core.h"

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __ogs_event_domain

typedef struct ogs_queue_s {
    void              **data;
    unsigned int        nelts; /**< # elements */
    unsigned int        in;    /**< next empty location */
    unsigned int        out;   /**< next filled location */
    unsigned int        bounds;/**< max size of queue */
    unsigned int        full_waiters;
    unsigned int        empty_waiters;
    ogs_thread_mutex_t  one_big_mutex;
    ogs_thread_cond_t   not_empty;
    ogs_thread_cond_t   not_full;
    int                 terminated;
} ogs_queue_t;

/**
 * Detects when the ogs_queue_t is full. This utility function is expected
 * to be called from within critical sections, and is not threadsafe.
 */
#define ogs_queue_full(queue) ((queue)->nelts == (queue)->bounds)

/*
 * Upper bound on how long ogs_queue_push() (nominally an infinite wait)
 * will block on a full queue before returning OGS_RETRY. See queue_push().
 */
#define OGS_QUEUE_PUSH_MAX_WAIT ogs_time_from_msec(20)

/**
 * Detects when the ogs_queue_t is empty. This utility function is expected
 * to be called from within critical sections, and is not threadsafe.
 */
#define ogs_queue_empty(queue) ((queue)->nelts == 0)

/**
 * Callback routine that is called to destroy this
 * ogs_queue_t when its pool is destroyed.
 */
ogs_queue_t *ogs_queue_create(unsigned int capacity)
{
    ogs_queue_t *queue = ogs_calloc(1, sizeof *queue);
    if (!queue) {
        ogs_error("ogs_calloc() failed");
        return NULL;
    }
    ogs_assert(queue);

    ogs_thread_mutex_init(&queue->one_big_mutex);
    ogs_thread_cond_init(&queue->not_empty);
    ogs_thread_cond_init(&queue->not_full);

    /*
     * System calloc, not ogs_calloc: the latter goes through talloc, which
     * rejects any single allocation >= 256 MB (MAX_TALLOC_SIZE). The queue
     * is sized max.ue * pool_per_ue, so large deployments (> ~2M UEs with
     * the default multiplier of 16) exceed that cap and the daemon could
     * never start. This is init-time, like ogs_pool_init(), so bypassing
     * the talloc pool is also the right thing for fragmentation.
     */
    queue->data = calloc(capacity, sizeof(void*));
    if (!queue->data) {
        ogs_error("calloc[capacity:%d, sizeof(void*):%d] failed",
                (int)capacity, (int)sizeof(void*));
        return NULL;
    }
    queue->bounds = capacity;
    queue->nelts = 0;
    queue->in = 0;
    queue->out = 0;
    queue->terminated = 0;
    queue->full_waiters = 0;
    queue->empty_waiters = 0;

    return queue;
}

void ogs_queue_destroy(ogs_queue_t *queue)
{
    ogs_assert(queue);

    free(queue->data);  /* allocated with system calloc, see create */

    ogs_thread_cond_destroy(&queue->not_empty);
    ogs_thread_cond_destroy(&queue->not_full);
    ogs_thread_mutex_destroy(&queue->one_big_mutex);

    ogs_free(queue);
}

static int queue_push(ogs_queue_t *queue, void *data, ogs_time_t timeout,
        bool *was_empty)
{
    ogs_time_t deadline = 0;
    int rv;

    ogs_thread_mutex_lock(&queue->one_big_mutex);

    /* checked under the mutex: ogs_queue_term() sets it while holding
     * the same lock, so an unlocked read here is a data race */
    if (queue->terminated) {
        ogs_thread_mutex_unlock(&queue->one_big_mutex);
        return OGS_DONE; /* no more elements ever again */
    }

    /*
     * Wait until there is room. Infinite waiters LOOP on a still-full queue
     * after a cond wake — spurious wakes and multi-waiter races are normal,
     * and returning immediately used to drop the push (fatal for MME S1AP
     * TX_READY: s1ap_tx_pending leaks and the eNB hold list wedges).
     *
     * The loop is bounded, though. Every NF pushes onto ogs_app()->queue
     * from inside its main-thread poll and timer callbacks, and the main
     * thread is that queue's only consumer: an unbounded wait there is a
     * self-deadlock. The main loop stops polling, sockets it owns are never
     * read again, and the NF goes silently dead with full kernel Recv-Qs.
     * Give up after OGS_QUEUE_PUSH_MAX_WAIT so callers (all of which drop
     * and free on != OGS_OK, or retry from a thread where that is safe) can
     * make progress. Timed / try paths keep their old semantics.
     */
    while (ogs_queue_full(queue)) {
        if (!timeout) {
            ogs_thread_mutex_unlock(&queue->one_big_mutex);
            return OGS_RETRY;
        }
        if (queue->terminated) {
            ogs_thread_mutex_unlock(&queue->one_big_mutex);
            return OGS_DONE;
        }

        if (timeout < 0 && !deadline)
            deadline = ogs_time_now() + OGS_QUEUE_PUSH_MAX_WAIT;

        queue->full_waiters++;
        rv = ogs_thread_cond_timedwait(&queue->not_full,
                                       &queue->one_big_mutex,
                                       timeout > 0 ?
                                           timeout : OGS_QUEUE_PUSH_MAX_WAIT);
        queue->full_waiters--;
        if (rv != OGS_OK) {
            ogs_thread_mutex_unlock(&queue->one_big_mutex);
            return timeout > 0 ? rv : OGS_RETRY;
        }

        if (ogs_queue_full(queue)) {
            if (queue->terminated) {
                ogs_thread_mutex_unlock(&queue->one_big_mutex);
                return OGS_DONE;
            }
            if (timeout > 0) {
                ogs_warn("queue full (intr)");
                ogs_thread_mutex_unlock(&queue->one_big_mutex);
                return OGS_ERROR;
            }
            /* Infinite wait: spuriously woken or lost the free slot. */
            if (ogs_time_now() >= deadline) {
                ogs_thread_mutex_unlock(&queue->one_big_mutex);
                return OGS_RETRY;
            }
            continue;
        }
    }

    /* Observed under the mutex: lets producers skip the consumer
     * wakeup when the (fully-draining) consumer must still be awake. */
    if (was_empty)
        *was_empty = (queue->nelts == 0);

    queue->data[queue->in] = data;
    queue->in++;
    if (queue->in >= queue->bounds)
        queue->in -= queue->bounds;
    queue->nelts++;

    if (queue->empty_waiters) {
        ogs_trace("signal !empty");
        ogs_thread_cond_signal(&queue->not_empty);
    }

    ogs_thread_mutex_unlock(&queue->one_big_mutex);
    return OGS_OK;
}

int ogs_queue_push(ogs_queue_t *queue, void *data)
{
    return queue_push(queue, data, OGS_INFINITE_TIME, NULL);
}

/**
 * Push new data onto the queue. If the queue is full, return OGS_RETRY. If
 * the push operation completes successfully, it signals other threads
 * waiting in ogs_queue_pop() that they may continue consuming sockets.
 */
int ogs_queue_trypush(ogs_queue_t *queue, void *data)
{
    return queue_push(queue, data, 0, NULL);
}

/*
 * Like ogs_queue_trypush(), but reports (under the queue mutex)
 * whether the queue was EMPTY before this push. A consumer that
 * drains to empty before sleeping only needs a wakeup for the
 * empty -> non-empty transition; producers can skip the (syscall)
 * notify otherwise.
 */
int ogs_queue_trypush_hint(ogs_queue_t *queue, void *data, bool *was_empty)
{
    return queue_push(queue, data, 0, was_empty);
}

int ogs_queue_timedpush(ogs_queue_t *queue, void *data, ogs_time_t timeout)
{
    return queue_push(queue, data, timeout, NULL);
}

/**
 * not thread safe
 */
unsigned int ogs_queue_size(ogs_queue_t *queue) {
    return queue->nelts;
}

/**
 * not thread safe (diagnostic read; bounds is immutable after create)
 */
unsigned int ogs_queue_capacity(ogs_queue_t *queue) {
    return queue->bounds;
}

/**
 * Retrieves the next item from the queue. If there are no
 * items available, it will either return OGS_RETRY (timeout = 0),
 * or block until one becomes available (infinitely with timeout < 0,
 * otherwise until the given timeout expires). Once retrieved, the
 * item is placed into the address specified by 'data'.
 */
static int queue_pop(ogs_queue_t *queue, void **data, ogs_time_t timeout)
{
    int rv;

    ogs_thread_mutex_lock(&queue->one_big_mutex);

    if (queue->terminated) {
        ogs_thread_mutex_unlock(&queue->one_big_mutex);
        return OGS_DONE; /* no more elements ever again */
    }

    /* Keep waiting until we wake up and find that the queue is not empty. */
    while (ogs_queue_empty(queue)) {
        if (!timeout) {
            ogs_thread_mutex_unlock(&queue->one_big_mutex);
            return OGS_RETRY;
        }
        if (queue->terminated) {
            ogs_thread_mutex_unlock(&queue->one_big_mutex);
            return OGS_DONE;
        }

        queue->empty_waiters++;
        if (timeout > 0) {
            rv = ogs_thread_cond_timedwait(&queue->not_empty,
                                           &queue->one_big_mutex,
                                           timeout);
        } else {
            rv = ogs_thread_cond_wait(&queue->not_empty,
                                      &queue->one_big_mutex);
        }
        queue->empty_waiters--;
        if (rv != OGS_OK) {
            ogs_thread_mutex_unlock(&queue->one_big_mutex);
            return rv;
        }

        if (ogs_queue_empty(queue)) {
            if (queue->terminated) {
                ogs_thread_mutex_unlock(&queue->one_big_mutex);
                return OGS_DONE;
            }
            if (timeout > 0) {
                ogs_warn("queue empty (intr)");
                ogs_thread_mutex_unlock(&queue->one_big_mutex);
                return OGS_ERROR;
            }
            continue;
        }
    } 

    *data = queue->data[queue->out];
    queue->nelts--;

    queue->out++;
    if (queue->out >= queue->bounds)
        queue->out -= queue->bounds;
    if (queue->full_waiters) {
        ogs_trace("signal !full");
        ogs_thread_cond_signal(&queue->not_full);
    }

    ogs_thread_mutex_unlock(&queue->one_big_mutex);
    return OGS_OK;
}

int ogs_queue_pop(ogs_queue_t *queue, void **data)
{
    return queue_pop(queue, data, OGS_INFINITE_TIME);
}

int ogs_queue_trypop(ogs_queue_t *queue, void **data)
{
    return queue_pop(queue, data, 0);
}

int ogs_queue_timedpop(ogs_queue_t *queue, void **data, ogs_time_t timeout)
{
    return queue_pop(queue, data, timeout);
}

int ogs_queue_interrupt_all(ogs_queue_t *queue)
{
    ogs_debug("interrupt all");
    ogs_thread_mutex_lock(&queue->one_big_mutex);

    ogs_thread_cond_broadcast(&queue->not_empty);
    ogs_thread_cond_broadcast(&queue->not_full);

    ogs_thread_mutex_unlock(&queue->one_big_mutex);

    return OGS_OK;
}

int ogs_queue_term(ogs_queue_t *queue)
{
    ogs_thread_mutex_lock(&queue->one_big_mutex);

    /* we must hold one_big_mutex when setting this... otherwise,
     * we could end up setting it and waking everybody up just after a 
     * would-be popper checks it but right before they block
     */
    queue->terminated = 1;
    ogs_thread_mutex_unlock(&queue->one_big_mutex);

    return ogs_queue_interrupt_all(queue);
}

