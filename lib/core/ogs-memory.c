/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#if !defined(_WIN32)
#include <execinfo.h>
#include <unistd.h>
#endif

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __ogs_mem_domain

/*****************************************
 * Memory Pool - Use talloc library
 *****************************************/

void *__ogs_talloc_core;

static ogs_thread_mutex_t mutex;

/*
 * talloc_abort() (bad magic = use-after-free / heap overrun of a
 * talloc chunk) calls abort() WITHOUT any output unless a log
 * function is registered — production died with silent SIGABRTs and
 * truncated cores that could not be unwound. Log the reason and a
 * backtrace through the ogs log (and raw stderr as a fallback, in
 * case the log mutex is what got corrupted) before dying.
 */
static void mem_talloc_log(const char *message)
{
    ogs_fatal("talloc: %s", message);

#if !defined(_WIN32)
    {
        void *addrs[32];
        int n = backtrace(addrs, 32);
        backtrace_symbols_fd(addrs, n, STDERR_FILENO);
    }
#endif
}

static void mem_talloc_abort(const char *reason)
{
    mem_talloc_log(reason);
    abort();
}

void ogs_mem_init(void)
{
    /*
     * The mutex now only guards the few residual REAL talloc users
     * (sgwu/upf packet_pool setup, final leak report) via
     * ogs_mem_get_mutex(). The ogs_malloc/ogs_free hot path no longer
     * touches it at all -- see the comment above ogs_talloc_size().
     */
    ogs_thread_mutex_init(&mutex);

    talloc_enable_null_tracking();
    talloc_set_log_fn(mem_talloc_log);
    talloc_set_abort_fn(mem_talloc_abort);

#define TALLOC_MEMSIZE 1
    __ogs_talloc_core = talloc_named_const(NULL, TALLOC_MEMSIZE, "core");
}

void ogs_mem_final(void)
{
    if (talloc_total_size(__ogs_talloc_core) != TALLOC_MEMSIZE)
        talloc_report_full(__ogs_talloc_core, stderr);

    talloc_free(__ogs_talloc_core);

    ogs_thread_mutex_destroy(&mutex);
}

void *ogs_mem_get_mutex(void)
{
    return &mutex;
}

/*
 * PLAIN GLIBC HEAP, NOT TALLOC, AND NO GLOBAL MUTEX.
 *
 * These wrappers used to call talloc under one process-global mutex.
 * talloc itself is not thread-safe, so every ogs_malloc / ogs_calloc /
 * ogs_realloc / ogs_free / ogs_strdup / ogs_msprintf in the process --
 * including the thousands of ASN.1 CALLOC/FREEMEM per decoded S1AP
 * message across all s1ap-rx/tx/free and shard worker threads --
 * serialized on that single lock.
 *
 * Production DWARF profiling (MME, ~30 active threads, 841k samples)
 * showed ~40% of ALL cycles in pthread_mutex_lock/unlock + futex under
 * ogs_talloc_free/size/zero_size/realloc_size: a lock convoy that got
 * WORSE with every thread added. An ADAPTIVE_NP spin mutex was tried
 * first and did not help (the section is too hot for 20+ contenders).
 *
 * Nothing in the tree uses the talloc hierarchy for these allocations:
 * every call sites parents to the single global __ogs_talloc_core, so
 * talloc only ever provided the exit-time leak report. glibc malloc is
 * fully thread-safe with per-thread tcache/arenas, which removes the
 * global lock entirely. The ctx/name/location arguments are kept so
 * the ABI and every call site stay unchanged.
 *
 * Real talloc remains only for __ogs_talloc_core itself and the
 * vestigial sgwu/upf packet_pool (created once, single-threaded).
 */
void *ogs_talloc_size(const void *ctx, size_t size, const char *name)
{
    void *ptr = NULL;

    (void)ctx;
    (void)name;

    ptr = malloc(size);
    ogs_expect(ptr);

    return ptr;
}

void *ogs_talloc_zero_size(const void *ctx, size_t size, const char *name)
{
    void *ptr = NULL;

    (void)ctx;
    (void)name;

    ptr = calloc(1, size);
    ogs_expect(ptr);

    return ptr;
}

void *ogs_talloc_realloc_size(
        const void *context, void *oldptr, size_t size, const char *name)
{
    void *ptr = NULL;

    (void)context;
    (void)name;

    /* match talloc_realloc(): size 0 frees */
    if (size == 0) {
        free(oldptr);
        return NULL;
    }

    ptr = realloc(oldptr, size);
    ogs_expect(ptr);

    return ptr;
}

int ogs_talloc_free(void *ptr, const char *location)
{
    (void)location;

    free(ptr);

    return 0;
}

/*****************************************
 * Memory Pool - Use pkbuf library
 *****************************************/

void *ogs_malloc_debug(size_t size, const char *file_line)
{
    size_t headroom = 0;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(size);

    headroom = sizeof(ogs_pkbuf_t *);
    pkbuf = ogs_pkbuf_alloc_debug(NULL, headroom + size, file_line);
    if (!pkbuf) {
        ogs_error("ogs_pkbuf_alloc_debug[headroom:%d, size:%d] failed",
                (int)headroom, (int)size);
        return NULL;
    }

    ogs_pkbuf_reserve(pkbuf, headroom);
    memcpy(pkbuf->head, &pkbuf, headroom);
    ogs_pkbuf_put(pkbuf, size);

    return pkbuf->data;
}

int ogs_free_debug(void *ptr)
{
    size_t headroom;
    ogs_pkbuf_t *pkbuf = NULL;

    if (!ptr)
        return OGS_ERROR;

    headroom = sizeof(ogs_pkbuf_t *);
    memcpy(&pkbuf, (unsigned char*)ptr - headroom, headroom);
    ogs_assert(pkbuf);

    ogs_pkbuf_free(pkbuf);

    return OGS_OK;
}

void *ogs_calloc_debug(size_t nmemb, size_t size, const char *file_line)
{
    void *ptr = NULL;

    ptr = ogs_malloc_debug(nmemb * size, file_line);
    if (!ptr) {
        ogs_error("ogs_malloc_debug[nmemb:%d, size:%d] failed",
                (int)nmemb, (int)size);
        return NULL;
    }

    memset(ptr, 0, nmemb * size);
    return ptr;
}

void *ogs_realloc_debug(void *ptr, size_t size, const char *file_line)
{
    size_t headroom = 0;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_cluster_t *cluster = NULL;

    if (!ptr)
        return ogs_malloc(size);

    headroom = sizeof(ogs_pkbuf_t *);

    memcpy(&pkbuf, (unsigned char*)ptr - headroom, headroom);

    if (!pkbuf) {
        ogs_error("Cannot get pkbuf from ptr[%p], headroom[%d]",
                ptr, (int)headroom);
        return NULL;
    }

    cluster = pkbuf->cluster;
    if (!cluster) {
        ogs_error("No cluster");
        return NULL;
    }

    if (!size) {
        ogs_pkbuf_free(pkbuf);
        return NULL;
    }

    if (size > (cluster->size - headroom)) {
        void *new = NULL;

        new = ogs_malloc_debug(size, file_line);
        if (!new) {
            ogs_error("ogs_malloc_debug[%d] failed", (int)size);
            return NULL;
        }

        memcpy(new, ptr, pkbuf->len);

        ogs_pkbuf_free(pkbuf);
        return new;
    } else {
        pkbuf->tail = pkbuf->data + size;
        pkbuf->len = size;
        return ptr;
    }
}
