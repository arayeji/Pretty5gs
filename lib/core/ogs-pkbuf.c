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

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __ogs_mem_domain

#if OGS_USE_TALLOC == 0
#define OGS_CLUSTER_128_SIZE    128
#define OGS_CLUSTER_256_SIZE    256
#define OGS_CLUSTER_512_SIZE    512
#define OGS_CLUSTER_1024_SIZE   1024
#define OGS_CLUSTER_2048_SIZE   2048
#define OGS_CLUSTER_8192_SIZE   8192
#define OGS_CLUSTER_32768_SIZE  32768

/*
 *
 * In lib/core/ogs-kqueue.c:69
 *   context->change_list = ogs_calloc(
 *       pollset->capacity, sizeof(struct kevent));
 *   1. pollset->capacity : 1024*16
 *   2. sizeof(struct kevent) : 64
 *   3. sizeof(ogs_pkbuf_t *) is headroom in ogs_calloc()
 *
 * So, we use BIG_SIZE : 1024*(16*64=1024)*64+8
 */
#define OGS_CLUSTER_BIG_SIZE    (1024*1024+sizeof(ogs_pkbuf_t *))

typedef uint8_t ogs_cluster_128_t[OGS_CLUSTER_128_SIZE];
typedef uint8_t ogs_cluster_256_t[OGS_CLUSTER_256_SIZE];
typedef uint8_t ogs_cluster_512_t[OGS_CLUSTER_512_SIZE];
typedef uint8_t ogs_cluster_1024_t[OGS_CLUSTER_1024_SIZE];
typedef uint8_t ogs_cluster_2048_t[OGS_CLUSTER_2048_SIZE];
typedef uint8_t ogs_cluster_8192_t[OGS_CLUSTER_8192_SIZE];
typedef uint8_t ogs_cluster_32768_t[OGS_CLUSTER_32768_SIZE];
typedef uint8_t ogs_cluster_big_t[OGS_CLUSTER_BIG_SIZE];

OGS_STATIC_ASSERT(sizeof(ogs_cluster_128_t) % sizeof(void *) == 0);
OGS_STATIC_ASSERT(sizeof(ogs_cluster_256_t) % sizeof(void *) == 0);
OGS_STATIC_ASSERT(sizeof(ogs_cluster_512_t) % sizeof(void *) == 0);
OGS_STATIC_ASSERT(sizeof(ogs_cluster_1024_t) % sizeof(void *) == 0);
OGS_STATIC_ASSERT(sizeof(ogs_cluster_2048_t) % sizeof(void *) == 0);
OGS_STATIC_ASSERT(sizeof(ogs_cluster_8192_t) % sizeof(void *) == 0);
OGS_STATIC_ASSERT(sizeof(ogs_cluster_32768_t) % sizeof(void *) == 0);
OGS_STATIC_ASSERT(sizeof(ogs_cluster_big_t) % sizeof(void *) == 0);

typedef struct ogs_pkbuf_pool_s {
    OGS_POOL(pkbuf, ogs_pkbuf_t);
    OGS_POOL(cluster, ogs_cluster_t);

    OGS_POOL(cluster_128, ogs_cluster_128_t);
    OGS_POOL(cluster_256, ogs_cluster_256_t);
    OGS_POOL(cluster_512, ogs_cluster_512_t);
    OGS_POOL(cluster_1024, ogs_cluster_1024_t);
    OGS_POOL(cluster_2048, ogs_cluster_2048_t);
    OGS_POOL(cluster_8192, ogs_cluster_8192_t);
    OGS_POOL(cluster_32768, ogs_cluster_32768_t);
    OGS_POOL(cluster_big, ogs_cluster_big_t);

    ogs_thread_mutex_t mutex;
} ogs_pkbuf_pool_t;

static OGS_POOL(pkbuf_pool, ogs_pkbuf_pool_t);
static ogs_pkbuf_pool_t *default_pool = NULL;

/*
 * Optional per-thread pool: when set, ogs_pkbuf_alloc(NULL, ...) tries
 * this pool before the process-global default_pool. The default pool's
 * single mutex is taken by EVERY alloc/free/copy in the process; on an
 * NF with many worker threads (MME shard/RX/TX/IO) it becomes the one
 * lock everybody contends on. A thread pool moves the alloc side to a
 * per-thread mutex; frees keep routing through pkbuf->pool so a buffer
 * allocated here can safely be freed by any other thread. Exhaustion
 * (or a size class the thread pool does not stock) silently falls back
 * to default_pool, so sizing a thread pool too small degrades to
 * today's behavior instead of dropping packets.
 */
static OGS_THREAD_LOCAL ogs_pkbuf_pool_t *thread_pool = NULL;

static ogs_cluster_t *cluster_alloc(
        ogs_pkbuf_pool_t *pool, unsigned int size, bool quiet);
static void cluster_free(ogs_pkbuf_pool_t *pool, ogs_cluster_t *cluster);
static ogs_pkbuf_t *pkbuf_alloc_from(ogs_pkbuf_pool_t *pool,
        unsigned int size, const char *file_line, bool quiet);
#endif

void ogs_pkbuf_thread_pool_set(ogs_pkbuf_pool_t *pool)
{
#if OGS_USE_TALLOC == 0
    thread_pool = pool;
#endif
}

ogs_pkbuf_pool_t *ogs_pkbuf_thread_pool_get(void)
{
#if OGS_USE_TALLOC == 0
    return thread_pool;
#else
    return NULL;
#endif
}

void *ogs_pkbuf_put_data(
        ogs_pkbuf_t *pkbuf, const void *data, unsigned int len)
{
    void *tmp = ogs_pkbuf_put(pkbuf, len);

    memcpy(tmp, data, len);
    return tmp;
}

void ogs_pkbuf_init(void)
{
#if OGS_USE_TALLOC == 0
    ogs_pool_init(&pkbuf_pool, ogs_core()->pkbuf.pool);

#endif
}

void ogs_pkbuf_final(void)
{
#if OGS_USE_TALLOC == 0
    ogs_pool_final(&pkbuf_pool);
#endif
}

void ogs_pkbuf_default_init(ogs_pkbuf_config_t *config)
{
#if OGS_USE_TALLOC == 0
    ogs_assert(config);
    memset(config, 0, sizeof *config);

    config->cluster_128_pool = 65536;
    config->cluster_256_pool = 16384;
    config->cluster_512_pool = 4096;
    config->cluster_1024_pool = 2048;
    config->cluster_2048_pool = 1024;
    config->cluster_8192_pool = 256;
    config->cluster_32768_pool = 64;
    config->cluster_big_pool = 8;
#endif
}

void ogs_pkbuf_default_create(ogs_pkbuf_config_t *config)
{
#if OGS_USE_TALLOC == 0
    default_pool = ogs_pkbuf_pool_create(config);
#endif
}

void ogs_pkbuf_default_destroy(void)
{
#if OGS_USE_TALLOC == 0
    ogs_pkbuf_pool_destroy(default_pool);
#endif
}

ogs_pkbuf_pool_t *ogs_pkbuf_pool_create(ogs_pkbuf_config_t *config)
{
    ogs_pkbuf_pool_t *pool = NULL;
#if OGS_USE_TALLOC == 0
    int tmp = 0;

    ogs_assert(config);

    ogs_pool_alloc(&pkbuf_pool, &pool);
    ogs_assert(pool);
    memset(pool, 0, sizeof *pool);

    ogs_thread_mutex_init(&pool->mutex);

    tmp = config->cluster_128_pool + config->cluster_256_pool +
        config->cluster_512_pool + config->cluster_1024_pool +
        config->cluster_2048_pool + config->cluster_8192_pool +
        config->cluster_32768_pool + config->cluster_big_pool;

    ogs_pool_init(&pool->pkbuf, tmp);
    ogs_pool_init(&pool->cluster, tmp);

    ogs_pool_init(&pool->cluster_128, config->cluster_128_pool);
    ogs_pool_init(&pool->cluster_256, config->cluster_256_pool);
    ogs_pool_init(&pool->cluster_512, config->cluster_512_pool);
    ogs_pool_init(&pool->cluster_1024, config->cluster_1024_pool);
    ogs_pool_init(&pool->cluster_2048, config->cluster_2048_pool);
    ogs_pool_init(&pool->cluster_8192, config->cluster_8192_pool);
    ogs_pool_init(&pool->cluster_32768, config->cluster_32768_pool);
    ogs_pool_init(&pool->cluster_big, config->cluster_big_pool);
#endif

    return pool;
}

#define ogs_pkbuf_pool_final(pool) do { \
    if (((pool)->size != (pool)->avail)) { \
        int i; \
        ogs_error("%d in '%s[%d]' were not released.", \
                (pool)->size - (pool)->avail, (pool)->name, (pool)->size); \
        for (i = 0; i < (pool)->size; i++) { \
            ogs_pkbuf_t *pkbuf = (pool)->index[i]; \
            if (pkbuf) { \
                ogs_log_print(OGS_LOG_ERROR, "SIZE[%d] is not freed. (%s)\n", \
                        pkbuf->len, pkbuf->file_line); \
            } \
        } \
    } \
    free((pool)->free); \
    free((pool)->array); \
    free((pool)->index); \
} while (0)

void ogs_pkbuf_pool_destroy(ogs_pkbuf_pool_t *pool)
{
#if OGS_USE_TALLOC == 0
    ogs_assert(pool);

    ogs_pkbuf_pool_final(&pool->pkbuf);
    ogs_pool_final(&pool->cluster);

    ogs_pool_final(&pool->cluster_128);
    ogs_pool_final(&pool->cluster_256);
    ogs_pool_final(&pool->cluster_512);
    ogs_pool_final(&pool->cluster_1024);
    ogs_pool_final(&pool->cluster_2048);
    ogs_pool_final(&pool->cluster_8192);
    ogs_pool_final(&pool->cluster_32768);
    ogs_pool_final(&pool->cluster_big);

    ogs_thread_mutex_destroy(&pool->mutex);

    ogs_pool_free(&pkbuf_pool, pool);
#endif
}

ogs_pkbuf_t *ogs_pkbuf_alloc_debug(
        ogs_pkbuf_pool_t *pool, unsigned int size, const char *file_line)
{
#if OGS_USE_TALLOC == 1
    ogs_pkbuf_t *pkbuf = NULL;

    pkbuf = ogs_talloc_zero_size(pool, sizeof(*pkbuf) + size, file_line);
    if (!pkbuf) {
        ogs_error("ogs_pkbuf_alloc() failed [size=%d]", size);
        return NULL;
    }

    pkbuf->head = pkbuf->_data;
    pkbuf->end = pkbuf->_data + size;

    pkbuf->len = 0;

    pkbuf->data = pkbuf->_data;
    pkbuf->tail = pkbuf->_data;

    pkbuf->file_line = file_line; /* For debug */

    return pkbuf;
#else
    ogs_pkbuf_t *pkbuf = NULL;

    if (pool == NULL && thread_pool) {
        /* Try the calling thread's private pool first; on exhaustion
         * fall back (quietly) to the shared default pool below. */
        pkbuf = pkbuf_alloc_from(thread_pool, size, file_line, true);
        if (pkbuf)
            return pkbuf;
    }

    if (pool == NULL)
        pool = default_pool;
    ogs_assert(pool);

    return pkbuf_alloc_from(pool, size, file_line, false);
#endif
}

#if OGS_USE_TALLOC == 0
static ogs_pkbuf_t *pkbuf_alloc_from(ogs_pkbuf_pool_t *pool,
        unsigned int size, const char *file_line, bool quiet)
{
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_cluster_t *cluster = NULL;

    ogs_assert(pool);

    ogs_thread_mutex_lock(&pool->mutex);

    cluster = cluster_alloc(pool, size, quiet);
    if (!cluster) {
        if (!quiet)
            ogs_error("ogs_pkbuf_alloc() failed [size=%d]", size);
        ogs_thread_mutex_unlock(&pool->mutex);
        return NULL;
    }

    ogs_pool_alloc(&pool->pkbuf, &pkbuf);
    if (!pkbuf) {
        cluster_free(pool, cluster);
        if (!quiet)
            ogs_error("ogs_pkbuf_alloc() failed [size=%d]", size);
        ogs_thread_mutex_unlock(&pool->mutex);
        return NULL;
    }

    OGS_OBJECT_REF(cluster);

    ogs_thread_mutex_unlock(&pool->mutex);

    /* pkbuf and (unshared) cluster are exclusively ours from here on:
     * initialize outside the pool mutex to keep the hold time minimal */
    memset(pkbuf, 0, sizeof(*pkbuf));

    pkbuf->cluster = cluster;

    pkbuf->len = 0;

    pkbuf->data = cluster->buffer;
    pkbuf->head = cluster->buffer;
    pkbuf->tail = cluster->buffer;
    pkbuf->end = cluster->buffer + size;

    pkbuf->file_line = file_line; /* For debug */

    pkbuf->pool = pool;

    return pkbuf;
}
#endif

void ogs_pkbuf_free(ogs_pkbuf_t *pkbuf)
{
#if OGS_USE_TALLOC == 1
    ogs_talloc_free(pkbuf, OGS_FILE_LINE);
#else
    ogs_pkbuf_pool_t *pool = NULL;
    ogs_cluster_t *cluster = NULL;
    ogs_assert(pkbuf);

    pool = pkbuf->pool;
    ogs_assert(pool);

    ogs_thread_mutex_lock(&pool->mutex);

    cluster = pkbuf->cluster;
    ogs_assert(cluster);

    if (OGS_OBJECT_IS_REF(cluster))
        OGS_OBJECT_UNREF(cluster);
    else
        cluster_free(pool, pkbuf->cluster);

    ogs_pool_free(&pool->pkbuf, pkbuf);

    ogs_thread_mutex_unlock(&pool->mutex);
#endif
}

ogs_pkbuf_t *ogs_pkbuf_copy_debug(ogs_pkbuf_t *pkbuf, const char *file_line)
{
#if OGS_USE_TALLOC == 1
    ogs_pkbuf_t *newbuf;
#else
    ogs_pkbuf_pool_t *pool = NULL;
    ogs_pkbuf_t *newbuf = NULL;
#endif
    int size = 0;

    ogs_assert(pkbuf);
    size = pkbuf->end - pkbuf->head;
    if (size <= 0) {
        ogs_error("Invalid argument[size=%d, head=%p, end=%p] in (%s)",
                size, pkbuf->head, pkbuf->end, file_line);
        return NULL;
    }

#if OGS_USE_TALLOC == 1
    newbuf = ogs_pkbuf_alloc_debug(NULL, size, file_line);
    if (!newbuf) {
        ogs_error("ogs_pkbuf_alloc() failed [size=%d]", size);
        return NULL;
    }

    /* copy data */
    memcpy(newbuf->_data, pkbuf->_data, size);

    /* copy header */
    newbuf->len = pkbuf->len;

    newbuf->tail += pkbuf->tail - pkbuf->_data;
    newbuf->data += pkbuf->data - pkbuf->_data;

    return newbuf;
#else
    pool = pkbuf->pool;
    ogs_assert(pool);

    ogs_thread_mutex_lock(&pool->mutex);

    ogs_pool_alloc(&pool->pkbuf, &newbuf);
    if (!newbuf) {
        ogs_error("ogs_pkbuf_copy() failed [size=%d]", size);
        ogs_thread_mutex_unlock(&pool->mutex);
        return NULL;
    }
    ogs_assert(newbuf);
    memcpy(newbuf, pkbuf, sizeof *pkbuf);

    OGS_OBJECT_REF(newbuf->cluster);

    ogs_thread_mutex_unlock(&pool->mutex);
#endif

    return newbuf;
}

#if OGS_USE_TALLOC == 0
static ogs_cluster_t *cluster_alloc(
        ogs_pkbuf_pool_t *pool, unsigned int size, bool quiet)
{
    ogs_cluster_t *cluster = NULL;
    void *buffer = NULL;
    unsigned int cluster_size = 0;
    ogs_assert(pool);

    ogs_pool_alloc(&pool->cluster, &cluster);
    if (!cluster) {
        if (!quiet)
            ogs_error("ogs_pool_alloc() failed [size=%u]", size);
        return NULL;
    }
    memset(cluster, 0, sizeof(*cluster));

    if (size <= OGS_CLUSTER_128_SIZE) {
        ogs_pool_alloc(&pool->cluster_128, (ogs_cluster_128_t**)&buffer);
        cluster_size = OGS_CLUSTER_128_SIZE;
    } else if (size <= OGS_CLUSTER_256_SIZE) {
        ogs_pool_alloc(&pool->cluster_256, (ogs_cluster_256_t**)&buffer);
        cluster_size = OGS_CLUSTER_256_SIZE;
    } else if (size <= OGS_CLUSTER_512_SIZE) {
        ogs_pool_alloc(&pool->cluster_512, (ogs_cluster_512_t**)&buffer);
        cluster_size = OGS_CLUSTER_512_SIZE;
    } else if (size <= OGS_CLUSTER_1024_SIZE) {
        ogs_pool_alloc(&pool->cluster_1024, (ogs_cluster_1024_t**)&buffer);
        cluster_size = OGS_CLUSTER_1024_SIZE;
    } else if (size <= OGS_CLUSTER_2048_SIZE) {
        ogs_pool_alloc(&pool->cluster_2048, (ogs_cluster_2048_t**)&buffer);
        cluster_size = OGS_CLUSTER_2048_SIZE;
    } else if (size <= OGS_CLUSTER_8192_SIZE) {
        ogs_pool_alloc(&pool->cluster_8192, (ogs_cluster_8192_t**)&buffer);
        cluster_size = OGS_CLUSTER_8192_SIZE;
    } else if (size <= OGS_CLUSTER_32768_SIZE) {
        ogs_pool_alloc(&pool->cluster_32768, (ogs_cluster_32768_t**)&buffer);
        cluster_size = OGS_CLUSTER_32768_SIZE;
    } else if (size <= OGS_CLUSTER_BIG_SIZE) {
        ogs_pool_alloc(&pool->cluster_big, (ogs_cluster_big_t**)&buffer);
        cluster_size = OGS_CLUSTER_BIG_SIZE;
    } else {
        ogs_fatal("invalid size = %d", size);
        ogs_assert_if_reached();
    }

    if (!buffer) {
        if (!quiet)
            ogs_error("ogs_pool_alloc() failed [size=%u]", size);
        /* the meta entry leaked here before; give it back so pool
         * exhaustion (or a size class stocked with 0 entries in a
         * per-thread pool) does not slowly drain pool->cluster */
        ogs_pool_free(&pool->cluster, cluster);
        return NULL;
    }

    cluster->size = cluster_size;
    cluster->buffer = buffer;

    return cluster;
}

static void cluster_free(ogs_pkbuf_pool_t *pool, ogs_cluster_t *cluster)
{
    ogs_assert(pool);
    ogs_assert(cluster);
    ogs_assert(cluster->buffer);

    switch (cluster->size) {
    case OGS_CLUSTER_128_SIZE:
        ogs_pool_free(&pool->cluster_128, (ogs_cluster_128_t*)cluster->buffer);
        break;
    case OGS_CLUSTER_256_SIZE:
        ogs_pool_free(&pool->cluster_256, (ogs_cluster_256_t*)cluster->buffer);
        break;
    case OGS_CLUSTER_512_SIZE:
        ogs_pool_free(&pool->cluster_512, (ogs_cluster_512_t*)cluster->buffer);
        break;
    case OGS_CLUSTER_1024_SIZE:
        ogs_pool_free(
                &pool->cluster_1024, (ogs_cluster_1024_t*)cluster->buffer);
        break;
    case OGS_CLUSTER_2048_SIZE:
        ogs_pool_free(
                &pool->cluster_2048, (ogs_cluster_2048_t*)cluster->buffer);
        break;
    case OGS_CLUSTER_8192_SIZE:
        ogs_pool_free(
                &pool->cluster_8192, (ogs_cluster_8192_t*)cluster->buffer);
        break;
    case OGS_CLUSTER_32768_SIZE:
        ogs_pool_free(
                &pool->cluster_32768, (ogs_cluster_32768_t*)cluster->buffer);
        break;
    case OGS_CLUSTER_BIG_SIZE:
        ogs_pool_free(&pool->cluster_big, (ogs_cluster_big_t*)cluster->buffer);
        break;
    default:
        ogs_assert_if_reached();
    }

    ogs_pool_free(&pool->cluster, cluster);
}
#endif
