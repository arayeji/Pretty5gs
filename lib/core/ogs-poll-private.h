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

#ifndef OGS_POLL_PRIVATE_H
#define OGS_POLL_PRIVATE_H

#if !defined(OGS_CORE_COMPILATION)
#error "This private header cannot be included directly."
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ogs_poll_s {
    ogs_lnode_t node;
    int index;

    short when;
    ogs_socket_t fd;
    ogs_poll_handler_f handler;
    void *data;

    ogs_pollset_t *pollset;
} ogs_poll_t;

typedef struct ogs_pollset_s {
    void *context;
    OGS_POOL(pool, ogs_poll_t);

    struct {
        ogs_socket_t fd[2];
        ogs_poll_t *poll;
    } notify;

    unsigned int capacity;

    /* see ogs_pollset_set_dispatch_hooks() */
    ogs_pollset_hook_f dispatch_enter;
    ogs_pollset_hook_f dispatch_leave;
    void *dispatch_data;
} ogs_pollset_t;

#define ogs_pollset_dispatch_enter(__pOLLSET) \
    do { \
        if ((__pOLLSET)->dispatch_enter) \
            (__pOLLSET)->dispatch_enter((__pOLLSET)->dispatch_data); \
    } while (0)

#define ogs_pollset_dispatch_leave(__pOLLSET) \
    do { \
        if ((__pOLLSET)->dispatch_leave) \
            (__pOLLSET)->dispatch_leave((__pOLLSET)->dispatch_data); \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* OGS_POLL_PRIVATE_H */
