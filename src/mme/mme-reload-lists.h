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

#if !defined(MME_RELOAD_LISTS_H_INCLUDED)
#define MME_RELOAD_LISTS_H_INCLUDED

#include "ogs-app.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SIGHUP reload: list updates with full replace semantics (add, remove,
 * reorder). Returns the number of new entries merged or appended where
 * add-only helpers are still used internally.
 */
int mme_reload_lists_key_add_only(const char *mme_key, ogs_yaml_iter_t *mme_iter);
int mme_reload_gtpc_client_add_only(ogs_yaml_iter_t *gtpc_iter);

/*
 * Incremented by add-only reload helpers (including scalar policy keys).
 * Reset at the start of each SIGHUP reload pass.
 */
extern volatile int mme_reload_lists_changed;

#ifdef __cplusplus
}
#endif

#endif /* MME_RELOAD_LISTS_H_INCLUDED */
