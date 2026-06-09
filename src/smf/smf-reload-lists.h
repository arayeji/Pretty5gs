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

#if !defined(SMF_RELOAD_LISTS_H_INCLUDED)
#define SMF_RELOAD_LISTS_H_INCLUDED

#include "ogs-app.h"

#ifdef __cplusplus
extern "C" {
#endif

void smf_context_reload_runtime(void);

extern int smf_reload_lists_changed;

#ifdef __cplusplus
}
#endif

#endif /* SMF_RELOAD_LISTS_H_INCLUDED */
