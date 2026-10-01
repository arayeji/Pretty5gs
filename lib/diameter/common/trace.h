/*
 * Copyright (C) 2026 Open5GS contributors
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

#if !defined(OGS_DIAMETER_INSIDE) && !defined(OGS_DIAMETER_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_DIAM_TRACE_H
#define OGS_DIAM_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

int ogs_diam_trace_init(void);
void ogs_diam_trace_final(void);

/*
 * PACKET dump of a Diameter message for a traced IMSI, with the
 * connection endpoints of the peer it travelled on.
 *   dir "rx": dumped now (endpoints recorded when freeDiameter received it)
 *   dir "tx": dumped when freeDiameter puts it on the wire (final bytes,
 *             hop-by-hop id set); nothing if it is never sent
 */
void ogs_diam_trace_msg(const char *imsi_bcd, const char *dir, struct msg *msg);

#ifdef __cplusplus
}
#endif

#endif /* OGS_DIAM_TRACE_H */
