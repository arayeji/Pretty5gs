/*
 * Copyright (C) 2025 by Juraj Elias <juraj.elias@gmail.com>
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

/*
 * ENB info - MME eNBs JSON dumper for the Prometheus HTTP server (/enb-info).
 * - enb_id, plmn, s1 info, enb_IP, supported ta_list, num_connceted_ues
 * - pager: /enb-info?page=0&page_size=100 (0-based, page=-1 without paging) Default: page=0 page_size=100=MAXSIZE
 *
 * curl -s "http://127.0.0.2:9090/enb-info?" |jq . 
 * {
 *   "items": [
 *     {
 *       "enb_id": 264040,
 *       "plmn": "99970",
 *       "network": {
 *         "mme_name": "efire-mme0"
 *       },
 *       "s1": {
 *         "sctp": {
 *           "peer": "[192.168.168.254]:36412",
 *           "max_out_streams": 10,
 *           "next_ostream_id": 3
 *         },
 *         "setup_success": true
 *       },
 *       "supported_ta_list": [
 *         {
 *           "tac": "0001",
 *           "plmn": "99970"
 *         }
 *       ],
 *       "num_connected_ues": 1
 *     }
 *   ],
 *   "pager": {
 *     "page": 0,
 *     "page_size": 100,
 *     "count": 1
 *   }
 * }
*/

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "ogs-core.h"
#include "ogs-proto.h"
#include "ogs-metrics.h"
#include "mme-context.h"
#include "enb-info.h"

#include "sbi/openapi/external/cJSON.h"
#include "metrics/prometheus/json_pager.h"

#ifndef ENB_INFO_PAGE_SIZE_DEFAULT
#define ENB_INFO_PAGE_SIZE_DEFAULT 100U
#endif


size_t mme_dump_enb_info(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    /*
     * Default to the historic 100-per-page when the caller did not
     * specify, but no longer clamp on the upper bound. The HTTP
     * layer (serve_json_from_dumper) grows its buffer to fit, so
     * very large page_size values are honoured directly.
     */
    if (page_size == 0) page_size = ENB_INFO_PAGE_SIZE_DEFAULT;

    return mme_dump_enb_info_paged(buf, buflen, page, page_size, q);
}

static inline const char *safe_sa_str(const ogs_sockaddr_t *sa)
{
    if (!sa) return "";
    int fam = ((const struct sockaddr *)&sa->sa)->sa_family;
    if (fam != AF_INET && fam != AF_INET6) return "";
    return ogs_sockaddr_to_string_static((ogs_sockaddr_t *)sa);
}

/*
 * Compare an ogs_sockaddr to a textual IPv4/IPv6 query value. The
 * comparison is exact-text against the IP portion of
 * ogs_sockaddr_to_string_static (which has the form "[ipv6]:port"
 * or "ipv4:port"), so we strip the brackets and the trailing
 * ":port" before strcmp.
 */
static bool sa_matches_ip(const ogs_sockaddr_t *sa, const char *needle)
{
    if (!sa || !needle || !*needle) return false;
    const char *s = ogs_sockaddr_to_string_static((ogs_sockaddr_t *)sa);
    if (!s) return false;
    /* IPv6 form: [::1]:36412 - lift the bracketed part */
    if (s[0] == '[') {
        const char *end = strchr(s + 1, ']');
        if (!end) return false;
        size_t len = (size_t)(end - (s + 1));
        return strlen(needle) == len && strncmp(s + 1, needle, len) == 0;
    }
    const char *colon = strrchr(s, ':');
    if (!colon) return strcmp(s, needle) == 0;
    size_t len = (size_t)(colon - s);
    return strlen(needle) == len && strncmp(s, needle, len) == 0;
}

size_t mme_dump_enb_info_paged(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    if (!buf || buflen == 0) return 0;

    const bool no_paging = json_pager_setup(&page, &page_size,
            ENB_INFO_PAGE_SIZE_DEFAULT);

    const size_t start_index = json_pager_safe_start_index(no_paging, page, page_size);

    mme_context_t *ctxt = mme_self();

    /* root */
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        if (buflen >= 3) { memcpy(buf, "{}", 3); return 2; }
        if (buflen) buf[0] = '\0';
        return 0;
    }

    /* items array */
    cJSON *items = cJSON_AddArrayToObject(root, "items");
    if (!items) {
        cJSON_Delete(root);
        if (buflen >= 3) { memcpy(buf, "{}", 3); return 2; }
        if (buflen) buf[0] = '\0';
        return 0;
    }

    size_t idx = 0, emitted = 0, total = 0;
    bool has_next = false;
    bool oom = false;

    /*
     * This dumper runs on the MHD thread (see lib/metrics/prometheus/
     * context.c). Take the coarse metrics dump lock so the MME main
     * thread can't free an mme_enb_t / enb_ue_t we are iterating.
     * Released right before json_pager_finalize() since the rest of
     * the work only touches the cJSON tree built above.
     */
    ogs_metrics_dump_lock();

    mme_enb_t *enb = NULL;
    ogs_list_for_each(&ctxt->enb_list, enb) {
        /*
         * Server-side filters. Apply BEFORE the paging cursor so
         * paging is over the filtered subset, not over the full
         * list (which would make most pages empty).
         */
        if (q && q->has_enb_id && enb->enb_id != q->enb_id)
            continue;
        if (q && q->ip && *q->ip && !sa_matches_ip(enb->sctp.addr, q->ip))
            continue;

        total++;

        int act = json_pager_advance(no_paging, idx, start_index, emitted, page_size, &has_next);
        if (act == 1) { idx++; continue; }
        if (act == 0) {
        /*
         * Use the maintained per-eNB counter rather than walking
         * enb->enb_ue_list. The list is mutated by the MME main
         * thread, and we are running on the MHD worker thread; the
         * counter is a single int (atomic read) so a stale value is
         * the worst case here, not a use-after-free.
         */
        size_t num_connected_ues = (size_t)(enb->num_enb_ues > 0 ? enb->num_enb_ues : 0);

        /* eNB object (build fully before attaching) */
        cJSON *e = cJSON_CreateObject();
        if (!e) { oom = true; break; }

        /* enb_id */
        if (!cJSON_AddNumberToObject(e, "enb_id", (double)(unsigned)enb->enb_id)) { cJSON_Delete(e); oom = true; break; }

        /* plmn */
        {
            char plmn_str[OGS_PLMNIDSTRLEN] = {0};
            ogs_plmn_id_to_string(&enb->plmn_id, plmn_str);
            if (!cJSON_AddStringToObject(e, "plmn", plmn_str)) { cJSON_Delete(e); oom = true; break; }
        }

        /* network */
        {
            cJSON *network = cJSON_CreateObject();
            if (!network) { cJSON_Delete(e); oom = true; break; }
            if (!cJSON_AddStringToObject(network, "mme_name", ctxt->mme_name ? ctxt->mme_name : "")) {
                cJSON_Delete(network); cJSON_Delete(e); oom = true; break;
            }
            cJSON_AddItemToObjectCS(e, "network", network);
        }

        /* s1 + sctp block */
        {
            cJSON *s1 = cJSON_CreateObject();
            if (!s1) { cJSON_Delete(e); oom = true; break; }

            if (!cJSON_AddBoolToObject(s1, "setup_success", enb->state.s1_setup_success ? 1 : 0)) {
                cJSON_Delete(s1); cJSON_Delete(e); oom = true; break;
            }

            /*  sctp  */
            cJSON *sctp = cJSON_CreateObject();
            if (!sctp) { cJSON_Delete(s1); cJSON_Delete(e); oom = true; break; }

            if (!cJSON_AddStringToObject(sctp, "peer", safe_sa_str(enb->sctp.addr))) {
                cJSON_Delete(sctp); cJSON_Delete(s1); cJSON_Delete(e); oom = true; break;
            }
            if (!cJSON_AddNumberToObject(sctp, "max_out_streams", (double)enb->max_num_of_ostreams)) {
                cJSON_Delete(sctp); cJSON_Delete(s1); cJSON_Delete(e); oom = true; break;
            }
            if (!cJSON_AddNumberToObject(sctp, "next_ostream_id", (double)(unsigned)enb->ostream_id)) {
                cJSON_Delete(sctp); cJSON_Delete(s1); cJSON_Delete(e); oom = true; break;
            }

            cJSON_AddItemToObjectCS(s1, "sctp", sctp);
            cJSON_AddItemToObjectCS(e, "s1", s1);
        }

        /* supported_ta_list (LTE TAC is 16-bit) */
        {
            cJSON *tas = cJSON_CreateArray();
            if (!tas) { cJSON_Delete(e); oom = true; break; }

            bool inner_oom = false;
            int t;

            for (t = 0; t < enb->num_of_supported_ta_list; t++) {
                cJSON *ta = cJSON_CreateObject();
                if (!ta) { inner_oom = true; break; }

                char tac_hex[5];
                snprintf(tac_hex, sizeof tac_hex, "%04X", (unsigned)enb->supported_ta_list[t].tac);
                if (!cJSON_AddStringToObject(ta, "tac", tac_hex)) {
                    cJSON_Delete(ta); inner_oom = true; break;
                }

                char ta_plmn[OGS_PLMNIDSTRLEN] = {0};
                ogs_plmn_id_to_string(&enb->supported_ta_list[t].plmn_id, ta_plmn);
                if (!cJSON_AddStringToObject(ta, "plmn", ta_plmn)) {
                    cJSON_Delete(ta); inner_oom = true; break;
                }

                cJSON_AddItemToArray(tas, ta);
            }

            if (inner_oom) { cJSON_Delete(tas); cJSON_Delete(e); oom = true; break; }

            cJSON_AddItemToObjectCS(e, "supported_ta_list", tas);
        }

        /* num_connected_ues */
        if (!cJSON_AddNumberToObject(e, "num_connected_ues", (double)num_connected_ues)) {
            cJSON_Delete(e); oom = true; break;
        }

        /* success -> append to items[] */
        cJSON_AddItemToArray(items, e);
        emitted++;
        }
        idx++;
    }

    ogs_metrics_dump_unlock();

    json_pager_add_trailing(root, no_paging, page, page_size,
                            emitted, total, has_next && !oom, "/enb-info", oom);

    return json_pager_finalize(root, buf, buflen);
}

