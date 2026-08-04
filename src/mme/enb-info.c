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

/*
 * Value snapshot of one eNB, filled under mme_ctx_lock(). The cJSON
 * build (the expensive part: one malloc + snprintf per field) runs
 * after unlock, so a scrape no longer stalls main/workers for the
 * whole page. No pointers into live context survive the unlock.
 */
typedef struct enb_snap_s {
    uint32_t        enb_id;
    ogs_plmn_id_t   plmn_id;
    bool            s1_setup_success;
    char            peer[OGS_ADDRSTRLEN + 16]; /* "[v6]:port" form */
    int             max_out_streams;
    unsigned        next_ostream_id;
    int             num_ta;
    struct {
        uint16_t        tac;
        ogs_plmn_id_t   plmn_id;
    } ta[OGS_MAX_NUM_OF_SUPPORTED_TA];
    size_t          num_connected_ues;
    double          ovl_level;
    double          ovl_signalled;
    double          ovl_tx_queue;
    double          ovl_shed_total;
    double          ovl_rate_shed_total;
} enb_snap_t;

/* Hard bound on one response's snapshot allocation (~1.7 KB each). */
#define ENB_INFO_SNAP_MAX 4096

/* Runs under mme_ctx_lock(); must not allocate or block. */
static void enb_snapshot_fill(enb_snap_t *s, const mme_enb_t *enb)
{
    int t;

    memset(s, 0, sizeof(*s));

    s->enb_id = enb->enb_id;
    s->plmn_id = enb->plmn_id;
    s->s1_setup_success = enb->state.s1_setup_success ? true : false;
    ogs_cpystrn(s->peer, safe_sa_str(enb->sctp.addr), sizeof(s->peer));
    s->max_out_streams = enb->max_num_of_ostreams;
    s->next_ostream_id = (unsigned)enb->ostream_id;

    s->num_ta = enb->num_of_supported_ta_list;
    if (s->num_ta > OGS_MAX_NUM_OF_SUPPORTED_TA)
        s->num_ta = OGS_MAX_NUM_OF_SUPPORTED_TA;
    if (s->num_ta < 0)
        s->num_ta = 0;
    for (t = 0; t < s->num_ta; t++) {
        s->ta[t].tac = enb->supported_ta_list[t].tac;
        s->ta[t].plmn_id = enb->supported_ta_list[t].plmn_id;
    }

    s->num_connected_ues =
        (size_t)(enb->num_enb_ues > 0 ? enb->num_enb_ues : 0);

    s->ovl_level = (double)enb->overload.level;
    s->ovl_signalled = (double)enb->overload.signalled_level;
    s->ovl_tx_queue = (double)enb->overload.congested_depth;
    s->ovl_shed_total = (double)enb->overload.shed_total;
    s->ovl_rate_shed_total = (double)enb->overload.rate_shed_total;
}

/* Runs WITHOUT the context lock: pure value -> cJSON conversion. */
static cJSON *enb_snap_to_json(const enb_snap_t *s, const char *mme_name)
{
    cJSON *e = cJSON_CreateObject();
    if (!e) return NULL;

    if (!cJSON_AddNumberToObject(e, "enb_id",
                (double)(unsigned)s->enb_id)) goto fail;

    /* plmn */
    {
        char plmn_str[OGS_PLMNIDSTRLEN] = {0};
        ogs_plmn_id_to_string(&s->plmn_id, plmn_str);
        if (!cJSON_AddStringToObject(e, "plmn", plmn_str)) goto fail;
    }

    /* network */
    {
        cJSON *network = cJSON_CreateObject();
        if (!network) goto fail;
        if (!cJSON_AddStringToObject(network, "mme_name",
                    mme_name ? mme_name : "")) {
            cJSON_Delete(network); goto fail;
        }
        cJSON_AddItemToObjectCS(e, "network", network);
    }

    /* s1 + sctp block */
    {
        cJSON *s1 = cJSON_CreateObject();
        if (!s1) goto fail;

        if (!cJSON_AddBoolToObject(s1, "setup_success",
                    s->s1_setup_success ? 1 : 0)) {
            cJSON_Delete(s1); goto fail;
        }

        cJSON *sctp = cJSON_CreateObject();
        if (!sctp) { cJSON_Delete(s1); goto fail; }

        if (!cJSON_AddStringToObject(sctp, "peer", s->peer) ||
            !cJSON_AddNumberToObject(sctp, "max_out_streams",
                    (double)s->max_out_streams) ||
            !cJSON_AddNumberToObject(sctp, "next_ostream_id",
                    (double)s->next_ostream_id)) {
            cJSON_Delete(sctp); cJSON_Delete(s1); goto fail;
        }

        cJSON_AddItemToObjectCS(s1, "sctp", sctp);
        cJSON_AddItemToObjectCS(e, "s1", s1);
    }

    /* supported_ta_list (LTE TAC is 16-bit) */
    {
        cJSON *tas = cJSON_CreateArray();
        if (!tas) goto fail;

        int t;
        for (t = 0; t < s->num_ta; t++) {
            cJSON *ta = cJSON_CreateObject();
            if (!ta) { cJSON_Delete(tas); goto fail; }

            char tac_hex[5];
            snprintf(tac_hex, sizeof tac_hex, "%04X",
                    (unsigned)s->ta[t].tac);

            char ta_plmn[OGS_PLMNIDSTRLEN] = {0};
            ogs_plmn_id_to_string(&s->ta[t].plmn_id, ta_plmn);

            if (!cJSON_AddStringToObject(ta, "tac", tac_hex) ||
                !cJSON_AddStringToObject(ta, "plmn", ta_plmn)) {
                cJSON_Delete(ta); cJSON_Delete(tas); goto fail;
            }

            cJSON_AddItemToArray(tas, ta);
        }

        cJSON_AddItemToObjectCS(e, "supported_ta_list", tas);
    }

    if (!cJSON_AddNumberToObject(e, "num_connected_ues",
                (double)s->num_connected_ues)) goto fail;

    /* overload block */
    {
        cJSON *ovl = cJSON_CreateObject();
        if (!ovl) goto fail;

        if (!cJSON_AddNumberToObject(ovl, "level", s->ovl_level) ||
            !cJSON_AddNumberToObject(ovl, "signalled_level",
                    s->ovl_signalled) ||
            !cJSON_AddNumberToObject(ovl, "tx_queue", s->ovl_tx_queue) ||
            !cJSON_AddNumberToObject(ovl, "shed_total",
                    s->ovl_shed_total) ||
            !cJSON_AddNumberToObject(ovl, "rate_shed_total",
                    s->ovl_rate_shed_total)) {
            cJSON_Delete(ovl); goto fail;
        }

        cJSON_AddItemToObjectCS(e, "overload", ovl);
    }

    return e;

fail:
    cJSON_Delete(e);
    return NULL;
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

    char mme_name[256] = "";
    enb_snap_t *snaps = NULL;
    size_t snap_cap = 0;

    /*
     * Snapshot phase. This dumper runs on the MHD thread; hold
     * mme_ctx_lock() only while copying scalar values out of the
     * live eNB objects. The cJSON build below runs after unlock, so
     * a scrape no longer stalls the MME for the whole JSON build.
     */
    mme_ctx_lock();

    if (ctxt->mme_name)
        ogs_cpystrn(mme_name, ctxt->mme_name, sizeof(mme_name));

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
        if (act != 0) { idx++; continue; } /* skip / page full: keep counting total */

        if (emitted >= ENB_INFO_SNAP_MAX) {
            /* snapshot allocation bound: report truncated, keep counting */
            oom = true;
            has_next = true;
            idx++;
            continue;
        }

        if (emitted == snap_cap) {
            size_t ncap = snap_cap ? snap_cap * 2 : 64;
            enb_snap_t *n = ogs_realloc(snaps, ncap * sizeof(*n));
            if (!n) { oom = true; break; }
            snaps = n;
            snap_cap = ncap;
        }

        enb_snapshot_fill(&snaps[emitted], enb);
        emitted++;
        idx++;
    }

    mme_ctx_unlock();

    /* Build phase: values only, no live context pointers. */
    {
        size_t i;
        for (i = 0; i < emitted; i++) {
            cJSON *e = enb_snap_to_json(&snaps[i], mme_name);
            if (!e) { oom = true; break; }
            cJSON_AddItemToArray(items, e);
        }
        if (i < emitted)
            emitted = i;
    }

    if (snaps)
        ogs_free(snaps);

    json_pager_add_trailing(root, no_paging, page, page_size,
                            emitted, total, has_next && !oom, "/enb-info", oom);

    return json_pager_finalize(root, buf, buflen);
}

