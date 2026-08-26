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
 *
 * Connected MME UEs (LTE) JSON dumper for the Prometheus HTTP server (/ue-info).
 * - supi, cm_state, enb_info, location, ambr, sgw, pdn (with pgw), pdn_count
 * - pager: /ue-info?page=0&page_size=100 (0-based, page=-1 without paging) Default: page=0 page_size=100=MAXSIZE
 *
 * path: http://MME_IP:9090/ue-info
 * 
 * curl -s "http://127.0.0.2:9090/ue-info?" |jq . 
 * {
 *   "items": [
 *     {
 *       "supi": "999700000021632",
 *       "domain": "EPS",
 *       "rat": "E-UTRA",
 *       "cm_state": "connected",
 *       "enb": {
 *         "ostream_id": 3,
 *         "mme_ue_ngap_id": 3,
 *         "ran_ue_ngap_id": 9,
 *         "enb_id": 264040,
 *         "cell_id": 67594275
 *       },
 *       "location": {
 *         "tai": {
 *           "plmn": "99970",
 *           "tac_hex": "0001",
 *           "tac": 1
 *         },
 *         "timestamp": 1778223227627488
 *       },
 *       "ambr": {
 *         "downlink": 1000000000,
 *         "uplink": 1000000000
 *       },
 *       "sgw": {
 *         "address": "172.16.28.85",
 *         "port": 2123,
 *         "s11_teid": 12345
 *       },
 *       "pdn": [
 *         {
 *           "apn": "internet",
 *           "pgw": {
 *             "address": "10.0.0.5",
 *             "s5c_teid": 67890,
 *             "config_selected": "10.0.0.1"
 *           },
 *           "qos_flows": [
 *             {
 *               "ebi": 5
 *             }
 *           ],
 *           "qci": 9,
 *           "ebi": 5,
 *           "bearer_count": 1,
 *           "pdu_state": "active"
 *         }
 *       ],
 *       "pdn_count": 1
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

#include "ogs-core.h"
#include "ogs-proto.h"
#include "ogs-metrics.h"

#include "mme-context.h"
#include "ue-info.h"
#include "mme-context.h"

#include "metrics/prometheus/json_pager.h"
#include "metrics/ogs-metrics.h"
#include "sbi/openapi/external/cJSON.h"

#ifndef MME_UE_INFO_PAGE_SIZE_DEFAULT
#define MME_UE_INFO_PAGE_SIZE_DEFAULT 100U
#endif


size_t mme_dump_ue_info(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    return mme_dump_ue_info_paged(buf, buflen, page, page_size, q);
}

static bool ogs_ip_to_string(const ogs_ip_t *ip, char *buf, size_t buflen)
{
    char ipbuf[OGS_ADDRSTRLEN];

    if (!ip || !buf || buflen == 0)
        return false;

    buf[0] = '\0';

    if (ip->ipv4) {
        ogs_cpystrn(buf, OGS_INET_NTOP(&ip->addr, ipbuf), buflen);
        return true;
    }
    if (ip->ipv6) {
        ogs_cpystrn(buf, OGS_INET6_NTOP(ip->addr6, ipbuf), buflen);
        return true;
    }

    return false;
}

/*
 * Value snapshot of one UE, filled under mme_ctx_lock(). The cJSON
 * build (mallocs + snprintf per field) runs after unlock, so a poll
 * of /ue-info no longer stalls main and the shard workers for the
 * whole JSON build. No pointers into live context survive the unlock.
 */
#define UE_INFO_SNAP_MAX 4096   /* hard bound per response (~2 KB each) */
#define UE_INFO_MAX_PDN  8      /* captured PDNs; pdn_count stays exact */

typedef struct ue_pdn_snap_s {
    char        apn[OGS_MAX_APN_LEN + 1];
    int         qci;            /* 0 = absent */
    unsigned    ebi_root;
    unsigned    bearer_count;
    int         num_ebis;
    uint8_t     ebis[OGS_MAX_NUM_OF_BEARER];
    bool        has_pgw;        /* emit the pgw object at all */
    bool        has_pgw_addr;
    char        pgw_addr[OGS_ADDRSTRLEN];
    uint32_t    pgw_s5c_teid;
    bool        has_pgw_cfg;
    char        pgw_cfg[OGS_ADDRSTRLEN];
    bool        has_ue_ip4;
    char        ue_ip4[OGS_ADDRSTRLEN];
    bool        has_ue_ip6;
    char        ue_ip6[OGS_ADDRSTRLEN];
} ue_pdn_snap_t;

typedef struct ue_snap_s {
    char        supi[OGS_MAX_IMSI_BCD_LEN + 2];
    bool        connected;
    uint16_t    enb_ostream_id;
    bool        has_ran;
    uint32_t    mme_ue_s1ap_id;
    uint32_t    enb_ue_s1ap_id;
    bool        has_enb_id;
    uint32_t    enb_id;
    uint32_t    cell_id;        /* 0 = absent */
    ogs_plmn_id_t tai_plmn;
    uint16_t    tac;
    uint64_t    loc_ts;
    uint64_t    ambr_dl;
    uint64_t    ambr_ul;
    bool        has_sgw;
    char        sgw_addr[OGS_ADDRSTRLEN];
    int         sgw_port;
    uint32_t    s11_teid;       /* 0 = absent */
    int         num_pdn;        /* captured (<= UE_INFO_MAX_PDN) */
    size_t      pdn_count;      /* actual sessions on the UE */
    ue_pdn_snap_t pdn[UE_INFO_MAX_PDN];
} ue_snap_t;

/* Runs under mme_ctx_lock(); copies values only, no allocation. */
static void ue_snapshot_fill(ue_snap_t *s, const mme_ue_t *ue)
{
    memset(s, 0, sizeof(*s));

    ogs_cpystrn(s->supi, ue->imsi_bcd, sizeof(s->supi));
    s->connected = ECM_CONNECTED(ue) ? true : false;
    s->enb_ostream_id = ue->enb_ostream_id;

    enb_ue_t *ran = enb_ue_find_by_id(ue->enb_ue_id);
    if (ran) {
        s->has_ran = true;
        s->mme_ue_s1ap_id = ran->mme_ue_s1ap_id;
        s->enb_ue_s1ap_id = ran->enb_ue_s1ap_id;

        mme_enb_t *enb_obj = mme_enb_find_by_id(ran->enb_id);
        if (enb_obj && enb_obj->enb_id_presence) {
            s->has_enb_id = true;
            s->enb_id = enb_obj->enb_id;
        }

        /* prefer last reported E-UTRAN_CGI from RAN; else UE's e_cgi */
        if (ran->saved.e_cgi.cell_id)
            s->cell_id = ran->saved.e_cgi.cell_id;
        else if (ue->e_cgi.cell_id)
            s->cell_id = ue->e_cgi.cell_id;
    }

    s->tai_plmn = ue->tai.plmn_id;
    s->tac = ue->tai.tac;
    s->loc_ts = (uint64_t)ue->ue_location_timestamp;
    s->ambr_dl = ue->ambr.downlink;
    s->ambr_ul = ue->ambr.uplink;

    /* selected SGW (S11) */
    {
        sgw_ue_t *sgw_ue = sgw_ue_find_by_id(ue->sgw_ue_id);
        if (sgw_ue && sgw_ue->sgw && sgw_ue->sgw->gnode.sa_list) {
            OGS_ADDR(sgw_ue->sgw->gnode.sa_list, s->sgw_addr);
            s->sgw_port = (int)OGS_PORT(sgw_ue->sgw->gnode.sa_list);
            s->s11_teid = sgw_ue->sgw_s11_teid;
            s->has_sgw = true;
        }
    }

    /* PDNs */
    {
        mme_sess_t *sess = NULL;
        ogs_list_for_each(&((mme_ue_t *)ue)->sess_list, sess) {
            s->pdn_count++;
            if (s->num_pdn >= UE_INFO_MAX_PDN)
                continue;       /* keep the count exact, stop capturing */

            ue_pdn_snap_t *p = &s->pdn[s->num_pdn];

            if (sess->session && sess->session->name &&
                    sess->session->name[0])
                ogs_cpystrn(p->apn, sess->session->name, sizeof(p->apn));

            mme_bearer_t *b = NULL;
            ogs_list_for_each(&sess->bearer_list, b) {
                if (!b || b->ebi == 0) continue;
                p->bearer_count++;
                if (p->ebi_root == 0 || (unsigned)b->ebi < p->ebi_root)
                    p->ebi_root = (unsigned)b->ebi;
                if (p->num_ebis < (int)OGS_ARRAY_SIZE(p->ebis))
                    p->ebis[p->num_ebis++] = b->ebi;
            }

            if (sess->session && sess->session->qos.index > 0)
                p->qci = sess->session->qos.index;

            /* UE address from the CSR-response PAA (also present for
             * home-routed roamers, where the home PGW assigned it). */
            switch (sess->paa.session_type) {
            case OGS_PDU_SESSION_TYPE_IPV4:
                OGS_INET_NTOP(&sess->paa.addr, p->ue_ip4);
                p->has_ue_ip4 = true;
                break;
            case OGS_PDU_SESSION_TYPE_IPV6:
                OGS_INET6_NTOP(sess->paa.addr6, p->ue_ip6);
                p->has_ue_ip6 = true;
                break;
            case OGS_PDU_SESSION_TYPE_IPV4V6:
                OGS_INET_NTOP(&sess->paa.both.addr, p->ue_ip4);
                p->has_ue_ip4 = true;
                OGS_INET6_NTOP(sess->paa.both.addr6, p->ue_ip6);
                p->has_ue_ip6 = true;
                break;
            default:
                break;
            }

            /* PGW: runtime + configured address */
            {
                bool has_runtime = false, has_config = false;
                mme_pgw_t *pgw = NULL;

                if (sess->pgw_s5c_ip.ipv4 || sess->pgw_s5c_ip.ipv6)
                    has_runtime = ogs_ip_to_string(&sess->pgw_s5c_ip,
                            p->pgw_addr, sizeof(p->pgw_addr));

                pgw = mme_pgw_find_for_sess(&mme_self()->pgw_list, sess);
                if (pgw && pgw->sa_list) {
                    OGS_ADDR(pgw->sa_list, p->pgw_cfg);
                    has_config = true;
                }

                p->has_pgw_addr = has_runtime;
                p->has_pgw_cfg = has_config;
                p->pgw_s5c_teid = sess->pgw_s5c_teid;
                p->has_pgw = has_runtime || has_config ||
                    sess->pgw_s5c_teid != 0;
            }

            s->num_pdn++;
        }
    }
}

/* Runs WITHOUT the context lock: pure value -> cJSON conversion. */
static cJSON *ue_snap_to_json(const ue_snap_t *s)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;

    /* identity */
    if (s->supi[0]) {
        if (!cJSON_AddStringToObject(o, "supi", s->supi)) goto end;
    }
    if (!cJSON_AddStringToObject(o, "domain", "EPS")) goto end;
    if (!cJSON_AddStringToObject(o, "rat", "E-UTRA")) goto end;
    if (!cJSON_AddStringToObject(o, "cm_state",
                s->connected ? "connected" : "idle")) goto end;

    /* enb */
    {
        cJSON *enb = cJSON_CreateObject();
        if (!enb) goto end;

        if (!cJSON_AddNumberToObject(enb, "ostream_id",
                    (double)s->enb_ostream_id)) {
            cJSON_Delete(enb); goto end;
        }
        if (s->has_ran) {
            if (!cJSON_AddNumberToObject(enb, "mme_ue_ngap_id",
                        (double)s->mme_ue_s1ap_id) ||
                !cJSON_AddNumberToObject(enb, "ran_ue_ngap_id",
                        (double)s->enb_ue_s1ap_id)) {
                cJSON_Delete(enb); goto end;
            }
            if (s->has_enb_id &&
                !cJSON_AddNumberToObject(enb, "enb_id",
                        (double)s->enb_id)) {
                cJSON_Delete(enb); goto end;
            }
            if (s->cell_id &&
                !cJSON_AddNumberToObject(enb, "cell_id",
                        (double)s->cell_id)) {
                cJSON_Delete(enb); goto end;
            }
        }

        cJSON_AddItemToObjectCS(o, "enb", enb);
    }

    /* location */
    {
        cJSON *loc = cJSON_CreateObject();
        if (!loc) goto end;

        cJSON *tai = cJSON_CreateObject();
        if (!tai) { cJSON_Delete(loc); goto end; }

        char plmn_str[OGS_PLMNIDSTRLEN] = {0};
        ogs_plmn_id_to_string(&s->tai_plmn, plmn_str);

        char tac_hex[8];
        (void)snprintf(tac_hex, sizeof tac_hex, "%04x", (unsigned)s->tac);

        if (!cJSON_AddStringToObject(tai, "plmn", plmn_str) ||
            !cJSON_AddStringToObject(tai, "tac_hex", tac_hex) ||
            !cJSON_AddNumberToObject(tai, "tac", (double)s->tac)) {
            cJSON_Delete(tai); cJSON_Delete(loc); goto end;
        }

        cJSON_AddItemToObjectCS(loc, "tai", tai);

        /* Last location update timestamp (epoch microseconds); 0 means
         * not yet updated. Field name aligned with AMF /ue-info. */
        if (!cJSON_AddNumberToObject(loc, "timestamp",
                    (double)s->loc_ts)) {
            cJSON_Delete(loc); goto end;
        }

        cJSON_AddItemToObjectCS(o, "location", loc);
    }

    /* ambr */
    {
        cJSON *ambr = cJSON_CreateObject();
        if (!ambr) goto end;
        if (!cJSON_AddNumberToObject(ambr, "downlink",
                    (double)s->ambr_dl) ||
            !cJSON_AddNumberToObject(ambr, "uplink",
                    (double)s->ambr_ul)) {
            cJSON_Delete(ambr); goto end;
        }
        cJSON_AddItemToObjectCS(o, "ambr", ambr);
    }

    /* selected SGW (S11) */
    if (s->has_sgw) {
        cJSON *sgw = cJSON_CreateObject();
        if (!sgw) goto end;
        if (!cJSON_AddStringToObject(sgw, "address", s->sgw_addr) ||
            !cJSON_AddNumberToObject(sgw, "port", (double)s->sgw_port)) {
            cJSON_Delete(sgw); goto end;
        }
        if (s->s11_teid &&
            !cJSON_AddNumberToObject(sgw, "s11_teid",
                    (double)s->s11_teid)) {
            cJSON_Delete(sgw); goto end;
        }
        cJSON_AddItemToObjectCS(o, "sgw", sgw);
    }

    /* pdn + pdn_count */
    {
        cJSON *arr = cJSON_CreateArray();
        if (!arr) goto end;

        int i;
        for (i = 0; i < s->num_pdn; i++) {
            const ue_pdn_snap_t *p = &s->pdn[i];

            cJSON *it = cJSON_CreateObject();
            if (!it) { cJSON_Delete(arr); goto end; }

            if (p->apn[0] &&
                !cJSON_AddStringToObject(it, "apn", p->apn)) {
                cJSON_Delete(it); cJSON_Delete(arr); goto end;
            }

            cJSON *qarr = cJSON_CreateArray();
            if (!qarr) { cJSON_Delete(it); cJSON_Delete(arr); goto end; }

            int e;
            for (e = 0; e < p->num_ebis; e++) {
                cJSON *qf = cJSON_CreateObject();
                if (!qf) {
                    cJSON_Delete(qarr); cJSON_Delete(it);
                    cJSON_Delete(arr); goto end;
                }
                if (!cJSON_AddNumberToObject(qf, "ebi",
                            (double)p->ebis[e])) {
                    cJSON_Delete(qf); cJSON_Delete(qarr);
                    cJSON_Delete(it); cJSON_Delete(arr); goto end;
                }
                cJSON_AddItemToArray(qarr, qf);
            }

            cJSON_AddItemToObjectCS(it, "qos_flows", qarr);

            if (p->qci > 0 &&
                !cJSON_AddNumberToObject(it, "qci", (double)p->qci)) {
                cJSON_Delete(it); cJSON_Delete(arr); goto end;
            }
            if (p->ebi_root &&
                !cJSON_AddNumberToObject(it, "ebi",
                        (double)p->ebi_root)) {
                cJSON_Delete(it); cJSON_Delete(arr); goto end;
            }
            if (!cJSON_AddNumberToObject(it, "bearer_count",
                        (double)p->bearer_count)) {
                cJSON_Delete(it); cJSON_Delete(arr); goto end;
            }
            if (!cJSON_AddStringToObject(it, "pdu_state",
                        p->bearer_count ? "active" : "unknown")) {
                cJSON_Delete(it); cJSON_Delete(arr); goto end;
            }

            if (p->has_ue_ip4 &&
                !cJSON_AddStringToObject(it, "ipv4", p->ue_ip4)) {
                cJSON_Delete(it); cJSON_Delete(arr); goto end;
            }
            if (p->has_ue_ip6 &&
                !cJSON_AddStringToObject(it, "ipv6", p->ue_ip6)) {
                cJSON_Delete(it); cJSON_Delete(arr); goto end;
            }

            if (p->has_pgw) {
                cJSON *pgw = cJSON_CreateObject();
                if (!pgw) { cJSON_Delete(it); cJSON_Delete(arr); goto end; }
                if (p->has_pgw_addr &&
                    !cJSON_AddStringToObject(pgw, "address",
                            p->pgw_addr)) {
                    cJSON_Delete(pgw); cJSON_Delete(it);
                    cJSON_Delete(arr); goto end;
                }
                if (p->pgw_s5c_teid &&
                    !cJSON_AddNumberToObject(pgw, "s5c_teid",
                            (double)p->pgw_s5c_teid)) {
                    cJSON_Delete(pgw); cJSON_Delete(it);
                    cJSON_Delete(arr); goto end;
                }
                if (p->has_pgw_cfg &&
                    !cJSON_AddStringToObject(pgw, "config_selected",
                            p->pgw_cfg)) {
                    cJSON_Delete(pgw); cJSON_Delete(it);
                    cJSON_Delete(arr); goto end;
                }
                cJSON_AddItemToObjectCS(it, "pgw", pgw);
            }

            cJSON_AddItemToArray(arr, it);
        }

        cJSON_AddItemToObjectCS(o, "pdn", arr);
        if (!cJSON_AddNumberToObject(o, "pdn_count",
                    (double)s->pdn_count)) goto end;
    }

    return o;

end:
    cJSON_Delete(o);
    return NULL;
}

/* Grow-by-doubling snapshot slot; NULL = bound hit or allocation fail. */
static ue_snap_t *ue_snap_slot(ue_snap_t **arr, size_t *cap, size_t used)
{
    if (used >= UE_INFO_SNAP_MAX)
        return NULL;
    if (used == *cap) {
        size_t ncap = *cap ? *cap * 2 : 64;
        ue_snap_t *n = ogs_realloc(*arr, ncap * sizeof(*n));
        if (!n)
            return NULL;
        *arr = n;
        *cap = ncap;
    }
    return &(*arr)[used];
}

size_t mme_dump_ue_info_paged(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    if (!buf || buflen == 0) return 0;

    const bool no_paging = json_pager_setup(&page, &page_size,
            MME_UE_INFO_PAGE_SIZE_DEFAULT);

    const size_t start_index = json_pager_safe_start_index(no_paging, page, page_size);

    cJSON *root  = cJSON_CreateObject();
    if (!root) {
        if (buflen >= 3) { memcpy(buf, "{}", 3); return 2; }
        if (buflen) buf[0] = '\0';
        return 0;
    }

    cJSON *items = cJSON_CreateArray();
    if (!items) {
        cJSON_Delete(root);
        if (buflen >= 3) { memcpy(buf, "{}", 3); return 2; }
        if (buflen) buf[0] = '\0';
        return 0;
    }

    size_t idx = 0, emitted = 0, total = 0;
    bool has_next = false, oom = false;

    mme_context_t *ctxt = mme_self();
    if (!ctxt) {
        cJSON_Delete(items);
        cJSON_Delete(root);
        if (buflen >= 3) { memcpy(buf, "{}", 3); return 2; }
        if (buflen) buf[0] = '\0';
        return 0;
    }

    ue_snap_t *snaps = NULL;
    size_t snap_cap = 0;

    /*
     * Snapshot phase. The MHD daemon runs on its own thread; hold
     * mme_ctx_lock() only while copying values out of the live UE
     * objects (the lock pairs with mme_ue_add / mme_ue_remove and
     * the sess/bearer list mutators). The cJSON build below runs
     * after unlock, so a poll no longer stalls main/workers for the
     * whole JSON build.
     */
    mme_ctx_lock();

    if (q && q->imsi && *q->imsi) {
        /*
         * Fast path for exact-IMSI queries (NMS IMSI watch / trace
         * panel polls /ue-info?imsi= every few seconds). Resolve via
         * the IMSI hash so the lock is held for one lookup + one
         * value copy.
         */
        mme_ue_t *ue = mme_ue_find_by_imsi_bcd(q->imsi);
        if (ue && q->has_enb_id) {
            enb_ue_t *ran = enb_ue_find_by_id(ue->enb_ue_id);
            mme_enb_t *e  = ran ? mme_enb_find_by_id(ran->enb_id) : NULL;
            if (!e || e->enb_id != q->enb_id) ue = NULL;
        }
        if (ue) {
            total = 1;
            int act = json_pager_advance(no_paging, idx, start_index,
                    emitted, page_size, &has_next);
            if (act == 0) {
                ue_snap_t *slot = ue_snap_slot(&snaps, &snap_cap, emitted);
                if (!slot) oom = true;
                else { ue_snapshot_fill(slot, ue); emitted++; }
            }
            idx++;
        }
    } else if (q && q->has_enb_id) {
        /*
         * Fast path for per-eNB queries (NMS Live page fires one
         * /ue-info?enb_id= per selected eNodeB on every poll). Walk
         * only that eNB's enb_ue_list instead of every UE in the
         * system; both lists are mutated under the same ctx lock we
         * hold here.
         */
        mme_enb_t *enb = mme_enb_find_by_enb_id(q->enb_id);
        enb_ue_t *ran = NULL;
        if (enb) ogs_list_for_each(&enb->enb_ue_list, ran) {
            mme_ue_t *ue = mme_ue_find_by_id(ran->mme_ue_id);
            /* Skip stale associations: the UE must still point back
             * at this enb_ue as its current RAN context. */
            if (!ue || ue->enb_ue_id != ran->id) continue;

            total++;

            int act = json_pager_advance(no_paging, idx, start_index,
                    emitted, page_size, &has_next);
            if (act == 1) { idx++; continue; }
            if (act == 0) {
                ue_snap_t *slot = ue_snap_slot(&snaps, &snap_cap, emitted);
                if (!slot) { oom = true; break; }

                ue_snapshot_fill(slot, ue);
                emitted++;
            }
            idx++;
        }
    } else {
        mme_ue_t *ue = NULL;
        ogs_list_for_each(&ctxt->mme_ue_list, ue) {
            total++;

            int act = json_pager_advance(no_paging, idx, start_index,
                    emitted, page_size, &has_next);
            if (act == 1) { idx++; continue; }
            if (act == 0) {
                ue_snap_t *slot = ue_snap_slot(&snaps, &snap_cap, emitted);
                if (!slot) { oom = true; break; }

                ue_snapshot_fill(slot, ue);
                emitted++;
            }
            idx++;
        }
    }

    mme_ctx_unlock();

    /* Build phase: values only, no live context pointers. */
    {
        size_t i;
        for (i = 0; i < emitted; i++) {
            cJSON *one = ue_snap_to_json(&snaps[i]);
            if (!one) { oom = true; break; }
            cJSON_AddItemToArray(items, one);
        }
        if (i < emitted)
            emitted = i;
    }

    if (snaps)
        ogs_free(snaps);

    /* attach only when array is fully built */
    cJSON_AddItemToObjectCS(root, "items", items);
    json_pager_add_trailing(root, no_paging, page, page_size, emitted, total,
                            has_next && !oom, "/ue-info", oom);

    return json_pager_finalize(root, buf, buflen);
}

