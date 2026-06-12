/*
 * Copyright (C) 2025 by Sukchan Lee <acetcom@gmail.com>
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
 * Active PDN sessions JSON dumper for the metrics HTTP server (/pdn-info).
 *
 * curl -s "http://127.0.0.3:9090/pdn-info?imsi=001010000000001"
 * curl -s "http://127.0.0.3:9090/pdn-info?enb_ip=10.1.2.3"
 * curl -s "http://127.0.0.3:9090/pdn-info?ue_ip=10.45.0.7&page_size=50"
 */

#include "pdn-info.h"

#include "context.h"

#include "ogs-metrics.h"
#include "metrics/prometheus/json_pager.h"

#include <cJSON.h>

static int ip_to_text(const ogs_ip_t *ip, char *out, size_t outlen)
{
    const char *ret;

    if (!ip || !out || outlen == 0)
        return 0;

    out[0] = '\0';

    if (ip->ipv4) {
        ret = OGS_INET_NTOP(&ip->addr, out);
        if (ret)
            return 1;
    }

    if (ip->ipv6) {
        ret = OGS_INET6_NTOP(ip->addr6, out);
        if (ret)
            return 1;
    }

    return 0;
}

static bool ogs_ip_matches_query(const ogs_ip_t *ip, const char *needle)
{
    char buf[OGS_ADDRSTRLEN] = "";

    if (!ip || !needle || !*needle)
        return false;
    if (!ip_to_text(ip, buf, sizeof(buf)))
        return false;
    return strcmp(buf, needle) == 0;
}

static bool sess_matches_ran_ip(const sgwc_sess_t *sess, const char *ran_ip)
{
    sgwc_bearer_t *bearer = NULL;

    ogs_assert(sess);

    ogs_list_for_each(&sess->bearer_list, bearer) {
        sgwc_tunnel_t *dl_tunnel = NULL;

        if (!bearer)
            continue;

        dl_tunnel = sgwc_dl_tunnel_in_bearer(bearer);
        if (dl_tunnel && ogs_ip_matches_query(&dl_tunnel->remote_ip, ran_ip))
            return true;
    }

    return false;
}

static bool ue_matches_ran_ip(const sgwc_ue_t *ue, const char *ran_ip)
{
    sgwc_sess_t *sess = NULL;

    ogs_assert(ue);

    ogs_list_for_each(&ue->sess_list, sess) {
        if (sess_matches_ran_ip(sess, ran_ip))
            return true;
    }

    return false;
}

static bool sess_matches_ue_ip(const sgwc_sess_t *sess, const char *ue_ip)
{
    ogs_ip_t ip;

    ogs_assert(sess);
    ogs_assert(ue_ip);

    if (!sess->paa.session_type)
        return false;

    if (ogs_paa_to_ip(&sess->paa, &ip) != OGS_OK)
        return false;

    if (ip.ipv4) {
        char ip4[OGS_ADDRSTRLEN] = "";
        OGS_INET_NTOP(&ip.addr, ip4);
        if (ip4[0] && strcmp(ip4, ue_ip) == 0)
            return true;
    }
    if (ip.ipv6) {
        char ip6[OGS_ADDRSTRLEN] = "";
        OGS_INET6_NTOP(ip.addr6, ip6);
        if (ip6[0] && strcmp(ip6, ue_ip) == 0)
            return true;
    }

    return false;
}

static cJSON *build_qos_flows_array(const sgwc_sess_t *sess)
{
    cJSON *arr = cJSON_CreateArray();
    sgwc_bearer_t *bearer = NULL;
    unsigned qci_val;

    if (!arr)
        return NULL;

    ogs_list_for_each(&((sgwc_sess_t *)sess)->bearer_list, bearer) {
        cJSON *q = NULL;

        if (!bearer || bearer->ebi == 0)
            continue;

        qci_val = (unsigned)sess->session.qos.index;

        q = cJSON_CreateObject();
        if (!q) {
            cJSON_Delete(arr);
            return NULL;
        }

        cJSON_AddItemToObjectCS(q, "ebi",
                cJSON_CreateNumber((double)(unsigned)bearer->ebi));
        if (qci_val > 0)
            cJSON_AddItemToObjectCS(q, "qci",
                    cJSON_CreateNumber((double)qci_val));

        cJSON_AddItemToArray(arr, q);
    }

    return arr;
}

static cJSON *build_location_object(const sgwc_ue_t *ue)
{
    cJSON *loc = NULL;
    cJSON *tai = NULL;
    cJSON *ecgi = NULL;
    char plmn[OGS_PLMNIDSTRLEN] = "";
    char ecgi_plmn[OGS_PLMNIDSTRLEN] = "";
    char tac[7] = "";
    char cell[9] = "";

    ogs_assert(ue);

    if (!ue->uli_presence)
        return NULL;

    loc = cJSON_CreateObject();
    tai = cJSON_CreateObject();
    ecgi = cJSON_CreateObject();
    if (!loc || !tai || !ecgi) {
        cJSON_Delete(loc);
        cJSON_Delete(tai);
        cJSON_Delete(ecgi);
        return NULL;
    }

    ogs_plmn_id_to_string(&ue->e_tai.plmn_id, plmn);
    snprintf(tac, sizeof(tac), "%04x", (unsigned)ue->e_tai.tac);
    cJSON_AddItemToObjectCS(tai, "plmn", cJSON_CreateString(plmn));
    cJSON_AddItemToObjectCS(tai, "tac", cJSON_CreateString(tac));
    cJSON_AddItemToObjectCS(loc, "tai", tai);

    ogs_plmn_id_to_string(&ue->e_cgi.plmn_id, ecgi_plmn);
    snprintf(cell, sizeof(cell), "%07x", (unsigned)ue->e_cgi.cell_id);
    cJSON_AddItemToObjectCS(ecgi, "plmn", cJSON_CreateString(ecgi_plmn));
    cJSON_AddItemToObjectCS(ecgi, "cell_id", cJSON_CreateString(cell));
    cJSON_AddItemToObjectCS(loc, "ecgi", ecgi);

    return loc;
}

static cJSON *build_single_pdn_object(const sgwc_sess_t *sess,
        const sgwc_ue_t *ue)
{
    cJSON *pdn = NULL;
    sgwc_bearer_t *def_bearer = NULL;
    ogs_ip_t ip;
    char pgw_addr[OGS_ADDRSTRLEN] = "";

    ogs_assert(sess);
    ogs_assert(ue);

    pdn = cJSON_CreateObject();
    if (!pdn)
        return NULL;

    def_bearer = sgwc_default_bearer_in_sess((sgwc_sess_t *)sess);
    if (def_bearer && def_bearer->ebi > 0) {
        cJSON_AddItemToObjectCS(pdn, "ebi",
                cJSON_CreateNumber((double)(unsigned)def_bearer->ebi));
    }

    cJSON_AddItemToObjectCS(pdn, "apn",
            cJSON_CreateString(sess->session.name ? sess->session.name : ""));

    if (sess->paa.session_type &&
            ogs_paa_to_ip(&sess->paa, &ip) == OGS_OK) {
        if (ip.ipv4) {
            char ip4[OGS_ADDRSTRLEN] = "";
            OGS_INET_NTOP(&ip.addr, ip4);
            if (ip4[0])
                cJSON_AddItemToObjectCS(pdn, "ipv4", cJSON_CreateString(ip4));
        }
        if (ip.ipv6) {
            char ip6[OGS_ADDRSTRLEN] = "";
            OGS_INET6_NTOP(ip.addr6, ip6);
            if (ip6[0])
                cJSON_AddItemToObjectCS(pdn, "ipv6", cJSON_CreateString(ip6));
        }
    }

    if (sess->charging_id) {
        cJSON_AddItemToObjectCS(pdn, "charging_id",
                cJSON_CreateNumber((double)sess->charging_id));
    }

    {
        cJSON *qarr = build_qos_flows_array(sess);
        if (!qarr) {
            cJSON_Delete(pdn);
            return NULL;
        }
        cJSON_AddItemToObjectCS(pdn, "qos_flows", qarr);
    }

    if (sess->gnode && sess->gnode->sa_list)
        OGS_ADDR(sess->gnode->sa_list, pgw_addr);

    if (def_bearer) {
        sgwc_tunnel_t *dl_tunnel = sgwc_dl_tunnel_in_bearer(def_bearer);
        char enb_ip[OGS_ADDRSTRLEN] = "";

        if (dl_tunnel && ip_to_text(&dl_tunnel->remote_ip, enb_ip, sizeof(enb_ip))) {
            cJSON *s1u = cJSON_CreateObject();
            if (!s1u) {
                cJSON_Delete(pdn);
                return NULL;
            }
            cJSON_AddItemToObjectCS(s1u, "enb_addr", cJSON_CreateString(enb_ip));
            if (dl_tunnel->remote_teid) {
                cJSON_AddItemToObjectCS(s1u, "enb_teid",
                        cJSON_CreateNumber((double)dl_tunnel->remote_teid));
            }
            cJSON_AddItemToObjectCS(pdn, "s1u", s1u);
        }
    }

    {
        cJSON *s5 = cJSON_CreateObject();
        if (!s5) {
            cJSON_Delete(pdn);
            return NULL;
        }
        cJSON_AddItemToObjectCS(s5, "sgw_s5c_teid",
                cJSON_CreateNumber((double)sess->sgw_s5c_teid));
        cJSON_AddItemToObjectCS(s5, "pgw_s5c_teid",
                cJSON_CreateNumber((double)sess->pgw_s5c_teid));
        if (pgw_addr[0])
            cJSON_AddItemToObjectCS(s5, "pgw_addr", cJSON_CreateString(pgw_addr));
        cJSON_AddItemToObjectCS(pdn, "s5", s5);
    }

    {
        cJSON *sxa = cJSON_CreateObject();
        if (!sxa) {
            cJSON_Delete(pdn);
            return NULL;
        }
        cJSON_AddItemToObjectCS(sxa, "sgwc_seid",
                cJSON_CreateNumber((double)sess->sgwc_sxa_seid));
        cJSON_AddItemToObjectCS(sxa, "sgwu_seid",
                cJSON_CreateNumber((double)sess->sgwu_sxa_seid));
        cJSON_AddItemToObjectCS(pdn, "sxa", sxa);
    }

    cJSON_AddItemToObjectCS(pdn, "usage_ul_octets",
            cJSON_CreateNumber((double)sess->usage_ul_octets));
    cJSON_AddItemToObjectCS(pdn, "usage_dl_octets",
            cJSON_CreateNumber((double)sess->usage_dl_octets));

    {
        cJSON *loc = build_location_object(ue);
        if (loc)
            cJSON_AddItemToObjectCS(pdn, "location", loc);
    }

    return pdn;
}

static cJSON *build_ue_object(const sgwc_ue_t *ue)
{
    cJSON *ueo = NULL;
    cJSON *pdns = NULL;
    sgwc_sess_t *sess = NULL;

    ogs_assert(ue);

    ueo = cJSON_CreateObject();
    if (!ueo)
        return NULL;

    cJSON_AddItemToObjectCS(ueo, "imsi",
            cJSON_CreateString(ue->imsi_bcd[0] ? ue->imsi_bcd : ""));

    pdns = cJSON_CreateArray();
    if (!pdns) {
        cJSON_Delete(ueo);
        return NULL;
    }

    ogs_list_for_each(&ue->sess_list, sess) {
        cJSON *pdn = build_single_pdn_object(sess, ue);
        if (!pdn) {
            cJSON_Delete(pdns);
            cJSON_Delete(ueo);
            return NULL;
        }
        cJSON_AddItemToArray(pdns, pdn);
    }

    cJSON_AddItemToObjectCS(ueo, "pdn", pdns);
    cJSON_AddItemToObjectCS(ueo, "pdn_count",
            cJSON_CreateNumber((double)ogs_list_count(&ue->sess_list)));

    return ueo;
}

size_t sgwc_dump_pdn_info(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    const bool no_paging = (page == SIZE_MAX);
    const size_t start_index = json_pager_safe_start_index(no_paging, page, page_size);
    cJSON *root = NULL;
    cJSON *items = NULL;
    sgwc_context_t *ctx = sgwc_self();
    sgwc_ue_t *ue = NULL;
    size_t idx = 0, emitted = 0;
    bool has_next = false, oom = false;

    if (!buf || buflen == 0)
        return 0;

    if (!no_paging) {
        if (page_size == 0)
            page_size = PDN_INFO_PAGE_SIZE_DEFAULT;
    } else {
        page_size = SIZE_MAX;
        page = 0;
    }

    root = cJSON_CreateObject();
    if (!root) {
        if (buflen >= 3) {
            memcpy(buf, "{}", 2);
            buf[2] = '\0';
            return 2;
        }
        if (buflen)
            buf[0] = '\0';
        return 0;
    }

    items = cJSON_CreateArray();
    if (!items) {
        cJSON_Delete(root);
        if (buflen >= 3) {
            memcpy(buf, "{}", 2);
            buf[2] = '\0';
            return 2;
        }
        if (buflen)
            buf[0] = '\0';
        return 0;
    }

    ogs_metrics_dump_lock();

    ogs_list_for_each(&ctx->sgw_ue_list, ue) {
        if (q && q->imsi && *q->imsi) {
            if (!ue->imsi_bcd[0] || strcmp(ue->imsi_bcd, q->imsi) != 0)
                continue;
        }
        if (q && q->ue_ip && *q->ue_ip) {
            bool match = false;
            sgwc_sess_t *sess = NULL;

            ogs_list_for_each(&ue->sess_list, sess) {
                if (sess_matches_ue_ip(sess, q->ue_ip)) {
                    match = true;
                    break;
                }
            }
            if (!match)
                continue;
        }
        if (q && q->ip && *q->ip) {
            if (!ue_matches_ran_ip(ue, q->ip))
                continue;
        }

        {
            int act = json_pager_advance(no_paging, idx, start_index,
                    emitted, page_size, &has_next);
            if (act == 1) {
                idx++;
                continue;
            }
            if (act == 2)
                break;
        }

        {
            cJSON *ueo = build_ue_object(ue);
            if (!ueo) {
                oom = true;
                break;
            }
            cJSON_AddItemToArray(items, ueo);
            emitted++;
            idx++;
        }
    }

    ogs_metrics_dump_unlock();

    cJSON_AddItemToObjectCS(root, "items", items);
    json_pager_add_trailing(root, no_paging, page, page_size, emitted,
            has_next && !oom, "/pdn-info", oom);

    return json_pager_finalize(root, buf, buflen);
}
