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
 * curl -s "http://127.0.0.3:9090/pdn-info?rat=EUTRAN"
 */

#include "pdn-info.h"

#include "context.h"

#include "ogs-metrics.h"
#include "metrics/prometheus/json_pager.h"

#include "sbi/openapi/external/cJSON.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

static const char *sgwc_gtp_rat_type_name(uint8_t rat)
{
    switch (rat) {
    case OGS_GTP2_RAT_TYPE_UTRAN:
        return "UTRAN";
    case OGS_GTP2_RAT_TYPE_GERAN:
        return "GERAN";
    case OGS_GTP2_RAT_TYPE_WLAN:
        return "WLAN";
    case OGS_GTP2_RAT_TYPE_GAN:
        return "GAN";
    case OGS_GTP2_RAT_TYPE_HSPA_EVOLUTION:
        return "HSPA_EVOLUTION";
    case OGS_GTP2_RAT_TYPE_EUTRAN:
        return "EUTRAN";
    case OGS_GTP2_RAT_TYPE_VIRTUAL:
        return "VIRTUAL";
    case OGS_GTP2_RAT_TYPE_EUTRAN_NB_IOT:
        return "EUTRAN_NB_IOT";
    default:
        return NULL;
    }
}

static const char *sgwc_sess_rat_name(const sgwc_sess_t *sess)
{
    if (!sess || !sess->gtp_rat_type)
        return NULL;

    return sgwc_gtp_rat_type_name(sess->gtp_rat_type);
}

bool sgwc_sess_rat_metric_labels(const sgwc_sess_t *sess,
        const char **rat, const char **gtp_if)
{
    static const char gtp_if_s11[] = "s11";
    static const char gtp_if_gn[] = "gn";

    if (!sess || !rat || !gtp_if)
        return false;

    *rat = sgwc_sess_rat_name(sess);
    if (!*rat)
        return false;

    if (sess->gn)
        *gtp_if = gtp_if_gn;
    else
        *gtp_if = gtp_if_s11;

    return true;
}

static cJSON *build_rat_object(const sgwc_sess_t *sess)
{
    const char *name;
    cJSON *rat;

    if (!sess || !sess->gtp_rat_type)
        return NULL;

    name = sgwc_gtp_rat_type_name(sess->gtp_rat_type);
    if (!name)
        return NULL;

    rat = cJSON_CreateObject();
    if (!rat)
        return NULL;

    cJSON_AddItemToObjectCS(rat, "name", cJSON_CreateString(name));
    cJSON_AddItemToObjectCS(rat, "gtp", cJSON_CreateNumber(sess->gtp_rat_type));
    if (sess->gn)
        cJSON_AddItemToObjectCS(rat, "gtp_if", cJSON_CreateString("gn"));
    else
        cJSON_AddItemToObjectCS(rat, "gtp_if", cJSON_CreateString("s11"));

    return rat;
}

static bool sgwc_sess_matches_pdn_filters(const sgwc_sess_t *sess,
        const ogs_metrics_query_t *q)
{
    const char *rat_name = NULL;

    if (!sess || !q)
        return true;

    if (q->rat && *q->rat) {
        rat_name = sgwc_sess_rat_name(sess);
        if (!rat_name || strcasecmp(rat_name, q->rat) != 0)
            return false;
    }

    return true;
}

static bool sgwc_ue_has_matching_pdn(const sgwc_ue_t *ue,
        const ogs_metrics_query_t *q)
{
    sgwc_sess_t *sess = NULL;

    ogs_assert(ue);

    ogs_list_for_each(&ue->sess_list, sess) {
        if (sgwc_sess_matches_pdn_filters(sess, q))
            return true;
    }

    return false;
}

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

/* Non-IMSI UE-level filters (ue_ip / ran ip / rat), shared by the
 * full-list walk and the exact-IMSI fast path. */
static bool sgwc_ue_matches_secondary_filters(const sgwc_ue_t *ue,
        const ogs_metrics_query_t *q);

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

static bool sgwc_ue_matches_secondary_filters(const sgwc_ue_t *ue,
        const ogs_metrics_query_t *q)
{
    if (!q)
        return true;

    if (q->ue_ip && *q->ue_ip) {
        bool match = false;
        sgwc_sess_t *sess = NULL;

        ogs_list_for_each(&ue->sess_list, sess) {
            if (sess_matches_ue_ip(sess, q->ue_ip)) {
                match = true;
                break;
            }
        }
        if (!match)
            return false;
    }
    if (q->ip && *q->ip) {
        if (!ue_matches_ran_ip(ue, q->ip))
            return false;
    }
    if (q->rat && *q->rat) {
        if (!sgwc_ue_has_matching_pdn(ue, q))
            return false;
    }

    return true;
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

static bool sgwc_plmn_is_set(const ogs_plmn_id_t *plmn)
{
    static const uint8_t zero[OGS_PLMN_ID_LEN];

    return plmn && memcmp(plmn, zero, OGS_PLMN_ID_LEN) != 0;
}

static bool sgwc_json_add_plmn_from_nas(
        cJSON *o, const ogs_nas_plmn_id_t *nas)
{
    ogs_plmn_id_t plmn;
    char buf[OGS_PLMNIDSTRLEN];

    if (!o || !nas)
        return false;

    ogs_nas_to_plmn_id(&plmn, nas);
    if (!sgwc_plmn_is_set(&plmn))
        return false;
    ogs_plmn_id_to_string(&plmn, buf);
    return cJSON_AddStringToObject(o, "plmn", buf) != NULL;
}

static bool sgwc_json_add_hex16(cJSON *o, const char *key, unsigned value)
{
    char buf[8];

    if (!o || !key)
        return false;
    snprintf(buf, sizeof(buf), "%04x", value & 0xffffu);
    return cJSON_AddStringToObject(o, key, buf) != NULL;
}

static cJSON *build_location_object(
        const sgwc_ue_t *ue, const sgwc_sess_t *sess)
{
    cJSON *loc = NULL;
    bool added = false;
    ogs_gtp2_uli_t uli2;
    ogs_gtp1_uli_t uli1;
    ogs_tlv_octet_t octet;

    ogs_assert(ue);

    loc = cJSON_CreateObject();
    if (!loc)
        return NULL;

    if (sess && sgwc_plmn_is_set(&sess->serving_plmn_id)) {
        char buf[OGS_PLMNIDSTRLEN];
        ogs_plmn_id_to_string(&sess->serving_plmn_id, buf);
        if (cJSON_AddStringToObject(loc, "plmn", buf))
            added = true;
    }

    memset(&octet, 0, sizeof(octet));
    if (ue->uli_pkbuf && ue->uli_pkbuf->data && ue->uli_pkbuf->len) {
        octet.presence = 1;
        octet.data = ue->uli_pkbuf->data;
        octet.len = ue->uli_pkbuf->len;
    }

    if (octet.presence &&
            ogs_gtp2_parse_uli(&uli2, &octet) == octet.len) {
        if (uli2.flags.tai) {
            cJSON *tai = cJSON_CreateObject();
            if (tai) {
                sgwc_json_add_plmn_from_nas(tai, &uli2.tai.nas_plmn_id);
                sgwc_json_add_hex16(tai, "tac", uli2.tai.tac);
                cJSON_AddItemToObjectCS(loc, "tai", tai);
                added = true;
            }
        }
        if (uli2.flags.e_cgi) {
            cJSON *ecgi = cJSON_CreateObject();
            if (ecgi) {
                char cell[9];
                sgwc_json_add_plmn_from_nas(ecgi, &uli2.e_cgi.nas_plmn_id);
                snprintf(cell, sizeof(cell), "%07x",
                        (unsigned)(uli2.e_cgi.cell_id & 0x0fffffffu));
                cJSON_AddStringToObject(ecgi, "cell_id", cell);
                cJSON_AddItemToObjectCS(loc, "ecgi", ecgi);
                added = true;
            }
        }
        if (uli2.flags.rai) {
            cJSON *rai = cJSON_CreateObject();
            if (rai) {
                sgwc_json_add_plmn_from_nas(rai, &uli2.rai.nas_plmn_id);
                sgwc_json_add_hex16(rai, "lac", uli2.rai.lac);
                sgwc_json_add_hex16(rai, "rac", uli2.rai.rac);
                cJSON_AddItemToObjectCS(loc, "rai", rai);
                added = true;
            }
        }
        if (uli2.flags.sai) {
            cJSON *sai = cJSON_CreateObject();
            if (sai) {
                sgwc_json_add_plmn_from_nas(sai, &uli2.sai.nas_plmn_id);
                sgwc_json_add_hex16(sai, "lac", uli2.sai.lac);
                sgwc_json_add_hex16(sai, "sac", uli2.sai.sac);
                cJSON_AddItemToObjectCS(loc, "sai", sai);
                added = true;
            }
        }
        if (uli2.flags.cgi) {
            cJSON *cgi = cJSON_CreateObject();
            if (cgi) {
                sgwc_json_add_plmn_from_nas(cgi, &uli2.cgi.nas_plmn_id);
                sgwc_json_add_hex16(cgi, "lac", uli2.cgi.lac);
                sgwc_json_add_hex16(cgi, "ci", uli2.cgi.ci);
                cJSON_AddItemToObjectCS(loc, "cgi", cgi);
                added = true;
            }
        }
        if (uli2.flags.lai) {
            cJSON *lai = cJSON_CreateObject();
            if (lai) {
                sgwc_json_add_plmn_from_nas(lai, &uli2.lai.nas_plmn_id);
                sgwc_json_add_hex16(lai, "lac", uli2.lai.lac);
                cJSON_AddItemToObjectCS(loc, "lai", lai);
                added = true;
            }
        }
    } else if (octet.presence &&
            ogs_gtp1_parse_uli(&uli1, &octet) > 0) {
        ogs_plmn_id_t plmn_id;
        char buf[OGS_PLMNIDSTRLEN];

        switch (uli1.geo_loc_type) {
        case OGS_GTP1_GEO_LOC_TYPE_CGI:
            ogs_nas_to_plmn_id(&plmn_id, &uli1.cgi.nas_plmn_id);
            if (sgwc_plmn_is_set(&plmn_id)) {
                cJSON *cgi = cJSON_CreateObject();
                if (cgi) {
                    ogs_plmn_id_to_string(&plmn_id, buf);
                    cJSON_AddStringToObject(cgi, "plmn", buf);
                    sgwc_json_add_hex16(cgi, "lac", uli1.cgi.lac);
                    sgwc_json_add_hex16(cgi, "ci", uli1.cgi.ci);
                    cJSON_AddItemToObjectCS(loc, "cgi", cgi);
                    added = true;
                }
            }
            break;
        case OGS_GTP1_GEO_LOC_TYPE_SAI:
            ogs_nas_to_plmn_id(&plmn_id, &uli1.sai.nas_plmn_id);
            if (sgwc_plmn_is_set(&plmn_id)) {
                cJSON *sai = cJSON_CreateObject();
                if (sai) {
                    ogs_plmn_id_to_string(&plmn_id, buf);
                    cJSON_AddStringToObject(sai, "plmn", buf);
                    sgwc_json_add_hex16(sai, "lac", uli1.sai.lac);
                    sgwc_json_add_hex16(sai, "sac", uli1.sai.sac);
                    cJSON_AddItemToObjectCS(loc, "sai", sai);
                    added = true;
                }
            }
            break;
        case OGS_GTP1_GEO_LOC_TYPE_RAI:
            ogs_nas_to_plmn_id(&plmn_id, &uli1.rai.nas_plmn_id);
            if (sgwc_plmn_is_set(&plmn_id)) {
                cJSON *rai = cJSON_CreateObject();
                if (rai) {
                    ogs_plmn_id_to_string(&plmn_id, buf);
                    cJSON_AddStringToObject(rai, "plmn", buf);
                    sgwc_json_add_hex16(rai, "lac", uli1.rai.lac);
                    sgwc_json_add_hex16(rai, "rac", uli1.rai.rac);
                    cJSON_AddItemToObjectCS(loc, "rai", rai);
                    added = true;
                }
            }
            break;
        default:
            break;
        }
    } else if (ue->uli_presence && sgwc_plmn_is_set(&ue->e_tai.plmn_id)) {
        /* Fallback if raw ULI cannot be parsed. */
        cJSON *tai = cJSON_CreateObject();
        if (tai) {
            char buf[OGS_PLMNIDSTRLEN];
            char tac[8];
            ogs_plmn_id_to_string(&ue->e_tai.plmn_id, buf);
            snprintf(tac, sizeof(tac), "%04x", (unsigned)ue->e_tai.tac);
            cJSON_AddStringToObject(tai, "plmn", buf);
            cJSON_AddStringToObject(tai, "tac", tac);
            cJSON_AddItemToObjectCS(loc, "tai", tai);
            added = true;
        }
        if (sgwc_plmn_is_set(&ue->e_cgi.plmn_id)) {
            cJSON *ecgi = cJSON_CreateObject();
            if (ecgi) {
                char buf[OGS_PLMNIDSTRLEN];
                char cell[9];
                ogs_plmn_id_to_string(&ue->e_cgi.plmn_id, buf);
                snprintf(cell, sizeof(cell), "%07x",
                        (unsigned)ue->e_cgi.cell_id);
                cJSON_AddStringToObject(ecgi, "plmn", buf);
                cJSON_AddStringToObject(ecgi, "cell_id", cell);
                cJSON_AddItemToObjectCS(loc, "ecgi", ecgi);
                added = true;
            }
        }
    }

    if (!added) {
        cJSON_Delete(loc);
        return NULL;
    }

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
        cJSON *rat = build_rat_object(sess);
        if (rat)
            cJSON_AddItemToObjectCS(pdn, "rat", rat);
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
        sgwc_tunnel_t *ul_tunnel = sgwc_ul_tunnel_in_bearer(def_bearer);
        char enb_ip[OGS_ADDRSTRLEN] = "";
        char pgw_u_ip[OGS_ADDRSTRLEN] = "";

        if (ul_tunnel && ip_to_text(&ul_tunnel->remote_ip, pgw_u_ip, sizeof(pgw_u_ip))) {
            cJSON *pgw_u = cJSON_CreateObject();
            if (!pgw_u) {
                cJSON_Delete(pdn);
                return NULL;
            }
            cJSON_AddItemToObjectCS(pgw_u, "addr", cJSON_CreateString(pgw_u_ip));
            if (ul_tunnel->remote_teid) {
                cJSON_AddItemToObjectCS(pgw_u, "teid",
                        cJSON_CreateNumber((double)ul_tunnel->remote_teid));
            }
            cJSON_AddItemToObjectCS(pdn, "pgw_u", pgw_u);
        }

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
        if (sess->pfcp_node) {
            const char *pfcp_addr =
                ogs_pfcp_node_pfcp_endpoint(sess->pfcp_node);
            const char *service_host =
                ogs_pfcp_node_service_host(sess->pfcp_node);

            if (pfcp_addr && pfcp_addr[0]) {
                cJSON_AddItemToObjectCS(sxa, "pfcp_addr",
                        cJSON_CreateString(pfcp_addr));
                cJSON_AddItemToObjectCS(sxa, "sgwu_addr",
                        cJSON_CreateString(pfcp_addr));
            }
            if (service_host && service_host[0]) {
                cJSON_AddItemToObjectCS(sxa, "service_addr",
                        cJSON_CreateString(service_host));
            }
        }
        cJSON_AddItemToObjectCS(pdn, "sxa", sxa);
    }

    cJSON_AddItemToObjectCS(pdn, "usage_ul_octets",
            cJSON_CreateNumber((double)sess->usage_ul_octets));
    cJSON_AddItemToObjectCS(pdn, "usage_dl_octets",
            cJSON_CreateNumber((double)sess->usage_dl_octets));

    {
        cJSON *loc = build_location_object(ue, sess);
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
    if (!buf || buflen == 0)
        return 0;

    const bool no_paging = json_pager_setup(&page, &page_size,
            PDN_INFO_PAGE_SIZE_DEFAULT);
    const size_t start_index = json_pager_safe_start_index(no_paging, page, page_size);
    cJSON *root = NULL;
    cJSON *items = NULL;
    sgwc_context_t *ctx = sgwc_self();
    sgwc_ue_t *ue = NULL;
    size_t idx = 0, emitted = 0, total = 0;
    bool has_next = false, oom = false;

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

    if (q && q->imsi && *q->imsi) {
        /*
         * Fast path for exact-IMSI queries (NMS IMSI watch / trace
         * panel polls /pdn-info?imsi= every few seconds). Walking the
         * whole sgw_ue_list under the dump lock scales with total
         * subscribers; resolve via the IMSI hash instead.
         */
        ue = sgwc_ue_find_by_imsi_bcd(q->imsi);
        if (ue && sgwc_ue_matches_secondary_filters(ue, q)) {
            total = 1;
            int act = json_pager_advance(no_paging, idx, start_index,
                    emitted, page_size, &has_next);
            if (act == 0) {
                cJSON *ueo = build_ue_object(ue);
                if (!ueo) oom = true;
                else { cJSON_AddItemToArray(items, ueo); emitted++; }
            }
            idx++;
        }
        goto done;
    }

    ogs_list_for_each(&ctx->sgw_ue_list, ue) {
        if (!sgwc_ue_matches_secondary_filters(ue, q))
            continue;

        total++;

        {
            int act = json_pager_advance(no_paging, idx, start_index,
                    emitted, page_size, &has_next);
            if (act == 1) {
                idx++;
                continue;
            }
            if (act == 0) {
            cJSON *ueo = build_ue_object(ue);
            if (!ueo) {
                oom = true;
                break;
            }
            cJSON_AddItemToArray(items, ueo);
            emitted++;
            }
        }
        idx++;
    }

done:
    ogs_metrics_dump_unlock();

    cJSON_AddItemToObjectCS(root, "items", items);
    json_pager_add_trailing(root, no_paging, page, page_size, emitted, total,
            has_next && !oom, "/pdn-info", oom);

    return json_pager_finalize(root, buf, buflen);
}
