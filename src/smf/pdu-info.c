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
 * Connected PDUs JSON dumper for the Prometheus HTTP server (/pdu-info).
 * - 5G PDUs:  psi+dnn, snssai, rat.{name,sbi}, qos_flows [{qfi,5qi}], n3.{gnb,upf},
 *             n4.{pfcp_addr,service_addr,...}, pdu_state
 * - LTE PDUs: ebi(+psi if non-zero)+apn, rat.{name,gtp,gtp_if}, qos_flows [{ebi,qci}],
 *             n4, s5.{pgw_u,...}, pdu_state
 * - Gn PDP:   same as LTE; rat.name is UTRAN/GERAN/EUTRAN from GTP RAT Type IE
 * - UE-level: ue_activity ("active"/"unknown"/"idle")
 * - pager: /pdu-info?page=0&page_size=100 (0-based, page=SIZE_MAX -> no paging)
 *
 * path: http://SMF_IP:9090/pdu-info
 *
 * curl -s "http://127.0.0.4:9090/pdu-info?gnb_ip=10.1.2.3"
 * curl -s "http://127.0.0.4:9090/pdu-info?rat=UTRAN&lac=1034"
 * curl -s "http://127.0.0.4:9090/pdu-info?enb_id=264040"
 * curl -s "http://127.0.0.4:9090/pdu-info?page_size=1" |jq . 
 * {
 *   "items": [
 *     {
 *       "supi": "imsi-231510000114763",
 *       "pdu": [
 *         {
 *           "psi": 1,
 *           "dnn": "internet",
 *           "ipv4": "10.45.0.11",
 *           "snssai": {
 *             "sst": 1,
 *             "sd": "ffffff"
 *           },
 *           "qos_flows": [
 *             {
 *               "qfi": 1,
 *               "5qi": 9
 *             }
 *           ],
 *           "n3": {
 *             "gnb": {
 *               "teid": 76,
 *               "addr": "[192.168.168.100]:2152"
 *             },
 *             "upf": {
 *               "teid": 11426,
 *               "addr": "[192.168.168.7]:2152",
 *               "pdr_id": 2
 *             }
 *           },
 *           "pdu_state": "inactive",
 *           "ue_location_timestamp": 1778223227627488
 *         }
 *       ],
 *       "ue_activity": "idle"
 *     }
 *   ],
 *   "pager": {
 *     "page": 0,
 *     "page_size": 100,
 *     "count": 1,
 *   }
 * }
 */ 

#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <limits.h>

#include "ogs-core.h"
#include "ogs-gtp.h"
#include "ogs-metrics.h"
#include "context.h"
#include "pdu-info.h"
#include "sbi/openapi/external/cJSON.h"
#include "metrics/prometheus/json_pager.h"

#ifndef OGS_GTPV1_U_UDP_PORT
#define OGS_GTPV1_U_UDP_PORT 2152
#endif

/* Only used in ip_is_unspecified (currently disabled) */
/* static const uint8_t zero6[OGS_IPV6_LEN] = {0}; */

static const char *smf_gtp_rat_type_name(uint8_t rat)
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

static const char *smf_sbi_rat_type_name(OpenAPI_rat_type_e rat)
{
    switch (rat) {
    case OpenAPI_rat_type_NR:
        return "NR";
    case OpenAPI_rat_type_EUTRA:
        return "EUTRA";
    case OpenAPI_rat_type_WLAN:
        return "WLAN";
    case OpenAPI_rat_type_NBIOT:
        return "NBIOT";
    case OpenAPI_rat_type_UTRA:
        return "UTRAN";
    case OpenAPI_rat_type_GERA:
        return "GERAN";
    default:
        return NULL;
    }
}

static inline uint32_t u24_to_u32(ogs_uint24_t v)
{
    uint32_t x = 0;
    memcpy(&x, &v, sizeof(v) < sizeof(x) ? sizeof(v) : sizeof(x));
    return (x & 0xFFFFFFu);
}

static inline bool bearer_list_has_qfi(const smf_sess_t *s)
{
    if (!s) return false;
    smf_bearer_t *b = NULL;
    ogs_list_for_each(&((smf_sess_t *)s)->bearer_list, b) {
        if (b && b->qfi > 0) return true;
    }
    return false;
}

/* 5G heuristic: S-NSSAI present or any QFI bearer */
static inline bool looks_5g_sess(const smf_sess_t *s)
{
    if (!s) return false;
    if (s->s_nssai.sst != 0) return true;
    if (u24_to_u32(s->s_nssai.sd) != 0) return true;
    if (bearer_list_has_qfi(s)) return true;
    return false;
}

static cJSON *build_rat_object(const smf_sess_t *sess, bool is5g)
{
    cJSON *rat = NULL;
    const char *name = NULL;

    if (!sess)
        return NULL;

    if (is5g && sess->sbi_rat_type != OpenAPI_rat_type_NULL) {
        name = smf_sbi_rat_type_name(sess->sbi_rat_type);
        if (!name)
            return NULL;
        rat = cJSON_CreateObject();
        if (!rat)
            return NULL;
        cJSON_AddItemToObjectCS(rat, "name", cJSON_CreateString(name));
        cJSON_AddItemToObjectCS(rat, "sbi", cJSON_CreateString(name));
        return rat;
    }

    if (!sess->gtp_rat_type)
        return NULL;

    name = smf_gtp_rat_type_name(sess->gtp_rat_type);
    if (!name)
        return NULL;

    rat = cJSON_CreateObject();
    if (!rat)
        return NULL;

    cJSON_AddItemToObjectCS(rat, "name", cJSON_CreateString(name));
    cJSON_AddItemToObjectCS(rat, "gtp", cJSON_CreateNumber(sess->gtp_rat_type));
    if (sess->gtp.version == 1)
        cJSON_AddItemToObjectCS(rat, "gtp_if", cJSON_CreateString("gn"));
    else if (sess->gtp.version == 2)
        cJSON_AddItemToObjectCS(rat, "gtp_if", cJSON_CreateString("s5"));

    return rat;
}

static const char *smf_sess_rat_name(const smf_sess_t *sess)
{
    if (!sess)
        return NULL;

    /*
     * Use sess->epc (set at GTP session create) rather than looks_5g_sess()
     * so metrics and filters stay stable for the lifetime of the session.
     */
    if (!sess->epc && sess->sbi_rat_type != OpenAPI_rat_type_NULL)
        return smf_sbi_rat_type_name(sess->sbi_rat_type);

    if (sess->gtp_rat_type)
        return smf_gtp_rat_type_name(sess->gtp_rat_type);

    if (!sess->epc && sess->psi)
        return "NR";

    return NULL;
}

bool smf_sess_rat_metric_labels(const smf_sess_t *sess,
        const char **rat, const char **gtp_if)
{
    static const char rat_nr[] = "NR";
    static const char gtp_if_sbi[] = "sbi";
    static const char gtp_if_gn[] = "gn";
    static const char gtp_if_s5[] = "s5";

    if (!sess || !rat || !gtp_if)
        return false;

    if (!sess->epc) {
        *rat = smf_sess_rat_name(sess);
        if (!*rat)
            *rat = rat_nr;
        *gtp_if = gtp_if_sbi;
        return true;
    }

    *rat = smf_gtp_rat_type_name(sess->gtp_rat_type);
    if (!*rat)
        return false;

    if (sess->gtp.version == 1)
        *gtp_if = gtp_if_gn;
    else
        *gtp_if = gtp_if_s5;

    return true;
}

static bool smf_plmn_id_is_set(const ogs_plmn_id_t *plmn)
{
    return plmn && (plmn->mcc1 || plmn->mcc2 || plmn->mcc3);
}

static uint16_t smf_sess_lac_for_filter(const smf_sess_t *sess)
{
    if (!sess)
        return 0;

    if (looks_5g_sess(sess))
        return (uint16_t)(sess->nr_tai.tac.v & 0xffff);

    if (sess->gtp.version == 1 &&
            sess->gtp.user_location_information.presence)
        return sess->uli_lac;

    return sess->e_tai.tac;
}

static bool smf_sess_matches_enb_id(const smf_sess_t *sess, uint32_t enb_id)
{
    uint32_t derived;

    if (!sess || looks_5g_sess(sess) || sess->gtp.version == 1)
        return false;

    if (!sess->e_cgi.cell_id)
        return false;

    derived = sess->e_cgi.cell_id >> 8;
    return derived == enb_id;
}

static bool smf_sess_matches_pdu_filters(const smf_sess_t *sess,
        const ogs_metrics_query_t *q)
{
    const char *rat_name = NULL;

    if (!sess || !q)
        return true;

    if (q->rat && *q->rat) {
        rat_name = smf_sess_rat_name(sess);
        if (!rat_name || strcasecmp(rat_name, q->rat) != 0)
            return false;
    }

    if (q->has_lac) {
        if (smf_sess_lac_for_filter(sess) != q->lac)
            return false;
    }

    if (q->has_enb_id) {
        if (!smf_sess_matches_enb_id(sess, q->enb_id))
            return false;
    }

    return true;
}

static bool smf_ue_has_matching_pdu(const smf_ue_t *ue,
        const ogs_metrics_query_t *q)
{
    smf_sess_t *sess = NULL;

    ogs_assert(ue);

    ogs_list_for_each(&ue->sess_list, sess) {
        if (smf_sess_matches_pdu_filters(sess, q))
            return true;
    }

    return false;
}

static cJSON *build_location_object(const smf_sess_t *sess)
{
    cJSON *loc = NULL;
    const bool is5g = looks_5g_sess(sess);
    char plmn[OGS_PLMNIDSTRLEN] = "";

    if (!sess)
        return NULL;

    if (is5g) {
        cJSON *tai = NULL;
        cJSON *ncgi = NULL;
        char tac[7] = "";
        char cell[11] = "";

        if (!smf_plmn_id_is_set(&sess->nr_tai.plmn_id))
            return NULL;

        loc = cJSON_CreateObject();
        tai = cJSON_CreateObject();
        ncgi = cJSON_CreateObject();
        if (!loc || !tai || !ncgi) {
            cJSON_Delete(loc);
            cJSON_Delete(tai);
            cJSON_Delete(ncgi);
            return NULL;
        }

        ogs_plmn_id_to_string(&sess->nr_tai.plmn_id, plmn);
        snprintf(tac, sizeof(tac), "%06x",
                (unsigned)(sess->nr_tai.tac.v & 0xffffff));
        cJSON_AddItemToObjectCS(tai, "plmn", cJSON_CreateString(plmn));
        cJSON_AddItemToObjectCS(tai, "tac", cJSON_CreateString(tac));
        cJSON_AddItemToObjectCS(loc, "tai", tai);

        if (smf_plmn_id_is_set(&sess->nr_cgi.plmn_id)) {
            char ncgi_plmn[OGS_PLMNIDSTRLEN] = "";
            ogs_plmn_id_to_string(&sess->nr_cgi.plmn_id, ncgi_plmn);
            snprintf(cell, sizeof(cell), "%09llx",
                    (unsigned long long)(sess->nr_cgi.cell_id & 0xfffffffffULL));
            cJSON_AddItemToObjectCS(ncgi, "plmn", cJSON_CreateString(ncgi_plmn));
            cJSON_AddItemToObjectCS(ncgi, "cell_id", cJSON_CreateString(cell));
            cJSON_AddItemToObjectCS(loc, "ncgi", ncgi);
        } else {
            cJSON_Delete(ncgi);
        }

        return loc;
    }

    if (sess->gtp.version == 1 &&
            sess->gtp.user_location_information.presence) {
        loc = cJSON_CreateObject();
        if (!loc)
            return NULL;

        switch (sess->uli_geo_loc_type) {
        case OGS_GTP1_GEO_LOC_TYPE_CGI: {
            cJSON *cgi = cJSON_CreateObject();
            if (!cgi) {
                cJSON_Delete(loc);
                return NULL;
            }
            ogs_plmn_id_to_string(&sess->serving_plmn_id, plmn);
            cJSON_AddItemToObjectCS(loc, "type", cJSON_CreateString("cgi"));
            cJSON_AddItemToObjectCS(cgi, "plmn", cJSON_CreateString(plmn));
            cJSON_AddItemToObjectCS(cgi, "lac",
                    cJSON_CreateNumber((double)sess->uli_lac));
            cJSON_AddItemToObjectCS(cgi, "ci",
                    cJSON_CreateNumber((double)sess->uli_ci));
            cJSON_AddItemToObjectCS(loc, "cgi", cgi);
            break;
        }
        case OGS_GTP1_GEO_LOC_TYPE_SAI: {
            cJSON *sai = cJSON_CreateObject();
            if (!sai) {
                cJSON_Delete(loc);
                return NULL;
            }
            ogs_plmn_id_to_string(&sess->serving_plmn_id, plmn);
            cJSON_AddItemToObjectCS(loc, "type", cJSON_CreateString("sai"));
            cJSON_AddItemToObjectCS(sai, "plmn", cJSON_CreateString(plmn));
            cJSON_AddItemToObjectCS(sai, "lac",
                    cJSON_CreateNumber((double)sess->uli_lac));
            cJSON_AddItemToObjectCS(sai, "sac",
                    cJSON_CreateNumber((double)sess->uli_sac));
            cJSON_AddItemToObjectCS(loc, "sai", sai);
            break;
        }
        case OGS_GTP1_GEO_LOC_TYPE_RAI: {
            cJSON *rai = cJSON_CreateObject();
            if (!rai) {
                cJSON_Delete(loc);
                return NULL;
            }
            ogs_plmn_id_to_string(&sess->serving_plmn_id, plmn);
            cJSON_AddItemToObjectCS(loc, "type", cJSON_CreateString("rai"));
            cJSON_AddItemToObjectCS(rai, "plmn", cJSON_CreateString(plmn));
            cJSON_AddItemToObjectCS(rai, "lac",
                    cJSON_CreateNumber((double)sess->uli_lac));
            cJSON_AddItemToObjectCS(rai, "rac",
                    cJSON_CreateNumber((double)sess->uli_rac));
            cJSON_AddItemToObjectCS(loc, "rai", rai);
            break;
        }
        default:
            cJSON_Delete(loc);
            return NULL;
        }

        if (sess->uli_lac) {
            cJSON_AddItemToObjectCS(loc, "lac",
                    cJSON_CreateNumber((double)sess->uli_lac));
        }

        return loc;
    }

    if (smf_plmn_id_is_set(&sess->e_tai.plmn_id)) {
        cJSON *tai = NULL;
        cJSON *ecgi = NULL;
        char ecgi_plmn[OGS_PLMNIDSTRLEN] = "";
        char tac[7] = "";
        char cell[9] = "";

        loc = cJSON_CreateObject();
        tai = cJSON_CreateObject();
        ecgi = cJSON_CreateObject();
        if (!loc || !tai || !ecgi) {
            cJSON_Delete(loc);
            cJSON_Delete(tai);
            cJSON_Delete(ecgi);
            return NULL;
        }

        ogs_plmn_id_to_string(&sess->e_tai.plmn_id, plmn);
        snprintf(tac, sizeof(tac), "%04x", (unsigned)sess->e_tai.tac);
        cJSON_AddItemToObjectCS(tai, "plmn", cJSON_CreateString(plmn));
        cJSON_AddItemToObjectCS(tai, "tac", cJSON_CreateString(tac));
        cJSON_AddItemToObjectCS(loc, "tai", tai);

        if (smf_plmn_id_is_set(&sess->e_cgi.plmn_id)) {
            ogs_plmn_id_to_string(&sess->e_cgi.plmn_id, ecgi_plmn);
            snprintf(cell, sizeof(cell), "%07x",
                    (unsigned)(sess->e_cgi.cell_id & 0x0fffffffu));
            cJSON_AddItemToObjectCS(ecgi, "plmn", cJSON_CreateString(ecgi_plmn));
            cJSON_AddItemToObjectCS(ecgi, "cell_id", cJSON_CreateString(cell));
            cJSON_AddItemToObjectCS(ecgi, "enb_id",
                    cJSON_CreateNumber((double)(sess->e_cgi.cell_id >> 8)));
            cJSON_AddItemToObjectCS(loc, "ecgi", ecgi);
        } else {
            cJSON_Delete(ecgi);
        }

        return loc;
    }

    return NULL;
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

/* Only used in handover function (currently disabled) */
/*
static bool ip_is_unspecified(const ogs_ip_t *ip)
{
    if (!ip)
        return true;

    if (ip->ipv4 && ip->addr == 0)
        return true;

    if (ip->ipv6 && memcmp(ip->addr6, zero6, sizeof(zero6)) == 0)
        return true;

    if (!ip->ipv4 && !ip->ipv6)
        return true;

    return false;
}
*/

static cJSON *addr_string_item(const ogs_ip_t *ip, int port)
{
    if (!ip) return NULL;
    char ipbuf[OGS_ADDRSTRLEN] = "";
    if (!ip_to_text(ip, ipbuf, sizeof ipbuf)) return NULL;
    char buf[OGS_ADDRSTRLEN + 16];
    snprintf(buf, sizeof buf, "[%s]:%d", ipbuf, port);
    return cJSON_CreateString(buf);
}

static cJSON *addr_string_from_sockaddr(ogs_sockaddr_t *sa4, ogs_sockaddr_t *sa6, int default_port)
{
    ogs_ip_t ip;
    memset(&ip, 0, sizeof(ip));
    if (OGS_OK != ogs_sockaddr_to_ip(sa4, sa6, &ip))
        return NULL;
    return addr_string_item(&ip, default_port);
}

static inline int up_state_of(const smf_sess_t *s)
{
    if (!s) return 0;
    int u = (int)s->up_cnx_state;
    if (u == 0) u = (int)s->nsmf_param.up_cnx_state;
    return u;
}

static inline bool has_n3_teid(const smf_sess_t *s)
{
    return s && (s->remote_ul_teid != 0U || s->remote_dl_teid != 0U);
}

static bool smf_sess_matches_ran_ip(const smf_sess_t *sess, const char *needle)
{
    if (!sess || !needle || !*needle)
        return false;

    /* 5G: gNB N3-U (user plane). LTE PGW/SMF has no eNB GTP-U address. */
    if (!looks_5g_sess(sess))
        return false;

    if (ogs_ip_matches_query(&sess->remote_dl_ip, needle))
        return true;
    if (ogs_ip_matches_query(&sess->handover.gnb_n3_ip, needle))
        return true;

    return false;
}

static bool smf_ue_matches_ran_ip(const smf_ue_t *ue, const char *needle)
{
    smf_sess_t *sess = NULL;

    ogs_assert(ue);

    ogs_list_for_each(&ue->sess_list, sess) {
        if (smf_sess_matches_ran_ip(sess, needle))
            return true;
    }

    return false;
}

static const char *pdu_state_from_5g(const smf_sess_t *sess)
{
    if (!sess) return "unknown";
    if ((int)sess->resource_status == (int)OpenAPI_resource_status_RELEASED)
        return "inactive";
    if (up_state_of(sess) == (int)OpenAPI_up_cnx_state_DEACTIVATED)
        return "inactive";
    if (sess->n1_released || sess->n2_released)
        return "inactive";
    if (!has_n3_teid(sess))
        return "inactive";
    return "active";
}

/* LTE/EPC state at SMF scope: unknown */
static const char *pdu_state_from_lte(const smf_sess_t *sess)
{
    (void)sess;
    return "unknown";
}

/* ---------- N3 object (gNB from sess->remote_dl_*, UPF from PDR F-TEID) ---------- */

static cJSON *build_n3_object_5g(const smf_sess_t *sess)
{
    /* Build n3 object with "gnb" and "upf" children. If nothing to emit or OOM, return NULL. */
    if (!sess) return NULL;

    cJSON *n3  = cJSON_CreateObject();
    if (!n3) return NULL;

    /* -------- gNB (DL endpoint) from sess->remote_dl_* -------- */
    if (sess->remote_dl_teid || sess->remote_dl_ip.ipv4 || sess->remote_dl_ip.ipv6) {
        cJSON *gnb = cJSON_CreateObject();
        if (!gnb) { cJSON_Delete(n3); return NULL; }
        bool has_content = false;

        if (sess->remote_dl_teid) {
            cJSON *t = cJSON_CreateNumber((double)(unsigned)sess->remote_dl_teid);
            if (!t) { cJSON_Delete(gnb); cJSON_Delete(n3); return NULL; }
            cJSON_AddItemToObjectCS(gnb, "teid", t);
            has_content = true;
        }

        cJSON *gs = addr_string_item(&sess->remote_dl_ip, OGS_GTPV1_U_UDP_PORT);
        if (gs) {
            cJSON_AddItemToObjectCS(gnb, "addr", gs);
            has_content = true;
        }

        if (has_content) {
            cJSON_AddItemToObjectCS(n3, "gnb", gnb);
        } else {
            cJSON_Delete(gnb);
        }
    }

    /* -------- UPF (UL endpoint) from PFCP PDR F-TEID -------- */
    do {
        ogs_pfcp_pdr_t *pdr = NULL, *pick = NULL;
        ogs_list_for_each(&((smf_sess_t *)sess)->pfcp.pdr_list, pdr) {
            if (pdr && pdr->f_teid_len > 0 &&
                pdr->src_if == OGS_PFCP_INTERFACE_ACCESS) { pick = pdr; break; }
        }
        if (!pick) {
            ogs_list_for_each(&((smf_sess_t *)sess)->pfcp.pdr_list, pdr) {
                if (pdr && pdr->f_teid_len > 0) { pick = pdr; break; }
            }
        }
        if (!pick) break;

        ogs_ip_t ip;
        memset(&ip, 0, sizeof(ip));

        if (OGS_OK == ogs_pfcp_f_teid_to_ip(&pick->f_teid, &ip)) {
            cJSON *upf = cJSON_CreateObject();
            if (!upf) { cJSON_Delete(n3); return NULL; }

            bool has_content = false;

            if (pick->f_teid.teid) {
                cJSON *t = cJSON_CreateNumber((double)(unsigned)pick->f_teid.teid);
                if (!t) { cJSON_Delete(upf); cJSON_Delete(n3); return NULL; }
                cJSON_AddItemToObjectCS(upf, "teid", t);
                has_content = true;
            }

            cJSON *addr = addr_string_item(&ip, OGS_GTPV1_U_UDP_PORT);
            if (addr) {
                cJSON_AddItemToObjectCS(upf, "addr", addr);
                has_content = true;
            }

            if (pick->id) {
                cJSON *pid = cJSON_CreateNumber((double)(unsigned)pick->id);
                if (!pid) { cJSON_Delete(upf); cJSON_Delete(n3); return NULL; }
                cJSON_AddItemToObjectCS(upf, "pdr_id", pid);
                has_content = true;
            }

            if (has_content) {
                cJSON_AddItemToObjectCS(n3, "upf", upf);
            } else {
                cJSON_Delete(upf);
            }
        }
    } while (0);

    if (n3->child == NULL) { cJSON_Delete(n3); return NULL; }
    return n3;
}

/* Selected UPF (N4 PFCP peer) for this PDU session */
static cJSON *build_n4_object(const smf_sess_t *sess)
{
    const char *pfcp_addr = NULL;
    const char *service_host = NULL;
    cJSON *n4 = NULL;

    if (!sess || !sess->pfcp_node)
        return NULL;

    pfcp_addr = ogs_pfcp_node_pfcp_endpoint(sess->pfcp_node);
    if (!pfcp_addr || !pfcp_addr[0])
        return NULL;

    n4 = cJSON_CreateObject();
    if (!n4)
        return NULL;

    cJSON_AddItemToObjectCS(n4, "pfcp_addr", cJSON_CreateString(pfcp_addr));

    service_host = ogs_pfcp_node_service_host(sess->pfcp_node);
    if (service_host && service_host[0]) {
        cJSON_AddItemToObjectCS(n4, "service_addr",
                cJSON_CreateString(service_host));
    }

    if (sess->smf_n4_seid) {
        cJSON_AddItemToObjectCS(n4, "smf_seid",
                cJSON_CreateNumber((double)sess->smf_n4_seid));
    }
    if (sess->upf_n4_seid) {
        cJSON_AddItemToObjectCS(n4, "upf_seid",
                cJSON_CreateNumber((double)sess->upf_n4_seid));
    }

    return n4;
}

/* LTE/EPC S5: PGW-U GTP-U endpoint advertised to the SGW */
static cJSON *build_s5_object_lte(const smf_sess_t *sess)
{
    smf_bearer_t *bearer = NULL;
    cJSON *s5 = NULL;
    bool has_content = false;
    char sgw_addr[OGS_ADDRSTRLEN] = "";

    if (!sess || looks_5g_sess(sess))
        return NULL;

    bearer = smf_default_bearer_in_sess((smf_sess_t *)sess);

    s5 = cJSON_CreateObject();
    if (!s5)
        return NULL;

    if (sess->gnode && sess->gnode->sa_list) {
        OGS_ADDR(sess->gnode->sa_list, sgw_addr);
        if (sgw_addr[0]) {
            cJSON_AddItemToObjectCS(s5, "sgw_addr",
                    cJSON_CreateString(sgw_addr));
            has_content = true;
        }
    }

    if (bearer) {
        cJSON *pgw_u = NULL;
        cJSON *sgw_u = NULL;

        if (bearer->pgw_s5u_teid ||
                bearer->pgw_s5u_addr || bearer->pgw_s5u_addr6) {
            pgw_u = cJSON_CreateObject();
            if (!pgw_u) {
                cJSON_Delete(s5);
                return NULL;
            }

            if (bearer->pgw_s5u_teid) {
                cJSON_AddItemToObjectCS(pgw_u, "teid",
                        cJSON_CreateNumber((double)bearer->pgw_s5u_teid));
                has_content = true;
            }

            {
                cJSON *addr = addr_string_from_sockaddr(
                        bearer->pgw_s5u_addr, bearer->pgw_s5u_addr6,
                        OGS_GTPV1_U_UDP_PORT);
                if (addr) {
                    cJSON_AddItemToObjectCS(pgw_u, "addr", addr);
                    has_content = true;
                }
            }

            if (pgw_u->child)
                cJSON_AddItemToObjectCS(s5, "pgw_u", pgw_u);
            else
                cJSON_Delete(pgw_u);
        }

        if (bearer->sgw_s5u_teid || bearer->sgw_s5u_ip.ipv4 ||
                bearer->sgw_s5u_ip.ipv6) {
            sgw_u = cJSON_CreateObject();
            if (!sgw_u) {
                cJSON_Delete(s5);
                return NULL;
            }

            if (bearer->sgw_s5u_teid) {
                cJSON_AddItemToObjectCS(sgw_u, "teid",
                        cJSON_CreateNumber((double)bearer->sgw_s5u_teid));
                has_content = true;
            }

            {
                cJSON *addr = addr_string_item(
                        &bearer->sgw_s5u_ip, OGS_GTPV1_U_UDP_PORT);
                if (addr) {
                    cJSON_AddItemToObjectCS(sgw_u, "addr", addr);
                    has_content = true;
                }
            }

            if (sgw_u->child)
                cJSON_AddItemToObjectCS(s5, "sgw_u", sgw_u);
            else
                cJSON_Delete(sgw_u);
        }
    }

    if (!has_content) {
        cJSON_Delete(s5);
        return NULL;
    }

    return s5;
}

/* Handover function disabled */
/*
static cJSON *build_handover_object_5g(const smf_sess_t *sess)
{
    if (!sess) return NULL;
    int any = 0;
    cJSON *ho = cJSON_CreateObject();
    if (!ho) return NULL;

    if (sess->handover.prepared) {
        cJSON *b = cJSON_CreateBool(1);
        if (!b) { cJSON_Delete(ho); return NULL; }
        cJSON_AddItemToObjectCS(ho, "prepared", b);
        any = 1;
    }
    if (sess->handover.indirect_data_forwarding) {
        cJSON *b = cJSON_CreateBool(1);
        if (!b) { cJSON_Delete(ho); return NULL; }
        cJSON_AddItemToObjectCS(ho, "indirect_data_forwarding", b);
        any = 1;
    }
    if (sess->handover.data_forwarding_not_possible) {
        cJSON *b = cJSON_CreateBool(1);
        if (!b) { cJSON_Delete(ho); return NULL; }
        cJSON_AddItemToObjectCS(ho, "data_forwarding_not_possible", b);
        any = 1;
    }

    // Target gNB (N3 for target cell)
    if (sess->handover.gnb_n3_teid || !ip_is_unspecified(&sess->handover.gnb_n3_ip)) {
        cJSON *gnb = cJSON_CreateObject();
        if (!gnb) { cJSON_Delete(ho); return NULL; }
        bool has_content = false;

        if (sess->handover.gnb_n3_teid) {
            cJSON *t = cJSON_CreateNumber((double)(unsigned)sess->handover.gnb_n3_teid);
            if (!t) { cJSON_Delete(gnb); cJSON_Delete(ho); return NULL; }
            cJSON_AddItemToObjectCS(gnb, "teid", t);
            has_content = true;
        }
        cJSON *addr = addr_string_item(&sess->handover.gnb_n3_ip, OGS_GTPV1_U_UDP_PORT);
        if (addr) {
            cJSON_AddItemToObjectCS(gnb, "addr", addr);
            has_content = true;
        }

        if (has_content) {
            cJSON_AddItemToObjectCS(ho, "target_gnb", gnb);
            any = 1;
        } else {
            cJSON_Delete(gnb);
        }
    }

    if (sess->handover.local_dl_teid || sess->handover.remote_dl_teid ||
        sess->handover.local_dl_addr || sess->handover.local_dl_addr6 ||
        !ip_is_unspecified(&sess->handover.remote_dl_ip)) {

        cJSON *fwd = cJSON_CreateObject();
        if (!fwd) { cJSON_Delete(ho); return NULL; }

        // Local endpoint (SMF side of indirect forwarding tunnel)
        if (sess->handover.local_dl_teid || sess->handover.local_dl_addr || sess->handover.local_dl_addr6) {
            cJSON *loc = cJSON_CreateObject();
            if (!loc) { cJSON_Delete(fwd); cJSON_Delete(ho); return NULL; }
            bool has_content = false;

            if (sess->handover.local_dl_teid) {
                cJSON *t = cJSON_CreateNumber((double)(unsigned)sess->handover.local_dl_teid);
                if (!t) { cJSON_Delete(loc); cJSON_Delete(fwd); cJSON_Delete(ho); return NULL; }
                cJSON_AddItemToObjectCS(loc, "teid", t);
                has_content = true;
            }
            cJSON *laddr = addr_string_from_sockaddr(sess->handover.local_dl_addr,
                                                     sess->handover.local_dl_addr6,
                                                     OGS_GTPV1_U_UDP_PORT);
            if (laddr) {
                cJSON_AddItemToObjectCS(loc, "addr", laddr);
                has_content = true;
            }

            if (has_content) {
                cJSON_AddItemToObjectCS(fwd, "local", loc);
            } else {
                cJSON_Delete(loc);
            }
        }

        // Remote endpoint (UPF side of indirect forwarding tunnel)
        if (sess->handover.remote_dl_teid || !ip_is_unspecified(&sess->handover.remote_dl_ip)) {
            cJSON *rem = cJSON_CreateObject();
            if (!rem) { cJSON_Delete(fwd); cJSON_Delete(ho); return NULL; }
            bool has_content = false;

            if (sess->handover.remote_dl_teid) {
                cJSON *t = cJSON_CreateNumber((double)(unsigned)sess->handover.remote_dl_teid);
                if (!t) { cJSON_Delete(rem); cJSON_Delete(fwd); cJSON_Delete(ho); return NULL; }
                cJSON_AddItemToObjectCS(rem, "teid", t);
                has_content = true;
            }
            cJSON *raddr = addr_string_item(&sess->handover.remote_dl_ip, OGS_GTPV1_U_UDP_PORT);
            if (raddr) {
                cJSON_AddItemToObjectCS(rem, "addr", raddr);
                has_content = true;
            }

            if (has_content) {
                cJSON_AddItemToObjectCS(fwd, "upf", rem);
            } else {
                cJSON_Delete(rem);
            }
        }

        if (fwd->child != NULL) {
            cJSON_AddItemToObjectCS(ho, "dl_forwarding", fwd);
            any = 1;
        } else {
            cJSON_Delete(fwd);
        }
    }

    if (!any) { cJSON_Delete(ho); return NULL; }
    return ho;
}
*/

static cJSON *build_snssai_object(const smf_sess_t *sess)
{
    cJSON *sn = cJSON_CreateObject();
    if (!sn) return NULL;

    cJSON *sst = cJSON_CreateNumber((double)sess->s_nssai.sst);
    if (!sst) { cJSON_Delete(sn); return NULL; }
    cJSON_AddItemToObjectCS(sn, "sst", sst);

    char sd[7];
    snprintf(sd, sizeof sd, "%06x", (unsigned)u24_to_u32(sess->s_nssai.sd));
    cJSON *sdj = cJSON_CreateString(sd);
    if (!sdj) { cJSON_Delete(sn); return NULL; }
    cJSON_AddItemToObjectCS(sn, "sd", sdj);

    return sn;
}

static cJSON *build_qos_flows_array_5g(const smf_sess_t *sess)
{
    cJSON *arr = cJSON_CreateArray();
    if (!arr) return NULL;

    smf_bearer_t *b = NULL;
    ogs_list_for_each(&((smf_sess_t *)sess)->bearer_list, b) {
        if (!b || b->qfi == 0) continue;

        cJSON *q = cJSON_CreateObject();
        if (!q) { cJSON_Delete(arr); return NULL; }

        cJSON *qfi = cJSON_CreateNumber((double)(unsigned)b->qfi);
        if (!qfi) { cJSON_Delete(q); cJSON_Delete(arr); return NULL; }
        cJSON_AddItemToObjectCS(q, "qfi", qfi);

        if (b->qos.index > 0) {
            cJSON *q5 = cJSON_CreateNumber((double)(unsigned)b->qos.index);
            if (!q5) { cJSON_Delete(q); cJSON_Delete(arr); return NULL; }
            cJSON_AddItemToObjectCS(q, "5qi", q5);
        }

        cJSON_AddItemToArray(arr, q);
    }

    return arr;
}

static cJSON *build_qos_flows_array_lte(const smf_sess_t *sess)
{
    cJSON *arr = cJSON_CreateArray();
    if (!arr) return NULL;

    smf_bearer_t *b = NULL;
    ogs_list_for_each(&((smf_sess_t *)sess)->bearer_list, b) {
        if (!b || b->ebi == 0) continue;

        unsigned qci_val = (unsigned)b->qos.index;
        if (qci_val == 0) qci_val = (unsigned)sess->session.qos.index;

        cJSON *q = cJSON_CreateObject();
        if (!q) { cJSON_Delete(arr); return NULL; }

        cJSON *ebi = cJSON_CreateNumber((double)(unsigned)b->ebi);
        if (!ebi) { cJSON_Delete(q); cJSON_Delete(arr); return NULL; }
        cJSON_AddItemToObjectCS(q, "ebi", ebi);

        if (qci_val > 0) {
            cJSON *qci = cJSON_CreateNumber((double)qci_val);
            if (!qci) { cJSON_Delete(q); cJSON_Delete(arr); return NULL; }
            cJSON_AddItemToObjectCS(q, "qci", qci);
        }

        cJSON_AddItemToArray(arr, q);
    }

    return arr;
}

static cJSON *build_single_pdu_object(const smf_sess_t *sess, int *any_active, int *any_unknown)
{
    cJSON *pdu = cJSON_CreateObject();
    if (!pdu) return NULL;

    /* 5G vs LTE fields */
    const bool is5g = looks_5g_sess(sess);
    if (is5g) {
        cJSON *psi = cJSON_CreateNumber((double)(unsigned)sess->psi);
        if (!psi) { cJSON_Delete(pdu); return NULL; }
        cJSON_AddItemToObjectCS(pdu, "psi", psi);

        const char *dnn_c = (sess->session.name ? sess->session.name : "");
        cJSON *dnn = cJSON_CreateString(dnn_c);
        if (!dnn) { cJSON_Delete(pdu); return NULL; }
        cJSON_AddItemToObjectCS(pdu, "dnn", dnn);
    } else {
        if (sess->psi > 0) {
            cJSON *psi = cJSON_CreateNumber((double)(unsigned)sess->psi);
            if (!psi) { cJSON_Delete(pdu); return NULL; }
            cJSON_AddItemToObjectCS(pdu, "psi", psi);
        }

        /* EBI root if present */
        unsigned ebi_root = 0;
        smf_bearer_t *b0 = NULL;
        ogs_list_for_each(&((smf_sess_t *)sess)->bearer_list, b0) {
            if (b0 && b0->ebi > 0) { ebi_root = (unsigned)b0->ebi; break; }
        }
        cJSON *ebi = cJSON_CreateNumber((double)ebi_root);
        if (!ebi) { cJSON_Delete(pdu); return NULL; }
        cJSON_AddItemToObjectCS(pdu, "ebi", ebi);

        const char *apn_c = (sess->session.name ? sess->session.name : "");
        cJSON *apn = cJSON_CreateString(apn_c);
        if (!apn) { cJSON_Delete(pdu); return NULL; }
        cJSON_AddItemToObjectCS(pdu, "apn", apn);
    }

    /* IPs */
    {
        char ip4[OGS_ADDRSTRLEN] = "";
        char ip6[OGS_ADDRSTRLEN] = "";
        if (sess->ipv4) OGS_INET_NTOP(&sess->ipv4->addr, ip4);
        if (sess->ipv6) OGS_INET6_NTOP(&sess->ipv6->addr, ip6);

        if (ip4[0]) {
            cJSON *s = cJSON_CreateString(ip4);
            if (!s) { cJSON_Delete(pdu); return NULL; }
            cJSON_AddItemToObjectCS(pdu, "ipv4", s);
        }
        if (ip6[0]) {
            cJSON *s = cJSON_CreateString(ip6);
            if (!s) { cJSON_Delete(pdu); return NULL; }
            cJSON_AddItemToObjectCS(pdu, "ipv6", s);
        }
    }

    /* S-NSSAI */
    {
        cJSON *sn = build_snssai_object(sess);
        if (!sn) { cJSON_Delete(pdu); return NULL; }
        cJSON_AddItemToObjectCS(pdu, "snssai", sn);
    }

    /* RAT (GTP Gn/S5 or 5G SBI) */
    {
        cJSON *rat = build_rat_object(sess, is5g);
        if (rat)
            cJSON_AddItemToObjectCS(pdu, "rat", rat);
    }

    /* User location (Gn ULI, LTE TAI/ECGI, or 5G TAI/NCGI) */
    {
        cJSON *loc = build_location_object(sess);
        if (loc)
            cJSON_AddItemToObjectCS(pdu, "location", loc);
    }

    /* QoS flows */
    {
        cJSON *qarr = is5g ? build_qos_flows_array_5g(sess)
                           : build_qos_flows_array_lte(sess);
        if (!qarr) { cJSON_Delete(pdu); return NULL; }
        cJSON_AddItemToObjectCS(pdu, "qos_flows", qarr);
    }

    /* N3 + Handover (5GS only) */
    if (is5g) {
        cJSON *n3 = build_n3_object_5g(sess);
        if (n3) cJSON_AddItemToObjectCS(pdu, "n3", n3);

        /* Handover disabled */
        /*
        cJSON *ho = build_handover_object_5g(sess);
        if (ho) cJSON_AddItemToObjectCS(pdu, "handover", ho);
        */
    }

    {
        cJSON *n4 = build_n4_object(sess);
        if (n4)
            cJSON_AddItemToObjectCS(pdu, "n4", n4);
    }

    if (!is5g) {
        cJSON *s5 = build_s5_object_lte(sess);
        if (s5)
            cJSON_AddItemToObjectCS(pdu, "s5", s5);
    }

    /* PDU state + UE activity aggregation */
    {
        const char *state = is5g ? pdu_state_from_5g(sess) : pdu_state_from_lte(sess);
        cJSON *st = cJSON_CreateString(state);
        if (!st) { cJSON_Delete(pdu); return NULL; }
        cJSON_AddItemToObjectCS(pdu, "pdu_state", st);

        if (any_active && !strcmp(state, "active")) *any_active = 1;
        else if (any_unknown && !strcmp(state, "unknown")) *any_unknown = 1;
    }

    /* Last location update timestamp (epoch microseconds, ogs_time_t).
     * A value of 0 means the location has not yet been updated by the
     * peer NF for this session.
     * Inherited from the UE context at each N1/N2 location-bearing event
     * (Initial Registration, TAU/Registration Update, Handover, Service
     * Request response). Exposed for external reconciliation tools that
     * need to age PDU sessions — e.g. distinguish a truly stale session
     * from one that is legitimately idle-parked for later Resume. */
    {
        cJSON *ts = cJSON_CreateNumber((double)sess->ue_location_timestamp);
        if (!ts) { cJSON_Delete(pdu); return NULL; }
        cJSON_AddItemToObjectCS(pdu, "ue_location_timestamp", ts);
    }

    /* PFCP URR session totals (same counters as RADIUS/Ga CDR). */
    {
        cJSON *ul = cJSON_CreateNumber((double)sess->gy.ul_octets);
        if (!ul) { cJSON_Delete(pdu); return NULL; }
        cJSON_AddItemToObjectCS(pdu, "usage_ul_octets", ul);

        cJSON *dl = cJSON_CreateNumber((double)sess->gy.dl_octets);
        if (!dl) { cJSON_Delete(pdu); return NULL; }
        cJSON_AddItemToObjectCS(pdu, "usage_dl_octets", dl);
    }

    return pdu;
}

static cJSON *build_ue_object(const smf_ue_t *ue, const ogs_metrics_query_t *q)
{
    cJSON *ueo = cJSON_CreateObject();
    if (!ueo) return NULL;

    /* UE identity */
    const char *id = (ue->supi && ue->supi[0]) ? ue->supi :
                     (ue->imsi_bcd[0] ? ue->imsi_bcd : "");
    cJSON *idj = cJSON_CreateString(id);
    if (!idj) { cJSON_Delete(ueo); return NULL; }
    cJSON_AddItemToObjectCS(ueo, "supi", idj);

    /* PDUs */
    cJSON *pdus = cJSON_CreateArray();
    if (!pdus) { cJSON_Delete(ueo); return NULL; }

    int any_active = 0, any_unknown = 0;
    int pdu_count = 0;

    smf_sess_t *sess = NULL;
    ogs_list_for_each(&ue->sess_list, sess) {
        if (q && !smf_sess_matches_pdu_filters(sess, q))
            continue;

        cJSON *pdu = build_single_pdu_object(sess, &any_active, &any_unknown);
        if (!pdu) { cJSON_Delete(pdus); cJSON_Delete(ueo); return NULL; }
        cJSON_AddItemToArray(pdus, pdu);
        pdu_count++;
    }

    if (pdu_count == 0) {
        cJSON_Delete(pdus);
        cJSON_Delete(ueo);
        return NULL;
    }

    cJSON_AddItemToObjectCS(ueo, "pdu", pdus);

    /* UE activity */
    {
        const char *ue_act = any_active ? "active" : (any_unknown ? "unknown" : "idle");
        cJSON *ua = cJSON_CreateString(ue_act);
        if (!ua) { cJSON_Delete(ueo); return NULL; }
        cJSON_AddItemToObjectCS(ueo, "ue_activity", ua);
    }

    return ueo;
}

static void pdu_by_rat_count_inc(cJSON *summary, const char *rat_name)
{
    cJSON *by_rat = NULL;
    cJSON *entry = NULL;
    int count = 0;

    if (!summary || !rat_name || !*rat_name)
        return;

    by_rat = cJSON_GetObjectItemCaseSensitive(summary, "pdu_by_rat");
    if (!by_rat) {
        by_rat = cJSON_CreateObject();
        if (!by_rat)
            return;
        cJSON_AddItemToObjectCS(summary, "pdu_by_rat", by_rat);
    }

    entry = cJSON_GetObjectItemCaseSensitive(by_rat, rat_name);
    if (entry && cJSON_IsNumber(entry)) {
        count = entry->valueint + 1;
        cJSON_SetIntValue(entry, count);
        return;
    }

    cJSON_AddItemToObjectCS(by_rat, rat_name, cJSON_CreateNumber(1));
}

static bool smf_ue_matches_query(const smf_ue_t *ue, const ogs_metrics_query_t *q)
{
    if (!ue || !q)
        return true;

    if (q->supi && *q->supi) {
        if (!ue->supi || strcmp(ue->supi, q->supi) != 0)
            return false;
    }
    if (q->imsi && *q->imsi) {
        if (!ue->imsi_bcd[0] || strcmp(ue->imsi_bcd, q->imsi) != 0)
            return false;
    }
    if (q->ue_ip && *q->ue_ip) {
        bool match = false;
        smf_sess_t *s = NULL;
        ogs_list_for_each(&ue->sess_list, s) {
            char ip4[OGS_ADDRSTRLEN] = "";
            char ip6[OGS_ADDRSTRLEN] = "";
            if (s->ipv4) OGS_INET_NTOP(&s->ipv4->addr, ip4);
            if (s->ipv6) OGS_INET6_NTOP(&s->ipv6->addr, ip6);
            if ((ip4[0] && strcmp(ip4, q->ue_ip) == 0) ||
                (ip6[0] && strcmp(ip6, q->ue_ip) == 0)) {
                match = true;
                break;
            }
        }
        if (!match)
            return false;
    }
    if (q->ip && *q->ip) {
        if (!smf_ue_matches_ran_ip(ue, q->ip))
            return false;
    }

    return true;
}

static void collect_pdu_by_rat_for_ue(cJSON *summary, const smf_ue_t *ue,
        const ogs_metrics_query_t *q)
{
    smf_sess_t *sess = NULL;

    ogs_list_for_each(&ue->sess_list, sess) {
        const char *rat_name = NULL;

        if (!smf_sess_matches_pdu_filters(sess, q))
            continue;

        rat_name = smf_sess_rat_name(sess);
        if (!rat_name)
            rat_name = "UNKNOWN";

        pdu_by_rat_count_inc(summary, rat_name);
    }
}

static void collect_pdu_by_rat_summary(cJSON *summary, const ogs_metrics_query_t *q)
{
    smf_context_t *smf = smf_self();
    smf_ue_t *ue = NULL;

    ogs_list_for_each(&smf->smf_ue_list, ue) {
        if (!smf_ue_matches_query(ue, q))
            continue;

        collect_pdu_by_rat_for_ue(summary, ue, q);
    }
}

size_t smf_dump_pdu_info_paged(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    if (!buf || buflen == 0) return 0;

    const bool no_paging = json_pager_setup(&page, &page_size,
            PDU_INFO_PAGE_SIZE_DEFAULT);

    const size_t start_index = json_pager_safe_start_index(no_paging, page, page_size);

    cJSON *root = cJSON_CreateObject();
    if (!root) { if (buflen >= 3) { memcpy(buf, "{}", 3); return 2; } if (buflen) buf[0] = '\0'; return 0; }

    cJSON *items = cJSON_CreateArray();
    if (!items) { cJSON_Delete(root); if (buflen >= 3) { memcpy(buf, "{}", 3); return 2; } if (buflen) buf[0] = '\0'; return 0; }

    cJSON *summary = cJSON_CreateObject();
    if (!summary) {
        cJSON_Delete(items);
        cJSON_Delete(root);
        if (buflen >= 3) { memcpy(buf, "{}", 3); return 2; }
        if (buflen) buf[0] = '\0';
        return 0;
    }

    size_t idx = 0, emitted = 0, total = 0;
    bool has_next = false, oom = false;

    smf_context_t *smf = smf_self();
    smf_ue_t *ue = NULL;

    /*
     * MHD now serves /pdu-info on its own thread; take the metrics
     * dump lock around the SMF context iteration so the main thread
     * can't free an smf_ue / smf_sess / bearer mid-traversal.
     */
    ogs_metrics_dump_lock();

    if (q && ((q->imsi && *q->imsi) || (q->supi && *q->supi))) {
        /*
         * Fast path for exact-subscriber queries (NMS IMSI watch /
         * trace panel polls /pdu-info?imsi= every few seconds).
         * Walking the whole smf_ue_list under the dump lock scales
         * with total subscribers; resolve via the IMSI/SUPI hash and
         * keep the remaining filters via smf_ue_matches_query().
         */
        ue = (q->imsi && *q->imsi) ?
                smf_ue_find_by_imsi_bcd(q->imsi) :
                smf_ue_find_by_supi((char *)q->supi);
        if (ue && smf_ue_matches_query(ue, q) &&
            (!((q->rat && *q->rat) || q->has_lac || q->has_enb_id) ||
             smf_ue_has_matching_pdu(ue, q))) {
            collect_pdu_by_rat_for_ue(summary, ue, q);
            total = 1;
            int act = json_pager_advance(no_paging, idx, start_index,
                    emitted, page_size, &has_next);
            if (act == 0) {
                cJSON *ueo = build_ue_object(ue, q);
                if (!ueo) oom = true;
                else { cJSON_AddItemToArray(items, ueo); emitted++; }
            }
            idx++;
        }
        goto done;
    }

    collect_pdu_by_rat_summary(summary, q);

    ogs_list_for_each(&smf->smf_ue_list, ue) {
        /*
         * UE-level filters first. SUPI compares the full "imsi-..."
         * string; the IMSI filter compares against imsi_bcd. The
         * ue_ip filter walks the UE's sessions because the IP is
         * per-session (a single UE can hold multiple PDU sessions
         * with different IPs).
         */
        if (!smf_ue_matches_query(ue, q))
            continue;
        if (q && ((q->rat && *q->rat) || q->has_lac || q->has_enb_id)) {
            if (!smf_ue_has_matching_pdu(ue, q))
                continue;
        }

        total++;

        int act = json_pager_advance(no_paging, idx, start_index, emitted, page_size, &has_next);
        if (act == 1) { idx++; continue; }
        if (act == 0) {
        cJSON *ueo = build_ue_object(ue, q);
        if (!ueo) { oom = true; break; }

        cJSON_AddItemToArray(items, ueo);
        emitted++;
        }
        idx++;
    }

done:
    ogs_metrics_dump_unlock();

    cJSON_AddItemToObjectCS(root, "items", items);
    if (summary->child)
        cJSON_AddItemToObjectCS(root, "summary", summary);
    else
        cJSON_Delete(summary);
    json_pager_add_trailing(root, no_paging, page, page_size, emitted, total,
            has_next && !oom, "/pdu-info", oom);

    return json_pager_finalize(root, buf, buflen);
}

size_t smf_dump_pdu_info(char *buf, size_t buflen,
        size_t page, size_t page_size, const ogs_metrics_query_t *q)
{
    return smf_dump_pdu_info_paged(buf, buflen, page, page_size, q);
}

