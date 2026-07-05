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

#include "ogs-gtp.h"
#include "mme-context.h"
#include "mme-gtp-path.h"
#include "mme-roam-access.h"
#include "eplmn-config.h"
#include "mme-reload-lists.h"

int mme_reload_lists_changed = 0;

static uint16_t reload_yaml_parse_port(const char *v, uint16_t default_port)
{
    if (!v || !v[0])
        return default_port;
    return (uint16_t)atoi(v);
}

static uint32_t reload_yaml_parse_uint32(const char *v)
{
    ogs_assert(v);

    if (v[0] == '0' && (v[1] == 'x' || v[1] == 'X'))
        return (uint32_t)ogs_uint64_from_string_hexadecimal((char *)v);

    return (uint32_t)strtoul(v, NULL, 10);
}

static int reload_parse_plmn_id(ogs_yaml_iter_t *parent_iter,
        ogs_plmn_id_t *plmn_id)
{
    const char *mcc = NULL;
    const char *mnc = NULL;
    ogs_yaml_iter_t plmn_id_iter;

    ogs_assert(parent_iter);
    ogs_assert(plmn_id);

    ogs_yaml_iter_recurse(parent_iter, &plmn_id_iter);
    while (ogs_yaml_iter_next(&plmn_id_iter)) {
        const char *plmn_id_key = ogs_yaml_iter_key(&plmn_id_iter);
        ogs_assert(plmn_id_key);

        if (!strcmp(plmn_id_key, "mcc"))
            mcc = ogs_yaml_iter_value(&plmn_id_iter);
        else if (!strcmp(plmn_id_key, "mnc"))
            mnc = ogs_yaml_iter_value(&plmn_id_iter);
    }

    if (!mcc || !mnc)
        return OGS_ERROR;

    ogs_plmn_id_build(plmn_id, atoi(mcc), atoi(mnc), strlen(mnc));
    return OGS_OK;
}

static void reload_gtpc_client_parse_plmn_id_key(
        ogs_yaml_iter_t *iter, const char *key,
        bool *serving_plmn_parsed, ogs_plmn_id_t *serving_plmn,
        bool *imsi_plmn_parsed, ogs_plmn_id_t *imsi_plmn)
{
    ogs_plmn_id_t plmn_id;

    ogs_assert(iter);
    ogs_assert(key);
    ogs_assert(serving_plmn_parsed);
    ogs_assert(serving_plmn);
    ogs_assert(imsi_plmn_parsed);
    ogs_assert(imsi_plmn);

    if (reload_parse_plmn_id(iter, &plmn_id) != OGS_OK)
        return;

    if (!strcmp(key, "imsi_plmn_id")) {
        *imsi_plmn_parsed = true;
        memcpy(imsi_plmn, &plmn_id, sizeof(plmn_id));
        return;
    }

    if (!strcmp(key, "serving_plmn_id")) {
        *serving_plmn_parsed = true;
        memcpy(serving_plmn, &plmn_id, sizeof(plmn_id));
        return;
    }

    if (!strcmp(key, "plmn_id")) {
        if (mme_self()->inbound_roam_gtpc_plmn_id_is_imsi_plmn) {
            *imsi_plmn_parsed = true;
            memcpy(imsi_plmn, &plmn_id, sizeof(plmn_id));
        } else {
            *serving_plmn_parsed = true;
            memcpy(serving_plmn, &plmn_id, sizeof(plmn_id));
        }
    }
}

static ogs_eps_tai0_list_t *reload_served_tai_list0(int index)
{
    mme_context_t *self = mme_self();
    ogs_eps_tai0_list_t **list0 = NULL;

    ogs_assert(index >= 0 && index < OGS_MAX_NUM_OF_SUPPORTED_TA);

    list0 = &self->served_tai[index].list0;
    if (*list0 == NULL) {
        *list0 = ogs_calloc(1, sizeof(ogs_eps_tai0_list_t));
        ogs_assert(*list0);
    }

    return *list0;
}

static void reload_served_tai_clear_all(void)
{
    mme_context_t *self = mme_self();
    int i;

    for (i = 0; i < OGS_MAX_NUM_OF_SUPPORTED_TA; i++) {
        if (self->served_tai[i].list0) {
            ogs_free(self->served_tai[i].list0);
            self->served_tai[i].list0 = NULL;
        }
    }

    memset(self->served_tai, 0, sizeof(self->served_tai));
    self->num_of_served_tai = 0;
}

static int reload_served_tai_add_one(
        const ogs_plmn_id_t *plmn_id, uint16_t tac)
{
    mme_context_t *self = mme_self();
    ogs_eps_tai_t tai;
    ogs_eps_tai2_list_t *list2 = NULL;
    int i;

    ogs_assert(plmn_id);

    memset(&tai, 0, sizeof(tai));
    memcpy(&tai.plmn_id, plmn_id, OGS_PLMN_ID_LEN);
    tai.tac = tac;

    if (mme_find_served_tai(&tai) >= 0)
        return 0;

    for (i = 0; i < self->num_of_served_tai; i++) {
        list2 = &self->served_tai[i].list2;
        if (list2->num >= OGS_MAX_NUM_OF_TAI)
            continue;

        list2->type = OGS_TAI2_TYPE;
        list2->tai[list2->num].plmn_id = *plmn_id;
        list2->tai[list2->num].tac = tac;
        list2->num++;
        mme_reload_lists_changed++;
        ogs_reload_audit_note(" served TAI added PLMN=%06x TAC=0x%04x",
                ogs_plmn_id_hexdump(plmn_id), tac);
        return 1;
    }

    if (self->num_of_served_tai >= OGS_MAX_NUM_OF_SUPPORTED_TA) {
        ogs_reload_audit_warn("served TAI list full (max %d)",
                OGS_MAX_NUM_OF_SUPPORTED_TA);
        return 0;
    }

    i = self->num_of_served_tai;
    (void)reload_served_tai_list0(i);
    list2 = &self->served_tai[i].list2;
    list2->type = OGS_TAI2_TYPE;
    list2->tai[0].plmn_id = *plmn_id;
    list2->tai[0].tac = tac;
    list2->num = 1;
    self->num_of_served_tai++;
    mme_reload_lists_changed++;
    ogs_reload_audit_note(" served TAI added PLMN=%06x TAC=0x%04x",
            ogs_plmn_id_hexdump(plmn_id), tac);
    return 1;
}

static int reload_served_tai_add_range(
        const ogs_plmn_id_t *plmn_id, uint16_t start, uint16_t end)
{
    uint32_t tac;
    int added = 0;

    ogs_assert(plmn_id);

    if (end < start)
        return 0;

    for (tac = start; tac <= end; tac++)
        added += reload_served_tai_add_one(plmn_id, (uint16_t)tac);

    return added;
}

static mme_access_control_t *reload_access_control_find(
        const char *imsi_prefix, bool plmn_configured,
        const ogs_plmn_id_t *plmn_id)
{
    mme_context_t *self = mme_self();
    int i;

    for (i = 0; i < self->num_of_access_control; i++) {
        mme_access_control_t *ac = &self->access_control[i];

        if (imsi_prefix && imsi_prefix[0]) {
            if (strcmp(ac->imsi_prefix, imsi_prefix) != 0)
                continue;
        } else if (ac->imsi_prefix[0])
            continue;

        if (plmn_configured) {
            if (!ac->plmn_id_configured)
                continue;
            if (memcmp(&ac->plmn_id, plmn_id, OGS_PLMN_ID_LEN) != 0)
                continue;
        } else if (ac->plmn_id_configured) {
            continue;
        }

        return ac;
    }

    return NULL;
}

static void reload_access_control_parse_uint32_list(
        ogs_yaml_iter_t *iter, mme_access_control_t *ac, bool enb)
{
    ogs_yaml_iter_t list_iter;

    ogs_assert(iter);
    ogs_assert(ac);

    ogs_yaml_iter_recurse(iter, &list_iter);
    if (ogs_yaml_iter_type(&list_iter) == YAML_MAPPING_NODE) {
        ogs_reload_audit_warn("access_control tac/enb list must be a sequence");
        return;
    }

    do {
        const char *v = NULL;

        if (ogs_yaml_iter_type(&list_iter) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&list_iter))
                break;
        }

        v = ogs_yaml_iter_value(&list_iter);
        if (!v)
            continue;

        if (enb) {
            if (mme_access_control_enb_add(ac, reload_yaml_parse_uint32(v)))
                mme_reload_lists_changed++;
        } else {
            if (mme_access_control_tac_add(ac,
                        (uint16_t)reload_yaml_parse_uint32(v)))
                mme_reload_lists_changed++;
        }
    } while (ogs_yaml_iter_type(&list_iter) == YAML_SEQUENCE_NODE);
}

static mme_pgw_t *reload_pgw_find_by_addr(const ogs_sockaddr_t *addr)
{
    mme_pgw_t *pgw = NULL;

    ogs_assert(addr);

    ogs_list_for_each(&mme_self()->pgw_list, pgw) {
        ogs_sockaddr_t *sa = NULL;

        for (sa = pgw->sa_list; sa; sa = sa->next) {
            if (ogs_sockaddr_is_equal(sa, addr))
                return pgw;
        }
    }

    return NULL;
}

static bool reload_sgw_tac_has(mme_sgw_t *sgw, uint16_t tac)
{
    int i;

    ogs_assert(sgw);

    for (i = 0; i < sgw->num_of_tac; i++) {
        if (sgw->tac[i] == tac)
            return true;
    }

    return false;
}

static bool reload_sgw_ecell_has(mme_sgw_t *sgw, uint32_t e_cell_id)
{
    int i;

    ogs_assert(sgw);

    for (i = 0; i < sgw->num_of_e_cell_id; i++) {
        if (sgw->e_cell_id[i] == e_cell_id)
            return true;
    }

    return false;
}

static void reload_sgw_tac_add(mme_sgw_t *sgw, uint16_t tac)
{
    ogs_assert(sgw);

    if (reload_sgw_tac_has(sgw, tac))
        return;

    if (sgw->num_of_tac >= (int)ogs_global_conf()->max.tai) {
        ogs_reload_audit_warn("sgwc tac list full on peer");
        return;
    }

    sgw->tac[sgw->num_of_tac++] = tac;
    mme_reload_lists_changed++;
}

static void reload_sgw_ecell_add(mme_sgw_t *sgw, uint32_t e_cell_id)
{
    ogs_assert(sgw);

    if (reload_sgw_ecell_has(sgw, e_cell_id))
        return;

    if (sgw->num_of_e_cell_id >= OGS_MAX_NUM_OF_CELL_ID) {
        ogs_reload_audit_warn("sgwc e_cell_id list full on peer");
        return;
    }

    sgw->e_cell_id[sgw->num_of_e_cell_id++] = e_cell_id;
    mme_reload_lists_changed++;
}

static bool reload_pgw_tac_has(mme_pgw_t *pgw, uint16_t tac)
{
    int i;

    ogs_assert(pgw);

    for (i = 0; i < pgw->num_of_tac; i++) {
        if (pgw->tac[i] == tac)
            return true;
    }

    return false;
}

static bool reload_pgw_apn_has(mme_pgw_t *pgw, const char *apn)
{
    int i;

    ogs_assert(pgw);
    ogs_assert(apn);

    for (i = 0; i < pgw->num_of_apn; i++) {
        if (pgw->apn[i] && !ogs_strcasecmp(pgw->apn[i], apn))
            return true;
    }

    return false;
}

static void reload_pgw_tac_add(mme_pgw_t *pgw, uint16_t tac)
{
    ogs_assert(pgw);

    if (reload_pgw_tac_has(pgw, tac))
        return;

    if (pgw->num_of_tac >= (int)ogs_global_conf()->max.tai) {
        ogs_reload_audit_warn("smf tac list full on peer");
        return;
    }

    pgw->tac[pgw->num_of_tac++] = tac;
    mme_reload_lists_changed++;
}

static void reload_pgw_apn_add(mme_pgw_t *pgw, const char *apn)
{
    char *copy = NULL;

    ogs_assert(pgw);
    ogs_assert(apn);

    if (reload_pgw_apn_has(pgw, apn))
        return;

    if (pgw->num_of_apn >= OGS_MAX_NUM_OF_APN) {
        ogs_reload_audit_warn("smf apn list full on peer");
        return;
    }

    copy = ogs_strdup(apn);
    ogs_assert(copy);
    pgw->apn[pgw->num_of_apn++] = copy;
    mme_reload_lists_changed++;
}

static bool reload_pgw_ecell_has(mme_pgw_t *pgw, uint32_t e_cell_id)
{
    int i;

    ogs_assert(pgw);

    for (i = 0; i < pgw->num_of_e_cell_id; i++) {
        if (pgw->e_cell_id[i] == e_cell_id)
            return true;
    }

    return false;
}

static void reload_pgw_ecell_add(mme_pgw_t *pgw, uint32_t e_cell_id)
{
    ogs_assert(pgw);

    if (reload_pgw_ecell_has(pgw, e_cell_id))
        return;

    if (pgw->num_of_e_cell_id >= OGS_MAX_NUM_OF_CELL_ID) {
        ogs_reload_audit_warn("smf e_cell_id list full on peer");
        return;
    }

    pgw->e_cell_id[pgw->num_of_e_cell_id++] = e_cell_id;
    mme_reload_lists_changed++;
}

static int reload_hss_map_replace(ogs_yaml_iter_t *mme_iter)
{
    ogs_yaml_iter_t hss_map_array, hss_map_iter;
    int count = 0;

    mme_hssmap_remove_all();

    ogs_yaml_iter_recurse(mme_iter, &hss_map_array);
    do {
        if (ogs_yaml_iter_type(&hss_map_array) == YAML_MAPPING_NODE) {
            memcpy(&hss_map_iter, &hss_map_array, sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(&hss_map_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&hss_map_array))
                break;
            ogs_yaml_iter_recurse(&hss_map_array, &hss_map_iter);
        } else if (ogs_yaml_iter_type(&hss_map_array) == YAML_SCALAR_NODE) {
            break;
        } else {
            ogs_reload_audit_warn("unexpected YAML node in hss_map reload");
            break;
        }

        while (ogs_yaml_iter_next(&hss_map_iter)) {
            const char *mnc = NULL, *mcc = NULL;
            char *realm = NULL, *host = NULL;
            const char *hss_map_key = ogs_yaml_iter_key(&hss_map_iter);
            ogs_assert(hss_map_key);

            if (!strcmp(hss_map_key, "plmn_id")) {
                ogs_yaml_iter_t plmn_id_iter;

                ogs_yaml_iter_recurse(&hss_map_iter, &plmn_id_iter);
                while (ogs_yaml_iter_next(&plmn_id_iter)) {
                    const char *plmn_id_key =
                        ogs_yaml_iter_key(&plmn_id_iter);
                    ogs_assert(plmn_id_key);

                    if (!strcmp(plmn_id_key, "host")) {
                        const char *v = ogs_yaml_iter_value(&plmn_id_iter);
                        if (v) host = ogs_strndup(v, OGS_MAX_FQDN_LEN);
                    } else if (!strcmp(plmn_id_key, "realm")) {
                        const char *v = ogs_yaml_iter_value(&plmn_id_iter);
                        if (v) realm = ogs_strndup(v, OGS_MAX_FQDN_LEN);
                    } else if (!strcmp(plmn_id_key, "mcc")) {
                        mcc = ogs_yaml_iter_value(&plmn_id_iter);
                    } else if (!strcmp(plmn_id_key, "mnc")) {
                        mnc = ogs_yaml_iter_value(&plmn_id_iter);
                    }
                }

                if (mcc && mnc) {
                    ogs_plmn_id_t plmn_id;
                    mme_hssmap_t *hssmap = NULL;

                    ogs_plmn_id_build(&plmn_id,
                            atoi(mcc), atoi(mnc), strlen(mnc));

                    hssmap = mme_hssmap_add(&plmn_id, realm, host);
                    ogs_assert(hssmap);
                    count++;
                    mme_reload_lists_changed++;

                    if (host) ogs_free(host);
                    if (realm) ogs_free(realm);
                }
            }
        }
    } while (ogs_yaml_iter_type(&hss_map_array) == YAML_SEQUENCE_NODE);

    if (count > 0 || ogs_list_first(&mme_self()->hssmap_list) == NULL) {
        mme_reload_lists_changed++;
        ogs_reload_audit_note(" hss_map replaced (%d entries)", count);
    }

    return count;
}

static int reload_imsi_acl_replace(ogs_yaml_iter_t *mme_iter)
{
    mme_context_t *self = mme_self();
    ogs_yaml_iter_t acl_array, acl_iter;
    char new_acl[MME_MAX_IMSI_ACL][OGS_MAX_IMSI_BCD_LEN + 1];
    int new_count = 0;

    /* Zero-fill so the change-detection memcmp below compares defined
     * bytes past each prefix's NUL terminator */
    memset(new_acl, 0, sizeof(new_acl));

    ogs_yaml_iter_recurse(mme_iter, &acl_array);
    do {
        if (ogs_yaml_iter_type(&acl_array) == YAML_MAPPING_NODE) {
            break;
        } else if (ogs_yaml_iter_type(&acl_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&acl_array))
                break;
            ogs_yaml_iter_recurse(&acl_array, &acl_iter);
        } else if (ogs_yaml_iter_type(&acl_array) == YAML_SCALAR_NODE) {
            ogs_yaml_iter_recurse(mme_iter, &acl_iter);
        } else {
            ogs_reload_audit_warn("unexpected YAML node in imsi_acl reload");
            break;
        }

        while (ogs_yaml_iter_next(&acl_iter)) {
            const char *v = ogs_yaml_iter_value(&acl_iter);

            if (!v || !v[0])
                continue;
            if (new_count >= MME_MAX_IMSI_ACL) {
                ogs_reload_audit_warn("imsi_acl list full (max %d)", MME_MAX_IMSI_ACL);
                break;
            }

            ogs_cpystrn(new_acl[new_count], v, OGS_MAX_IMSI_BCD_LEN + 1);
            new_count++;
        }
    } while (ogs_yaml_iter_type(&acl_array) == YAML_SEQUENCE_NODE &&
            ogs_yaml_iter_next(&acl_array));

    if (new_count != self->num_of_imsi_acl ||
            (new_count > 0 && memcmp(new_acl, self->imsi_acl,
             new_count * sizeof(new_acl[0])) != 0) ||
            (new_count == 0 && self->num_of_imsi_acl > 0)) {
        self->num_of_imsi_acl = new_count;
        if (new_count > 0)
            memcpy(self->imsi_acl, new_acl,
                    new_count * sizeof(self->imsi_acl[0]));
        mme_reload_lists_changed++;
        ogs_reload_audit_note(" imsi_acl replaced (%d entries)", new_count);
    }

    return new_count;
}

static int reload_access_control_replace(ogs_yaml_iter_t *mme_iter)
{
    mme_context_t *self = mme_self();
    ogs_yaml_iter_t access_control_array, access_control_iter;
    int added = 0;

    mme_access_control_free_all();
    self->num_of_access_control = 0;

    ogs_yaml_iter_recurse(mme_iter, &access_control_array);
    do {
        char imsi_prefix_buf[OGS_MAX_IMSI_BCD_LEN + 1];
        ogs_plmn_id_t plmn_id;
        bool plmn_configured = false;
        bool entry_configured = false;
        int entry_reject_cause = 0;
        mme_access_control_t *ac = NULL;
        int before;

        imsi_prefix_buf[0] = '\0';
        memset(&plmn_id, 0, sizeof(plmn_id));

        if (ogs_yaml_iter_type(&access_control_array) == YAML_MAPPING_NODE) {
            memcpy(&access_control_iter, &access_control_array,
                    sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(&access_control_array) ==
                YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&access_control_array))
                break;
            ogs_yaml_iter_recurse(&access_control_array, &access_control_iter);
        } else if (ogs_yaml_iter_type(&access_control_array) ==
                YAML_SCALAR_NODE) {
            break;
        } else {
            ogs_reload_audit_warn("unexpected YAML node in access_control reload");
            break;
        }

        while (ogs_yaml_iter_next(&access_control_iter)) {
            const char *mnc = NULL, *mcc = NULL;
            int reject_cause = 0;
            const char *access_control_key =
                ogs_yaml_iter_key(&access_control_iter);
            ogs_assert(access_control_key);

            if (!strcmp(access_control_key, "default_reject_cause")) {
                const char *v = ogs_yaml_iter_value(&access_control_iter);
                if (v) self->default_reject_cause = atoi(v);
            } else if (!strcmp(access_control_key, "reject_cause")) {
                const char *v = ogs_yaml_iter_value(&access_control_iter);
                if (v) entry_reject_cause = atoi(v);
            } else if (!strcmp(access_control_key, "imsi_prefix")) {
                const char *v = ogs_yaml_iter_value(&access_control_iter);
                if (v) {
                    ogs_cpystrn(imsi_prefix_buf, v, sizeof(imsi_prefix_buf));
                    entry_configured = true;
                }
            } else if (!strcmp(access_control_key, "plmn_id")) {
                ogs_yaml_iter_t plmn_id_iter;

                ogs_yaml_iter_recurse(&access_control_iter, &plmn_id_iter);
                while (ogs_yaml_iter_next(&plmn_id_iter)) {
                    const char *plmn_id_key =
                        ogs_yaml_iter_key(&plmn_id_iter);
                    ogs_assert(plmn_id_key);

                    if (!strcmp(plmn_id_key, "reject_cause")) {
                        const char *v = ogs_yaml_iter_value(&plmn_id_iter);
                        if (v) reject_cause = atoi(v);
                    } else if (!strcmp(plmn_id_key, "mcc")) {
                        mcc = ogs_yaml_iter_value(&plmn_id_iter);
                    } else if (!strcmp(plmn_id_key, "mnc")) {
                        mnc = ogs_yaml_iter_value(&plmn_id_iter);
                    }
                }

                if (mcc && mnc) {
                    ogs_plmn_id_build(&plmn_id,
                            atoi(mcc), atoi(mnc), strlen(mnc));
                    plmn_configured = true;
                    entry_configured = true;
                    if (reject_cause)
                        entry_reject_cause = reject_cause;
                }
            } else if (!strcmp(access_control_key, "tac") ||
                    !strcmp(access_control_key, "enb_id")) {
                entry_configured = true;

                if (!ac) {
                    ac = reload_access_control_find(
                            imsi_prefix_buf[0] ? imsi_prefix_buf : NULL,
                            plmn_configured, &plmn_id);
                    if (!ac) {
                        if (self->num_of_access_control >=
                                OGS_MAX_NUM_OF_PLMN_PER_MME) {
                            ogs_reload_audit_warn("access_control list full");
                            break;
                        }
                        ac = &self->access_control[
                                self->num_of_access_control];
                        memset(ac, 0, sizeof(*ac));
                        if (imsi_prefix_buf[0])
                            ogs_cpystrn(ac->imsi_prefix, imsi_prefix_buf,
                                    sizeof(ac->imsi_prefix));
                        if (plmn_configured) {
                            ac->plmn_id = plmn_id;
                            ac->plmn_id_configured = true;
                        }
                        if (entry_reject_cause)
                            ac->reject_cause = entry_reject_cause;
                        self->num_of_access_control++;
                        added++;
                        mme_reload_lists_changed++;
                        ogs_reload_audit_note(" access_control entry added");
                    }
                }

                reload_access_control_parse_uint32_list(
                        &access_control_iter, ac,
                        !strcmp(access_control_key, "enb_id"));
            }
        }

        if (!entry_configured)
            continue;

        before = mme_reload_lists_changed;
        if (!ac) {
            ac = reload_access_control_find(
                    imsi_prefix_buf[0] ? imsi_prefix_buf : NULL,
                    plmn_configured, &plmn_id);
            if (!ac) {
                if (self->num_of_access_control >=
                        OGS_MAX_NUM_OF_PLMN_PER_MME) {
                    ogs_reload_audit_warn("access_control list full");
                    continue;
                }
                ac = &self->access_control[self->num_of_access_control];
                memset(ac, 0, sizeof(*ac));
                if (imsi_prefix_buf[0])
                    ogs_cpystrn(ac->imsi_prefix, imsi_prefix_buf,
                            sizeof(ac->imsi_prefix));
                if (plmn_configured) {
                    ac->plmn_id = plmn_id;
                    ac->plmn_id_configured = true;
                }
                if (entry_reject_cause)
                    ac->reject_cause = entry_reject_cause;
                self->num_of_access_control++;
                added++;
                mme_reload_lists_changed++;
                ogs_reload_audit_note(" access_control entry added");
            }
        }

        if (mme_reload_lists_changed == before && ac &&
                (imsi_prefix_buf[0] || plmn_configured))
            ogs_debug("SIGHUP: access_control entry unchanged");
    } while (ogs_yaml_iter_type(&access_control_array) ==
            YAML_SEQUENCE_NODE);

    if (self->num_of_access_control > 0 || added > 0) {
        mme_reload_lists_changed++;
        ogs_reload_audit_note(" access_control replaced (%d entries)",
                self->num_of_access_control);
    } else if (added == 0) {
        mme_reload_lists_changed++;
        ogs_reload_audit_note(" access_control replaced (0 entries)");
    }

    return added;
}

static int reload_equivalent_plmn_replace(ogs_yaml_iter_t *mme_iter)
{
    mme_context_t *self = mme_self();
    ogs_plmn_id_t new_eplmn[OGS_NAS_MAX_PLMN];
    int new_count = 0;
    int rv;

    rv = mme_eplmn_parse_config(mme_iter, &new_count, new_eplmn);
    if (rv != OGS_OK) {
        ogs_reload_audit_warn("equivalent_plmn YAML parse failed");
        return 0;
    }

    if (new_count != self->num_of_eplmn ||
            (new_count > 0 && memcmp(new_eplmn, self->eplmn,
             new_count * sizeof(new_eplmn[0])) != 0) ||
            (new_count == 0 && self->num_of_eplmn > 0)) {
        self->num_of_eplmn = new_count;
        if (new_count > 0)
            memcpy(self->eplmn, new_eplmn,
                    new_count * sizeof(self->eplmn[0]));
        mme_reload_lists_changed++;
        ogs_reload_audit_note(" equivalent_plmn replaced (%d entries)",
                new_count);
    }

    return new_count;
}

static int reload_served_tai_add_from_yaml(ogs_yaml_iter_t *mme_iter)
{
    ogs_yaml_iter_t tai_array, tai_iter;
    int added = 0;

    ogs_yaml_iter_recurse(mme_iter, &tai_array);
    do {
        const char *mcc = NULL, *mnc = NULL;
        int num_of_tac = 0;
        uint16_t *start = NULL;
        uint16_t *end = NULL;
        int tac;

        start = ogs_calloc(ogs_global_conf()->max.tai, sizeof(uint16_t));
        end = ogs_calloc(ogs_global_conf()->max.tai, sizeof(uint16_t));
        ogs_assert(start);
        ogs_assert(end);

        if (ogs_yaml_iter_type(&tai_array) == YAML_MAPPING_NODE) {
            memcpy(&tai_iter, &tai_array, sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(&tai_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&tai_array)) {
                ogs_free(start);
                ogs_free(end);
                break;
            }
            ogs_yaml_iter_recurse(&tai_array, &tai_iter);
        } else if (ogs_yaml_iter_type(&tai_array) == YAML_SCALAR_NODE) {
            ogs_free(start);
            ogs_free(end);
            break;
        } else {
            ogs_free(start);
            ogs_free(end);
            ogs_reload_audit_warn("unexpected YAML node in served TAI reload");
            break;
        }

        while (ogs_yaml_iter_next(&tai_iter)) {
            const char *tai_key = ogs_yaml_iter_key(&tai_iter);
            ogs_assert(tai_key);

            if (!strcmp(tai_key, "plmn_id")) {
                ogs_yaml_iter_t plmn_id_iter;

                ogs_yaml_iter_recurse(&tai_iter, &plmn_id_iter);
                while (ogs_yaml_iter_next(&plmn_id_iter)) {
                    const char *plmn_id_key = ogs_yaml_iter_key(&plmn_id_iter);
                    ogs_assert(plmn_id_key);

                    if (!strcmp(plmn_id_key, "mcc"))
                        mcc = ogs_yaml_iter_value(&plmn_id_iter);
                    else if (!strcmp(plmn_id_key, "mnc"))
                        mnc = ogs_yaml_iter_value(&plmn_id_iter);
                }
            } else if (!strcmp(tai_key, "tac")) {
                ogs_yaml_iter_t tac_iter;

                ogs_yaml_iter_recurse(&tai_iter, &tac_iter);
                ogs_assert(ogs_yaml_iter_type(&tac_iter) != YAML_MAPPING_NODE);

                do {
                    char *v = NULL;
                    char *low = NULL, *high = NULL;

                    if (ogs_yaml_iter_type(&tac_iter) == YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&tac_iter))
                            break;
                    }

                    v = (char *)ogs_yaml_iter_value(&tac_iter);
                    if (!v)
                        continue;

                    low = strsep(&v, "-");
                    if (low && strlen(low) == 0)
                        low = NULL;
                    high = v;
                    if (high && strlen(high) == 0)
                        high = NULL;

                    if (!low)
                        continue;
                    if (num_of_tac >= (int)ogs_global_conf()->max.tai)
                        break;

                    start[num_of_tac] = (uint16_t)atoi(low);
                    if (high) {
                        end[num_of_tac] = (uint16_t)atoi(high);
                        if (end[num_of_tac] >= start[num_of_tac])
                            num_of_tac++;
                    } else {
                        end[num_of_tac] = start[num_of_tac];
                        num_of_tac++;
                    }
                } while (ogs_yaml_iter_type(&tac_iter) == YAML_SEQUENCE_NODE);
            }
        }

        if (mcc && mnc && num_of_tac) {
            ogs_plmn_id_t plmn_id;

            ogs_plmn_id_build(&plmn_id, atoi(mcc), atoi(mnc), strlen(mnc));
            for (tac = 0; tac < num_of_tac; tac++) {
                if (start[tac] == end[tac])
                    added += reload_served_tai_add_one(&plmn_id, start[tac]);
                else
                    added += reload_served_tai_add_range(
                            &plmn_id, start[tac], end[tac]);
            }
        }

        ogs_free(start);
        ogs_free(end);
    } while (ogs_yaml_iter_type(&tai_array) == YAML_SEQUENCE_NODE);

    return added;
}

static int reload_served_tai_replace(ogs_yaml_iter_t *mme_iter)
{
    /* Mirror of the anonymous served_tai element in mme_context_t,
     * used to walk the detached backup copy */
    struct served_tai_entry {
        ogs_eps_tai0_list_t *list0;
        ogs_eps_tai1_list_t list1;
        ogs_eps_tai2_list_t list2;
    } *backup = NULL;
    mme_context_t *self = mme_self();
    int backup_num, added, i;

    ogs_assert(sizeof(backup[0]) == sizeof(self->served_tai[0]));

    /*
     * Detach the current TAI table into a backup so a bad/empty `tai:`
     * section can be rejected instead of leaving the MME with zero
     * served TAIs (which would reject every attach).
     */
    backup = ogs_malloc(sizeof(self->served_tai));
    ogs_assert(backup);
    memcpy(backup, self->served_tai, sizeof(self->served_tai));
    backup_num = self->num_of_served_tai;

    memset(self->served_tai, 0, sizeof(self->served_tai));
    self->num_of_served_tai = 0;

    added = reload_served_tai_add_from_yaml(mme_iter);

    if (added <= 0 && backup_num > 0) {
        /* Roll back: drop partial allocations, restore previous table */
        reload_served_tai_clear_all();
        memcpy(self->served_tai, backup, sizeof(self->served_tai));
        self->num_of_served_tai = backup_num;
        ogs_free(backup);
        ogs_reload_audit_warn(
                "tai yielded no entries; previous served TAI list kept");
        return 0;
    }

    for (i = 0; i < OGS_MAX_NUM_OF_SUPPORTED_TA; i++) {
        if (backup[i].list0)
            ogs_free(backup[i].list0);
    }
    ogs_free(backup);

    mme_reload_lists_changed++;
    ogs_reload_audit_note(" served TAI replaced (%d TAC entries)", added);

    return added;
}

static int reload_trace_imsi_replace(ogs_yaml_iter_t *mme_iter)
{
    ogs_yaml_iter_t trace_array, trace_iter;
    int count = 0;

    ogs_trace_filter_clear();

    ogs_yaml_iter_recurse(mme_iter, &trace_array);
    do {
        if (ogs_yaml_iter_type(&trace_array) == YAML_MAPPING_NODE) {
            break;
        } else if (ogs_yaml_iter_type(&trace_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(&trace_array))
                break;
            ogs_yaml_iter_recurse(&trace_array, &trace_iter);
        } else if (ogs_yaml_iter_type(&trace_array) == YAML_SCALAR_NODE) {
            ogs_yaml_iter_recurse(mme_iter, &trace_iter);
        } else {
            ogs_reload_audit_warn("unexpected YAML node in trace_imsi reload");
            break;
        }

        while (ogs_yaml_iter_next(&trace_iter)) {
            const char *v = ogs_yaml_iter_value(&trace_iter);

            if (!v || !v[0])
                continue;
            if (ogs_trace_filter_add(v) != OGS_OK) {
                ogs_reload_audit_warn("trace_imsi could not add `%s'", v);
                continue;
            }
            count++;
        }
    } while (ogs_yaml_iter_type(&trace_array) == YAML_SEQUENCE_NODE &&
            ogs_yaml_iter_next(&trace_array));

    mme_reload_lists_changed++;
    ogs_reload_audit_note(" trace_imsi replaced (%d entries)", count);

    return count;
}

static int reload_emergency_replace(ogs_yaml_iter_t *mme_iter)
{
    mme_context_t *self = mme_self();
    ogs_yaml_iter_t emerg_iter;
    int added = 0;

    mme_emerg_remove_all();

    ogs_yaml_iter_recurse(mme_iter, &emerg_iter);
    while (ogs_yaml_iter_next(&emerg_iter)) {
        const char *emerg_key = ogs_yaml_iter_key(&emerg_iter);
        ogs_assert(emerg_key);

        if (!strcmp(emerg_key, "dnn")) {
            const char *dnn = ogs_yaml_iter_value(&emerg_iter);
            if (dnn) {
                self->emergency.dnn = dnn;
                mme_reload_lists_changed++;
            }
        } else if (!strcmp(emerg_key, "number")) {
            ogs_yaml_iter_t number_array, number_iter;

            ogs_yaml_iter_recurse(&emerg_iter, &number_array);
            do {
                const char *digits = NULL;
                uint8_t categories = 0;

                if (ogs_yaml_iter_type(&number_array) == YAML_MAPPING_NODE) {
                    memcpy(&number_iter, &number_array,
                            sizeof(ogs_yaml_iter_t));
                } else if (ogs_yaml_iter_type(&number_array) ==
                        YAML_SEQUENCE_NODE) {
                    if (!ogs_yaml_iter_next(&number_array))
                        break;
                    ogs_yaml_iter_recurse(&number_array, &number_iter);
                } else if (ogs_yaml_iter_type(&number_array) ==
                        YAML_SCALAR_NODE) {
                    break;
                } else {
                    ogs_reload_audit_warn("unexpected YAML node in emergency reload");
                    break;
                }

                while (ogs_yaml_iter_next(&number_iter)) {
                    const char *number_key = ogs_yaml_iter_key(&number_iter);
                    ogs_assert(number_key);

                    if (!strcmp(number_key, "digits")) {
                        digits = ogs_yaml_iter_value(&number_iter);
                    } else if (!strcmp(number_key, "categories")) {
                        ogs_yaml_iter_t categories_iter;

                        ogs_yaml_iter_recurse(&number_iter, &categories_iter);
                        ogs_assert(ogs_yaml_iter_type(&categories_iter) !=
                                YAML_MAPPING_NODE);

                        do {
                            const char *v = NULL;

                            if (ogs_yaml_iter_type(&categories_iter) ==
                                    YAML_SEQUENCE_NODE) {
                                if (!ogs_yaml_iter_next(&categories_iter))
                                    break;
                            }

                            v = ogs_yaml_iter_value(&categories_iter);
                            if (!v)
                                continue;

                            if (strstr(v, "police"))
                                categories |=
                                    OGS_NAS_SERVICE_CATEGORY_POLICE;
                            else if (strstr(v, "ambulance"))
                                categories |=
                                    OGS_NAS_SERVICE_CATEGORY_AMBULANCE;
                            else if (strstr(v, "fire"))
                                categories |=
                                    OGS_NAS_SERVICE_CATEGORY_FIRE_BRIGADE;
                            else if (strstr(v, "marine"))
                                categories |=
                                    OGS_NAS_SERVICE_CATEGORY_MARINE_GUARD;
                            else if (strstr(v, "mountain"))
                                categories |=
                                    OGS_NAS_SERVICE_CATEGORY_MOUNTAIN_RESCUE;
                            else {
                                categories = (uint8_t)strtol(v, NULL, 0);
                                if (categories < 1 || categories > 0x1f)
                                    ogs_warn("invalid categories `%s`", v);
                            }
                        } while (ogs_yaml_iter_type(&categories_iter) ==
                                YAML_SEQUENCE_NODE);
                    }
                }

                if (digits && categories > 0 && categories <= 0x1f) {
                    if (mme_emerg_add(categories, digits)) {
                        added++;
                    }
                }
            } while (ogs_yaml_iter_type(&number_array) ==
                    YAML_SEQUENCE_NODE);
        }
    }

    mme_reload_lists_changed++;
    ogs_reload_audit_note(" emergency config replaced (%d numbers)", added);

    return added;
}

static bool reload_gtpc_peer_wanted(
        ogs_yaml_iter_t *gtpc_iter, bool pgw,
        ogs_sockaddr_t *peer_sa_list, const ogs_sockaddr_t *peer_addr,
        bool *resolve_failed)
{
    ogs_yaml_iter_t gtpc_sub_iter;
    const char *client_key_want = pgw ? "smf" : "sgwc";

    ogs_assert(gtpc_iter);
    ogs_assert(resolve_failed);
    ogs_assert(peer_sa_list || peer_addr);

    ogs_yaml_iter_recurse(gtpc_iter, &gtpc_sub_iter);
    while (ogs_yaml_iter_next(&gtpc_sub_iter)) {
        const char *gtpc_key = ogs_yaml_iter_key(&gtpc_sub_iter);

        if (!gtpc_key || strcmp(gtpc_key, "client"))
            continue;

        ogs_yaml_iter_t client_iter;
        ogs_yaml_iter_recurse(&gtpc_sub_iter, &client_iter);
        while (ogs_yaml_iter_next(&client_iter)) {
            const char *client_key = ogs_yaml_iter_key(&client_iter);
            ogs_yaml_iter_t peer_array;

            if (!client_key || strcmp(client_key, client_key_want))
                continue;

            ogs_yaml_iter_recurse(&client_iter, &peer_array);
            do {
                ogs_yaml_iter_t peer_iter;
                int family = AF_UNSPEC;
                int i, num = 0;
                const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
                uint16_t port = ogs_gtp_self()->gtpc_port;
                ogs_sockaddr_t *resolved = NULL;

                if (ogs_yaml_iter_type(&peer_array) == YAML_MAPPING_NODE) {
                    memcpy(&peer_iter, &peer_array, sizeof(ogs_yaml_iter_t));
                } else if (ogs_yaml_iter_type(&peer_array) ==
                        YAML_SEQUENCE_NODE) {
                    if (!ogs_yaml_iter_next(&peer_array))
                        break;
                    ogs_yaml_iter_recurse(&peer_array, &peer_iter);
                } else {
                    break;
                }

                while (ogs_yaml_iter_next(&peer_iter)) {
                    const char *peer_key = ogs_yaml_iter_key(&peer_iter);

                    if (!peer_key)
                        continue;
                    if (!strcmp(peer_key, "family")) {
                        const char *v = ogs_yaml_iter_value(&peer_iter);
                        if (v)
                            family = atoi(v);
                    } else if (!strcmp(peer_key, "address")) {
                        ogs_yaml_iter_t hostname_iter;

                        ogs_yaml_iter_recurse(&peer_iter, &hostname_iter);
                        do {
                            if (ogs_yaml_iter_type(&hostname_iter) ==
                                    YAML_SEQUENCE_NODE) {
                                if (!ogs_yaml_iter_next(&hostname_iter))
                                    break;
                            }
                            if (num >= OGS_MAX_NUM_OF_HOSTNAME)
                                break;
                            hostname[num++] =
                                ogs_yaml_iter_value(&hostname_iter);
                        } while (ogs_yaml_iter_type(&hostname_iter) ==
                                YAML_SEQUENCE_NODE);
                    } else if (!strcmp(peer_key, "port")) {
                        const char *v = ogs_yaml_iter_value(&peer_iter);
                        if (v)
                            port = reload_yaml_parse_port(v, port);
                    }
                }

                for (i = 0; i < num; i++) {
                    if (ogs_addaddrinfo(&resolved, family, hostname[i],
                            port, 0) != OGS_OK) {
                        *resolve_failed = true;
                        continue;
                    }
                }

                ogs_filter_ip_version(&resolved,
                        ogs_global_conf()->parameter.no_ipv4,
                        ogs_global_conf()->parameter.no_ipv6,
                        ogs_global_conf()->parameter.prefer_ipv4);

                if (resolved) {
                    /*
                     * Match like mme_sgw_find_by_addr(): port first, then IP
                     * only (SGWC inbound roam may use a different source port).
                     */
                    if (ogs_sockaddr_check_any_match(
                                resolved, peer_sa_list, peer_addr, true) ||
                            ogs_sockaddr_check_any_match(
                                resolved, peer_sa_list, peer_addr, false)) {
                        ogs_freeaddrinfo(resolved);
                        return true;
                    }
                    ogs_freeaddrinfo(resolved);
                }
            } while (ogs_yaml_iter_type(&peer_array) == YAML_SEQUENCE_NODE);
        }
    }

    return false;
}

static void reload_gtpc_remove_stale(ogs_yaml_iter_t *gtpc_iter)
{
    mme_sgw_t *sgw = NULL, *next_sgw = NULL;
    mme_pgw_t *pgw = NULL, *next_pgw = NULL;
    char peer_buf[OGS_ADDRSTRLEN];

    ogs_list_for_each_safe(&mme_self()->sgw_list, next_sgw, sgw) {
        bool resolve_failed = false;

        if (reload_gtpc_peer_wanted(gtpc_iter, false, sgw->gnode.sa_list,
                &sgw->gnode.addr, &resolve_failed))
            continue;

        if (resolve_failed) {
            /* Cannot trust the wanted-set when DNS resolution failed;
             * keep the peer rather than dropping it on a transient error */
            ogs_reload_audit_warn(
                    "sgwc peer removal skipped (DNS resolution failure) "
                    "[%s]:%d",
                    OGS_ADDR(&sgw->gnode.addr, peer_buf),
                    OGS_PORT(&sgw->gnode.addr));
            continue;
        }

        if (mme_sgw_in_use(sgw)) {
            ogs_reload_audit_warn(
                    "sgwc peer removal skipped (S11 contexts) [%s]:%d",
                    OGS_ADDR(&sgw->gnode.addr, peer_buf),
                    OGS_PORT(&sgw->gnode.addr));
            continue;
        }

        ogs_reload_audit_note(" sgwc peer removed [%s]:%d",
                OGS_ADDR(&sgw->gnode.addr, peer_buf),
                OGS_PORT(&sgw->gnode.addr));
        mme_sgw_remove(sgw);
        mme_reload_lists_changed++;
    }

    ogs_list_for_each_safe(&mme_self()->pgw_list, next_pgw, pgw) {
        bool resolve_failed = false;
        ogs_sockaddr_t *pgw_addr = pgw->sa_list;

        if (!pgw_addr)
            continue;

        if (reload_gtpc_peer_wanted(gtpc_iter, true, pgw->sa_list, NULL,
                &resolve_failed))
            continue;

        if (resolve_failed) {
            ogs_reload_audit_warn(
                    "smf/pgw peer removal skipped (DNS resolution failure) "
                    "[%s]:%d",
                    OGS_ADDR(pgw_addr, peer_buf),
                    OGS_PORT(pgw_addr));
            continue;
        }

        ogs_reload_audit_note(" smf/pgw peer removed [%s]:%d",
                OGS_ADDR(pgw_addr, peer_buf),
                OGS_PORT(pgw_addr));
        mme_pgw_remove(pgw);
        mme_reload_lists_changed++;
    }
}

static int reload_gtpc_client_entry_add_only(
        ogs_yaml_iter_t *client_array, bool pgw)
{
    ogs_yaml_iter_t client_iter;
    int added = 0;

    do {
        ogs_sockaddr_t *addr = NULL;
        int family = AF_UNSPEC;
        int i, num = 0;
        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
        uint16_t port = ogs_gtp_self()->gtpc_port;
        uint16_t *tac = ogs_calloc(ogs_global_conf()->max.tai,
                sizeof(uint16_t));
        int num_of_tac = 0;
        uint32_t e_cell_id[OGS_MAX_NUM_OF_CELL_ID] = {0,};
        int num_of_e_cell_id = 0;
        bool serving_plmn_parsed = false;
        ogs_plmn_id_t serving_plmn;
        bool imsi_plmn_parsed = false;
        ogs_plmn_id_t imsi_plmn;
        const char *apn[OGS_MAX_NUM_OF_APN] = {NULL,};
        uint8_t num_of_apn = 0;
        mme_sgw_t *sgw = NULL;
        mme_pgw_t *pgw_node = NULL;
        int before = mme_reload_lists_changed;

        ogs_assert(tac);

        if (ogs_yaml_iter_type(client_array) == YAML_MAPPING_NODE) {
            memcpy(&client_iter, client_array, sizeof(ogs_yaml_iter_t));
        } else if (ogs_yaml_iter_type(client_array) == YAML_SEQUENCE_NODE) {
            if (!ogs_yaml_iter_next(client_array)) {
                ogs_free(tac);
                break;
            }
            ogs_yaml_iter_recurse(client_array, &client_iter);
        } else if (ogs_yaml_iter_type(client_array) == YAML_SCALAR_NODE) {
            ogs_free(tac);
            break;
        } else {
            ogs_free(tac);
            ogs_reload_audit_warn("unexpected YAML node in gtpc client reload");
            break;
        }

        while (ogs_yaml_iter_next(&client_iter)) {
            const char *client_key = ogs_yaml_iter_key(&client_iter);
            ogs_assert(client_key);

            if (!strcmp(client_key, "family")) {
                const char *v = ogs_yaml_iter_value(&client_iter);
                if (v) family = atoi(v);
            } else if (!strcmp(client_key, "address")) {
                ogs_yaml_iter_t hostname_iter;

                ogs_yaml_iter_recurse(&client_iter, &hostname_iter);
                do {
                    if (ogs_yaml_iter_type(&hostname_iter) ==
                            YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&hostname_iter))
                            break;
                    }
                    ogs_assert(num < OGS_MAX_NUM_OF_HOSTNAME);
                    hostname[num++] = ogs_yaml_iter_value(&hostname_iter);
                } while (ogs_yaml_iter_type(&hostname_iter) ==
                        YAML_SEQUENCE_NODE);
            } else if (!strcmp(client_key, "port")) {
                const char *v = ogs_yaml_iter_value(&client_iter);
                if (v) port = reload_yaml_parse_port(v, port);
            } else if (!strcmp(client_key, "apn")) {
                ogs_yaml_iter_t apn_iter;

                ogs_yaml_iter_recurse(&client_iter, &apn_iter);
                do {
                    if (ogs_yaml_iter_type(&apn_iter) == YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&apn_iter))
                            break;
                    }
                    ogs_assert(num_of_apn < OGS_MAX_NUM_OF_APN);
                    apn[num_of_apn++] = ogs_yaml_iter_value(&apn_iter);
                } while (ogs_yaml_iter_type(&apn_iter) == YAML_SEQUENCE_NODE);
            } else if (!strcmp(client_key, "tac")) {
                ogs_yaml_iter_t tac_iter;

                ogs_yaml_iter_recurse(&client_iter, &tac_iter);
                do {
                    const char *v = NULL;

                    if (ogs_yaml_iter_type(&tac_iter) == YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&tac_iter))
                            break;
                    }
                    if (num_of_tac >= (int)ogs_global_conf()->max.tai)
                        break;
                    v = ogs_yaml_iter_value(&tac_iter);
                    if (v)
                        tac[num_of_tac++] = (uint16_t)atoi(v);
                } while (ogs_yaml_iter_type(&tac_iter) == YAML_SEQUENCE_NODE);
            } else if (!strcmp(client_key, "e_cell_id")) {
                ogs_yaml_iter_t e_cell_id_iter;

                ogs_yaml_iter_recurse(&client_iter, &e_cell_id_iter);
                do {
                    const char *v = NULL;

                    if (ogs_yaml_iter_type(&e_cell_id_iter) ==
                            YAML_SEQUENCE_NODE) {
                        if (!ogs_yaml_iter_next(&e_cell_id_iter))
                            break;
                    }
                    if (num_of_e_cell_id >= OGS_MAX_NUM_OF_CELL_ID)
                        break;
                    v = ogs_yaml_iter_value(&e_cell_id_iter);
                    if (v) {
                        e_cell_id[num_of_e_cell_id] =
                            (uint32_t)ogs_uint64_from_string_hexadecimal(
                                    (char *)v);
                        num_of_e_cell_id++;
                    }
                } while (ogs_yaml_iter_type(&e_cell_id_iter) ==
                        YAML_SEQUENCE_NODE);
            } else if (!strcmp(client_key, "plmn_id") ||
                    !strcmp(client_key, "serving_plmn_id") ||
                    !strcmp(client_key, "imsi_plmn_id")) {
                reload_gtpc_client_parse_plmn_id_key(
                        &client_iter, client_key,
                        &serving_plmn_parsed, &serving_plmn,
                        &imsi_plmn_parsed, &imsi_plmn);
            }
        }

        for (i = 0; i < num; i++) {
            if (ogs_addaddrinfo(&addr, family, hostname[i], port, 0) != OGS_OK)
                ogs_error("SIGHUP: addaddrinfo failed for `%s'", hostname[i]);
        }

        ogs_filter_ip_version(&addr,
                ogs_global_conf()->parameter.no_ipv4,
                ogs_global_conf()->parameter.no_ipv6,
                ogs_global_conf()->parameter.prefer_ipv4);

        if (!addr) {
            ogs_free(tac);
            continue;
        }

        if (!pgw) {
            sgw = mme_sgw_find_by_addr(addr);
            if (!sgw) {
                char peer_buf[OGS_ADDRSTRLEN];
                int rv;

                sgw = mme_sgw_add(addr);
                if (!sgw) {
                    ogs_error("SIGHUP: failed to allocate SGW entry");
                    ogs_free(tac);
                    continue;
                }

                rv = ogs_gtp_connect(
                        ogs_gtp_self()->gtpc_sock, ogs_gtp_self()->gtpc_sock6,
                        &sgw->gnode);
                if (rv != OGS_OK) {
                    ogs_error("SIGHUP: gtp_connect() failed for SGW [%s]:%d",
                            OGS_ADDR(sgw->gnode.sa_list, peer_buf),
                            OGS_PORT(sgw->gnode.sa_list));
                    mme_sgw_remove(sgw);
                    ogs_free(tac);
                    continue;
                }

                ogs_reload_audit_note(" sgwc peer added [%s]:%d",
                        OGS_ADDR(&sgw->gnode.addr, peer_buf),
                        OGS_PORT(&sgw->gnode.addr));
                mme_gtp_send_sgw_echo(sgw);
                mme_sgw_echo_schedule(sgw);
                mme_reload_lists_changed++;
            } else {
                ogs_freeaddrinfo(addr);
            }

            for (i = 0; i < num_of_tac; i++)
                reload_sgw_tac_add(sgw, tac[i]);
            for (i = 0; i < num_of_e_cell_id; i++)
                reload_sgw_ecell_add(sgw, e_cell_id[i]);
            if (serving_plmn_parsed && !sgw->serving_plmn_present) {
                sgw->serving_plmn_present = true;
                memcpy(&sgw->serving_plmn_id, &serving_plmn,
                        sizeof(ogs_plmn_id_t));
                mme_reload_lists_changed++;
            }
            if (imsi_plmn_parsed && !sgw->imsi_plmn_present) {
                sgw->imsi_plmn_present = true;
                memcpy(&sgw->imsi_plmn_id, &imsi_plmn, sizeof(ogs_plmn_id_t));
                mme_reload_lists_changed++;
            }
        } else {
            pgw_node = reload_pgw_find_by_addr(addr);
            if (!pgw_node) {
                pgw_node = mme_pgw_add(addr);
                if (!pgw_node) {
                    ogs_error("SIGHUP: failed to allocate PGW entry");
                    ogs_free(tac);
                    continue;
                }
                mme_reload_lists_changed++;
                ogs_reload_audit_note(" smf/pgw peer added");
            } else {
                ogs_freeaddrinfo(addr);
            }

            for (i = 0; i < num_of_apn; i++) {
                if (apn[i])
                    reload_pgw_apn_add(pgw_node, apn[i]);
            }
            for (i = 0; i < num_of_tac; i++)
                reload_pgw_tac_add(pgw_node, tac[i]);
            for (i = 0; i < num_of_e_cell_id; i++)
                reload_pgw_ecell_add(pgw_node, e_cell_id[i]);
            if (serving_plmn_parsed && !pgw_node->serving_plmn_present) {
                pgw_node->serving_plmn_present = true;
                memcpy(&pgw_node->serving_plmn_id, &serving_plmn,
                        sizeof(ogs_plmn_id_t));
                mme_reload_lists_changed++;
            }
            if (imsi_plmn_parsed && !pgw_node->imsi_plmn_present) {
                pgw_node->imsi_plmn_present = true;
                memcpy(&pgw_node->imsi_plmn_id, &imsi_plmn,
                        sizeof(ogs_plmn_id_t));
                mme_reload_lists_changed++;
            }
        }

        if (mme_reload_lists_changed > before)
            added++;

        ogs_free(tac);
    } while (ogs_yaml_iter_type(client_array) == YAML_SEQUENCE_NODE);

    return added;
}

int mme_reload_gtpc_client_add_only(ogs_yaml_iter_t *gtpc_iter)
{
    ogs_yaml_iter_t gtpc_sub_iter;
    int added = 0;

    ogs_yaml_iter_recurse(gtpc_iter, &gtpc_sub_iter);
    while (ogs_yaml_iter_next(&gtpc_sub_iter)) {
        const char *gtpc_key = ogs_yaml_iter_key(&gtpc_sub_iter);
        ogs_assert(gtpc_key);

        if (!strcmp(gtpc_key, "client")) {
            ogs_yaml_iter_t client_iter;

            ogs_yaml_iter_recurse(&gtpc_sub_iter, &client_iter);
            while (ogs_yaml_iter_next(&client_iter)) {
                const char *client_key = ogs_yaml_iter_key(&client_iter);
                ogs_assert(client_key);

                if (!strcmp(client_key, "sgwc")) {
                    ogs_yaml_iter_t sgwc_array;

                    ogs_yaml_iter_recurse(&client_iter, &sgwc_array);
                    added += reload_gtpc_client_entry_add_only(
                            &sgwc_array, false);
                } else if (!strcmp(client_key, "smf")) {
                    ogs_yaml_iter_t smf_array;

                    ogs_yaml_iter_recurse(&client_iter, &smf_array);
                    added += reload_gtpc_client_entry_add_only(
                            &smf_array, true);
                }
            }
        }
    }

    reload_gtpc_remove_stale(gtpc_iter);

    return added;
}

static void reload_attach_accept_scalars(ogs_yaml_iter_t *mme_iter)
{
    mme_context_t *self = mme_self();
    ogs_yaml_iter_t aa_iter;

    ogs_yaml_iter_recurse(mme_iter, &aa_iter);
    while (ogs_yaml_iter_next(&aa_iter)) {
        const char *aa_key = ogs_yaml_iter_key(&aa_iter);
        ogs_assert(aa_key);

        if (!strcmp(aa_key, "tai_list")) {
            const char *v = ogs_yaml_iter_value(&aa_iter);
            if (v && !strcmp(v, "serving_only"))
                self->attach_accept.tai_list_serving_only = true;
            else if (v && !strcmp(v, "all"))
                self->attach_accept.tai_list_serving_only = false;
        } else if (!strcmp(aa_key, "equivalent_plmn_serving_only")) {
            self->attach_accept.equivalent_plmn_serving_only =
                ogs_yaml_iter_bool(&aa_iter);
        } else if (!strcmp(aa_key, "ims_voice_over_ps")) {
            self->attach_accept.ims_voice_over_ps =
                ogs_yaml_iter_bool(&aa_iter);
        }
    }
    mme_reload_lists_changed++;
}

int mme_reload_lists_key_add_only(const char *mme_key, ogs_yaml_iter_t *mme_iter)
{
    mme_context_t *self = mme_self();

    ogs_assert(mme_key);
    ogs_assert(mme_iter);

    if (!strcmp(mme_key, "tai"))
        return reload_served_tai_replace(mme_iter);
    if (!strcmp(mme_key, "access_control"))
        return reload_access_control_replace(mme_iter);
    if (!strcmp(mme_key, "hss_map"))
        return reload_hss_map_replace(mme_iter);
    if (!strcmp(mme_key, "equivalent_plmn"))
        return reload_equivalent_plmn_replace(mme_iter);
    if (!strcmp(mme_key, "imsi_acl"))
        return reload_imsi_acl_replace(mme_iter);
    if (!strcmp(mme_key, "trace_imsi"))
        return reload_trace_imsi_replace(mme_iter);
    if (!strcmp(mme_key, "emergency"))
        return reload_emergency_replace(mme_iter);
    if (!strcmp(mme_key, "attach_accept")) {
        reload_attach_accept_scalars(mme_iter);
        return 0;
    }

    if (!strcmp(mme_key, "equivalent_plmn_serving_only")) {
        self->attach_accept.equivalent_plmn_serving_only =
            ogs_yaml_iter_bool(mme_iter);
        mme_reload_lists_changed++;
    } else if (!strcmp(mme_key, "ims_voice_over_ps_in_s1_mode")) {
        self->attach_accept.ims_voice_over_ps =
            ogs_yaml_iter_bool(mme_iter);
        mme_reload_lists_changed++;
    } else if (!strcmp(mme_key, "tai_list_in_accept")) {
        const char *v = ogs_yaml_iter_value(mme_iter);
        if (v && !strcmp(v, "serving_only"))
            self->attach_accept.tai_list_serving_only = true;
        else if (v && !strcmp(v, "all"))
            self->attach_accept.tai_list_serving_only = false;
        mme_reload_lists_changed++;
    } else if (!strcmp(mme_key, "require_hss_map")) {
        self->require_hss_map_explicit = true;
        self->require_hss_map = ogs_yaml_iter_bool(mme_iter);
        mme_reload_lists_changed++;
    } else if (!strcmp(mme_key, "ambr_limit")) {
        ogs_yaml_iter_t ambr_iter;

        ogs_yaml_iter_recurse(mme_iter, &ambr_iter);
        while (ogs_yaml_iter_next(&ambr_iter)) {
            const char *ambr_key = ogs_yaml_iter_key(&ambr_iter);
            ogs_assert(ambr_key);

            if (!strcmp(ambr_key, "enabled"))
                self->ambr_limit.enabled = ogs_yaml_iter_bool(&ambr_iter);
            else if (!strcmp(ambr_key, "force"))
                self->ambr_limit.force = ogs_yaml_iter_bool(&ambr_iter);
            else if (!strcmp(ambr_key, "downlink") ||
                    !strcmp(ambr_key, "downlink_mbps")) {
                const char *v = ogs_yaml_iter_value(&ambr_iter);
                if (v) {
                    uint64_t bps = (uint64_t)atoi(v) * 1000000ULL;
                    if (bps > UINT32_MAX)
                        bps = UINT32_MAX;
                    self->ambr_limit.downlink_bps = (uint32_t)bps;
                }
            } else if (!strcmp(ambr_key, "uplink") ||
                    !strcmp(ambr_key, "uplink_mbps")) {
                const char *v = ogs_yaml_iter_value(&ambr_iter);
                if (v) {
                    uint64_t bps = (uint64_t)atoi(v) * 1000000ULL;
                    if (bps > UINT32_MAX)
                        bps = UINT32_MAX;
                    self->ambr_limit.uplink_bps = (uint32_t)bps;
                }
            }
        }
        if (self->ambr_limit.uplink_bps == 0)
            self->ambr_limit.uplink_bps = self->ambr_limit.downlink_bps;
        mme_reload_lists_changed++;
    } else {
        return 0;
    }

    return 0;
}
