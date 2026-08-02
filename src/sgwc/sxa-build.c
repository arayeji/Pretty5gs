/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#include "sxa-build.h"

static bool sgwc_sxa_tunnel_matches_modify(
        sgwc_tunnel_t *tunnel, uint64_t modify_flags)
{
    ogs_assert(tunnel);

    if ((modify_flags &
         (OGS_PFCP_MODIFY_DL_ONLY|
          OGS_PFCP_MODIFY_UL_ONLY|
          OGS_PFCP_MODIFY_INDIRECT)) == 0)
        return true;

    if ((modify_flags & OGS_PFCP_MODIFY_DL_ONLY) &&
        tunnel->interface_type == OGS_GTP2_F_TEID_S5_S8_SGW_GTP_U)
        return true;

    if ((modify_flags & OGS_PFCP_MODIFY_UL_ONLY) &&
        tunnel->interface_type == OGS_GTP2_F_TEID_S1_U_SGW_GTP_U)
        return true;

    if ((modify_flags & OGS_PFCP_MODIFY_INDIRECT) &&
        (tunnel->interface_type ==
            OGS_GTP2_F_TEID_SGW_GTP_U_FOR_DL_DATA_FORWARDING ||
         tunnel->interface_type ==
            OGS_GTP2_F_TEID_SGW_GTP_U_FOR_UL_DATA_FORWARDING))
        return true;

    return false;
}

ogs_pkbuf_t *sgwc_sxa_build_session_establishment_request(
        uint8_t type, sgwc_sess_t *sess)
{
    ogs_pfcp_message_t *pfcp_message = NULL;
    ogs_pfcp_session_establishment_request_t *req = NULL;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_urr_t *urr = NULL;
    ogs_pfcp_qer_t *qer = NULL;
    int i, rv;

    ogs_pfcp_node_id_t node_id;
    ogs_pfcp_f_seid_t f_seid;
    int len;

    sgwc_ue_t *sgwc_ue = NULL;
    ogs_pfcp_user_id_t user_id;
    char user_id_buf[sizeof(ogs_pfcp_user_id_t)];

    ogs_debug("Session Establishment Request");
    ogs_assert(sess);

    pfcp_message = ogs_calloc(1, sizeof(*pfcp_message));
    if (!pfcp_message) {
        ogs_error("ogs_calloc() failed");
        return NULL;
    }

    req = &pfcp_message->pfcp_session_establishment_request;

    /* Node ID */
    rv = ogs_pfcp_sockaddr_to_node_id(&node_id, &len);
    if (rv != OGS_OK) {
        ogs_error("ogs_pfcp_sockaddr_to_node_id() failed");
        ogs_free(pfcp_message);
        return NULL;
    }
    req->node_id.presence = 1;
    req->node_id.data = &node_id;
    req->node_id.len = len;

    /* F-SEID */
    rv = ogs_pfcp_sockaddr_to_f_seid(&f_seid, &len);
    if (rv != OGS_OK) {
        ogs_error("ogs_pfcp_sockaddr_to_f_seid() failed");
        ogs_free(pfcp_message);
        return NULL;
    }
    f_seid.seid = htobe64(sess->sgwc_sxa_seid);
    req->cp_f_seid.presence = 1;
    req->cp_f_seid.data = &f_seid;
    req->cp_f_seid.len = len;

    /* User ID */
    if (sgwc_self()->pfcp_send_user_id) {
        sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
        if (sgwc_ue) {
            memset(&user_id, 0, sizeof(ogs_pfcp_user_id_t));
            if (sgwc_ue->imsi_len) {
                user_id.imsif = 1;
                user_id.imsi_len = sgwc_ue->imsi_len;
                ogs_assert(sgwc_ue->imsi_len <= OGS_MAX_IMSI_LEN);
                memcpy(user_id.imsi, sgwc_ue->imsi, sgwc_ue->imsi_len);
            }
            if (sgwc_ue->msisdn_len) {
                user_id.msisdnf = 1;
                user_id.msisdn_len = sgwc_ue->msisdn_len;
                ogs_assert(sgwc_ue->msisdn_len <= OGS_MAX_MSISDN_LEN);
                memcpy(user_id.msisdn, sgwc_ue->msisdn, sgwc_ue->msisdn_len);
            }

            if (user_id.flags) {
                ogs_pfcp_build_user_id(
                        &req->user_id, &user_id, user_id_buf,
                        sizeof(user_id_buf));
                req->user_id.presence = 1;
            }
        }
    }

    ogs_pfcp_pdrbuf_init();

    /* Create PDR */
    i = 0;
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        ogs_pfcp_build_create_pdr(&req->create_pdr[i], i, pdr);
        i++;
    }

    /* Create FAR */
    i = 0;
    ogs_list_for_each(&sess->pfcp.far_list, far) {
        ogs_pfcp_build_create_far(&req->create_far[i], i, far);
        i++;
    }

    /* Create URR */
    i = 0;
    ogs_list_for_each(&sess->pfcp.urr_list, urr) {
        ogs_pfcp_build_create_urr(&req->create_urr[i], i, urr);
        i++;
    }

    /* Create QER */
    i = 0;
    ogs_list_for_each(&sess->pfcp.qer_list, qer) {
        ogs_pfcp_build_create_qer(&req->create_qer[i], i, qer);
        i++;
    }

    /* Create BAR */
    if (sess->pfcp.bar) {
        ogs_pfcp_build_create_bar(&req->create_bar, sess->pfcp.bar);
    }

    pfcp_message->h.type = type;
    pkbuf = ogs_pfcp_build_msg(pfcp_message);
    ogs_expect(pkbuf);

    ogs_pfcp_pdrbuf_clear();
    ogs_free(pfcp_message);

    return pkbuf;
}

ogs_pkbuf_t *sgwc_sxa_build_bearer_to_modify_list(
        uint8_t type, sgwc_sess_t *sess, ogs_pfcp_xact_t *xact)
{
    ogs_pfcp_message_t *pfcp_message = NULL;
    ogs_pfcp_session_modification_request_t *req = NULL;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    sgwc_tunnel_t *tunnel = NULL;
    sgwc_bearer_t *bearer = NULL;

    int num_of_remove_pdr = 0;
    int num_of_remove_far = 0;
    int num_of_create_pdr = 0;
    int num_of_create_far = 0;
    int num_of_create_urr = 0;
    int num_of_update_pdr = 0;
    int num_of_update_far = 0;

    uint64_t modify_flags = 0;
    int total = 0;

    ogs_debug("Session Modification Request");

    ogs_assert(sess);
    ogs_assert(xact);
    modify_flags = xact->modify_flags;
    ogs_assert(modify_flags);
    ogs_debug("PFCP Session Modification build start: "
            "sess_id=%d xact=%p flags=0x%llx bearer_to_modify_count=%d",
            sess->id, xact, (unsigned long long)modify_flags,
            ogs_list_count(&xact->bearer_to_modify_list));

    pfcp_message = ogs_calloc(1, sizeof(*pfcp_message));
    if (!pfcp_message) {
        ogs_error("ogs_calloc() failed");
        return NULL;
    }

    req = &pfcp_message->pfcp_session_modification_request;

    if (modify_flags & OGS_PFCP_MODIFY_CREATE) {
        ogs_pfcp_pdrbuf_init();
    }

    if ((modify_flags & OGS_PFCP_MODIFY_CREATE) &&
            ogs_global_conf()->parameter.use_upg_vpp == true) {
        ogs_list_for_each_entry(
                &xact->bearer_to_modify_list, bearer, to_modify_node) {
            ogs_list_for_each(&bearer->tunnel_list, tunnel) {
                if (!sgwc_sxa_tunnel_matches_modify(tunnel, modify_flags))
                    continue;

                far = tunnel->far;
                if (far) {
                    ogs_pfcp_build_create_far(
                            &req->create_far[num_of_create_far],
                            num_of_create_far, far);
                    num_of_create_far++;
                } else
                    ogs_assert_if_reached();
            }
        }
    }

    if (modify_flags & OGS_PFCP_MODIFY_CREATE) {
        ogs_list_for_each_entry(
                &xact->bearer_to_modify_list, bearer, to_modify_node) {
            /*
             * A dedicated bearer is installed with two PFCP Session
             * Modifications (UL_ONLY leg then DL_ONLY leg) whose Create PDRs
             * both reference the bearer's single URR. The URR must be created
             * exactly once: the second leg's Create PDR only needs to
             * reference the existing URR ID. Re-sending Create URR for an
             * already-installed URR ID is invalid per TS 29.244 and a strict
             * UPF (e.g. UPG/VPP) rejects the whole modification with cause 73
             * (RULE_CREATION_MODIFICATION_FAILURE), leaving the bearer
             * half-built (PDR/FAR of the second leg never installed).
             */
            if (bearer->urr && !bearer->urr_created) {
                ogs_pfcp_build_create_urr(
                        &req->create_urr[num_of_create_urr],
                        num_of_create_urr, bearer->urr);
                num_of_create_urr++;
                bearer->urr_created = true;
            }
        }
    }

    ogs_list_for_each_entry(
            &xact->bearer_to_modify_list, bearer, to_modify_node) {
        ogs_list_for_each(&bearer->tunnel_list, tunnel) {
            if (sgwc_sxa_tunnel_matches_modify(tunnel, modify_flags)) {

                if (modify_flags & OGS_PFCP_MODIFY_REMOVE) {

                    pdr = tunnel->pdr;
                    if (pdr) {
                        ogs_pfcp_tlv_remove_pdr_t *message =
                            &req->remove_pdr[num_of_remove_pdr];

                        message->presence = 1;
                        message->pdr_id.presence = 1;
                        message->pdr_id.u16 = pdr->id;

                        num_of_remove_pdr++;
                    } else
                        ogs_assert_if_reached();

                    far = tunnel->far;
                    if (far) {
                        ogs_pfcp_tlv_remove_far_t *message =
                            &req->remove_far[num_of_remove_far];

                        message->presence = 1;
                        message->far_id.presence = 1;
                        message->far_id.u32 = far->id;

                        num_of_remove_far++;
                    } else
                        ogs_assert_if_reached();

                } else if (modify_flags & OGS_PFCP_MODIFY_CREATE) {
                    if (ogs_global_conf()->parameter.use_upg_vpp == true) {
                        /* Create-FAR already sent above for UPG/VPP */
                    } else {
                        pdr = tunnel->pdr;
                        if (pdr) {
                            ogs_pfcp_build_create_pdr(
                                    &req->create_pdr[num_of_create_pdr],
                                    num_of_create_pdr, pdr);
                            num_of_create_pdr++;

                            ogs_list_add(&xact->pdr_to_create_list,
                                            &pdr->to_create_node);
                        } else
                            ogs_assert_if_reached();

                        far = tunnel->far;
                        if (far) {
                            ogs_pfcp_build_create_far(
                                    &req->create_far[num_of_create_far],
                                    num_of_create_far, far);

                            num_of_create_far++;
                        } else
                            ogs_assert_if_reached();
                    }
                }

                if (modify_flags & OGS_PFCP_MODIFY_DEACTIVATE) {

                    far = tunnel->far;
                    if (far) {
                        ogs_pfcp_build_update_far_deactivate(
                                &req->update_far[num_of_update_far],
                                num_of_update_far, far);

                        num_of_update_far++;
                        if (tunnel->interface_type ==
                                OGS_GTP2_F_TEID_S5_S8_SGW_GTP_U)
                            sgwc_sess_note_dl_buffering(sess);
                    } else
                        ogs_assert_if_reached();

                } else if (modify_flags & OGS_PFCP_MODIFY_DROP) {

                    far = tunnel->far;
                    if (far) {
                        ogs_pfcp_build_update_far_drop(
                                &req->update_far[num_of_update_far],
                                num_of_update_far, far);

                        num_of_update_far++;
                        if (tunnel->interface_type ==
                                OGS_GTP2_F_TEID_S5_S8_SGW_GTP_U)
                            sgwc_sess_clear_dl_buffering(sess);
                    } else
                        ogs_assert_if_reached();

                } else if (modify_flags & OGS_PFCP_MODIFY_REARM) {

                    /* DROP → BUFF|NOCP: restore DDN/paging reachability */
                    far = tunnel->far;
                    if (far) {
                        ogs_pfcp_build_update_far_deactivate(
                                &req->update_far[num_of_update_far],
                                num_of_update_far, far);

                        num_of_update_far++;
                        if (tunnel->interface_type ==
                                OGS_GTP2_F_TEID_S5_S8_SGW_GTP_U)
                            sgwc_sess_note_dl_buffering(sess);
                    } else
                        ogs_assert_if_reached();

                } else if (modify_flags & OGS_PFCP_MODIFY_ACTIVATE) {

                    far = tunnel->far;
                    if (far) {
                        if (modify_flags & OGS_PFCP_MODIFY_END_MARKER) {
                            far->smreq_flags.send_end_marker_packets = 1;
                        }

                        ogs_pfcp_build_update_far_activate(
                                &req->update_far[num_of_update_far],
                                num_of_update_far, far);

                        num_of_update_far++;

                        /* Clear all FAR flags */
                        tunnel->far->smreq_flags.value = 0;
                        if (tunnel->interface_type ==
                                OGS_GTP2_F_TEID_S5_S8_SGW_GTP_U)
                            sgwc_sess_clear_dl_buffering(sess);
                    } else
                        ogs_assert_if_reached();

                }

                if (modify_flags & OGS_PFCP_MODIFY_OUTER_HEADER_REMOVAL) {
                    /* Update PDR */
                    pdr = tunnel->pdr;
                    if (pdr) {
                        ogs_pfcp_build_update_pdr(
                                &req->update_pdr[num_of_update_pdr],
                                num_of_update_pdr, pdr, modify_flags);
                        num_of_update_pdr++;
                    } else
                        ogs_assert_if_reached();
                }
            }
        }
    }

    if ((modify_flags & OGS_PFCP_MODIFY_CREATE) &&
            ogs_global_conf()->parameter.use_upg_vpp == true) {
        ogs_list_for_each_entry(
                &xact->bearer_to_modify_list, bearer, to_modify_node) {
            ogs_list_for_each(&bearer->tunnel_list, tunnel) {
                if (!sgwc_sxa_tunnel_matches_modify(tunnel, modify_flags))
                    continue;

                pdr = tunnel->pdr;
                if (pdr) {
                    ogs_pfcp_build_create_pdr(
                            &req->create_pdr[num_of_create_pdr],
                            num_of_create_pdr, pdr);
                    num_of_create_pdr++;

                    ogs_list_add(&xact->pdr_to_create_list,
                                    &pdr->to_create_node);
                } else
                    ogs_assert_if_reached();
            }
        }
    }

    total = num_of_remove_pdr + num_of_remove_far + num_of_create_pdr +
            num_of_create_far + num_of_create_urr + num_of_update_pdr +
            num_of_update_far;

    if (!total) {
        ogs_error("PFCP Session Modification build invalid state: "
                "sess_id=%d xact=%p flags=0x%llx remove_pdr=%d remove_far=%d "
                "create_pdr=%d create_far=%d create_urr=%d update_pdr=%d "
                "update_far=%d",
                sess->id, xact, (unsigned long long)modify_flags,
                num_of_remove_pdr, num_of_remove_far,
                num_of_create_pdr, num_of_create_far, num_of_create_urr,
                num_of_update_pdr, num_of_update_far);
        ogs_assert_if_reached();
    }

    pfcp_message->h.type = type;
    pkbuf = ogs_pfcp_build_msg(pfcp_message);
    ogs_expect(pkbuf);

    if (modify_flags & OGS_PFCP_MODIFY_CREATE) {
        ogs_pfcp_pdrbuf_clear();
    }

    ogs_free(pfcp_message);

    return pkbuf;
}

ogs_pkbuf_t *sgwc_sxa_build_session_deletion_request(
        uint8_t type, sgwc_sess_t *sess)
{
    ogs_pfcp_message_t *pfcp_message = NULL;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_debug("Session Deletion Request");
    ogs_assert(sess);

    pfcp_message = ogs_calloc(1, sizeof(*pfcp_message));
    if (!pfcp_message) {
        ogs_error("ogs_calloc() failed");
        return NULL;
    }

    pfcp_message->h.type = type;
    pkbuf = ogs_pfcp_build_msg(pfcp_message);
    ogs_expect(pkbuf);

    ogs_free(pfcp_message);

    return pkbuf;
}
