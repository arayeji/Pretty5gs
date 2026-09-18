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

#include "ogs-sctp.h"
#include <errno.h>
#include <stdint.h>

#include "mme-event.h"
#include "mme-sm.h"
#include "mme-timer.h"
#include "mme-trace.h"
#include "mme-path.h"

#include "sgsap-path.h"
#include "sgsap-io.h"

void mme_sgs_ts6_1_timer_start(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);
    ogs_assert(mme_ue->t_sgs_ts6_1);

    mme_ue->sgs_lu_pending = true;
    mme_ue->sgs_cs_unavailable = false;
    ogs_timer_start(mme_ue->t_sgs_ts6_1,
            mme_timer_cfg(MME_TIMER_SGS_TS6_1)->duration);
}

void mme_sgs_ts6_1_timer_stop(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    mme_ue->sgs_lu_pending = false;
    if (mme_ue->t_sgs_ts6_1)
        ogs_timer_stop(mme_ue->t_sgs_ts6_1);
}

void mme_sgs_mark_vlr_unreliable(mme_vlr_t *vlr)
{
    ogs_assert(vlr);

    /* TS 29.118 5.7.3.1: VLR-Reliable = false for all UEs of this VLR */
    vlr->sgs_reset_gen++;
    if (!vlr->sgs_reset_gen)
        vlr->sgs_reset_gen = 1;

    ogs_info("[SGsAP] RESET-INDICATION: VLR-Reliable=false gen=%u",
            vlr->sgs_reset_gen);
}

void mme_sgs_mark_ue_vlr_reliable(mme_ue_t *mme_ue, const mme_vlr_t *vlr)
{
    ogs_assert(mme_ue);
    if (!vlr)
        return;
    mme_ue->vlr_reliable_gen = vlr->sgs_reset_gen;
}

void mme_sgs_mark_ue_vlr_unreliable(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    /*
     * TS 29.118 5.11.4: VLR-Reliable = false until the next successful
     * SGs Location-Update Accept (which calls mark_ue_vlr_reliable).
     */
    if (mme_ue->csmap && mme_ue->csmap->vlr)
        mme_ue->vlr_reliable_gen = mme_ue->csmap->vlr->sgs_reset_gen - 1;
    else
        mme_ue->vlr_reliable_gen = UINT32_MAX;
}

bool mme_sgs_need_location_update(const mme_ue_t *mme_ue)
{
    if (!mme_ue || !mme_ue->csmap ||
        ogs_global_conf()->parameter.ignore_sgs == true ||
        mme_ue->network_access_mode !=
            OGS_NETWORK_ACCESS_MODE_PACKET_AND_CIRCUIT)
        return false;

    /*
     * TS 29.118 5.2.2.2.1: Combined attach/TAU shall start SGs LU
     * (IMSI attach, LAI change, SGs-NULL, or MME change). Always
     * sending LU on Combined covers those shall-cases.
     */
    if (mme_ue->nas_eps.update.value ==
            OGS_NAS_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING ||
        mme_ue->nas_eps.update.value ==
            OGS_NAS_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING_WITH_IMSI_ATTACH)
        return true;

    /*
     * After RELEASE with cause IMSI unknown / detached-for-non-EPS
     * (5.11.4) the MME is SGs-NULL and must request re-attach for
     * non-EPS. Open5GS cannot send a NAS IMSI-only detach without
     * tearing down EPS, so recover on the next TA/periodic TAU.
     * Do not use "no P-TMSI" alone — that would LU EPS-only UEs.
     */
    if (mme_ue->sgs_reestablish_needed &&
        (mme_ue->nas_eps.update.value ==
            OGS_NAS_EPS_UPDATE_TYPE_TA_UPDATING ||
         mme_ue->nas_eps.update.value ==
            OGS_NAS_EPS_UPDATE_TYPE_PERIODIC_UPDATING))
        return true;

    /*
     * TS 29.118 5.2.2.2.1: if VLR-Reliable is false, the MME may
     * start Location-Update on periodic TAU while the UE is still
     * attached for non-EPS. Combined already always sends LU above.
     */
    if (mme_ue->nas_eps.update.value ==
            OGS_NAS_EPS_UPDATE_TYPE_PERIODIC_UPDATING &&
        MME_CURRENT_P_TMSI_IS_AVAILABLE(mme_ue) &&
        !MME_VLR_RELIABLE(mme_ue))
        return true;

    return false;
}

bool mme_sgs_need_periodic_vlr_refresh(const mme_ue_t *mme_ue)
{
    if (!mme_ue || mme_ue->sgs_lu_pending || mme_ue->sgs_cs_unavailable)
        return false;

    /*
     * Already-associated idle UE: periodic TAU must refresh the VLR
     * implicit-detach timer (T3212). 29.118 5.2.2.2.1 does not require
     * this while VLR-Reliable is true; without it the MSC Purge-MS
     * while the MME still looks registered.
     * Combined / reestablish / !VLR-Reliable already hold TAU for LU.
     */
    if (mme_ue->nas_eps.update.value !=
            OGS_NAS_EPS_UPDATE_TYPE_PERIODIC_UPDATING)
        return false;

    if (!MME_CURRENT_P_TMSI_IS_AVAILABLE(mme_ue))
        return false;

    if (!MME_SGSAP_IS_CONNECTED(mme_ue))
        return false;

    /* Do not start a keep-alive while a P-TMSI realloc is in flight. */
    if (MME_NEXT_P_TMSI_IS_AVAILABLE(mme_ue))
        return false;

    if (mme_sgs_need_location_update(mme_ue))
        return false;

    /* SGs TX already wedged: another LU storm would make it worse. */
    if (mme_ue->csmap && mme_ue->csmap->vlr &&
            mme_ue->csmap->vlr->tx_stall_since)
        return false;

    return true;
}

void mme_sgs_send_periodic_vlr_refresh(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    if (mme_ue->sgs_lu_pending)
        return;

    mme_ue->sgs_lu_refresh = true;
    if (sgsap_send_location_update_request(mme_ue) != OGS_OK) {
        mme_ue->sgs_lu_refresh = false;
        if (ogs_log_guard())
            ogs_warn("[%s] SGs VLR refresh not sent (VLR/SGs unavailable)",
                    mme_ue->imsi_bcd);
    }
}

/*
 * TS 29.118 9.4.1 EPS location update type, selected per 5.2.2.2:
 *   IMSI attach - combined Attach, or combined TAU with IMSI attach.
 *   Normal      - everything else (combined TA/LA updating without
 *                 IMSI attach, and the periodic-TAU T3212 keep-alive).
 *
 * Two cases take IMSI attach even though the UE did not ask for it,
 * because the VLR has no MM context to *update*:
 *
 *   5.11.4 - RELEASE-REQUEST with "IMSI unknown" or "IMSI detached for
 *     non-EPS services" put the association in SGs-NULL. The spec
 *     recovery is a NAS IMSI-detach so the UE re-attaches for non-EPS,
 *     which this MME cannot send without de-registering EPS as well
 *     (see mme_sgs_association_released), so signal the attach on the
 *     SGs leg instead.
 *   5.7.3.1 - after RESET-INDICATION the VLR lost its MM contexts.
 *
 * A Normal LU in those two cases asks the VLR to refresh a record it
 * does not have; whether it then creates one and marks the subscriber
 * IMSI-attached - which is what gates MT CS paging and MT SMS - is
 * MSC-dependent, so do not rely on it.
 */
uint8_t mme_sgs_eps_update_type(const mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    if (mme_ue->nas_eps.type == MME_EPS_TYPE_ATTACH_REQUEST)
        return SGSAP_EPS_UPDATE_IMSI_ATTACH;

    if (mme_ue->nas_eps.type == MME_EPS_TYPE_TAU_REQUEST &&
            mme_ue->nas_eps.update.value ==
                OGS_NAS_EPS_UPDATE_TYPE_COMBINED_TA_LA_UPDATING_WITH_IMSI_ATTACH)
        return SGSAP_EPS_UPDATE_IMSI_ATTACH;

    if (mme_ue->sgs_reestablish_needed || !MME_VLR_RELIABLE(mme_ue))
        return SGSAP_EPS_UPDATE_IMSI_ATTACH;

    return SGSAP_EPS_UPDATE_NORMAL;
}

bool mme_sgs_claim_procedure_lu(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    /*
     * Combined/attach/reestablish LU must drive Attach/TAU Accept.
     *
     * A keep-alive (periodic-TAU T3212 refresh) already in flight can
     * neither be reused nor raced:
     *   - it carries EPS-Update-Type Normal and the pre-procedure LAI,
     *     so a Combined-with-IMSI-attach would never reach the VLR as
     *     an IMSI attach; and
     *   - SGsAP LU Accept carries no transaction id, so if we simply
     *     sent a second LU we could not tell the two Accepts apart:
     *     the keep-alive's Accept would complete the procedure early
     *     and the real one would be dropped as stale, losing any
     *     P-TMSI it reallocated.
     *
     * So serialise instead: let the keep-alive finish, and send the
     * real procedure LU from its Accept handler. One extra round-trip
     * on a rare collision (a Combined procedure arriving inside Ts6-1
     * of a periodic TAU), in exchange for an unambiguous exchange.
     * Ts6-1 is restarted by that second send, so the procedure still
     * gets a full timer. Reject / Ts6-1 timeout clear the flag and
     * fall through to continue_without_cs so nothing hangs.
     */
    if (mme_ue->sgs_lu_refresh) {
        mme_ue->sgs_lu_procedure_deferred = true;
        return false;
    }

    /* A procedure LU is genuinely in flight: wait for its Accept. */
    return !mme_ue->sgs_lu_pending;
}

/*
 * Keep-alive Accept/Reject/timeout with an Attach or TAU parked behind
 * it (see mme_sgs_claim_procedure_lu). Returns true when it has taken
 * over the procedure, i.e. the caller must not also complete it.
 */
bool mme_sgs_resume_deferred_procedure_lu(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    if (!mme_ue->sgs_lu_procedure_deferred)
        return false;

    mme_ue->sgs_lu_procedure_deferred = false;

    /* sgs_lu_refresh is already clear, so this Accept drives the
     * Attach/TAU Accept. */
    if (sgsap_send_location_update_request(mme_ue) != OGS_OK) {
        if (ogs_log_guard())
            ogs_warn("[%s] deferred SGs procedure LU not sent "
                    "(VLR/SGs unavailable); continue without CS",
                    mme_ue->imsi_bcd);
        mme_sgs_continue_without_cs(mme_ue, "sgsap_lu_send_failed");
        return true;
    }

    ogs_info("[%s] SGs keep-alive done; procedure Location-Update "
            "(EPS-Type[%d] update[%d]) sent",
            mme_ue->imsi_bcd, mme_ue->nas_eps.type,
            mme_ue->nas_eps.update.value);
    return true;
}

/*
 * TS 29.118 5.7.3.1 / 5.11.4 left this UE with VLR-Reliable = false
 * (VLR RESET-INDICATION, or RELEASE-REQUEST with IMSI unknown /
 * detached-for-non-EPS). Recovery is otherwise only the next Combined
 * or periodic TAU, i.e. up to a full T3412 (~54 min) with MO SMS
 * refused for every UE on that VLR at once. Re-establish on demand
 * instead, one UE at a time: sgs_lu_pending rate-limits per UE and
 * only UEs that actually try to use CS pay for an LU, so this is not
 * the all-UE signalling storm that 5.7.3.1 warns about.
 */
void mme_sgs_request_vlr_reestablish(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    if (MME_VLR_RELIABLE(mme_ue))
        return;
    if (mme_ue->sgs_lu_pending)
        return;
    if (!MME_SGSAP_IS_CONNECTED(mme_ue))
        return;
    /* SGs TX already wedged: another LU would only deepen the queue. */
    if (mme_ue->csmap && mme_ue->csmap->vlr &&
            mme_ue->csmap->vlr->tx_stall_since)
        return;

    /*
     * Refresh-style: the Accept must only clear VLR-Reliable, never
     * drive an Attach/TAU Accept or a P-TMSI realloc for a UE that is
     * mid-SMS and will not answer a TAU Complete.
     */
    mme_ue->sgs_lu_refresh = true;
    if (sgsap_send_location_update_request(mme_ue) != OGS_OK) {
        mme_ue->sgs_lu_refresh = false;
        if (ogs_log_guard())
            ogs_warn("[%s] SGs re-establish LU not sent "
                    "(VLR/SGs unavailable)", mme_ue->imsi_bcd);
        return;
    }

    ogs_info("[%s] SGs VLR-Reliable=false; re-establish Location-Update "
            "sent on demand", mme_ue->imsi_bcd);
}

void mme_sgs_association_released(mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);

    /*
     * TS 29.118 5.11.4: RELEASE with "IMSI unknown" or
     * "IMSI detached for non-EPS services" — SGs-NULL and
     * VLR-Reliable = false. SMS/no-cause RELEASE must not call this.
     *
     * Do not stop Ts6-1 / sgs_lu_pending: an in-flight Location-Update
     * is the re-establishment. Do not set sgs_cs_unavailable — that
     * would force EPS-only + #18 on the next Combined Accept.
     *
     * Do not send NAS Detach Request (IMSI detach): Detach Accept in
     * this MME de-registers EPS. Combined / sgs_reestablish LU is the
     * 24.301 re-attach path we can complete safely.
     */
    mme_ue_clear_p_tmsi(mme_ue);
    mme_ue->sgs_reestablish_needed = true;
    mme_sgs_mark_ue_vlr_unreliable(mme_ue);

    ogs_info("[%s] SGs association SGs-NULL, VLR-Reliable=false "
            "(re-establish on next TAU%s)",
            mme_ue->imsi_bcd,
            mme_ue->sgs_lu_pending ? ", LU already in flight" : "");
}

int sgsap_open(void)
{
    mme_vlr_t *vlr = NULL;

    ogs_list_for_each(&mme_self()->vlr_list, vlr) {
        mme_event_t e;

        memset(&e, 0, sizeof(e));
        e.vlr = vlr;

        ogs_fsm_init(&vlr->sm, sgsap_state_initial, sgsap_state_final, &e);
    }

    return OGS_OK;
}

void sgsap_close(void)
{
    mme_vlr_t *vlr = NULL;

    ogs_list_for_each(&mme_self()->vlr_list, vlr) {
        mme_event_t e;
        memset(&e, 0, sizeof(e));
        e.vlr = vlr;

        ogs_fsm_fini(&vlr->sm, &e);
    }
}

int sgsap_send(ogs_sock_t *sock, ogs_pkbuf_t *pkbuf, uint16_t stream_no)
{
    int sent;

    ogs_assert(pkbuf);

    if (!sock || sock->fd == INVALID_SOCKET) {
        if (ogs_log_guard())
            ogs_warn("SGsAP send failed: VLR SCTP socket not connected "
                    "(stream[%d] len[%d])",
                    stream_no, pkbuf ? (int)pkbuf->len : 0);
        ogs_pkbuf_free(pkbuf);
        return OGS_NOTFOUND;
    }

    sent = ogs_sctp_sendmsg(sock, pkbuf->data, pkbuf->len,
            NULL, OGS_SCTP_SGSAP_PPID, stream_no);
    if (sent < 0 && ogs_socket_errno_would_block()) {
        /*
         * Send buffer full (EAGAIN). Do not free pkbuf — caller may
         * requeue. Rate-limit the log: under LU/SMS storms this used
         * to flood ERROR for every dropped LU/Service-Request.
         */
        if (ogs_log_guard())
            ogs_warn("SGsAP SCTP send buffer full (EAGAIN) "
                    "len:%d ssn:%d — will retry/drop",
                    (int)pkbuf->len, stream_no);
        return OGS_RETRY;
    }
    if (sent < 0 || sent != pkbuf->len) {
        int err = ogs_socket_errno;
        bool assoc_lost = (err == EPIPE || err == ECONNRESET ||
                err == ENOTCONN || err == ECONNABORTED
#ifdef ESHUTDOWN
                || err == ESHUTDOWN
#endif
                );

        /* Peer reset / we already ABORTed: every Combined LU/SMS would
         * otherwise ERROR until COMM_LOST is processed. */
        if (assoc_lost) {
            if (ogs_log_guard())
                ogs_warn("SGsAP SCTP association down (%d:%s) "
                        "len:%d — drop, reconnect",
                        err, strerror(err), (int)pkbuf->len);
            ogs_pkbuf_free(pkbuf);
            return OGS_NOTFOUND;
        }
        if (ogs_log_guard())
            ogs_warn("ogs_sctp_sendmsg(len:%d,ssn:%d) error (%d:%s)",
                    (int)pkbuf->len, stream_no, err, strerror(err));
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    ogs_pkbuf_free(pkbuf);
    return OGS_OK;
}

static bool sgsap_pkbuf_imsi_bcd(const ogs_pkbuf_t *pkbuf,
        char *imsi_bcd, size_t buflen)
{
    uint8_t *p, *end;

    if (!pkbuf || pkbuf->len < 1 || !imsi_bcd || buflen < 2)
        return false;

    imsi_bcd[0] = '\0';
    p = (uint8_t *)pkbuf->data + 1;
    end = (uint8_t *)pkbuf->data + pkbuf->len;
    while (p + 2 <= end) {
        uint8_t tag = p[0];
        uint8_t len = p[1];
        uint8_t *val = p + 2;

        if (val + len > end)
            break;
        if (tag == SGSAP_IE_IMSI_TYPE) {
            if (!SGSAP_IMSI_LEN_OK(len))
                return false;
            ogs_nas_eps_imsi_to_bcd(
                    (ogs_nas_mobile_identity_imsi_t *)val, len, imsi_bcd);
            return imsi_bcd[0] != '\0';
        }
        p = val + len;
    }
    return false;
}

void sgsap_trace_packet(const char *imsi, const char *dir,
        const ogs_pkbuf_t *pkbuf)
{
    char peeked[OGS_MAX_IMSI_BCD_LEN + 1];
    const char *use = imsi;

    if (!pkbuf || !pkbuf->data || !pkbuf->len)
        return;
    if (!ogs_trace_filter_active())
        return;
    if (!use || !use[0]) {
        if (!sgsap_pkbuf_imsi_bcd(pkbuf, peeked, sizeof(peeked)))
            return;
        use = peeked;
    }
    ogs_trace_packet(use, "sgsap", dir, pkbuf->data, pkbuf->len);
}

int sgsap_send_to_vlr_with_sid(
        mme_vlr_t *vlr, ogs_pkbuf_t *pkbuf, uint16_t stream_no)
{
    ogs_sock_t *sock = NULL;

    ogs_assert(vlr);
    if (vlr->retired) {
        ogs_error("SGsAP not sent: VLR [%s] retired after SIGHUP",
                ogs_sockaddr_to_string_static(vlr->sa_list) ?
                    ogs_sockaddr_to_string_static(vlr->sa_list) : "-");
        if (pkbuf)
            ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }
    if (!pkbuf) {
        ogs_error("sgsap_send_to_vlr_with_sid: no PDU");
        return OGS_ERROR;
    }

    sgsap_trace_packet(NULL, "tx", pkbuf);

    ogs_debug("    StreamNO[%d] VLR-IP[%s]",
            stream_no, ogs_sockaddr_to_string_static(vlr->sa_list));

    /*
     * mme.sgsap_io_thread: hand the PDU to the dedicated VLR send
     * thread. Callers may be UE owner shards (CSFB/SMS with
     * mme.workers > 0) while main tears the VLR socket down; the IO
     * thread re-resolves vlr->sock under mme_ctx_lock so the "socket
     * down" check happens where it cannot race.
     */
    if (sgsap_io_active())
        return sgsap_io_post_send(vlr, pkbuf, stream_no);

    sock = vlr->sock;
    if (!sock || sock->fd == INVALID_SOCKET) {
        if (ogs_log_guard())
            ogs_warn("SGsAP not sent: VLR SCTP down VLR[%s] stream[%d] "
                    "(VLR association lost or not established)",
                ogs_sockaddr_to_string_static(vlr->sa_list) ?
                    ogs_sockaddr_to_string_static(vlr->sa_list) : "-",
                stream_no);
        ogs_pkbuf_free(pkbuf);
        return OGS_NOTFOUND;
    }

    {
        int rv = sgsap_send(sock, pkbuf, stream_no);
        if (rv == OGS_RETRY) {
            /* Sync path has no POLLOUT waiter — drop after the warn. */
            ogs_pkbuf_free(pkbuf);
            return OGS_ERROR;
        }
        if (rv == OGS_NOTFOUND && vlr->sock)
            sgsap_event_push(MME_EVENT_SGSAP_LO_CONNREFUSED,
                    vlr->sock, NULL, NULL, 0, 0);
        return rv;
    }
}

int sgsap_send_to_vlr(mme_ue_t *mme_ue, ogs_pkbuf_t *pkbuf)
{
    mme_csmap_t *csmap = NULL;
    mme_vlr_t *vlr = NULL;

    ogs_assert(pkbuf);

    ogs_assert(mme_ue);
    csmap = mme_ue->csmap;
    if (!csmap) {
        ogs_error("[%s] SGsAP not sent: no CSMAP (no VLR mapping for TAI)",
                mme_log_imsi(mme_ue));
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }
    vlr = csmap->vlr;
    if (!vlr) {
        ogs_error("[%s] SGsAP not sent: CSMAP has no VLR",
                mme_log_imsi(mme_ue));
        ogs_pkbuf_free(pkbuf);
        return OGS_ERROR;
    }

    ogs_debug("    TAI[PLMN_ID:%06x,TAC:%d]",
                ogs_plmn_id_hexdump(&csmap->tai.nas_plmn_id), csmap->tai.tac);
    ogs_debug("    LAI[PLMN_ID:%06x,LAC:%d]",
                ogs_plmn_id_hexdump(&csmap->lai.nas_plmn_id), csmap->lai.lac);

    return sgsap_send_to_vlr_with_sid(vlr, pkbuf, mme_ue->vlr_ostream_id);
}

int sgsap_send_location_update_request(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    if (mme_ue->sgs_lu_refresh)
        ogs_debug("[%s] SGSAP: Location-Update-Request (VLR refresh)",
                mme_ue->imsi_bcd);
    else
        ogs_info("[%s] SGSAP: Location-Update-Request "
                "(EPS-Type[%d] update[%d]%s)",
                mme_ue->imsi_bcd, mme_ue->nas_eps.type,
                mme_ue->nas_eps.update.value,
                mme_ue->sgs_reestablish_needed ? " reestablish" : "");

    pkbuf = sgsap_build_location_update_request(mme_ue);
    if (!pkbuf) {
        ogs_error("sgsap_build_location_update_request() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);
    /* VLR down / TX stall / queue high-water is expected; callers continue
     * without CS. Do not ogs_expect — that floods ERROR on every Combined
     * attach/TAU. */

    if (rv == OGS_OK)
        mme_sgs_ts6_1_timer_start(mme_ue);

    return rv;
}

int sgsap_send_tmsi_reallocation_complete(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] TMSI-REALLOCATION-COMPLETE");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);

    pkbuf = sgsap_build_tmsi_reallocation_complete(mme_ue);
    if (!pkbuf) {
        ogs_error("sgsap_build_tmsi_reallocation_complete() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);

    return rv;
}

int sgsap_send_ue_activity_indication(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] Tx UE-ACTIVITY-IND");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);

    pkbuf = sgsap_build_ue_activity_indication(mme_ue);
    if (!pkbuf) {
        ogs_error("sgsap_build_tmsi_reallocation_complete() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);

    return rv;
}

int sgsap_send_detach_indication(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    pkbuf = sgsap_build_detach_indication(mme_ue);
    if (!pkbuf) {
        ogs_error("sgsap_build_detach_indication() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);

    return rv;
}

int sgsap_send_mo_csfb_indication(mme_ue_t *mme_ue)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] MO-CSFB-INDICATION");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);

    pkbuf = sgsap_build_mo_csfb_indication(mme_ue);
    if (!pkbuf) {
        ogs_error("sgsap_build_mo_csfb_indication() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);

    return rv;
}

int sgsap_send_paging_reject(mme_ue_t *mme_ue, uint8_t sgs_cause)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] PAGING-REJECT");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);

    pkbuf = sgsap_build_paging_reject(
                &mme_ue->nas_mobile_identity_imsi,
                SGSAP_IE_IMSI_LEN, sgs_cause);
    if (!pkbuf) {
        ogs_error("sgsap_build_paging_reject() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);

    return rv;
}

int sgsap_send_service_request(mme_ue_t *mme_ue, uint8_t emm_mode)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] SERVICE-REQUEST");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);
    ogs_debug("    SERVICE_INDICATOR[%d]", mme_ue->service_indicator);
    ogs_debug("    EMM_MODE[%d]", emm_mode);

    pkbuf = sgsap_build_service_request(mme_ue, emm_mode);
    if (!pkbuf) {
        ogs_error("sgsap_build_service_request() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);

    return rv;
}

int sgsap_send_reset_ack(mme_vlr_t *vlr)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(vlr);

    ogs_debug("[SGSAP] RESET-ACK");

    pkbuf = sgsap_build_reset_ack(vlr);
    if (!pkbuf) {
        ogs_error("sgsap_build_reset_ack() failed");
        return OGS_ERROR;
    }
    rv =  sgsap_send_to_vlr_with_sid(vlr, pkbuf, 0);

    return rv;
}

int sgsap_send_uplink_unitdata(mme_ue_t *mme_ue,
        ogs_nas_eps_message_container_t *nas_message_container)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);
    ogs_assert(nas_message_container);

    /*
     * TS 29.118 5.11.2.1: do not tunnel NAS to the VLR while
     * VLR-Reliable is false; the MME must request re-attach for
     * non-EPS instead.
     */
    if (!MME_VLR_RELIABLE(mme_ue)) {
        ogs_info("[%s] SGsAP UPLINK-UNITDATA not sent: "
                "VLR-Reliable=false (TS 29.118 5.11.2.1); "
                "re-establishing SGs now",
                mme_ue->imsi_bcd);
        /*
         * This SM is lost (the UE retransmits at the CM/RP layer), but
         * without this the UE would keep failing until its next TAU.
         */
        mme_sgs_request_vlr_reestablish(mme_ue);
        return OGS_ERROR;
    }

    ogs_debug("[SGSAP] UPLINK-UNITDATA");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);
    ogs_log_hexdump(OGS_LOG_DEBUG,
            nas_message_container->buffer, nas_message_container->length);

    pkbuf = sgsap_build_uplink_unidata(mme_ue, nas_message_container);
    if (!pkbuf) {
        ogs_error("sgsap_build_uplink_unidata() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);

    return rv;
}

int sgsap_send_ue_unreachable(mme_ue_t *mme_ue, uint8_t sgs_cause)
{
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_assert(mme_ue);

    ogs_debug("[SGSAP] UE-UNREACHABLE");
    ogs_debug("    IMSI[%s]", mme_ue->imsi_bcd);
    ogs_debug("    CAUSE[%d]", sgs_cause);

    pkbuf = sgsap_build_ue_unreachable(mme_ue, sgs_cause);
    if (!pkbuf) {
        ogs_error("sgsap_build_ue_unreachable() failed");
        return OGS_ERROR;
    }
    rv = sgsap_send_to_vlr(mme_ue, pkbuf);

    return rv;
}
