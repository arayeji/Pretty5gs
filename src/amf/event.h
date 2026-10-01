/*
 * Copyright (C) 2019-2022 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef AMF_EVENT_H
#define AMF_EVENT_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ogs_nas_5gs_message_s ogs_nas_5gs_message_t;
typedef struct NGAP_NGAP_PDU ogs_ngap_message_t;
typedef long NGAP_ProcedureCode_t;

typedef struct amf_gnb_s amf_gnb_t;
typedef struct ran_ue_s ran_ue_t;
typedef struct amf_ue_s amf_ue_t;
typedef struct amf_sess_s amf_sess_t;
typedef struct amf_bearer_s amf_bearer_t;

typedef enum {
    AMF_EVENT_BASE = OGS_MAX_NUM_OF_PROTO_EVENT,

    AMF_EVENT_NGAP_MESSAGE,
    AMF_EVENT_NGAP_TIMER,
    AMF_EVENT_NGAP_LO_ACCEPT,
    AMF_EVENT_NGAP_LO_SCTP_COMM_UP,
    AMF_EVENT_NGAP_LO_CONNREFUSED,
    /* RX worker confirmed poll removal: main may destroy e->ngap.sock */
    AMF_EVENT_NGAP_RX_SOCK_CLOSED,
    /* RX worker could not watch e->ngap.sock (fd died between accept
     * and watch); main tears the half-created gNB down */
    AMF_EVENT_NGAP_RX_WATCH_FAILED,
    /* IO thread dropped every reference to e->ngap.sock (write queue
     * and POLLOUT); see the close registry in ngap-io.c */
    AMF_EVENT_NGAP_IO_DRAINED,

    AMF_EVENT_5GMM_MESSAGE,
    AMF_EVENT_5GMM_TIMER,
    AMF_EVENT_5GSM_MESSAGE,
    AMF_EVENT_5GSM_TIMER,

    MAX_NUM_OF_AMF_EVENT,

} amf_event_e;

typedef struct amf_event_s {
    ogs_event_t h;

    ogs_pkbuf_t *pkbuf;

    struct {
        ogs_sock_t *sock;
        ogs_sockaddr_t *addr;
        uint16_t max_num_of_istreams;
        uint16_t max_num_of_ostreams;

        NGAP_ProcedureCode_t code;
        ogs_ngap_message_t *message;
        /* message was heap-decoded by an NGAP RX worker; the main loop
         * skips its own decode and frees pdu+struct after dispatch */
        bool rx_decoded;
    } ngap;

    struct {
        uint8_t type;
        ogs_nas_5gs_message_t *message;
    } nas;

    ogs_pool_id_t gnb_id;
    ogs_pool_id_t ran_ue_id;
    ogs_pool_id_t amf_ue_id;
    ogs_pool_id_t sess_id;

    ogs_timer_t *timer;
} amf_event_t;

OGS_STATIC_ASSERT(OGS_EVENT_SIZE >= sizeof(amf_event_t));

amf_event_t *amf_event_new(int id);

const char *amf_event_get_name(amf_event_t *e);

/*
 * amf_main() is the ONLY consumer of ogs_app()->queue. A blocking push
 * from that thread (poll/timer callback) waits on a drain that can
 * never happen. Push through amf_queue_push_main(): it never blocks
 * main and only retries briefly (~20 ms) on other threads.
 *
 * Returns OGS_OK (queued, pollset notified), OGS_RETRY (full; caller
 * frees the event) or OGS_DONE (queue terminated).
 */
void amf_event_mark_main_thread(void);
bool amf_event_on_main_thread(void);
int amf_queue_push_main(void *event);

/* main loop: bracket each dispatch, then drain what it pushed */
void amf_event_dispatch_begin(void);
void amf_event_dispatch_end(void);
void *amf_event_local_pop(void);

/* Terminate the app queue and the side queue; wakes main. */
void amf_event_term(void);

/*
 * NGAP CONNREFUSED side queue: teardowns must not compete with a full
 * NGAP message queue. Duplicates for one sock are coalesced. Init before
 * any RX/IO worker starts; main drains it before the app queue.
 */
void amf_event_ngap_connrefused_init(void);
void amf_event_ngap_connrefused_final(void);
int amf_event_ngap_connrefused_trypop(amf_event_t **e);

/* Push a pre-decoded NGAP message from an RX worker. Takes ownership
 * of addr, pkbuf and pdu (all freed on a full queue). */
void ngap_event_push_decoded(void *sock, ogs_sockaddr_t *addr,
        ogs_pkbuf_t *pkbuf, ogs_ngap_message_t *pdu);

void amf_sctp_event_push(int id,
        void *sock, ogs_sockaddr_t *addr, ogs_pkbuf_t *pkbuf,
        uint16_t max_num_of_istreams, uint16_t max_num_of_ostreams);

#ifdef __cplusplus
}
#endif

#endif /* AMF_EVENT_H */
