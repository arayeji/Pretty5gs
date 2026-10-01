/*
 * Copyright (C) 2026 by Ahmad Raeiji <ahmad.rayeji@gmail.com>
 *
 * This file is part of Open5GS / Pretty5GS.
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

#include "context.h"
#include "smf-workers.h"
#include "sbi-relay.h"

typedef enum {
    MAIN_CALL_PENDING,
    MAIN_CALL_RUNNING,
    MAIN_CALL_DONE,
    MAIN_CALL_ABANDONED,    /* caller gave up; main frees it if it runs */
} main_call_state_e;

typedef struct smf_main_call_s {
    smf_main_call_f fn;
    void *arg;
    main_call_state_e state;    /* call_mutex */
} smf_main_call_t;

static ogs_thread_mutex_t call_mutex;
static ogs_thread_cond_t call_cond;
static bool main_exiting;       /* call_mutex */
static bool relay_initialized;

static bool server_send_hook(
        ogs_sbi_stream_t *stream, ogs_sbi_response_t *response);

void smf_sbi_relay_init(void)
{
    ogs_assert(relay_initialized == false);

    ogs_thread_mutex_init(&call_mutex);
    ogs_thread_cond_init(&call_cond);
    main_exiting = false;
    ogs_sbi_server_set_send_hook(server_send_hook);

    relay_initialized = true;
}

void smf_sbi_relay_final(void)
{
    if (!relay_initialized)
        return;

    ogs_sbi_server_set_send_hook(NULL);
    ogs_thread_cond_destroy(&call_cond);
    ogs_thread_mutex_destroy(&call_mutex);

    relay_initialized = false;
}

bool smf_sbi_on_worker(void)
{
    return smf_workers_active() && ogs_worker_self_id() > 0;
}

/* Blocking push: main never waits on a worker, so it always drains. */
static int push_main_blocking(smf_event_t *e)
{
    int rv;

    if (smf_ctx_lock_held())
        rv = ogs_queue_trypush(ogs_app()->queue, e);
    else
        rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv == OGS_OK)
        ogs_pollset_notify(ogs_app()->pollset);
    return rv;
}

int smf_main_call(smf_main_call_f fn, void *arg)
{
    smf_main_call_t *call = NULL;
    smf_event_t *e = NULL;
    bool exiting;

    ogs_assert(fn);

    if (!smf_sbi_on_worker()) {
        fn(arg);
        return OGS_OK;
    }

    /* main may itself be waiting for that lock */
    ogs_assert(!smf_ctx_lock_held());

    ogs_thread_mutex_lock(&call_mutex);
    exiting = main_exiting;
    ogs_thread_mutex_unlock(&call_mutex);
    if (exiting)
        return OGS_ERROR;

    call = ogs_calloc(1, sizeof(*call));
    ogs_assert(call);
    call->fn = fn;
    call->arg = arg;
    call->state = MAIN_CALL_PENDING;

    e = smf_event_new(SMF_EVT_MAIN_CALL);
    e->h.sbi.data = call;
    if (push_main_blocking(e) != OGS_OK) {
        ogs_error("smf_main_call(): main queue unavailable");
        ogs_event_free(e);
        ogs_free(call);
        return OGS_ERROR;
    }

    ogs_thread_mutex_lock(&call_mutex);
    while (call->state != MAIN_CALL_DONE) {
        if (main_exiting && call->state == MAIN_CALL_PENDING) {
            call->state = MAIN_CALL_ABANDONED;
            ogs_thread_mutex_unlock(&call_mutex);
            return OGS_ERROR;
        }
        ogs_thread_cond_wait(&call_cond, &call_mutex);
    }
    ogs_thread_mutex_unlock(&call_mutex);

    ogs_free(call);
    return OGS_OK;
}

void smf_main_call_shutdown(void)
{
    if (!relay_initialized)
        return;

    ogs_thread_mutex_lock(&call_mutex);
    main_exiting = true;
    ogs_thread_cond_broadcast(&call_cond);
    ogs_thread_mutex_unlock(&call_mutex);
}

void smf_main_call_dispatch(smf_event_t *e)
{
    smf_main_call_t *call = NULL;

    ogs_assert(e);
    call = e->h.sbi.data;
    ogs_assert(call);

    ogs_thread_mutex_lock(&call_mutex);
    if (call->state == MAIN_CALL_ABANDONED) {
        ogs_thread_mutex_unlock(&call_mutex);
        ogs_free(call);
        return;
    }
    call->state = MAIN_CALL_RUNNING;
    ogs_thread_mutex_unlock(&call_mutex);

    call->fn(call->arg);

    ogs_thread_mutex_lock(&call_mutex);
    call->state = MAIN_CALL_DONE;
    ogs_thread_cond_broadcast(&call_cond);
    ogs_thread_mutex_unlock(&call_mutex);
}

/*
 * Server streams belong to smf-main's poll loop: a response built on a
 * worker is sent from main, if the stream still exists by then.
 */
static bool server_send_hook(
        ogs_sbi_stream_t *stream, ogs_sbi_response_t *response)
{
    smf_event_t *e = NULL;

    if (!smf_sbi_on_worker())
        return false;

    ogs_assert(stream);
    ogs_assert(response);

    e = smf_event_new(SMF_EVT_SBI_SEND);
    e->h.sbi.data = stream;
    e->h.sbi.response = response;
    e->sbi_stream_id = ogs_sbi_id_from_stream(stream);
    e->sbi_relayed = true;

    if (push_main_blocking(e) != OGS_OK) {
        ogs_error("SBI response dropped: main queue unavailable");
        smf_event_free(e);
    }

    return true;
}

void smf_sbi_relay_send_dispatch(smf_event_t *e)
{
    ogs_sbi_stream_t *stream = NULL;
    ogs_sbi_response_t *response = NULL;

    ogs_assert(e);
    response = e->h.sbi.response;
    ogs_assert(response);
    e->h.sbi.response = NULL;

    if (e->sbi_stream_id >= OGS_MIN_POOL_ID &&
        e->sbi_stream_id <= OGS_MAX_POOL_ID)
        stream = ogs_sbi_stream_find_by_id(e->sbi_stream_id);

    if (!stream || stream != e->h.sbi.data) {
        ogs_error("STREAM has already been removed [%d]", e->sbi_stream_id);
        ogs_sbi_response_free(response);
        return;
    }

    ogs_expect(true == ogs_sbi_server_send_response(stream, response));
}

static bool str_eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

static int owner_for_supi(const char *supi)
{
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];
    bool imsi_supi = false;
    int owner;

    if (!supi || !*supi)
        return -1;

    owner = smf_ue_owner_shard_by_supi(supi);
    if (owner >= 0)
        return owner;

    /* same hash as an EPC attach of this IMSI */
    memset(imsi_bcd, 0, sizeof(imsi_bcd));
    if (ogs_supi_to_imsi_bcd(supi, imsi_bcd, &imsi_supi) == OGS_OK &&
        imsi_supi == true)
        return smf_shard_for_new_imsi(imsi_bcd);

    return smf_shard_for_new_imsi(supi);
}

/* Shard that must handle a parsed request; -1 = main (node level). */
static int server_request_owner(ogs_sbi_message_t *m)
{
    const char *res0 = m->h.resource.component[0];
    const char *ref = m->h.resource.component[1];
    const char *op = m->h.resource.component[2];

    if (str_eq(m->h.service.name, OGS_SBI_SERVICE_NAME_NSMF_PDUSESSION)) {
        if (!str_eq(m->h.method, OGS_SBI_HTTP_METHOD_POST))
            return -1;

        if (str_eq(res0, OGS_SBI_RESOURCE_NAME_VSMF_PDU_SESSIONS))
            return smf_sess_owner_shard_by_ref(ref);

        if (!str_eq(res0, OGS_SBI_RESOURCE_NAME_SM_CONTEXTS) &&
            !str_eq(res0, OGS_SBI_RESOURCE_NAME_PDU_SESSIONS))
            return -1;

        if (str_eq(op, OGS_SBI_RESOURCE_NAME_MODIFY) ||
            str_eq(op, OGS_SBI_RESOURCE_NAME_RELEASE))
            return smf_sess_owner_shard_by_ref(ref);

        if (str_eq(res0, OGS_SBI_RESOURCE_NAME_SM_CONTEXTS))
            return m->SmContextCreateData ?
                owner_for_supi(m->SmContextCreateData->supi) : -1;

        return m->PduSessionCreateData ?
            owner_for_supi(m->PduSessionCreateData->supi) : -1;
    }

    if (str_eq(m->h.service.name, OGS_SBI_SERVICE_NAME_NSMF_CALLBACK) &&
        str_eq(res0, OGS_SBI_RESOURCE_NAME_SM_POLICY_NOTIFY))
        return smf_sess_owner_shard_by_ref(ref);

    return -1;
}

bool smf_sbi_relay_server_request(smf_event_t *e, ogs_sbi_message_t *message)
{
    smf_event_t *ne = NULL;
    ogs_sbi_stream_t *stream = NULL;
    int owner;

    ogs_assert(e);
    ogs_assert(message);

    if (!smf_workers_active() || e->sbi_relayed)
        return false;

    owner = server_request_owner(message);
    if (owner <= 0 || owner == ogs_worker_self_id())
        return false;

    ne = smf_event_new(OGS_EVENT_SBI_SERVER);
    ne->h.sbi.data = e->h.sbi.data;
    ne->sbi_relayed = true;
    ne->h.sbi.request = ogs_sbi_request_copy(e->h.sbi.request);
    if (ne->h.sbi.request && smf_event_post_shard(owner, ne) == OGS_OK)
        return true;

    ogs_error("SBI request not relayed to shard %d [%s]",
            owner, message->h.uri);
    smf_event_free(ne);

    stream = ogs_sbi_stream_find_by_id(OGS_POINTER_TO_UINT(e->h.sbi.data));
    if (stream)
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_SERVICE_UNAVAILABLE, message,
                "SMF shard busy", NULL, NULL));
    return true;
}

bool smf_sbi_relay_client_response(smf_event_t *e,
        ogs_pool_id_t sess_id, ogs_pool_id_t assoc_stream_id)
{
    smf_event_t *ne = NULL;
    int owner;

    ogs_assert(e);
    ogs_assert(e->h.sbi.response);

    if (!smf_workers_active() || e->sbi_relayed)
        return false;

    owner = smf_sess_owner_shard_by_id(sess_id);
    if (owner <= 0 || owner == ogs_worker_self_id())
        return false;

    /* the owner parses the response again */
    ogs_sbi_header_clear_parsed(&e->h.sbi.response->h);
    ogs_sbi_http_clear_parsed_parts(&e->h.sbi.response->http);

    ne = smf_event_new(OGS_EVENT_SBI_CLIENT);
    ne->h.sbi.response = e->h.sbi.response;
    ne->h.sbi.data = e->h.sbi.data;
    ne->h.sbi.state = e->h.sbi.state;
    ne->sess_id = sess_id;
    ne->sbi_stream_id = assoc_stream_id;
    ne->sbi_relayed = true;
    e->h.sbi.response = NULL;

    /* frees the response on failure */
    smf_event_push_shard(owner, ne);
    return true;
}
