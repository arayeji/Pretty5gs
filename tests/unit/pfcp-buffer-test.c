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

/*
 * DL buffering / DROBU state machine of the UP function
 * (TS 23.401 5.3.4.3, TS 29.244 5.2.3.1 / 5.2.4.3 / 8.2.104):
 *
 *  - BUFF|NOCP FAR buffers and reports ONLY the first buffered packet
 *  - BAR Suggested Buffering Packets Count caps the per-FAR buffer
 *  - DROBU discards the buffered packets WITHOUT changing Apply Action
 *    and re-arms the first-packet Downlink Data Report
 *  - DROP FAR silently discards and never buffers or reports
 */

#include "ogs-pfcp.h"
#include "core/abts.h"

typedef struct test_ctx_s {
    ogs_pfcp_sess_t sess;
    ogs_pfcp_bar_t bar;
    ogs_pfcp_far_t far;
    ogs_pfcp_pdr_t pdr;
} test_ctx_t;

static void test_ctx_init(test_ctx_t *t, uint8_t sbpc)
{
    memset(t, 0, sizeof(*t));

    ogs_list_init(&t->sess.far_list);
    ogs_list_add(&t->sess.far_list, &t->far);

    if (sbpc) {
        t->bar.suggested_buffering_packets_count = sbpc;
        t->sess.bar = &t->bar;
    }

    t->far.sess = &t->sess;
    t->far.apply_action =
        OGS_PFCP_APPLY_ACTION_BUFF | OGS_PFCP_APPLY_ACTION_NOCP;
    t->far.dst_if = OGS_PFCP_INTERFACE_ACCESS;
    /* far.gnode == NULL: not yet activated, the buffering path */

    t->pdr.far = &t->far;
    t->pdr.src_if = OGS_PFCP_INTERFACE_CORE;
}

static void test_ctx_fini(test_ctx_t *t)
{
    ogs_pfcp_far_drop_buffered_gtpu(&t->far);
}

static ogs_pkbuf_t *test_dl_packet(void)
{
    ogs_pkbuf_t *pkbuf = ogs_pkbuf_alloc(NULL, 200);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, 100);
    ogs_pkbuf_put(pkbuf, 60);
    memset(pkbuf->data, 0xab, 60);
    return pkbuf;
}

static bool test_deliver(test_ctx_t *t, ogs_pfcp_user_plane_report_t *report)
{
    return ogs_pfcp_up_handle_pdr(&t->pdr, OGS_GTPU_MSGTYPE_GPDU, 60,
            NULL, test_dl_packet(), report);
}

/* First buffered packet raises a Downlink Data Report; later ones do not */
static void test_buff_first_packet_reports(abts_case *tc, void *data)
{
    test_ctx_t t;
    ogs_pfcp_user_plane_report_t report;

    test_ctx_init(&t, 0);

    ABTS_TRUE(tc, test_deliver(&t, &report));
    ABTS_INT_EQUAL(tc, 1, report.type.downlink_data_report);
    ABTS_INT_EQUAL(tc, 1, t.far.num_of_buffered_gtpu);

    ABTS_TRUE(tc, test_deliver(&t, &report));
    ABTS_INT_EQUAL(tc, 0, report.type.downlink_data_report);
    ABTS_INT_EQUAL(tc, 2, t.far.num_of_buffered_gtpu);

    test_ctx_fini(&t);
}

/* BAR Suggested Buffering Packets Count is enforced as the buffer cap */
static void test_bar_sbpc_cap(abts_case *tc, void *data)
{
    test_ctx_t t;
    ogs_pfcp_user_plane_report_t report;
    int i;

    test_ctx_init(&t, 2);

    for (i = 0; i < 5; i++)
        ABTS_TRUE(tc, test_deliver(&t, &report));

    ABTS_INT_EQUAL(tc, 2, t.far.num_of_buffered_gtpu);

    test_ctx_fini(&t);
}

/* Without a BAR the historical 64-packet cap still applies */
static void test_default_cap(abts_case *tc, void *data)
{
    test_ctx_t t;
    ogs_pfcp_user_plane_report_t report;
    int i;

    test_ctx_init(&t, 0);

    for (i = 0; i < OGS_MAX_NUM_OF_GTPU_BUFFER + 10; i++)
        ABTS_TRUE(tc, test_deliver(&t, &report));

    ABTS_INT_EQUAL(tc, OGS_MAX_NUM_OF_GTPU_BUFFER,
            t.far.num_of_buffered_gtpu);

    test_ctx_fini(&t);
}

/*
 * DROBU: discards buffered packets, keeps Apply Action, re-arms the
 * first-packet report so a post-paging-failure DL packet pages again
 */
static void test_drobu_rearms_report(abts_case *tc, void *data)
{
    test_ctx_t t;
    ogs_pfcp_user_plane_report_t report;
    int dropped;

    test_ctx_init(&t, 0);

    ABTS_TRUE(tc, test_deliver(&t, &report));
    ABTS_TRUE(tc, test_deliver(&t, &report));
    ABTS_INT_EQUAL(tc, 2, t.far.num_of_buffered_gtpu);

    dropped = ogs_pfcp_sess_drop_buffered_gtpu(&t.sess);
    ABTS_INT_EQUAL(tc, 2, dropped);
    ABTS_INT_EQUAL(tc, 0, t.far.num_of_buffered_gtpu);
    ABTS_TRUE(tc, t.far.apply_action ==
            (OGS_PFCP_APPLY_ACTION_BUFF | OGS_PFCP_APPLY_ACTION_NOCP));

    /* next DL packet buffers again AND reports again */
    ABTS_TRUE(tc, test_deliver(&t, &report));
    ABTS_INT_EQUAL(tc, 1, report.type.downlink_data_report);
    ABTS_INT_EQUAL(tc, 1, t.far.num_of_buffered_gtpu);

    test_ctx_fini(&t);
}

/* DROP FAR: packet freed, no buffering, no report */
static void test_drop_action_discards(abts_case *tc, void *data)
{
    test_ctx_t t;
    ogs_pfcp_user_plane_report_t report;

    test_ctx_init(&t, 0);
    t.far.apply_action = OGS_PFCP_APPLY_ACTION_DROP;

    ABTS_TRUE(tc, test_deliver(&t, &report));
    ABTS_INT_EQUAL(tc, 0, report.type.downlink_data_report);
    ABTS_INT_EQUAL(tc, 0, t.far.num_of_buffered_gtpu);

    test_ctx_fini(&t);
}

abts_suite *test_pfcp_buffer(abts_suite *suite)
{
    suite = ADD_SUITE(suite);

    abts_run_test(suite, test_buff_first_packet_reports, NULL);
    abts_run_test(suite, test_bar_sbpc_cap, NULL);
    abts_run_test(suite, test_default_cap, NULL);
    abts_run_test(suite, test_drobu_rearms_report, NULL);
    abts_run_test(suite, test_drop_action_discards, NULL);

    return suite;
}
