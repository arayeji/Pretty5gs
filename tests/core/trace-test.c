/*
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

#include "ogs-core.h"
#include "core/abts.h"

#define TEST_IMSI "001010123456789"

static char log_path[64];
static ogs_log_t *log_sink;

static void capture_begin(void)
{
    ogs_snprintf(log_path, sizeof(log_path),
            "/tmp/ogs-trace-test-%d.log", (int)getpid());
    unlink(log_path);
    log_sink = ogs_log_add_file(log_path);
}

/* Returns a heap copy of everything logged since capture_begin(). */
static char *capture_end(void)
{
    FILE *fp;
    long size;
    char *buf;

    ogs_log_remove(log_sink);
    log_sink = NULL;

    fp = fopen(log_path, "r");
    if (!fp)
        return NULL;
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buf = ogs_calloc(1, size + 1);
    if (buf && size > 0 && fread(buf, 1, size, fp) != (size_t)size)
        buf[0] = '\0';
    fclose(fp);
    unlink(log_path);

    return buf;
}

static void addr4(ogs_sockaddr_t *a, const char *ip, uint16_t port)
{
    memset(a, 0, sizeof(*a));
    a->sin.sin_family = AF_INET;
    a->sin.sin_port = htobe16(port);
    inet_pton(AF_INET, ip, &a->sin.sin_addr);
}

static void addr6(ogs_sockaddr_t *a, const char *ip, uint16_t port)
{
    memset(a, 0, sizeof(*a));
    a->sin6.sin6_family = AF_INET6;
    a->sin6.sin6_port = htobe16(port);
    inet_pton(AF_INET6, ip, &a->sin6.sin6_addr);
}

static void test_link_inactive(abts_case *tc, void *data)
{
    ogs_trace_link_t link;
    ogs_sockaddr_t local, remote;

    ogs_trace_filter_clear();
    addr4(&local, "192.0.2.1", 2123);
    addr4(&remote, "192.0.2.2", 2123);

    ogs_trace_link_set(&link, OGS_TRACE_L4_UDP, &local, &remote);
    ABTS_INT_EQUAL(tc, OGS_TRACE_L4_NONE, link.l4);
    ABTS_STR_EQUAL(tc, "", link.local);
}

static void test_udp_direction(abts_case *tc, void *data)
{
    ogs_trace_link_t link;
    ogs_sockaddr_t local, remote;
    char *out;

    ogs_trace_filter_clear();
    ogs_trace_filter_add_ex(TEST_IMSI, true);
    addr4(&local, "192.0.2.1", 2123);
    addr4(&remote, "192.0.2.2", 2124);
    ogs_trace_link_set(&link, OGS_TRACE_L4_UDP, &local, &remote);
    ABTS_STR_EQUAL(tc, "192.0.2.1:2123", link.local);
    ABTS_STR_EQUAL(tc, "192.0.2.2:2124", link.remote);

    capture_begin();
    ogs_trace_packet_link(TEST_IMSI, "gtp", "tx", "\x48\x20", 2, &link);
    ogs_trace_packet_link(TEST_IMSI, "gtp", "rx", "\x48\x21", 2, &link);
    ogs_trace_packet_link("001019999999999", "gtp", "tx", "\x01", 1, &link);
    out = capture_end();
    ABTS_PTR_NOTNULL(tc, out);

    ABTS_PTR_NOTNULL(tc, strstr(out, "[IMSI:" TEST_IMSI "] PACKET: "
            "proto=gtp dir=tx len=2 ts="));
    ABTS_PTR_NOTNULL(tc, strstr(out,
            " l4=udp src=192.0.2.1:2123 dst=192.0.2.2:2124 b64=SCA="));
    ABTS_PTR_NOTNULL(tc, strstr(out,
            " l4=udp src=192.0.2.2:2124 dst=192.0.2.1:2123 b64=SCE="));
    ABTS_TRUE(tc, strstr(out, "001019999999999") == NULL);
    ABTS_TRUE(tc, strstr(out, " sid=") == NULL);
    ogs_free(out);

    ogs_trace_filter_clear();
}

static void test_sctp_ipv6(abts_case *tc, void *data)
{
    ogs_trace_link_t link;
    ogs_sockaddr_t local, remote;
    char *out;

    ogs_trace_filter_clear();
    ogs_trace_filter_add_ex(TEST_IMSI, true);
    addr6(&local, "2001:db8::1", 36412);
    addr6(&remote, "2001:db8::2", 40000);
    ogs_trace_link_set(&link, OGS_TRACE_L4_SCTP, &local, &remote);
    link.sctp_stream_present = true;
    link.sctp_stream = 3;
    link.sctp_ppid = 18;

    capture_begin();
    ogs_trace_packet_link(TEST_IMSI, "s1ap", "rx", "\x00", 1, &link);
    out = capture_end();
    ABTS_PTR_NOTNULL(tc, out);
    ABTS_PTR_NOTNULL(tc, strstr(out, " l4=sctp src=[2001:db8::2]:40000 "
            "dst=[2001:db8::1]:36412 sid=3 ppid=18 b64=AA=="));
    ogs_free(out);

    ogs_trace_filter_clear();
}

static void test_no_link(abts_case *tc, void *data)
{
    char *out;

    ogs_trace_filter_clear();
    ogs_trace_filter_add_ex(TEST_IMSI, true);

    capture_begin();
    ogs_trace_packet(TEST_IMSI, "nas", "rx", "\x07", 1);
    out = capture_end();
    ABTS_PTR_NOTNULL(tc, out);
    ABTS_PTR_NOTNULL(tc, strstr(out, "proto=nas dir=rx len=1 ts="));
    ABTS_TRUE(tc, strstr(out, " l4=") == NULL);
    ABTS_PTR_NOTNULL(tc, strstr(out, " b64=Bw=="));
    ogs_free(out);

    ogs_trace_filter_clear();
}

static void test_segments(abts_case *tc, void *data)
{
    size_t len = 2 * OGS_TRACE_PACKET_SEG + 100;
    uint8_t *pkt = ogs_calloc(1, len);
    char *out, *p;
    int lines = 0;
    char expect[64];

    ogs_trace_filter_clear();
    ogs_trace_filter_add_ex(TEST_IMSI, true);

    capture_begin();
    ogs_trace_packet(TEST_IMSI, "pfcp", "tx", pkt, len);
    out = capture_end();
    ABTS_PTR_NOTNULL(tc, out);

    for (p = out; (p = strstr(p, "PACKET: ")) != NULL; p++)
        lines++;
    ABTS_INT_EQUAL(tc, 3, lines);

    ogs_snprintf(expect, sizeof(expect), "len=%zu", len);
    ABTS_PTR_NOTNULL(tc, strstr(out, expect));
    ABTS_PTR_NOTNULL(tc, strstr(out, " seg=1/3 off=0 "));
    ogs_snprintf(expect, sizeof(expect), " seg=3/3 off=%d ",
            2 * OGS_TRACE_PACKET_SEG);
    ABTS_PTR_NOTNULL(tc, strstr(out, expect));
    ABTS_TRUE(tc, strstr(out, "trunc=1") == NULL);
    ogs_free(out);
    ogs_free(pkt);

    ogs_trace_filter_clear();
}

static void test_bound_rx_keeps_link(abts_case *tc, void *data)
{
    ogs_trace_link_t link;
    ogs_sockaddr_t local, remote;
    char *out, *p;

    ogs_trace_filter_clear();
    ogs_trace_filter_add_ex(TEST_IMSI, true);
    addr4(&local, "192.0.2.1", 8805);
    addr4(&remote, "192.0.2.9", 8805);
    ogs_trace_link_set(&link, OGS_TRACE_L4_UDP, &local, &remote);

    capture_begin();
    ogs_trace_packet_bind_rx_link("pfcp", "\x21\x32", 2, &link);
    ogs_trace_packet_on_imsi(TEST_IMSI);
    ogs_trace_packet_on_imsi(TEST_IMSI);
    out = capture_end();
    ABTS_PTR_NOTNULL(tc, out);
    ABTS_PTR_NOTNULL(tc, strstr(out, "proto=pfcp dir=rx len=2 ts="));
    ABTS_PTR_NOTNULL(tc, strstr(out,
            " l4=udp src=192.0.2.9:8805 dst=192.0.2.1:8805 b64=ITI="));
    p = strstr(out, "PACKET: ");
    ABTS_TRUE(tc, p && strstr(p + 1, "PACKET: ") == NULL);
    ogs_free(out);

    ogs_trace_filter_clear();
}

abts_suite *test_trace(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, test_link_inactive, NULL);
    abts_run_test(suite, test_udp_direction, NULL);
    abts_run_test(suite, test_sctp_ipv6, NULL);
    abts_run_test(suite, test_no_link, NULL);
    abts_run_test(suite, test_segments, NULL);
    abts_run_test(suite, test_bound_rx_keeps_link, NULL);

    return suite;
}
