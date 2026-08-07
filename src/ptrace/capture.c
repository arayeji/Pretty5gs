/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Packet capture: libpcap live/replay, AF_PACKET (Linux), PF_RING/DPDK stubs.
 */

#include "capture.h"
#include "capture-ring.h"

#include <pcap/pcap.h>
#include <errno.h>

#ifdef __linux__
#include <sys/socket.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#endif

static bool capture_running;
static ogs_thread_t *cap_threads[PTRACE_MAX_IFACES + 1];
static int num_cap_threads;

typedef struct cap_arg_s {
    int iface_idx;
    char path[PTRACE_MAX_PATH_LEN];
    ptrace_role_e role;
    char iface[PTRACE_MAX_DEV_LEN];
} cap_arg_t;

static cap_arg_t cap_args[PTRACE_MAX_IFACES + 1];

static void enqueue_packet(const uint8_t *data, uint16_t len,
        ogs_time_t ts, ptrace_role_e role, const char *iface)
{
    ptrace_context_t *ctx = ptrace_self();
    ptrace_packet_t *pkt;
    char ref[PTRACE_MAX_REF_LEN];

    if (!data || !len || !capture_running)
        return;
    if (len > PTRACE_MAX_PACKET)
        len = PTRACE_MAX_PACKET;

    pkt = ptrace_packet_alloc();
    if (!pkt) {
        ogs_warn("ptrace packet pool exhausted");
        return;
    }

    pkt->ts = ts ? ts : ogs_time_now();
    pkt->role = role;
    pkt->len = len;
    memcpy(pkt->data, data, len);
    if (iface)
        ogs_cpystrn(pkt->iface, iface, sizeof(pkt->iface));

    ref[0] = '\0';
    ptrace_ring_write(data, len, pkt->ts, ref, sizeof(ref));
    ogs_cpystrn(pkt->packet_ref, ref, sizeof(pkt->packet_ref));

    if (ogs_queue_trypush(ctx->pkt_queue, pkt) != OGS_OK) {
        ptrace_packet_free(pkt);
        return;
    }
    ctx->packets_in++;
}

static void pcap_dispatch_cb(u_char *user, const struct pcap_pkthdr *h,
        const u_char *bytes)
{
    cap_arg_t *arg = (cap_arg_t *)user;
    ogs_time_t ts;

    if (!capture_running || !h || !bytes)
        return;

    ts = ogs_time_from_sec(h->ts.tv_sec) + h->ts.tv_usec;
    enqueue_packet(bytes, (uint16_t)h->caplen, ts, arg->role, arg->iface);
}

static void pcap_thread(void *data)
{
    cap_arg_t *arg = data;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = NULL;

    ogs_assert(arg);

    if (arg->path[0]) {
        p = pcap_open_offline(arg->path, errbuf);
        if (!p) {
            ogs_error("pcap_open_offline(%s): %s", arg->path, errbuf);
            return;
        }
        ogs_info("ptrace replaying PCAP %s role=%s",
                arg->path, ptrace_role_str(arg->role));
    } else {
        p = pcap_open_live(arg->iface, PTRACE_MAX_PACKET, 1, 100, errbuf);
        if (!p) {
            ogs_error("pcap_open_live(%s): %s", arg->iface, errbuf);
            return;
        }
        ogs_info("ptrace live capture on %s role=%s",
                arg->iface, ptrace_role_str(arg->role));
    }

    while (capture_running) {
        int rc = pcap_dispatch(p, 64, pcap_dispatch_cb, (u_char *)arg);
        if (rc < 0) {
            ogs_error("pcap_dispatch: %s", pcap_geterr(p));
            break;
        }
        if (arg->path[0] && rc == 0)
            break; /* EOF on file replay */
        if (rc == 0)
            ogs_usleep(1000);
    }

    pcap_close(p);
}

#ifdef __linux__
static void afpacket_thread(void *data)
{
    cap_arg_t *arg = data;
    int fd = -1;
    struct sockaddr_ll sll;
    struct tpacket_req3 req;
    struct tpacket_block_desc *pbd;
    uint8_t *map = MAP_FAILED;
    unsigned int block_size = 1 << 22;
    unsigned int block_nr = 64;
    unsigned int frame_size = 1 << 11;
    unsigned int i;
    int pkt_ver = TPACKET_V3;

    ogs_assert(arg);

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        ogs_error("AF_PACKET socket: %s", strerror(errno));
        return;
    }

    memset(&req, 0, sizeof(req));
    req.tp_block_size = block_size;
    req.tp_block_nr = block_nr;
    req.tp_frame_size = frame_size;
    req.tp_frame_nr = (block_size * block_nr) / frame_size;
    req.tp_retire_blk_tov = 60;

    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION,
            &pkt_ver, sizeof(pkt_ver)) < 0) {
        ogs_error("PACKET_VERSION: %s", strerror(errno));
        goto done;
    }
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        ogs_error("PACKET_RX_RING: %s", strerror(errno));
        goto done;
    }

    map = mmap(NULL, (size_t)req.tp_block_size * req.tp_block_nr,
            PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        ogs_error("mmap AF_PACKET: %s", strerror(errno));
        goto done;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(arg->iface);
    if (!sll.sll_ifindex) {
        ogs_error("if_nametoindex(%s) failed", arg->iface);
        goto done;
    }
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        ogs_error("AF_PACKET bind: %s", strerror(errno));
        goto done;
    }

    ogs_info("ptrace AF_PACKET on %s role=%s",
            arg->iface, ptrace_role_str(arg->role));

    i = 0;
    while (capture_running) {
        pbd = (struct tpacket_block_desc *)(map + i * block_size);
        if ((pbd->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
            ogs_usleep(1000);
            continue;
        }

        {
            struct tpacket3_hdr *ppd =
                (struct tpacket3_hdr *)((uint8_t *)pbd +
                        pbd->hdr.bh1.offset_to_first_pkt);
            unsigned int j;
            for (j = 0; j < pbd->hdr.bh1.num_pkts; j++) {
                uint8_t *bytes = (uint8_t *)ppd + ppd->tp_mac;
                uint16_t len = ppd->tp_snaplen;
                ogs_time_t ts = ogs_time_from_sec(ppd->tp_sec) +
                        ppd->tp_nsec / 1000;
                enqueue_packet(bytes, len, ts, arg->role, arg->iface);
                ppd = (struct tpacket3_hdr *)((uint8_t *)ppd +
                        ppd->tp_next_offset);
            }
        }

        pbd->hdr.bh1.block_status = TP_STATUS_KERNEL;
        i = (i + 1) % block_nr;
    }

done:
    if (map != MAP_FAILED)
        munmap(map, (size_t)block_size * block_nr);
    if (fd >= 0)
        close(fd);
}
#endif

int ptrace_capture_open(void)
{
    ptrace_context_t *ctx = ptrace_self();
    int i;

    capture_running = true;
    num_cap_threads = 0;

    if (ctx->backend == PTRACE_BACKEND_PFRING ||
            ctx->backend == PTRACE_BACKEND_DPDK) {
        ogs_warn("ptrace backend %d not implemented; falling back to pcap",
                (int)ctx->backend);
        ctx->backend = PTRACE_BACKEND_PCAP;
    }

    if (ctx->pcap_file[0]) {
        cap_arg_t *arg = &cap_args[0];
        memset(arg, 0, sizeof(*arg));
        ogs_cpystrn(arg->path, ctx->pcap_file, sizeof(arg->path));
        arg->role = ctx->num_ifaces ? ctx->ifaces[0].role :
                PTRACE_ROLE_UNKNOWN;
        ogs_cpystrn(arg->iface, "pcap", sizeof(arg->iface));
        cap_threads[0] = ogs_thread_create(pcap_thread, arg);
        if (!cap_threads[0])
            return OGS_ERROR;
        num_cap_threads = 1;
        return OGS_OK;
    }

    if (ctx->num_ifaces == 0) {
        ogs_warn("ptrace: no capture interfaces configured");
        return OGS_OK;
    }

    for (i = 0; i < ctx->num_ifaces; i++) {
        cap_arg_t *arg = &cap_args[i];
        memset(arg, 0, sizeof(*arg));
        arg->iface_idx = i;
        arg->role = ctx->ifaces[i].role;
        ogs_cpystrn(arg->iface, ctx->ifaces[i].dev, sizeof(arg->iface));

        if (ctx->backend == PTRACE_BACKEND_AFPACKET) {
#ifdef __linux__
            cap_threads[i] = ogs_thread_create(afpacket_thread, arg);
#else
            ogs_warn("AF_PACKET unavailable; using libpcap for %s",
                    arg->iface);
            cap_threads[i] = ogs_thread_create(pcap_thread, arg);
#endif
        } else {
            cap_threads[i] = ogs_thread_create(pcap_thread, arg);
        }

        if (!cap_threads[i])
            return OGS_ERROR;
        num_cap_threads++;
    }

    return OGS_OK;
}

void ptrace_capture_close(void)
{
    int i;

    capture_running = false;
    for (i = 0; i < num_cap_threads; i++) {
        if (cap_threads[i]) {
            ogs_thread_destroy(cap_threads[i]);
            cap_threads[i] = NULL;
        }
    }
    num_cap_threads = 0;
}
