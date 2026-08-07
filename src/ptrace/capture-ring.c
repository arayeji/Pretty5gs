/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Disk-backed rotating PCAP ring for raw packet retrieval.
 */

#include "capture-ring.h"

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#define PTRACE_RING_FILES       8
#define PCAP_MAGIC              0xa1b2c3d4

typedef struct pcap_hdr_s {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

static struct {
    bool open;
    char dir[PTRACE_MAX_PATH_LEN];
    int size_gb;
    int cur_idx;
    uint64_t cur_bytes;
    uint64_t max_bytes;
    FILE *fp;
    ogs_thread_mutex_t lock;
} ring;

static void ring_path(char *buf, size_t buflen, int idx)
{
    snprintf(buf, buflen, "%s/ring-%02d.pcap", ring.dir, idx);
}

static int ring_open_file(int idx)
{
    char path[PTRACE_MAX_PATH_LEN];
    pcap_hdr_t hdr;

    ring_path(path, sizeof(path), idx);
    ring.fp = fopen(path, "wb");
    if (!ring.fp) {
        ogs_error("ptrace ring open failed: %s (%s)", path, strerror(errno));
        return OGS_ERROR;
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = PCAP_MAGIC;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.snaplen = PTRACE_MAX_PACKET;
    hdr.network = 1; /* Ethernet */
    if (fwrite(&hdr, 1, sizeof(hdr), ring.fp) != sizeof(hdr)) {
        ogs_error("ptrace ring write header failed");
        fclose(ring.fp);
        ring.fp = NULL;
        return OGS_ERROR;
    }

    ring.cur_idx = idx;
    ring.cur_bytes = sizeof(hdr);
    return OGS_OK;
}

int ptrace_ring_open(const char *path, int size_gb)
{
    memset(&ring, 0, sizeof(ring));
    if (!path || !path[0])
        return OGS_ERROR;

    ogs_cpystrn(ring.dir, path, sizeof(ring.dir));
    ring.size_gb = size_gb > 0 ? size_gb : 2;
    ring.max_bytes = ((uint64_t)ring.size_gb * 1024ULL * 1024ULL * 1024ULL) /
            PTRACE_RING_FILES;
    if (ring.max_bytes < 16 * 1024 * 1024)
        ring.max_bytes = 16 * 1024 * 1024;

    if (mkdir(ring.dir, 0755) < 0 && errno != EEXIST) {
        ogs_warn("ptrace ring mkdir %s: %s (will retry on write)",
                ring.dir, strerror(errno));
    }

    ogs_thread_mutex_init(&ring.lock);
    if (ring_open_file(0) != OGS_OK)
        return OGS_ERROR;

    ring.open = true;
    ogs_info("ptrace PCAP ring at %s (%d GB)", ring.dir, ring.size_gb);
    return OGS_OK;
}

void ptrace_ring_close(void)
{
    if (!ring.open)
        return;
    ogs_thread_mutex_lock(&ring.lock);
    if (ring.fp) {
        fclose(ring.fp);
        ring.fp = NULL;
    }
    ogs_thread_mutex_unlock(&ring.lock);
    ogs_thread_mutex_destroy(&ring.lock);
    ring.open = false;
}

int ptrace_ring_write(const uint8_t *data, uint16_t len, ogs_time_t ts,
        char *ref_out, size_t ref_len)
{
    pcaprec_hdr_t rec;
    long offset;
    int rv = OGS_OK;

    if (!ring.open || !data || !len)
        return OGS_ERROR;

    ogs_thread_mutex_lock(&ring.lock);

    if (!ring.fp ||
            ring.cur_bytes + sizeof(rec) + len > ring.max_bytes) {
        if (ring.fp) {
            fclose(ring.fp);
            ring.fp = NULL;
        }
        if (ring_open_file((ring.cur_idx + 1) % PTRACE_RING_FILES) != OGS_OK) {
            rv = OGS_ERROR;
            goto out;
        }
    }

    offset = ftell(ring.fp);
    memset(&rec, 0, sizeof(rec));
    rec.ts_sec = (uint32_t)ogs_time_sec(ts);
    rec.ts_usec = (uint32_t)ogs_time_usec(ts);
    rec.incl_len = len;
    rec.orig_len = len;

    if (fwrite(&rec, 1, sizeof(rec), ring.fp) != sizeof(rec) ||
            fwrite(data, 1, len, ring.fp) != len) {
        rv = OGS_ERROR;
        goto out;
    }

    ring.cur_bytes += sizeof(rec) + len;
    if (ref_out && ref_len)
        snprintf(ref_out, ref_len, "%d:%ld:%u",
                ring.cur_idx, offset, (unsigned)len);

out:
    ogs_thread_mutex_unlock(&ring.lock);
    return rv;
}

int ptrace_ring_export(const char *const *refs, int nrefs,
        const char *out_path)
{
    FILE *out = NULL;
    pcap_hdr_t hdr;
    int i;

    if (!refs || nrefs <= 0 || !out_path)
        return OGS_ERROR;

    out = fopen(out_path, "wb");
    if (!out)
        return OGS_ERROR;

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = PCAP_MAGIC;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.snaplen = PTRACE_MAX_PACKET;
    hdr.network = 1;
    fwrite(&hdr, 1, sizeof(hdr), out);

    for (i = 0; i < nrefs; i++) {
        int idx = 0;
        long offset = 0;
        unsigned len = 0;
        char path[PTRACE_MAX_PATH_LEN];
        FILE *in;
        uint8_t buf[PTRACE_MAX_PACKET + sizeof(pcaprec_hdr_t)];
        size_t need;

        if (sscanf(refs[i], "%d:%ld:%u", &idx, &offset, &len) != 3)
            continue;
        if (len > PTRACE_MAX_PACKET)
            continue;

        ring_path(path, sizeof(path), idx);
        in = fopen(path, "rb");
        if (!in)
            continue;
        if (fseek(in, offset, SEEK_SET) != 0) {
            fclose(in);
            continue;
        }
        need = sizeof(pcaprec_hdr_t) + len;
        if (fread(buf, 1, need, in) == need)
            fwrite(buf, 1, need, out);
        fclose(in);
    }

    fclose(out);
    return OGS_OK;
}
