/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 *
 * Disk-backed rotating PCAP ring for raw packet retrieval.
 * Writes run on a dedicated thread so decode workers never block on I/O.
 */

#include "capture-ring.h"
#include "context.h"
#include "identity.h"
#include "correlate.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#define PTRACE_RING_FILES       8
#define PTRACE_RING_SUFFIX_LEN  32  /* "/ring-00.pcap" + margin */
#define PTRACE_RING_PATH_LEN    (PTRACE_MAX_PATH_LEN + PTRACE_RING_SUFFIX_LEN)
#define PTRACE_RING_Q_SIZE      32768
#define PTRACE_RING_REF_MAP_MAX 65536
#define PTRACE_RING_BOOT_FILES  2
#define PCAP_MAGIC              0xa1b2c3d4

static int mkdir_p(const char *path)
{
    char *copy, *p;
    int rc = OGS_OK;

    if (!path || !*path)
        return OGS_ERROR;

    copy = ogs_strdup(path);
    if (!copy)
        return OGS_ERROR;

    for (p = copy + 1; *p; p++) {
        if (*p == '/') {
            char saved = *p;
            *p = '\0';
            if (mkdir(copy, 0755) != 0 && errno != EEXIST) {
                rc = OGS_ERROR;
                *p = saved;
                break;
            }
            *p = saved;
        }
    }
    if (rc == OGS_OK && mkdir(copy, 0755) != 0 && errno != EEXIST)
        rc = OGS_ERROR;

    ogs_free(copy);
    return rc;
}

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

typedef struct ring_item_s {
    ogs_lnode_t lnode;
    uint64_t seq;
    ogs_time_t ts;
    uint16_t len;
    uint8_t data[PTRACE_MAX_PACKET];
} ring_item_t;

typedef struct ring_ref_s {
    uint64_t seq;
    char ref[PTRACE_MAX_REF_LEN];
} ring_ref_t;

static OGS_POOL(ring_item_pool, ring_item_t);

static struct {
    bool open;
    char dir[PTRACE_MAX_PATH_LEN];
    int size_gb;
    int cur_idx;
    uint64_t cur_bytes;
    uint64_t max_bytes;
    FILE *fp;
    ogs_thread_mutex_t lock;

    ogs_queue_t *q;
    ogs_thread_t *writer;
    bool writer_running;
    ogs_thread_mutex_t pool_lock;
    uint64_t next_seq;
    uint64_t written;
    uint64_t q_drop;

    ogs_hash_t *ref_by_seq;
    ogs_thread_mutex_t ref_lock;
    uint64_t ref_count;
} ring;

static int ring_path(char *buf, size_t buflen, int idx)
{
    int n;

    if (!buf || buflen < PTRACE_RING_SUFFIX_LEN)
        return OGS_ERROR;

    n = snprintf(buf, buflen, "%s/ring-%02d.pcap", ring.dir, idx);
    if (n < 0 || (size_t)n >= buflen) {
        ogs_error("ptrace ring path too long (dir=%s idx=%d)",
                ring.dir, idx);
        return OGS_ERROR;
    }
    return OGS_OK;
}

static int ring_open_file(int idx)
{
    char path[PTRACE_RING_PATH_LEN];
    pcap_hdr_t hdr;

    if (ring_path(path, sizeof(path), idx) != OGS_OK)
        return OGS_ERROR;
    ring.fp = fopen(path, "wb");
    if (!ring.fp) {
        ogs_error("ptrace ring open failed: %s (%s)", path, strerror(errno));
        return OGS_ERROR;
    }
    /* Large stdio buffer — few syscalls under signaling bursts. */
    setvbuf(ring.fp, NULL, _IOFBF, 4 * 1024 * 1024);

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

static void ref_remember(uint64_t seq, const char *ref)
{
    ring_ref_t *rr;

    if (!ref || !ref[0] || !ring.ref_by_seq)
        return;

    ogs_thread_mutex_lock(&ring.ref_lock);
    if (ring.ref_count >= PTRACE_RING_REF_MAP_MAX) {
        /* Map full — drop this ref (export best-effort). Do not free
         * in-hash values while iterating (keys live inside values). */
        ogs_thread_mutex_unlock(&ring.ref_lock);
        return;
    }

    rr = ogs_calloc(1, sizeof(*rr));
    if (!rr) {
        ogs_thread_mutex_unlock(&ring.ref_lock);
        return;
    }
    rr->seq = seq;
    ogs_cpystrn(rr->ref, ref, sizeof(rr->ref));
    ogs_hash_set(ring.ref_by_seq, &rr->seq, sizeof(rr->seq), rr);
    ring.ref_count++;
    ogs_thread_mutex_unlock(&ring.ref_lock);
}

static int ring_write_sync(const uint8_t *data, uint16_t len, ogs_time_t ts,
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
    ring.written++;
    if (ref_out && ref_len)
        snprintf(ref_out, ref_len, "%d:%ld:%u",
                ring.cur_idx, offset, (unsigned)len);

out:
    ogs_thread_mutex_unlock(&ring.lock);
    return rv;
}

static void ring_writer_thread(void *data)
{
    (void)data;

    while (ring.writer_running) {
        ring_item_t *it = NULL;
        char ref[PTRACE_MAX_REF_LEN];
        int rv = ogs_queue_timedpop(ring.q, (void **)&it,
                ogs_time_from_msec(200));
        if (rv != OGS_OK || !it)
            continue;

        ref[0] = '\0';
        if (ring_write_sync(it->data, it->len, it->ts, ref, sizeof(ref))
                == OGS_OK && ref[0])
            ref_remember(it->seq, ref);

        ogs_thread_mutex_lock(&ring.pool_lock);
        ogs_pool_free(&ring_item_pool, it);
        ogs_thread_mutex_unlock(&ring.pool_lock);
    }
}

int ptrace_ring_open(const char *path, int size_gb)
{
    int start_idx = 0;
    int i;
    time_t newest = 0;

    memset(&ring, 0, sizeof(ring));
    if (!path || !path[0])
        return OGS_ERROR;

    ogs_cpystrn(ring.dir, path, sizeof(ring.dir));
    ring.size_gb = size_gb > 0 ? size_gb : 2;
    ring.max_bytes = ((uint64_t)ring.size_gb * 1024ULL * 1024ULL * 1024ULL) /
            PTRACE_RING_FILES;
    if (ring.max_bytes < 16 * 1024 * 1024)
        ring.max_bytes = 16 * 1024 * 1024;

    if (mkdir_p(ring.dir) != OGS_OK) {
        ogs_error("ptrace ring mkdir_p %s: %s",
                ring.dir, strerror(errno));
        return OGS_ERROR;
    }

    /* Continue after the newest existing file so bootstrap can still
     * read older slots; we only truncate the next write slot. */
    for (i = 0; i < PTRACE_RING_FILES; i++) {
        char p[PTRACE_RING_PATH_LEN];
        struct stat st;
        if (ring_path(p, sizeof(p), i) != OGS_OK)
            continue;
        if (stat(p, &st) == 0 && st.st_size > (off_t)sizeof(pcap_hdr_t) &&
                st.st_mtime >= newest) {
            newest = st.st_mtime;
            start_idx = (i + 1) % PTRACE_RING_FILES;
        }
    }

    ogs_thread_mutex_init(&ring.lock);
    ogs_thread_mutex_init(&ring.pool_lock);
    ogs_thread_mutex_init(&ring.ref_lock);
    ogs_pool_init(&ring_item_pool, PTRACE_RING_Q_SIZE);
    ring.q = ogs_queue_create(PTRACE_RING_Q_SIZE);
    if (!ring.q)
        return OGS_ERROR;
    ring.ref_by_seq = ogs_hash_make();
    if (!ring.ref_by_seq)
        return OGS_ERROR;

    if (ring_open_file(start_idx) != OGS_OK)
        return OGS_ERROR;

    ring.writer_running = true;
    ring.writer = ogs_thread_create(ring_writer_thread, NULL);
    if (!ring.writer) {
        ogs_error("ptrace ring writer thread failed");
        return OGS_ERROR;
    }

    ring.open = true;
    ogs_info("ptrace PCAP ring at %s (%d GB) async_q=%d start=%02d",
            ring.dir, ring.size_gb, PTRACE_RING_Q_SIZE, start_idx);
    return OGS_OK;
}

void ptrace_ring_close(void)
{
    if (!ring.open)
        return;

    ring.writer_running = false;
    if (ring.writer) {
        ogs_thread_destroy(ring.writer);
        ring.writer = NULL;
    }
    if (ring.q) {
        ring_item_t *it;
        while (ogs_queue_trypop(ring.q, (void **)&it) == OGS_OK && it) {
            ogs_pool_free(&ring_item_pool, it);
        }
        ogs_queue_term(ring.q);
        ogs_queue_destroy(ring.q);
        ring.q = NULL;
    }

    ogs_thread_mutex_lock(&ring.lock);
    if (ring.fp) {
        fflush(ring.fp);
        fclose(ring.fp);
        ring.fp = NULL;
    }
    ogs_thread_mutex_unlock(&ring.lock);

    if (ring.ref_by_seq) {
        ogs_hash_index_t *hi;
        for (hi = ogs_hash_first(ring.ref_by_seq); hi;
                hi = ogs_hash_next(hi))
            ogs_free(ogs_hash_this_val(hi));
        ogs_hash_destroy(ring.ref_by_seq);
        ring.ref_by_seq = NULL;
    }

    ogs_pool_final(&ring_item_pool);
    ogs_thread_mutex_destroy(&ring.ref_lock);
    ogs_thread_mutex_destroy(&ring.pool_lock);
    ogs_thread_mutex_destroy(&ring.lock);
    ring.open = false;
}

int ptrace_ring_write(const uint8_t *data, uint16_t len, ogs_time_t ts,
        char *ref_out, size_t ref_len)
{
    ring_item_t *it;
    ptrace_context_t *ctx = ptrace_self();
    uint64_t seq;

    if (!ring.open || !data || !len)
        return OGS_ERROR;
    if (len > PTRACE_MAX_PACKET)
        len = PTRACE_MAX_PACKET;

    ogs_thread_mutex_lock(&ring.pool_lock);
    ogs_pool_alloc(&ring_item_pool, &it);
    if (!it) {
        ogs_thread_mutex_unlock(&ring.pool_lock);
        ring.q_drop++;
        if (ctx)
            ctx->packets_ring_drop++;
        if (ref_out && ref_len)
            ref_out[0] = '\0';
        return OGS_ERROR;
    }
    seq = ++ring.next_seq;
    it->seq = seq;
    it->ts = ts ? ts : ogs_time_now();
    it->len = len;
    memcpy(it->data, data, len);
    ogs_thread_mutex_unlock(&ring.pool_lock);

    if (ogs_queue_trypush(ring.q, it) != OGS_OK) {
        ogs_thread_mutex_lock(&ring.pool_lock);
        ogs_pool_free(&ring_item_pool, it);
        ogs_thread_mutex_unlock(&ring.pool_lock);
        ring.q_drop++;
        if (ctx)
            ctx->packets_ring_drop++;
        if (ref_out && ref_len)
            ref_out[0] = '\0';
        return OGS_ERROR;
    }

    /* Provisional async ref — export resolves via seq map once written. */
    if (ref_out && ref_len)
        snprintf(ref_out, ref_len, "a:%llu", (unsigned long long)seq);
    return OGS_OK;
}

static int resolve_ref(const char *in, char *out, size_t outlen)
{
    uint64_t seq;
    ring_ref_t *rr;

    if (!in || !in[0] || !out || !outlen)
        return OGS_ERROR;

    if (in[0] == 'a' && in[1] == ':') {
        seq = (uint64_t)strtoull(in + 2, NULL, 10);
        ogs_thread_mutex_lock(&ring.ref_lock);
        rr = ogs_hash_get(ring.ref_by_seq, &seq, sizeof(seq));
        if (rr) {
            ogs_cpystrn(out, rr->ref, outlen);
            ogs_thread_mutex_unlock(&ring.ref_lock);
            return OGS_OK;
        }
        ogs_thread_mutex_unlock(&ring.ref_lock);
        return OGS_ERROR;
    }

    ogs_cpystrn(out, in, outlen);
    return OGS_OK;
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
        char path[PTRACE_RING_PATH_LEN];
        char concrete[PTRACE_MAX_REF_LEN];
        FILE *in;
        uint8_t buf[PTRACE_MAX_PACKET + sizeof(pcaprec_hdr_t)];
        size_t need;

        concrete[0] = '\0';
        if (resolve_ref(refs[i], concrete, sizeof(concrete)) != OGS_OK)
            continue;
        if (sscanf(concrete, "%d:%ld:%u", &idx, &offset, &len) != 3)
            continue;
        if (len > PTRACE_MAX_PACKET)
            continue;

        if (ring_path(path, sizeof(path), idx) != OGS_OK)
            continue;
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

static void bootstrap_one_packet(const uint8_t *data, uint16_t len,
        ogs_time_t ts)
{
    ptrace_id_event_t id;
    ptrace_event_t evt;

    if (!data || !len)
        return;

    if (!ptrace_identity_extract(data, len, ts, PTRACE_ROLE_UNKNOWN, NULL, &id))
        return;

    memset(&evt, 0, sizeof(evt));
    ptrace_identity_to_event(&id, &evt);
    ptrace_correlate_event(&evt);
}

static bool packet_maybe_identity(const uint8_t *d, uint16_t len)
{
    int i;
    if (!d || len < 6)
        return false;
    for (i = 0; i + 1 < len; i++) {
        /* Plain EMM Attach Request / Identity Response */
        if (d[i] == 0x07 && (d[i + 1] == 0x41 || d[i + 1] == 0x56))
            return true;
        /* Integrity-protected then plain EMM */
        if ((d[i] == 0x17 || d[i] == 0x37) && i + 7 < len &&
                d[i + 6] == 0x07 &&
                (d[i + 7] == 0x41 || d[i + 7] == 0x56))
            return true;
    }
    return false;
}

int ptrace_ring_bootstrap(const char *dir)
{
    int order[PTRACE_RING_FILES];
    time_t mtimes[PTRACE_RING_FILES];
    int nfiles = 0;
    int i, j;
    int pkts = 0;
    int decoded = 0;

    if (!dir || !dir[0])
        return OGS_ERROR;

    ogs_info("ptrace: bootstrapping UE index from ring %s", dir);

    for (i = 0; i < PTRACE_RING_FILES; i++) {
        char path[PTRACE_RING_PATH_LEN];
        struct stat st;
        int n = snprintf(path, sizeof(path), "%s/ring-%02d.pcap", dir, i);
        if (n < 0 || (size_t)n >= sizeof(path))
            continue;
        if (stat(path, &st) != 0 || st.st_size <= (off_t)sizeof(pcap_hdr_t))
            continue;
        order[nfiles] = i;
        mtimes[nfiles] = st.st_mtime;
        nfiles++;
    }

    /* Newest first */
    for (i = 0; i < nfiles; i++) {
        for (j = i + 1; j < nfiles; j++) {
            if (mtimes[j] > mtimes[i]) {
                time_t tm = mtimes[i];
                int ti = order[i];
                mtimes[i] = mtimes[j];
                order[i] = order[j];
                mtimes[j] = tm;
                order[j] = ti;
            }
        }
    }
    if (nfiles > PTRACE_RING_BOOT_FILES)
        nfiles = PTRACE_RING_BOOT_FILES;

    for (i = 0; i < nfiles; i++) {
        char path[PTRACE_RING_PATH_LEN];
        FILE *fp;
        pcap_hdr_t hdr;
        int n = snprintf(path, sizeof(path), "%s/ring-%02d.pcap",
                dir, order[i]);
        if (n < 0 || (size_t)n >= sizeof(path))
            continue;
        fp = fopen(path, "rb");
        if (!fp)
            continue;
        if (fread(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr) ||
                hdr.magic != PCAP_MAGIC) {
            fclose(fp);
            continue;
        }
        for (;;) {
            pcaprec_hdr_t rec;
            uint8_t buf[PTRACE_MAX_PACKET];
            ogs_time_t ts;

            if (fread(&rec, 1, sizeof(rec), fp) != sizeof(rec))
                break;
            if (rec.incl_len == 0 || rec.incl_len > PTRACE_MAX_PACKET) {
                if (rec.incl_len > PTRACE_MAX_PACKET &&
                        fseek(fp, (long)rec.incl_len, SEEK_CUR) != 0)
                    break;
                continue;
            }
            if (fread(buf, 1, rec.incl_len, fp) != rec.incl_len)
                break;
            pkts++;
            if (!packet_maybe_identity(buf, (uint16_t)rec.incl_len))
                continue;
            ts = ogs_time_from_sec(rec.ts_sec) + rec.ts_usec;
            bootstrap_one_packet(buf, (uint16_t)rec.incl_len, ts);
            decoded++;
        }
        fclose(fp);
    }

    ogs_info("ptrace: ring bootstrap done scanned=%d identity_pkts=%d "
            "ue_count=%d", pkts, decoded, ptrace_correlate_ue_count());
    return OGS_OK;
}

uint64_t ptrace_ring_queue_drops(void)
{
    return ring.q_drop;
}
