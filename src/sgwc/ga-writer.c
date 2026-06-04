/*
 * Copyright (C) 2026 by Open5GS Contributors
 *
 * SGW-CDR writer for Ga / GTP' (TS 32.298 SGWRecord, spool OGS_CDR_FORMAT_BER_SGW).
 */

#include "ga-writer.h"

#include "cdr/framing.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <process.h>
#define sgwc_mkdir(p) _mkdir(p)
#define sgwc_getpid() _getpid()
#else
#include <unistd.h>
#define sgwc_mkdir(p) mkdir((p), 0755)
#define sgwc_getpid() getpid()
#endif

#define SGWC_GA_RECORD_MAX  4096

/* TS 32.298 recordType: sgwRecord (wire value used by operator CGFs). */
#define CDR_RT_SGW_RECORD   84

/* CHOICE alternative tag for SGWRecord (PGW uses 79). */
#define CDR_OUTER_TAG_SGW   78

static struct {
    bool initialized;
    char *current_path;
    char *ready_dir;
    char *current_dir;
    char *seq_path;
    FILE *fp;
    uint32_t cur_records;
    uint32_t cur_bytes;
    ogs_time_t cur_opened;
} g;

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t off;
    bool overflow;
} ber_t;

static void ber_init(ber_t *b, uint8_t *buf, size_t cap)
{
    b->buf = buf; b->cap = cap; b->off = 0; b->overflow = false;
}

static void ber_raw(ber_t *b, const void *data, size_t len)
{
    if (b->overflow) return;
    if (b->off + len > b->cap) { b->overflow = true; return; }
    if (len > 0) memcpy(b->buf + b->off, data, len);
    b->off += len;
}

static void ber_u8(ber_t *b, uint8_t v) { ber_raw(b, &v, 1); }

static void ber_len(ber_t *b, size_t len)
{
    if (len < 0x80) ber_u8(b, (uint8_t)len);
    else if (len <= 0xff) { ber_u8(b, 0x81); ber_u8(b, (uint8_t)len); }
    else if (len <= 0xffff) {
        ber_u8(b, 0x82);
        ber_u8(b, (uint8_t)(len >> 8));
        ber_u8(b, (uint8_t)(len & 0xff));
    } else b->overflow = true;
}

static void ber_prim_ctx(ber_t *b, uint32_t tag, const void *value, size_t len)
{
    if (tag < 31) ber_u8(b, (uint8_t)(0x80 | tag));
    else { ber_u8(b, 0x9f); ber_u8(b, (uint8_t)tag); }
    ber_len(b, len);
    ber_raw(b, value, len);
}

static void ber_uint_ctx(ber_t *b, uint32_t tag, uint64_t v)
{
    uint8_t tmp[8];
    int n = 0;
    if (v == 0) tmp[n++] = 0;
    else {
        int shift;
        for (shift = 56; shift >= 0; shift -= 8)
            if ((v >> shift) & 0xff) break;
        for (; shift >= 0; shift -= 8)
            tmp[n++] = (uint8_t)((v >> shift) & 0xff);
    }
    ber_prim_ctx(b, tag, tmp, n);
}

static void ber_uint_be_ctx(ber_t *b, uint32_t tag, uint64_t v, int bytes)
{
    uint8_t tmp[8];
    int i;
    for (i = 0; i < bytes; i++)
        tmp[i] = (uint8_t)((v >> (8 * (bytes - 1 - i))) & 0xff);
    ber_prim_ctx(b, tag, tmp, bytes);
}

static size_t ber_begin_ctx(ber_t *b, uint32_t tag)
{
    size_t mark;
    if (tag < 31) ber_u8(b, (uint8_t)(0xa0 | tag));
    else { ber_u8(b, 0xbf); ber_u8(b, (uint8_t)tag); }
    mark = b->off;
    ber_u8(b, 0x82); ber_u8(b, 0); ber_u8(b, 0);
    return mark;
}

static void ber_end(ber_t *b, size_t mark)
{
    size_t inner;
    uint8_t lenbuf[3];
    unsigned lenlen;

    if (b->overflow) return;
    ogs_assert(mark + 3 <= b->off);
    inner = b->off - (mark + 3);

    if (inner < 0x80) {
        lenbuf[0] = (uint8_t)inner;
        lenlen = 1;
    } else if (inner <= 0xff) {
        lenbuf[0] = 0x81;
        lenbuf[1] = (uint8_t)inner;
        lenlen = 2;
    } else if (inner <= 0xffff) {
        lenbuf[0] = 0x82;
        lenbuf[1] = (uint8_t)(inner >> 8);
        lenbuf[2] = (uint8_t)(inner & 0xff);
        lenlen = 3;
    } else {
        b->overflow = true;
        return;
    }

    if (lenlen < 3) {
        memmove(b->buf + mark + lenlen, b->buf + mark + 3, inner);
        b->off -= (3 - lenlen);
    }
    memcpy(b->buf + mark, lenbuf, lenlen);
}

static size_t ber_begin_seq(ber_t *b)
{
    size_t mark;
    ber_u8(b, 0x30);
    mark = b->off;
    ber_u8(b, 0x82);
    ber_u8(b, 0x00);
    ber_u8(b, 0x00);
    return mark;
}

static size_t tbcd_encode(const char *digits, uint8_t *out, size_t out_cap)
{
    size_t n, i, o;
    n = digits ? strlen(digits) : 0;
    o = (n + 1) / 2;
    if (o > out_cap) return 0;
    memset(out, 0, o);
    for (i = 0; i < n; i++) {
        uint8_t d = (uint8_t)(digits[i] - '0');
        if (d > 9) return 0;
        if (i & 1) out[i / 2] |= (uint8_t)(d << 4);
        else out[i / 2] |= d;
    }
    if (n & 1) out[n / 2] |= 0xf0;
    return o;
}

static void timestamp_encode(ogs_time_t t, uint8_t out[9])
{
    struct tm lt;
    time_t sec = (time_t)(t / OGS_USEC_PER_SEC);
    long tz_min;
    int sign;

    ogs_localtime(sec, &lt);
    tz_min = ogs_timezone() / 60;
    sign = tz_min >= 0 ? '+' : '-';
    if (tz_min < 0) tz_min = -tz_min;

    out[0] = (uint8_t)(((lt.tm_year % 100) / 10) << 4 |
                       ((lt.tm_year % 100) % 10));
    out[1] = (uint8_t)(((lt.tm_mon + 1) / 10) << 4 |
                       ((lt.tm_mon + 1) % 10));
    out[2] = (uint8_t)((lt.tm_mday / 10) << 4 | (lt.tm_mday % 10));
    out[3] = (uint8_t)((lt.tm_hour / 10) << 4 | (lt.tm_hour % 10));
    out[4] = (uint8_t)((lt.tm_min / 10) << 4 | (lt.tm_min % 10));
    out[5] = (uint8_t)((lt.tm_sec / 10) << 4 | (lt.tm_sec % 10));
    out[6] = (uint8_t)sign;
    out[7] = (uint8_t)(((tz_min / 60) / 10) << 4 | ((tz_min / 60) % 10));
    out[8] = (uint8_t)(((tz_min % 60) / 10) << 4 | ((tz_min % 60) % 10));
}

static void plmn_encode(const ogs_plmn_id_t *plmn, uint8_t out[3])
{
    memcpy(out, plmn, 3);
}

static void encode_gsn_address_v4(ber_t *b, uint32_t outer_tag, uint32_t addr)
{
    size_t m;
    uint8_t v4[4];
    v4[0] = (uint8_t)(addr >> 24);
    v4[1] = (uint8_t)(addr >> 16);
    v4[2] = (uint8_t)(addr >> 8);
    v4[3] = (uint8_t)(addr & 0xff);
    m = ber_begin_ctx(b, outer_tag);
    ber_prim_ctx(b, 0, v4, 4);
    ber_end(b, m);
}

static size_t build_sgw_record(sgwc_sess_t *sess, sgwc_ue_t *sgwc_ue,
        uint8_t *out, size_t out_cap, bool is_stop, uint32_t interval_duration_s)
{
    sgwc_cdr_config_t *cfg = &sgwc_self()->cdr;
    ber_t b;
    size_t outer;
    uint8_t tmp[16];
    size_t n;
    ogs_time_t now = ogs_time_now();

    ogs_assert(sess && sgwc_ue);

    ber_init(&b, out, out_cap);
    outer = ber_begin_ctx(&b, CDR_OUTER_TAG_SGW);

    ber_uint_be_ctx(&b, 0, CDR_RT_SGW_RECORD, 1);

    if (sgwc_ue->imsi_bcd[0]) {
        n = tbcd_encode(sgwc_ue->imsi_bcd, tmp, sizeof(tmp));
        if (n) ber_prim_ctx(&b, 3, tmp, n);
    }

    if (cfg->local_address) {
        ogs_ipsubnet_t ipsub;
        if (ogs_ipsubnet(&ipsub, cfg->local_address, NULL) == OGS_OK &&
                ipsub.family == AF_INET)
            encode_gsn_address_v4(&b, 4, ntohl(ipsub.sub[0]));
    } else if (ogs_gtp_self()->gtpc_addr &&
            ogs_gtp_self()->gtpc_addr->ogs_sa_family == AF_INET) {
        encode_gsn_address_v4(&b, 4,
                ntohl(ogs_gtp_self()->gtpc_addr->sin.sin_addr.s_addr));
    }

    if (sess->charging_id)
        ber_uint_be_ctx(&b, 5, sess->charging_id, 4);

    /* [6] servingNodeAddress — PGW S5-C if known */
    if (sess->gnode && sess->gnode->ip.ipv4) {
        encode_gsn_address_v4(&b, 6, ntohl(sess->gnode->ip.addr));
    } else {
        encode_gsn_address_v4(&b, 6, 0);
    }

    if (sess->session.name)
        ber_prim_ctx(&b, 7, sess->session.name, strlen(sess->session.name));

    tmp[0] = 0x00;
    tmp[1] = sess->session.session_type ? sess->session.session_type :
            OGS_PDU_SESSION_TYPE_IPV4;
    ber_prim_ctx(&b, 8, tmp, 2);

    if (sess->paa.session_type == OGS_PDU_SESSION_TYPE_IPV4) {
        size_t m1 = ber_begin_ctx(&b, 9);
        encode_gsn_address_v4(&b, 0, ntohl(sess->paa.addr));
        ber_end(&b, m1);
    }

    {
        uint64_t ul_delta = sess->usage_ul_octets - sess->cdr.last_ul_octets;
        uint64_t dl_delta = sess->usage_dl_octets - sess->cdr.last_dl_octets;
        uint8_t ts[9];
        size_t list, row;
        uint64_t dur = interval_duration_s;

        if (!dur && sess->cdr.start_time && now > sess->cdr.start_time)
            dur = (uint64_t)((now - sess->cdr.start_time) / OGS_USEC_PER_SEC);

        list = ber_begin_ctx(&b, 12);
        row = ber_begin_seq(&b);
        ber_uint_ctx(&b, 3, ul_delta);
        ber_uint_ctx(&b, 4, dl_delta);
        tmp[0] = is_stop ? 2 : (sess->cdr.record_seq == 0 ? 0 : 3);
        ber_prim_ctx(&b, 5, tmp, 1);
        timestamp_encode(now, ts);
        ber_prim_ctx(&b, 6, ts, 9);
        ber_end(&b, row);
        ber_end(&b, list);
    }

    {
        uint8_t ts[9];
        ogs_time_t open_t = sess->cdr.start_time ? sess->cdr.start_time : now;
        timestamp_encode(open_t, ts);
        ber_prim_ctx(&b, 13, ts, 9);
    }

    ber_uint_ctx(&b, 14, interval_duration_s ? interval_duration_s :
            (sess->cdr.start_time && now > sess->cdr.start_time ?
             (uint64_t)((now - sess->cdr.start_time) / OGS_USEC_PER_SEC) : 0));

    tmp[0] = is_stop ? sess->cdr.cause_for_rec_closing : 0;
    ber_prim_ctx(&b, 15, tmp, 1);

    if (!is_stop || sess->cdr.record_seq > 0)
        ber_uint_ctx(&b, 17, sess->cdr.record_seq + 1);

    if (cfg->node_id)
        ber_prim_ctx(&b, 18, cfg->node_id, strlen(cfg->node_id));

    sgwc_self()->cdr_local_seq++;
    ber_uint_be_ctx(&b, 20, sgwc_self()->cdr_local_seq, 4);

    /* [22] servedMSISDN (TBCD) — same tag as PGWRecord (TS 32.298). */
    if (sgwc_ue->msisdn_bcd[0]) {
        n = tbcd_encode(sgwc_ue->msisdn_bcd, tmp, sizeof(tmp));
        if (n) ber_prim_ctx(&b, 22, tmp, n);
    }

    {
        uint8_t pl[3];
        plmn_encode(&sess->serving_plmn_id, pl);
        ber_prim_ctx(&b, 27, pl, 3);
    }

    if (sgwc_ue->uli_pkbuf && sgwc_ue->uli_pkbuf->len) {
        ber_prim_ctx(&b, 32, sgwc_ue->uli_pkbuf->data, sgwc_ue->uli_pkbuf->len);
    }

    /* SGW-CDR [36] p-GWAddressUsed */
    if (sess->gnode && sess->gnode->ip.ipv4) {
        size_t m = ber_begin_ctx(&b, 36);
        encode_gsn_address_v4(&b, 0, ntohl(sess->gnode->ip.addr));
        ber_end(&b, m);
    }

    {
        uint8_t ts[9];
        ogs_time_t st = sess->cdr.start_time ? sess->cdr.start_time : now;
        timestamp_encode(st, ts);
        ber_prim_ctx(&b, 38, ts, 9);
    }

    if (is_stop) {
        uint8_t ts[9];
        timestamp_encode(now, ts);
        ber_prim_ctx(&b, 39, ts, 9);
    }

    ber_end(&b, outer);
    if (b.overflow) return 0;
    return b.off;
}

static int mkdir_p(const char *path)
{
    char *copy, *p;
    int rc = OGS_OK;

    if (!path || !*path) return OGS_ERROR;
    copy = ogs_strdup(path);
    if (!copy) return OGS_ERROR;

    for (p = copy + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char saved = *p;
            *p = '\0';
            if (sgwc_mkdir(copy) != 0 && errno != EEXIST) {
                rc = OGS_ERROR;
                *p = saved;
                break;
            }
            *p = saved;
        }
    }
    if (rc == OGS_OK && sgwc_mkdir(copy) != 0 && errno != EEXIST)
        rc = OGS_ERROR;
    ogs_free(copy);
    return rc;
}

static void load_local_seq(void)
{
    FILE *fp;
    unsigned long v = 0;

    if (!g.seq_path) return;
    fp = fopen(g.seq_path, "r");
    if (!fp) return;
    if (fscanf(fp, "%lu", &v) == 1)
        sgwc_self()->cdr_local_seq = (uint32_t)v;
    fclose(fp);
}

static void persist_local_seq(void)
{
    FILE *fp;
    if (!g.seq_path) return;
    fp = fopen(g.seq_path, "w");
    if (!fp) return;
    fprintf(fp, "%u\n", sgwc_self()->cdr_local_seq);
    fclose(fp);
}

static int open_current_file(void)
{
    sgwc_cdr_config_t *cfg = &sgwc_self()->cdr;
    char name[256];
    const char *node = cfg->node_id ? cfg->node_id : "sgwc";

    if (g.fp) return OGS_OK;

    ogs_snprintf(name, sizeof(name), "%s/%s-%llu-%d.cdr",
            g.current_dir, node,
            (unsigned long long)(ogs_time_now() / OGS_USEC_PER_SEC),
            (int)sgwc_getpid());

    if (g.current_path) { ogs_free(g.current_path); g.current_path = NULL; }
    g.current_path = ogs_strdup(name);
    ogs_assert(g.current_path);

    g.fp = fopen(g.current_path, "ab");
    if (!g.fp) {
        ogs_warn("sgwc_ga_writer: cannot open '%s': %s",
                g.current_path, strerror(errno));
        return OGS_ERROR;
    }
    g.cur_records = 0;
    g.cur_bytes = 0;
    g.cur_opened = ogs_time_now();
    return OGS_OK;
}

static void rotate_locked(void)
{
    char ready_name[256];
    const char *base;

    if (!g.fp || !g.current_path) return;
    fflush(g.fp);
#if !defined(_WIN32)
    fsync(fileno(g.fp));
#endif
    fclose(g.fp);
    g.fp = NULL;

    base = strrchr(g.current_path, '/');
#ifdef _WIN32
    { const char *bb = strrchr(g.current_path, '\\');
      if (bb > base) base = bb; }
#endif
    base = base ? base + 1 : g.current_path;
    ogs_snprintf(ready_name, sizeof(ready_name), "%s/%s", g.ready_dir, base);
    if (rename(g.current_path, ready_name) != 0) {
        ogs_warn("sgwc_ga_writer: rotate failed '%s': %s",
                g.current_path, strerror(errno));
    } else {
        ogs_debug("sgwc_ga_writer: rotated '%s' (%u records)",
                ready_name, g.cur_records);
    }
    ogs_free(g.current_path);
    g.current_path = NULL;
    g.cur_records = 0;
    g.cur_bytes = 0;
    persist_local_seq();
}

static bool should_rotate(void)
{
    sgwc_cdr_config_t *cfg = &sgwc_self()->cdr;
    if (cfg->rotate_max_records && g.cur_records >= cfg->rotate_max_records)
        return true;
    if (cfg->rotate_max_bytes && g.cur_bytes >= cfg->rotate_max_bytes)
        return true;
    if (cfg->rotate_max_seconds &&
            ogs_time_now() - g.cur_opened >=
            ogs_time_from_sec(cfg->rotate_max_seconds))
        return true;
    return false;
}

static void write_record(const uint8_t *rec, size_t rec_len)
{
    uint8_t hdr[OGS_CDR_RECORD_HDR_LEN];

    if (!g.initialized || !rec || !rec_len) return;
    if (rec_len > 0xffff) return;
    if (!g.fp && open_current_file() != OGS_OK) return;

    memcpy(hdr, OGS_CDR_FILE_MAGIC, 4);
    hdr[4] = OGS_CDR_FILE_VERSION;
    hdr[5] = OGS_CDR_FORMAT_BER_SGW;
    hdr[6] = (uint8_t)(rec_len >> 8);
    hdr[7] = (uint8_t)(rec_len & 0xff);

    if (fwrite(hdr, 1, sizeof(hdr), g.fp) != sizeof(hdr) ||
            fwrite(rec, 1, rec_len, g.fp) != rec_len) {
        fclose(g.fp);
        g.fp = NULL;
        return;
    }
    /*
     * Skip the per-record fflush(): rotate_locked() always fflush()es
     * before fclose()/rename(), so the only durability window we widen
     * is "SGW-C crashes between rotations" - bounded to the current
     * libc buffer (~4 KiB). rotate_max_records / _bytes / _seconds
     * cap how much that can ever be. See src/smf/ga-writer.c for the
     * full rationale.
     */
    g.cur_records++;
    g.cur_bytes += (uint32_t)(rec_len + sizeof(hdr));
    if (should_rotate()) rotate_locked();
}

static void emit(sgwc_sess_t *sess, bool is_stop, uint32_t interval_duration_s)
{
    sgwc_ue_t *sgwc_ue = NULL;
    uint8_t rec[SGWC_GA_RECORD_MAX];
    size_t n;

    if (!sgwc_self()->cdr.enabled || !g.initialized) return;
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    if (!sgwc_ue) return;

    n = build_sgw_record(sess, sgwc_ue, rec, sizeof(rec), is_stop,
            interval_duration_s);
    if (!n) {
        ogs_warn("sgwc_ga_writer: encode failed sess_id=%d", (int)sess->id);
        return;
    }
    write_record(rec, n);

    sess->cdr.last_ul_octets = sess->usage_ul_octets;
    sess->cdr.last_dl_octets = sess->usage_dl_octets;
    sess->cdr.last_interval_duration_s = interval_duration_s;
    sess->cdr.record_seq++;
}

void sgwc_sess_usage_accumulate(sgwc_sess_t *sess,
        uint64_t ul_vol, uint64_t dl_vol, uint32_t duration_s)
{
    ogs_assert(sess);
    sess->usage_ul_octets += ul_vol;
    sess->usage_dl_octets += dl_vol;
    if (duration_s)
        sess->cdr.last_interval_duration_s = duration_s;
}

int sgwc_ga_writer_open(void)
{
    sgwc_cdr_config_t *cfg = &sgwc_self()->cdr;
    char path[512];

    if (!cfg->enabled) {
        ogs_info("sgwc_ga_writer: disabled");
        return OGS_OK;
    }
    if (!cfg->spool_dir || !*cfg->spool_dir) {
        ogs_error("sgwc_ga_writer: no spool_dir");
        return OGS_ERROR;
    }

    if (mkdir_p(cfg->spool_dir) != OGS_OK) return OGS_ERROR;
    ogs_snprintf(path, sizeof(path), "%s/current", cfg->spool_dir);
    if (mkdir_p(path) != OGS_OK) return OGS_ERROR;
    g.current_dir = ogs_strdup(path);

    ogs_snprintf(path, sizeof(path), "%s/ready", cfg->spool_dir);
    if (mkdir_p(path) != OGS_OK) return OGS_ERROR;
    g.ready_dir = ogs_strdup(path);

    ogs_snprintf(path, sizeof(path), "%s/.seq-sgwc", cfg->spool_dir);
    g.seq_path = ogs_strdup(path);

    load_local_seq();
    g.initialized = true;

    ogs_info("sgwc_ga_writer: spool='%s' node='%s' format=%s seq=%u",
            cfg->spool_dir, cfg->node_id ? cfg->node_id : "sgwc",
            ogs_cdr_format_name(OGS_CDR_FORMAT_BER_SGW),
            sgwc_self()->cdr_local_seq);
    return OGS_OK;
}

void sgwc_ga_writer_close(void)
{
    if (g.fp) rotate_locked();
    persist_local_seq();
    if (g.current_dir) { ogs_free(g.current_dir); g.current_dir = NULL; }
    if (g.ready_dir) { ogs_free(g.ready_dir); g.ready_dir = NULL; }
    if (g.seq_path) { ogs_free(g.seq_path); g.seq_path = NULL; }
    if (g.current_path) { ogs_free(g.current_path); g.current_path = NULL; }
    g.initialized = false;
}

void sgwc_ga_cdr_session_start(sgwc_sess_t *sess)
{
    sgwc_ue_t *sgwc_ue = NULL;

    if (!sgwc_self()->cdr.enabled) return;
    ogs_assert(sess);
    sgwc_ue = sgwc_ue_find_by_id(sess->sgwc_ue_id);
    if (sgwc_ue && sgwc_ue->uli_presence)
        memcpy(&sess->serving_plmn_id, &sgwc_ue->e_tai.plmn_id,
                sizeof(sess->serving_plmn_id));

    if (!sess->cdr.start_time)
        sess->cdr.start_time = ogs_time_now();

    if (sgwc_self()->cdr.triggers & SGWC_CDR_TRIG_START)
        emit(sess, false, 0);
}

void sgwc_ga_cdr_session_interim(sgwc_sess_t *sess, uint32_t interval_duration_s)
{
    if (!sgwc_self()->cdr.enabled) return;
    ogs_assert(sess);
    if (!(sgwc_self()->cdr.triggers & SGWC_CDR_TRIG_INTERIM)) return;
    emit(sess, false, interval_duration_s);
}

void sgwc_ga_cdr_session_stop(sgwc_sess_t *sess)
{
    if (!sgwc_self()->cdr.enabled) return;
    ogs_assert(sess);
    if (!(sgwc_self()->cdr.triggers & SGWC_CDR_TRIG_STOP)) return;
    emit(sess, true, sess->cdr.last_interval_duration_s);
}

void sgwc_ga_sess_clear(sgwc_sess_t *sess)
{
    ogs_assert(sess);
    sess->cdr.start_time = 0;
    sess->cdr.record_seq = 0;
    sess->cdr.last_ul_octets = 0;
    sess->cdr.last_dl_octets = 0;
    sess->cdr.last_interval_duration_s = 0;
    sess->cdr.cause_for_rec_closing = 0;
    sess->usage_ul_octets = 0;
    sess->usage_dl_octets = 0;
}
