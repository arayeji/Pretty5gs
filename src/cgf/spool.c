/*
 * Copyright (C) 2026 by Open5GS Contributors
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

#include "spool.h"

#include "cdr/framing.h"
#include "ogs-app.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#include <dirent.h>
#endif

/* On-disk framing — must match lib/cdr/framing.h and ga-writer modules. */
#define CDR_FILE_MAGIC      OGS_CDR_FILE_MAGIC
#define CDR_FILE_VERSION    OGS_CDR_FILE_VERSION
#define CDR_RECORD_HDR_LEN  OGS_CDR_RECORD_HDR_LEN

static cgf_spool_file_t *g_active = NULL;

/*
 * Spool scan state — ready/ can hold 100k+ files. Scanning the whole
 * directory on every file transition is O(n) per file (O(n²) to drain a
 * backlog). We scan once into a sorted queue and consume it in order;
 * a new scan runs only when the queue is exhausted.
 */
static char g_cached_next_path[512];
static ogs_time_t g_empty_until;

static char **g_pending_queue = NULL;
static uint32_t g_pending_count = 0;
static uint32_t g_pending_idx = 0;

/* ------------------------------------------------------------------ */

cgf_spool_file_t *cgf_spool_get_active(void) { return g_active; }

static const char *path_basename(const char *path)
{
    const char *base = strrchr(path, '/');
#ifdef _WIN32
    { const char *bb = strrchr(path, '\\'); if (bb > base) base = bb; }
#endif
    return base ? base + 1 : path;
}

static void spool_clear_cached_next(void)
{
    g_cached_next_path[0] = '\0';
}

static void pending_queue_free(void)
{
    uint32_t i;

    if (!g_pending_queue) return;
    for (i = 0; i < g_pending_count; i++)
        ogs_free(g_pending_queue[i]);
    ogs_free(g_pending_queue);
    g_pending_queue = NULL;
    g_pending_count = 0;
    g_pending_idx = 0;
}

static int cmp_basename(const void *a, const void *b)
{
    return strcmp(*(const char * const *)a, *(const char * const *)b);
}

static bool spool_is_cdr_name(const char *name)
{
    size_t nl;

    if (!name) return false;
    nl = strlen(name);
    return nl >= 4 && strcmp(name + nl - 4, ".cdr") == 0;
}

static bool spool_path_ready(const char *path)
{
    struct stat st;

    if (!path || !path[0]) return false;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int pending_queue_build(void)
{
    char **names = NULL;
    uint32_t n_names = 0, n_cap = 0;
    uint32_t i;

    pending_queue_free();

#ifdef _WIN32
    {
        WIN32_FIND_DATAA fd;
        HANDLE h;
        char pattern[512];

        ogs_snprintf(pattern, sizeof(pattern), "%s\\*.cdr",
                cgf_self()->ready_dir);
        h = FindFirstFileA(pattern, &fd);
        if (h == INVALID_HANDLE_VALUE) return OGS_ERROR;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (!spool_is_cdr_name(fd.cFileName)) continue;
            if (n_names >= n_cap) {
                n_cap = n_cap ? n_cap * 2 : 64;
                names = ogs_realloc(names, n_cap * sizeof(*names));
                ogs_assert(names);
            }
            names[n_names++] = ogs_strdup(fd.cFileName);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#else
    {
        DIR *d;
        struct dirent *ent;

        d = opendir(cgf_self()->ready_dir);
        if (!d) return OGS_ERROR;

        while ((ent = readdir(d)) != NULL) {
            if (!spool_is_cdr_name(ent->d_name)) continue;
            if (n_names >= n_cap) {
                n_cap = n_cap ? n_cap * 2 : 64;
                names = ogs_realloc(names, n_cap * sizeof(*names));
                ogs_assert(names);
            }
            names[n_names++] = ogs_strdup(ent->d_name);
        }
        closedir(d);
    }
#endif

    if (n_names == 0) {
        if (names) ogs_free(names);
        return OGS_ERROR;
    }

    qsort(names, n_names, sizeof(*names), cmp_basename);

    g_pending_queue = ogs_calloc(n_names, sizeof(*g_pending_queue));
    ogs_assert(g_pending_queue);
    for (i = 0; i < n_names; i++) {
        char path[512];
        ogs_snprintf(path, sizeof(path), "%s/%s",
                cgf_self()->ready_dir, names[i]);
        g_pending_queue[i] = ogs_strdup(path);
        ogs_free(names[i]);
    }
    ogs_free(names);
    g_pending_count = n_names;
    g_pending_idx = 0;
    return OGS_OK;
}

static void spool_reset_scan_state(void)
{
    spool_clear_cached_next();
    g_empty_until = 0;
    pending_queue_free();
}

static void spool_mark_empty(void)
{
    uint32_t poll_ms = cgf_self()->spool_poll_ms;

    /* Back off only one poll tick. Exponential backoff up to 30 s delayed
     * pickup of newly rotated files while cgfd was idle. */
    if (!poll_ms) poll_ms = 250;
    g_empty_until = ogs_time_now() + ogs_time_from_msec(poll_ms);
    spool_clear_cached_next();
    pending_queue_free();
}

static void spool_clear_empty_backoff(void)
{
    g_empty_until = 0;
}

static void free_file(cgf_spool_file_t *f)
{
    if (!f) return;
    if (f->data) ogs_free(f->data);
    if (f->path) ogs_free(f->path);
    ogs_free(f);
}

static int slurp(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *fp;
    long sz;
    size_t got;
    uint8_t *buf;

    fp = fopen(path, "rb");
    if (!fp) return OGS_ERROR;

    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return OGS_ERROR; }
    sz = ftell(fp);
    if (sz < 0) { fclose(fp); return OGS_ERROR; }
    rewind(fp);

    buf = ogs_malloc((size_t)sz);
    if (!buf) { fclose(fp); return OGS_ERROR; }
    got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (got != (size_t)sz) { ogs_free(buf); return OGS_ERROR; }

    *out = buf;
    *out_len = (size_t)sz;
    return OGS_OK;
}

static int pick_next_path(char *out_path, size_t out_cap)
{
    if (g_cached_next_path[0] && spool_path_ready(g_cached_next_path)) {
        ogs_snprintf(out_path, out_cap, "%s", g_cached_next_path);
        return OGS_OK;
    }

    spool_clear_cached_next();

    while (g_pending_idx < g_pending_count) {
        const char *candidate = g_pending_queue[g_pending_idx];

        g_pending_idx++;
        if (spool_path_ready(candidate)) {
            ogs_snprintf(out_path, out_cap, "%s", candidate);
            ogs_snprintf(g_cached_next_path, sizeof(g_cached_next_path),
                    "%s", candidate);
            return OGS_OK;
        }
    }

    if (pending_queue_build() != OGS_OK)
        return OGS_ERROR;

    while (g_pending_idx < g_pending_count) {
        const char *candidate = g_pending_queue[g_pending_idx];

        g_pending_idx++;
        if (spool_path_ready(candidate)) {
            ogs_snprintf(out_path, out_cap, "%s", candidate);
            ogs_snprintf(g_cached_next_path, sizeof(g_cached_next_path),
                    "%s", candidate);
            return OGS_OK;
        }
    }

    pending_queue_free();
    return OGS_ERROR;
}

static int quarantine_bad_header(const char *path)
{
    const char *base = path_basename(path);
    char dst[512];

    ogs_snprintf(dst, sizeof(dst), "%s/%s", cgf_self()->failed_dir, base);
    return rename(path, dst);
}

static bool open_spool_file(const char *path)
{
    cgf_spool_file_t *f;
    uint8_t *data = NULL;
    size_t data_len = 0;

    if (slurp(path, &data, &data_len) != OGS_OK) {
        ogs_warn("cgf: cannot read '%s'", path);
        spool_clear_cached_next();
        return false;
    }

    if (data_len >= CDR_RECORD_HDR_LEN) {
        if (memcmp(data, CDR_FILE_MAGIC, 4) != 0 ||
                data[4] != CDR_FILE_VERSION ||
                !ogs_cdr_format_is_valid(data[5])) {
            ogs_error("cgf: '%s' has bad spool header (magic/version/format), "
                    "quarantining", path);
            ogs_free(data);
            if (quarantine_bad_header(path) != 0) {
                ogs_warn("cgf: quarantine rename failed for '%s': %s",
                        path, strerror(errno));
            }
            spool_clear_cached_next();
            return false;
        }
    }

    f = ogs_calloc(1, sizeof(*f));
    ogs_assert(f);
    f->path = ogs_strdup(path);
    f->data = data;
    f->data_len = data_len;
    f->next_record_offset = 0;
    f->send_offset = 0;
    g_active = f;
    spool_clear_cached_next();

    ogs_info("cgf: opened spool file '%s' (%zu B, first_record=%s)",
            path, data_len,
            data_len >= OGS_CDR_RECORD_HDR_LEN ?
                ogs_cdr_format_name(data[5]) : "?");
    return true;
}

void cgf_spool_refill(void)
{
    char path[512];
    int attempts;

    if (g_active) return;
    if (g_empty_until && ogs_time_now() < g_empty_until) return;

    /* Try several candidates in one timer tick when early files are
     * unreadable or corrupt — avoids a full readdir every spool_poll. */
    for (attempts = 0; attempts < 8; attempts++) {
        if (pick_next_path(path, sizeof(path)) != OGS_OK) {
            spool_mark_empty();
            return;
        }

        if (open_spool_file(path))
            return;
    }

    ogs_warn("cgf: spool refill skipped %d unreadable/corrupt files in "
            "ready/", attempts);
}

uint32_t cgf_spool_stage_batch(cgf_spool_file_t *file,
        uint8_t *out, size_t out_cap, size_t *out_used,
        uint32_t max_records, size_t max_bytes)
{
    uint32_t n = 0;
    size_t used = 0;
    size_t off;

    ogs_assert(file && out && out_used);
    file->pending_batch_start = file->send_offset;
    off = file->send_offset;

    while (n < max_records && off + CDR_RECORD_HDR_LEN <= file->data_len) {
        uint8_t *h = file->data + off;
        uint16_t rec_len;
        size_t framed_len;

        if (memcmp(h, CDR_FILE_MAGIC, 4) != 0 ||
                h[4] != CDR_FILE_VERSION ||
                !ogs_cdr_format_is_valid(h[5])) {
            ogs_error("cgf: corrupt framing in '%s' at offset %zu",
                    file->path, off);
            /* Treat the rest of the file as lost; the caller will
             * quarantine on next ACK attempt. */
            break;
        }
        rec_len = (uint16_t)((h[6] << 8) | h[7]);
        if (off + CDR_RECORD_HDR_LEN + rec_len > file->data_len) {
            ogs_error("cgf: truncated record in '%s' at offset %zu",
                    file->path, off);
            break;
        }

        /* On the wire each record inside IE 252 is prefixed by its
         * own 2-byte big-endian length, so the stager emits that
         * length + record body. The caller (gtpp-path) only needs
         * to prepend the 4-byte sub-header once for the whole batch. */
        framed_len = 2u + rec_len;
        if (used + framed_len > out_cap) break;
        if (used + framed_len > max_bytes && n > 0) break;

        out[used + 0] = (uint8_t)(rec_len >> 8);
        out[used + 1] = (uint8_t)(rec_len & 0xff);
        memcpy(out + used + 2, h + CDR_RECORD_HDR_LEN, rec_len);
        used += framed_len;
        off += CDR_RECORD_HDR_LEN + rec_len;
        n++;
    }

    file->pending_batch_records = n;
    *out_used = used;
    return n;
}

static size_t offset_after_records(
        const cgf_spool_file_t *file, size_t start, uint32_t records)
{
    size_t off = start;
    uint32_t i;

    for (i = 0; i < records; i++) {
        const uint8_t *h;
        uint16_t rl;

        if (off + CDR_RECORD_HDR_LEN > file->data_len)
            return file->data_len;
        h = file->data + off;
        rl = (uint16_t)((h[6] << 8) | h[7]);
        if (off + CDR_RECORD_HDR_LEN + rl > file->data_len)
            return file->data_len;
        off += CDR_RECORD_HDR_LEN + rl;
    }
    return off;
}

static void move_to(cgf_spool_file_t *file, const char *dstdir)
{
    const char *base = strrchr(file->path, '/');
#ifdef _WIN32
    { const char *bb = strrchr(file->path, '\\'); if (bb > base) base = bb; }
#endif
    base = base ? base + 1 : file->path;
    {
        char dst[512];
        ogs_snprintf(dst, sizeof(dst), "%s/%s", dstdir, base);
        if (rename(file->path, dst) != 0) {
            ogs_warn("cgf: rename '%s' -> '%s' failed: %s",
                    file->path, dst, strerror(errno));
        }
    }
}

void cgf_spool_commit_send(cgf_spool_file_t *file,
        size_t batch_start, uint32_t records)
{
    ogs_assert(file);
    file->send_offset = offset_after_records(file, batch_start, records);
    file->pending_batch_records = 0;
    file->inflight_batches++;
}

static void drain_pending_acks(cgf_spool_file_t *file)
{
    bool advanced;

    do {
        uint32_t i;

        advanced = false;
        for (i = 0; i < file->num_pending_acks; i++) {
            cgf_spool_pending_ack_t *pa = &file->pending_acks[i];

            if (pa->batch_start != file->next_record_offset)
                continue;

            file->next_record_offset = offset_after_records(
                    file, pa->batch_start, pa->records);
            if (i + 1 < file->num_pending_acks) {
                memmove(&file->pending_acks[i],
                        &file->pending_acks[i + 1],
                        (file->num_pending_acks - i - 1) *
                        sizeof(*file->pending_acks));
            }
            file->num_pending_acks--;
            advanced = true;
            break;
        }
    } while (advanced);
}

static void maybe_finish_file(cgf_spool_file_t *file)
{
    if (!file) return;
    if (file->next_record_offset < file->data_len) return;
    if (file->inflight_batches > 0) return;

    /*
     * Retention policy for fully-acked files:
     *   cgf.purge_on_success=true  -> unlink (keeps disk bounded)
     *   cgf.purge_on_success=false -> move to done/ (default, legacy)
     */
    if (cgf_self()->purge_on_success) {
            if (unlink(file->path) != 0) {
                ogs_warn("cgf: fully delivered '%s' but unlink failed: %s "
                        "(file kept in ready/; will be re-sent on next "
                        "sweep if still present)",
                        file->path, strerror(errno));
            } else {
                ogs_info("cgf: fully delivered '%s' (purged)", file->path);
            }
    } else {
        ogs_info("cgf: fully delivered '%s', moving to done/",
                file->path);
        move_to(file, cgf_self()->done_dir);
    }
    if (file == g_active) g_active = NULL;
    spool_clear_cached_next();
    spool_clear_empty_backoff();
    free_file(file);
}

static bool pending_ack_exists(const cgf_spool_file_t *file,
        size_t batch_start)
{
    uint32_t i;

    for (i = 0; i < file->num_pending_acks; i++) {
        if (file->pending_acks[i].batch_start == batch_start)
            return true;
    }
    return false;
}

bool cgf_spool_ack_batch(cgf_spool_file_t *file,
        size_t batch_start, uint32_t records)
{
    ogs_assert(file);

    file->pending_batch_records = 0;
    if (file->inflight_batches > 0)
        file->inflight_batches--;

    if (batch_start < file->next_record_offset) {
        ogs_debug("cgf: duplicate DTRR ack for '%s' at offset %zu "
                "(confirmed through %zu)",
                file->path, batch_start, file->next_record_offset);
        maybe_finish_file(file);
        return true;
    }

    if (batch_start == file->next_record_offset) {
        file->next_record_offset = offset_after_records(
                file, batch_start, records);
        drain_pending_acks(file);
        maybe_finish_file(file);
        return true;
    }

    if (pending_ack_exists(file, batch_start)) {
        ogs_debug("cgf: duplicate buffered DTRR ack for '%s' at offset %zu",
                file->path, batch_start);
        maybe_finish_file(file);
        return true;
    }

    if (file->num_pending_acks >= CGF_MAX_INFLIGHT) {
        ogs_error("cgf: pending DTRR ack buffer full for '%s'",
                file->path);
        return false;
    }

    ogs_debug("cgf: buffered out-of-order DTRR ack for '%s' "
            "(got offset %zu, confirmed through %zu)",
            file->path, batch_start, file->next_record_offset);
    file->pending_acks[file->num_pending_acks].batch_start = batch_start;
    file->pending_acks[file->num_pending_acks].records = records;
    file->num_pending_acks++;
    maybe_finish_file(file);
    return true;
}

void cgf_spool_nack_batch(cgf_spool_file_t *file)
{
    ogs_assert(file);
    file->send_offset = file->next_record_offset;
    file->pending_batch_records = 0;
    file->inflight_batches = 0;
    file->num_pending_acks = 0;
}

void cgf_spool_quarantine(cgf_spool_file_t *file)
{
    if (!file) return;
    ogs_warn("cgf: quarantining '%s'", file->path);
    move_to(file, cgf_self()->failed_dir);
    if (file == g_active) {
        g_active = NULL;
        spool_clear_cached_next();
    }
    spool_clear_empty_backoff();
    free_file(file);
}

void cgf_spool_close(void)
{
    if (g_active) { free_file(g_active); g_active = NULL; }
    spool_reset_scan_state();
}
