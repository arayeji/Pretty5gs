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
 * Spool scan state — ready/ can hold 100k+ files. A full readdir on
 * every spool_poll tick was costing ~10% CPU. We keep a lexicographic
 * cursor (last handled basename), cache the next validated path, and
 * back off when the directory is empty.
 */
static char g_last_handled_base[256];
static bool g_last_handled_valid;
static char g_cached_next_path[512];
static ogs_time_t g_empty_until;

#define CGF_SPOOL_EMPTY_BACKOFF_MAX_MS 30000

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

static void spool_remember_handled(const char *path)
{
    const char *base = path_basename(path);
    ogs_snprintf(g_last_handled_base, sizeof(g_last_handled_base),
            "%s", base);
    g_last_handled_valid = (g_last_handled_base[0] != '\0');
    spool_clear_cached_next();
}

static void spool_reset_scan_state(void)
{
    g_last_handled_valid = false;
    g_last_handled_base[0] = '\0';
    spool_clear_cached_next();
    g_empty_until = 0;
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

static void spool_mark_empty(void)
{
    uint32_t poll_ms = cgf_self()->spool_poll_ms;
    static uint32_t empty_backoff_ms;
    ogs_time_t delay;

    if (!poll_ms) poll_ms = 1000;
    if (!empty_backoff_ms) empty_backoff_ms = poll_ms * 5;
    else if (empty_backoff_ms < CGF_SPOOL_EMPTY_BACKOFF_MAX_MS)
        empty_backoff_ms *= 2;
    if (empty_backoff_ms > CGF_SPOOL_EMPTY_BACKOFF_MAX_MS)
        empty_backoff_ms = CGF_SPOOL_EMPTY_BACKOFF_MAX_MS;

    delay = ogs_time_from_msec(empty_backoff_ms);
    g_empty_until = ogs_time_now() + delay;
    spool_clear_cached_next();
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

static int find_next_cdr(char *out_path, size_t out_cap,
        const char *after_base)
{
    /* Return the lexicographically smallest *.cdr in ready/, or — when
     * after_base is set — the smallest name strictly greater than it.
     * Filenames carry an epoch prefix so this matches insertion order. */
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char pattern[512];
    char best[256] = "";
    ogs_snprintf(pattern, sizeof(pattern), "%s\\*.cdr",
            cgf_self()->ready_dir);
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return OGS_ERROR;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!spool_is_cdr_name(fd.cFileName)) continue;
        if (after_base && after_base[0] &&
                strcmp(fd.cFileName, after_base) <= 0)
            continue;
        if (best[0] == '\0' || strcmp(fd.cFileName, best) < 0)
            ogs_snprintf(best, sizeof(best), "%s", fd.cFileName);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    if (best[0] == '\0') return OGS_ERROR;
    ogs_snprintf(out_path, out_cap, "%s/%s", cgf_self()->ready_dir, best);
    return OGS_OK;
#else
    DIR *d;
    struct dirent *ent;
    char best[256] = "";

    d = opendir(cgf_self()->ready_dir);
    if (!d) return OGS_ERROR;

    while ((ent = readdir(d)) != NULL) {
        if (!spool_is_cdr_name(ent->d_name)) continue;
        if (after_base && after_base[0] &&
                strcmp(ent->d_name, after_base) <= 0)
            continue;
        if (best[0] == '\0' || strcmp(ent->d_name, best) < 0)
            ogs_snprintf(best, sizeof(best), "%s", ent->d_name);
    }
    closedir(d);

    if (best[0] == '\0') return OGS_ERROR;
    ogs_snprintf(out_path, out_cap, "%s/%s", cgf_self()->ready_dir, best);
    return OGS_OK;
#endif
}

static int pick_next_path(char *out_path, size_t out_cap)
{
    const char *after = g_last_handled_valid ? g_last_handled_base : NULL;

    if (g_cached_next_path[0] && spool_path_ready(g_cached_next_path)) {
        ogs_snprintf(out_path, out_cap, "%s", g_cached_next_path);
        return OGS_OK;
    }

    spool_clear_cached_next();
    if (find_next_cdr(out_path, out_cap, after) != OGS_OK)
        return OGS_ERROR;

    ogs_snprintf(g_cached_next_path, sizeof(g_cached_next_path),
            "%s", out_path);
    return OGS_OK;
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
        spool_remember_handled(path);
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
            spool_remember_handled(path);
            return false;
        }
    }

    f = ogs_calloc(1, sizeof(*f));
    ogs_assert(f);
    f->path = ogs_strdup(path);
    f->data = data;
    f->data_len = data_len;
    f->next_record_offset = 0;
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
    file->pending_batch_start = file->next_record_offset;
    off = file->next_record_offset;

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

void cgf_spool_ack_batch(cgf_spool_file_t *file)
{
    ogs_assert(file);
    file->next_record_offset += 0; /* intentionally a no-op; we already
                                      advanced while staging */
    {
        /* Compute the new cursor: sum over pending batch records. */
        size_t off = file->pending_batch_start;
        uint32_t i;
        for (i = 0; i < file->pending_batch_records; i++) {
            uint8_t *h = file->data + off;
            uint16_t rl = (uint16_t)((h[6] << 8) | h[7]);
            off += CDR_RECORD_HDR_LEN + rl;
        }
        file->next_record_offset = off;
    }
    file->pending_batch_records = 0;

    if (file->next_record_offset >= file->data_len) {
        /*
         * Retention policy for fully-acked files:
         *   cgf.purge_on_success=true  -> unlink (keeps disk bounded)
         *   cgf.purge_on_success=false -> move to done/ (default, legacy)
         *
         * We still free the in-memory cgf_spool_file_t in both paths.
         * unlink() is best-effort: a failure (EACCES, etc.) logs a
         * warning but is not fatal; the next sweep will NOT re-pick the
         * file because the spool poller only scans ready/.
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
        spool_remember_handled(file->path);
        spool_clear_empty_backoff();
        free_file(file);
    }
}

void cgf_spool_nack_batch(cgf_spool_file_t *file)
{
    ogs_assert(file);
    /* Cursor hasn't advanced (we advance only on ACK), so NACK is a
     * no-op on the file itself. Callers typically follow up by closing
     * the active file (freeing g_active) so the next refill picks it
     * back up once the peer comes back. */
    file->pending_batch_records = 0;
}

void cgf_spool_quarantine(cgf_spool_file_t *file)
{
    if (!file) return;
    ogs_warn("cgf: quarantining '%s'", file->path);
    move_to(file, cgf_self()->failed_dir);
    if (file == g_active) {
        g_active = NULL;
        spool_remember_handled(file->path);
    }
    spool_clear_empty_backoff();
    free_file(file);
}

void cgf_spool_close(void)
{
    if (g_active) { free_file(g_active); g_active = NULL; }
    spool_reset_scan_state();
}
