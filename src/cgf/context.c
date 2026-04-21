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

#include "context.h"

#include "ogs-app.h"
#include <errno.h>
#include <strings.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define cgf_mkdir(p) _mkdir(p)
#else
#define cgf_mkdir(p) mkdir((p), 0755)
#endif

int __cgf_log_domain;

static cgf_context_t self;
static bool initialized = false;

cgf_context_t *cgf_self(void) { return &self; }

int cgf_context_init(void)
{
    ogs_assert(!initialized);
    memset(&self, 0, sizeof(self));

    ogs_log_install_domain(&__cgf_log_domain, "cgf", ogs_core()->log.level);

    /* Tunable defaults. See cgf.yaml.in for the user-facing description. */
    self.echo_interval_s = 60;
    self.request_rto_ms = 3000;
    self.request_retries = 4;
    self.failover_after_missed_echoes = 3;
    self.spool_poll_ms = 1000;
    self.max_records_per_packet = 5;
    self.max_bytes_per_packet = 1300;
    self.purge_on_success = false;

    /* DRP IE sub-header defaults. Matches the working peer capture:
     *   01        Data Record Format = BER
     *   19 06     Format Version = 0x1906
     * (No App ID / Release Id field — real CGFs don't expect one.) */
    self.drp_data_record_format = 1;
    self.drp_data_record_format_version = 0x1906;

    initialized = true;
    return OGS_OK;
}

void cgf_context_final(void)
{
    uint32_t i;

    if (!initialized) return;

    for (i = 0; i < self.num_of_peers; i++) {
        cgf_peer_t *p = &self.peers[i];
        if (p->addr) ogs_freeaddrinfo(p->addr);
        if (p->sock) ogs_sock_destroy(p->sock);
        if (p->xact.pkbuf) ogs_pkbuf_free(p->xact.pkbuf);
        memset(p, 0, sizeof(*p));
    }

    if (self.ready_dir) ogs_free(self.ready_dir);
    if (self.done_dir) ogs_free(self.done_dir);
    if (self.failed_dir) ogs_free(self.failed_dir);

    memset(&self, 0, sizeof(self));
    initialized = false;
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
            if (cgf_mkdir(copy) != 0 && errno != EEXIST) {
                rc = OGS_ERROR;
                *p = saved;
                break;
            }
            *p = saved;
        }
    }
    if (rc == OGS_OK && cgf_mkdir(copy) != 0 && errno != EEXIST)
        rc = OGS_ERROR;

    ogs_free(copy);
    return rc;
}

static int parse_peer_block(yaml_document_t *document,
        ogs_yaml_iter_t *peer_iter)
{
    cgf_peer_t *peer;
    const char *addr = NULL;
    uint16_t port = CGF_DEFAULT_GTPP_PORT;
    cgf_peer_role_e role = CGF_PEER_ROLE_PRIMARY;

    if (self.num_of_peers >= CGF_MAX_PEERS) {
        ogs_error("cgf: too many peers (max %d)", CGF_MAX_PEERS);
        return OGS_ERROR;
    }

    while (ogs_yaml_iter_next(peer_iter)) {
        const char *k = ogs_yaml_iter_key(peer_iter);
        const char *v = ogs_yaml_iter_value(peer_iter);
        if (!k) continue;
        if (!strcmp(k, "address")) addr = v;
        else if (!strcmp(k, "port")) { if (v) port = (uint16_t)atoi(v); }
        else if (!strcmp(k, "role")) {
            if (v && !strcmp(v, "secondary"))
                role = CGF_PEER_ROLE_SECONDARY;
        } else ogs_warn("cgf: unknown peer key `%s`", k);
    }

    if (!addr) {
        ogs_error("cgf: peer entry missing `address`");
        return OGS_ERROR;
    }

    peer = &self.peers[self.num_of_peers++];
    peer->address_str = addr;
    peer->port = port;
    peer->role = role;
    peer->state = CGF_PEER_STATE_DOWN;
    peer->next_seq = (uint16_t)(ogs_random32() & 0xffff);
    return OGS_OK;
}

int cgf_context_parse_config(void)
{
    yaml_document_t *document;
    ogs_yaml_iter_t root_iter;
    char path[512];

    document = ogs_app()->document;
    ogs_assert(document);

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        if (strcmp(root_key, "cgf") != 0) continue;

        ogs_yaml_iter_t cgf_iter;
        ogs_yaml_iter_recurse(&root_iter, &cgf_iter);
        while (ogs_yaml_iter_next(&cgf_iter)) {
            const char *k = ogs_yaml_iter_key(&cgf_iter);
            if (!k) continue;

            /* ogs_yaml_iter_value() asserts that the current node is a
             * YAML_SCALAR_NODE — calling it on `peer:` (sequence) or
             * `timers:`/`batch:` (mappings) aborts the process. Only
             * pull the scalar value for the scalar-valued keys. */
            if (!strcmp(k, "spool_dir") || !strcmp(k, "directory")) {
                self.spool_dir = ogs_yaml_iter_value(&cgf_iter);
            } else if (!strcmp(k, "node_id")) {
                self.node_id = ogs_yaml_iter_value(&cgf_iter);
            } else if (!strcmp(k, "purge_on_success")) {
                const char *v = ogs_yaml_iter_value(&cgf_iter);
                /* Accept the usual YAML truthy spellings. */
                if (v && (!strcasecmp(v, "true") || !strcasecmp(v, "yes") ||
                          !strcmp(v, "1") || !strcasecmp(v, "on")))
                    self.purge_on_success = true;
                else
                    self.purge_on_success = false;
            } else if (!strcmp(k, "peer")) {
                ogs_yaml_iter_t arr, it;
                ogs_yaml_iter_recurse(&cgf_iter, &arr);
                do {
                    OGS_YAML_ARRAY_NEXT(&arr, &it);
                    if (parse_peer_block(document, &it) != OGS_OK)
                        return OGS_ERROR;
                } while (ogs_yaml_iter_type(&arr) == YAML_SEQUENCE_NODE);
            } else if (!strcmp(k, "timers")) {
                ogs_yaml_iter_t t_iter;
                ogs_yaml_iter_recurse(&cgf_iter, &t_iter);
                while (ogs_yaml_iter_next(&t_iter)) {
                    const char *tk = ogs_yaml_iter_key(&t_iter);
                    const char *tv = ogs_yaml_iter_value(&t_iter);
                    if (!tk || !tv) continue;
                    if (!strcmp(tk, "echo_interval_s"))
                        self.echo_interval_s = (uint32_t)atoi(tv);
                    else if (!strcmp(tk, "request_rto_ms"))
                        self.request_rto_ms = (uint32_t)atoi(tv);
                    else if (!strcmp(tk, "request_retries"))
                        self.request_retries = (uint32_t)atoi(tv);
                    else if (!strcmp(tk, "failover_after_missed_echoes"))
                        self.failover_after_missed_echoes =
                                (uint32_t)atoi(tv);
                    else if (!strcmp(tk, "spool_poll_ms"))
                        self.spool_poll_ms = (uint32_t)atoi(tv);
                    else ogs_warn("cgf: unknown timer `%s`", tk);
                }
            } else if (!strcmp(k, "batch")) {
                ogs_yaml_iter_t b_iter;
                ogs_yaml_iter_recurse(&cgf_iter, &b_iter);
                while (ogs_yaml_iter_next(&b_iter)) {
                    const char *bk = ogs_yaml_iter_key(&b_iter);
                    const char *bv = ogs_yaml_iter_value(&b_iter);
                    if (!bk || !bv) continue;
                    if (!strcmp(bk, "max_records_per_packet"))
                        self.max_records_per_packet = (uint32_t)atoi(bv);
                    else if (!strcmp(bk, "max_bytes_per_packet"))
                        self.max_bytes_per_packet = (uint32_t)atoi(bv);
                    else ogs_warn("cgf: unknown batch `%s`", bk);
                }
            } else if (!strcmp(k, "drp")) {
                /* Data Record Packet sub-header overrides. All keys
                 * accept decimal or 0x-prefixed hex via strtoul(). */
                ogs_yaml_iter_t d_iter;
                ogs_yaml_iter_recurse(&cgf_iter, &d_iter);
                while (ogs_yaml_iter_next(&d_iter)) {
                    const char *dk = ogs_yaml_iter_key(&d_iter);
                    const char *dv = ogs_yaml_iter_value(&d_iter);
                    if (!dk || !dv) continue;
                    unsigned long n = strtoul(dv, NULL, 0);
                    if (!strcmp(dk, "data_record_format"))
                        self.drp_data_record_format = (uint8_t)n;
                    else if (!strcmp(dk, "data_record_format_version"))
                        self.drp_data_record_format_version = (uint16_t)n;
                    else ogs_warn("cgf: unknown drp `%s`", dk);
                }
            } else {
                ogs_warn("cgf: unknown key `%s`", k);
            }
        }
    }

    /* Sanity-check and prepare derived paths. */
    if (!self.spool_dir || !*self.spool_dir) {
        ogs_error("cgf: `cgf.spool_dir` is required");
        return OGS_ERROR;
    }
    if (self.num_of_peers == 0) {
        ogs_error("cgf: at least one peer must be configured");
        return OGS_ERROR;
    }

    ogs_snprintf(path, sizeof(path), "%s/ready", self.spool_dir);
    self.ready_dir = ogs_strdup(path);
    ogs_snprintf(path, sizeof(path), "%s/done", self.spool_dir);
    self.done_dir = ogs_strdup(path);
    ogs_snprintf(path, sizeof(path), "%s/failed", self.spool_dir);
    self.failed_dir = ogs_strdup(path);

    if (mkdir_p(self.done_dir) != OGS_OK) {
        ogs_warn("cgf: cannot create '%s'", self.done_dir);
    }
    if (mkdir_p(self.failed_dir) != OGS_OK) {
        ogs_warn("cgf: cannot create '%s'", self.failed_dir);
    }

    /* Primary always wins the initial active slot, regardless of order
     * in the config file. */
    {
        uint32_t i;
        self.active_peer_idx = 0;
        for (i = 0; i < self.num_of_peers; i++) {
            if (self.peers[i].role == CGF_PEER_ROLE_PRIMARY) {
                self.active_peer_idx = i;
                break;
            }
        }
    }

    return OGS_OK;
}
