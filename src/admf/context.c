/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "context.h"

#include <stdlib.h>
#include <string.h>

int __admf_log_domain;

static admf_context_t self;
static bool initialized = false;

admf_context_t *admf_self(void)
{
    return &self;
}

int admf_context_init(void)
{
    ogs_assert(!initialized);
    memset(&self, 0, sizeof(self));

    ogs_log_install_domain(&__admf_log_domain, "admf", ogs_core()->log.level);

    self.hi1_port = 9051;
    ogs_cpystrn(self.hi2_spool_dir, "/var/spool/open5gs/hi2",
            sizeof(self.hi2_spool_dir));

    ogs_li_target_set_init(&self.targets, OGS_LI_MAX_TARGETS);

    initialized = true;
    return OGS_OK;
}

void admf_context_final(void)
{
    if (!initialized)
        return;

    ogs_li_target_set_final(&self.targets);

    if (self.hi1_addr)
        ogs_freeaddrinfo(self.hi1_addr);

    memset(&self, 0, sizeof(self));
    initialized = false;
}

static int admf_x1_peer_add(const char *name, ogs_yaml_iter_t *iter)
{
    admf_x1_peer_t *peer = NULL;
    ogs_sockaddr_t *addr = NULL;
    const char *host = NULL;
    uint16_t port = 9090;

    ogs_assert(name);
    ogs_assert(iter);

    if (self.num_x1_peers >= ADMF_MAX_X1_PEERS) {
        ogs_error("ADMF X1 peer limit reached");
        return OGS_ERROR;
    }

    peer = &self.x1_peers[self.num_x1_peers++];
    ogs_cpystrn(peer->name, name, sizeof(peer->name));

    while (ogs_yaml_iter_next(iter)) {
        const char *key = ogs_yaml_iter_key(iter);
        ogs_assert(key);

        if (!strcmp(key, "addr") || !strcmp(key, "address")) {
            yaml_node_t *node =
                yaml_document_get_node(iter->document, iter->pair->value);
            ogs_assert(node);
            if (node->type == YAML_SCALAR_NODE) {
                host = (char *)node->data.scalar.value;
                ogs_assert(OGS_OK == ogs_addaddrinfo(&addr, AF_UNSPEC,
                            host, port, 0));
            }
        } else if (!strcmp(key, "port")) {
            const char *v = ogs_yaml_iter_value(iter);
            if (v)
                port = (uint16_t)atoi(v);
        }
    }

    if (!addr && host) {
        ogs_assert(OGS_OK == ogs_addaddrinfo(&addr, AF_UNSPEC, host, port, 0));
    }

    if (!addr) {
        ogs_error("ADMF X1 peer [%s]: missing addr", peer->name);
        self.num_x1_peers--;
        return OGS_ERROR;
    }

    peer->peer.addr = addr;
    peer->peer.port = port;
    ogs_cpystrn(peer->peer.host, host ? host : "127.0.0.1",
            sizeof(peer->peer.host));

    ogs_info("ADMF X1 peer [%s] %s:%u", peer->name,
            peer->peer.host, (unsigned)peer->peer.port);
    return OGS_OK;
}

int admf_context_parse_config(void)
{
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_app()->document;
    ogs_assert(document);

    ogs_yaml_iter_init(&root_iter, document);

    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);

        if (!strcmp(root_key, "admf")) {
            ogs_yaml_iter_t admf_iter;
            ogs_yaml_iter_recurse(&root_iter, &admf_iter);

            while (ogs_yaml_iter_next(&admf_iter)) {
                const char *admf_key = ogs_yaml_iter_key(&admf_iter);
                ogs_assert(admf_key);

                if (!strcmp(admf_key, "hi1")) {
                    ogs_yaml_iter_t hi1_iter;
                    ogs_yaml_iter_recurse(&admf_iter, &hi1_iter);

                    while (ogs_yaml_iter_next(&hi1_iter)) {
                        const char *hi1_key = ogs_yaml_iter_key(&hi1_iter);
                        ogs_assert(hi1_key);

                        if (!strcmp(hi1_key, "addr") ||
                                !strcmp(hi1_key, "address")) {
                            yaml_node_t *node = yaml_document_get_node(
                                    hi1_iter.document, hi1_iter.pair->value);
                            ogs_assert(node);
                            if (node->type == YAML_SCALAR_NODE) {
                                const char *v =
                                    (char *)node->data.scalar.value;
                                ogs_assert(OGS_OK == ogs_addaddrinfo(
                                            &self.hi1_addr, AF_UNSPEC,
                                            v, self.hi1_port, 0));
                            }
                        } else if (!strcmp(hi1_key, "port")) {
                            const char *v = ogs_yaml_iter_value(&hi1_iter);
                            if (v)
                                self.hi1_port = (uint16_t)atoi(v);
                        }
                    }
                } else if (!strcmp(admf_key, "mdf2")) {
                    ogs_yaml_iter_t mdf_iter;
                    ogs_yaml_iter_recurse(&admf_iter, &mdf_iter);

                    while (ogs_yaml_iter_next(&mdf_iter)) {
                        const char *mdf_key = ogs_yaml_iter_key(&mdf_iter);
                        ogs_assert(mdf_key);

                        if (!strcmp(mdf_key, "hi2_spool_dir")) {
                            ogs_cpystrn(self.hi2_spool_dir,
                                    ogs_yaml_iter_value(&mdf_iter),
                                    sizeof(self.hi2_spool_dir));
                        }
                    }
                } else if (!strcmp(admf_key, "x1")) {
                    ogs_yaml_iter_t x1_iter;
                    ogs_yaml_iter_recurse(&admf_iter, &x1_iter);

                    while (ogs_yaml_iter_next(&x1_iter)) {
                        const char *peer_name = ogs_yaml_iter_key(&x1_iter);
                        ogs_yaml_iter_t peer_iter;
                        ogs_assert(peer_name);

                        ogs_yaml_iter_recurse(&x1_iter, &peer_iter);
                        admf_x1_peer_add(peer_name, &peer_iter);
                    }
                }
            }
        }
    }

    if (!self.hi1_addr) {
        ogs_assert(OGS_OK == ogs_addaddrinfo(
                    &self.hi1_addr, AF_UNSPEC,
                    "0.0.0.0", self.hi1_port, 0));
    }

    ogs_info("ADMF HI1 listen %u, HI2 spool [%s]",
            (unsigned)self.hi1_port, self.hi2_spool_dir);
    return OGS_OK;
}
