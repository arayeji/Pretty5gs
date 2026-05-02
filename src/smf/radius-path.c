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

#include "radius-path.h"
#include "local-path.h"
#include "gtp-path.h"
#include "pfcp-path.h"

#include <openssl/evp.h>

#ifndef _WIN32
#include <sys/time.h>
#endif

/* ------------------------------------------------------------------ */
/* RADIUS codes and attributes                                        */
/* ------------------------------------------------------------------ */

/* RFC 2865 / 2866 codes */
#define RADIUS_CODE_ACCESS_REQUEST          1
#define RADIUS_CODE_ACCESS_ACCEPT           2
#define RADIUS_CODE_ACCESS_REJECT           3
#define RADIUS_CODE_ACCOUNTING_REQUEST      4
#define RADIUS_CODE_ACCOUNTING_RESPONSE     5

/* RFC 5176 (Dynamic Authorization Extensions) codes */
#define RADIUS_CODE_DISCONNECT_REQUEST      40
#define RADIUS_CODE_DISCONNECT_ACK          41
#define RADIUS_CODE_DISCONNECT_NAK          42
#define RADIUS_CODE_COA_REQUEST             43
#define RADIUS_CODE_COA_ACK                 44
#define RADIUS_CODE_COA_NAK                 45

/* Attributes */
#define RADIUS_ATTR_USER_NAME               1
#define RADIUS_ATTR_NAS_IP_ADDRESS          4
#define RADIUS_ATTR_NAS_PORT                5
#define RADIUS_ATTR_SERVICE_TYPE            6
#define RADIUS_ATTR_FRAMED_PROTOCOL         7
#define RADIUS_ATTR_FRAMED_IP_ADDRESS       8
#define RADIUS_ATTR_FRAMED_IP_NETMASK       9
#define RADIUS_ATTR_FRAMED_ROUTE            22
#define RADIUS_ATTR_FRAMED_IPV6_ROUTE       99
#define RADIUS_ATTR_VENDOR_SPECIFIC         26
#define RADIUS_ATTR_CALLED_STATION_ID       30
#define RADIUS_ATTR_CALLING_STATION_ID      31
#define RADIUS_ATTR_NAS_IDENTIFIER          32
#define RADIUS_ATTR_CLASS                   25
#define RADIUS_ATTR_ACCT_STATUS_TYPE        40
#define RADIUS_ATTR_ACCT_DELAY_TIME         41
#define RADIUS_ATTR_ACCT_INPUT_OCTETS       42
#define RADIUS_ATTR_ACCT_OUTPUT_OCTETS      43
#define RADIUS_ATTR_ACCT_SESSION_ID         44
#define RADIUS_ATTR_ACCT_AUTHENTIC          45
#define RADIUS_ATTR_ACCT_SESSION_TIME       46
#define RADIUS_ATTR_ACCT_INPUT_PACKETS      47
#define RADIUS_ATTR_ACCT_OUTPUT_PACKETS     48
#define RADIUS_ATTR_ACCT_TERMINATE_CAUSE    49
#define RADIUS_ATTR_NAS_PORT_TYPE           61
#define RADIUS_ATTR_ACCT_INTERIM_INTERVAL   85
#define RADIUS_ATTR_ACCT_INPUT_GIGAWORDS    52
#define RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS   53
#define RADIUS_ATTR_FRAMED_IPV6_PREFIX      97

/* RFC 5176 error cause */
#define RADIUS_ATTR_ERROR_CAUSE             101

/* 3GPP VSAs (TS 29.061 ?16.4) */
#define RADIUS_VENDOR_3GPP                  10415
#define RADIUS_3GPP_IMSI                    1
#define RADIUS_3GPP_IMEISV                  20
#define RADIUS_3GPP_USER_LOCATION_INFO      22

/* 3GPP-User-Location-Info Geographic Location Type (TS 29.061 ?16.4.7.2). */
#define RADIUS_3GPP_ULI_TYPE_CGI            0
#define RADIUS_3GPP_ULI_TYPE_TAI            128
#define RADIUS_3GPP_ULI_TYPE_ECGI           129
#define RADIUS_3GPP_ULI_TYPE_TAI_ECGI       130
#define RADIUS_3GPP_ULI_TYPE_TAI_NCGI       136

/* Acct-Status-Type values (RFC 2866) */
#define RADIUS_ACCT_STATUS_START            1
#define RADIUS_ACCT_STATUS_STOP             2
#define RADIUS_ACCT_STATUS_INTERIM_UPDATE   3

/* Acct-Terminate-Cause values (RFC 2866 ?5.10) */
#define RADIUS_TERM_USER_REQUEST            1
#define RADIUS_TERM_LOST_CARRIER            2
#define RADIUS_TERM_IDLE_TIMEOUT            4
#define RADIUS_TERM_SESSION_TIMEOUT         5
#define RADIUS_TERM_ADMIN_RESET             6
#define RADIUS_TERM_ADMIN_REBOOT            7
#define RADIUS_TERM_NAS_ERROR               9
#define RADIUS_TERM_NAS_REQUEST             10
#define RADIUS_TERM_NAS_REBOOT              11

/* RFC 5176 Error-Cause values (subset) */
#define RADIUS_ERR_CAUSE_SESSION_NOT_FOUND  503
#define RADIUS_ERR_CAUSE_ADMIN_PROHIBITED   501
#define RADIUS_ERR_CAUSE_MISSING_ATTR       402
#define RADIUS_ERR_CAUSE_UNSUPPORTED_SERVICE 405

#define RADIUS_SERVICE_TYPE_FRAMED          2
#define RADIUS_FRAMED_PROTOCOL_PPP          1
#define RADIUS_NAS_PORT_TYPE_WIRELESS_OTHER 23

#define RADIUS_PACKET_MAX                   4096
#define RADIUS_HDR_LEN                      20

#define RADIUS_DEFAULT_POD_PORT             3799

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __smf_log_domain

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static void sock_set_rcv_timeout(ogs_socket_t fd, unsigned ms)
{
#if defined(_WIN32)
    DWORD t = ms;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof(t));
#else
    struct timeval tv;

    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
#endif
}

static const char *radius_username(smf_ue_t *ue)
{
    ogs_assert(ue);
    if (ue->imsi_bcd[0])
        return ue->imsi_bcd;
    if (ue->supi && strncmp(ue->supi, "imsi-", 5) == 0)
        return ue->supi + 5;
    return ue->supi;
}

static uint32_t radius_pick_nas_ipv4(void)
{
    ogs_sbi_server_t *server = NULL;
    uint32_t addr_be;

    /* 1) Operator-configured radius.nas_ip wins. */
    if (smf_self()->radius.nas_ip) {
        if (ogs_ipv4_from_string(&addr_be,
                    smf_self()->radius.nas_ip) == OGS_OK)
            return addr_be;
        ogs_warn("radius.nas_ip is not a valid IPv4 address");
    }

    /* 2) First IPv4 SBI server address (present on 5GC deployments). */
    ogs_list_for_each(&ogs_sbi_self()->server_list, server) {
        ogs_sockaddr_t *a =
            server->advertise ? server->advertise : server->node.addr;

        for (; a; a = a->next) {
            if (a->ogs_sa_family == AF_INET)
                return a->sin.sin_addr.s_addr;
        }
    }

    /*
     * 3) Fall back to 127.0.0.1 so NAS-IP-Address is never missing.
     * Some AAA servers reject requests that lack NAS-IP-Address /
     * NAS-Identifier entirely. Warn once so the operator knows to set
     * radius.nas_ip explicitly.
     */
    {
        static bool warned = false;
        if (!warned) {
            ogs_warn("RADIUS: no NAS-IP-Address available, falling back "
                    "to 127.0.0.1; set smf.radius.nas_ip in smf.yaml");
            warned = true;
        }
    }
    addr_be = htobe32(0x7f000001);   /* 127.0.0.1 in network order */
    return addr_be;
}

static uint8_t *append_attr_raw(uint8_t *p, uint8_t type,
        const uint8_t *data, size_t dlen)
{
    ogs_assert(dlen <= 253);

    *p++ = type;
    *p++ = (uint8_t)(2 + dlen);
    if (dlen) memcpy(p, data, dlen);
    return p + dlen;
}

static uint8_t *append_attr_string(uint8_t *p, uint8_t type, const char *s)
{
    size_t sl;

    ogs_assert(p);
    ogs_assert(s);

    sl = strlen(s);
    return append_attr_raw(p, type, (const uint8_t *)s, sl);
}

static uint8_t *append_attr_u32_be(uint8_t *p, uint8_t type, uint32_t v_host)
{
    uint32_t v = htobe32(v_host);

    *p++ = type;
    *p++ = 6;
    memcpy(p, &v, sizeof(uint32_t));
    return p + sizeof(uint32_t);
}

static uint8_t *append_attr_ipv4(uint8_t *p, uint8_t type, uint32_t addr_be)
{
    *p++ = type;
    *p++ = 6;
    memcpy(p, &addr_be, 4);
    return p + 4;
}

static uint8_t *append_attr_framed_ipv6_prefix(uint8_t *p,
        const uint8_t *addr128, uint8_t prefix_len)
{
    uint8_t prefix_octets = (uint8_t)((prefix_len + 7) / 8);
    uint8_t alen = (uint8_t)(2 + 2 + 1 + prefix_octets);

    *p++ = RADIUS_ATTR_FRAMED_IPV6_PREFIX;
    *p++ = alen;
    memset(p, 0, 2);
    p += 2;
    *p++ = prefix_len;
    memcpy(p, addr128, prefix_octets);
    return p + prefix_octets;
}

/* Append a RADIUS Vendor-Specific (26) carrying a single sub-attribute.
 *   Vendor-Id (4) | Vendor-Type (1) | Vendor-Length (1) | Value (...)   */
static uint8_t *append_attr_vendor_bytes(uint8_t *p,
        uint32_t vendor_id, uint8_t vtype,
        const uint8_t *val, size_t val_len)
{
    uint32_t vendor_be = htobe32(vendor_id);
    uint8_t inner_len = (uint8_t)(2 + val_len);
    uint8_t outer_len = (uint8_t)(6 + inner_len);

    ogs_assert(val_len <= 240);

    *p++ = RADIUS_ATTR_VENDOR_SPECIFIC;
    *p++ = outer_len;
    memcpy(p, &vendor_be, 4);
    p += 4;
    *p++ = vtype;
    *p++ = inner_len;
    if (val_len)
        memcpy(p, val, val_len);
    return p + val_len;
}

static uint8_t *append_attr_vendor_string(uint8_t *p,
        uint32_t vendor_id, uint8_t vtype, const char *s)
{
    return append_attr_vendor_bytes(p, vendor_id, vtype,
            (const uint8_t *)s, strlen(s));
}

/* Re-emit the Class attribute chunks we saved from Access-Accept.
 * RFC 2865 ?5.25: Class attributes are opaque and must be echoed
 * unchanged. We split class_buf into up to 253-byte chunks. */
static uint8_t *append_class_attrs(uint8_t *p, const uint8_t *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        size_t chunk = len - off;

        if (chunk > 253) chunk = 253;
        p = append_attr_raw(p, RADIUS_ATTR_CLASS, buf + off, chunk);
        off += chunk;
    }
    return p;
}

static void md5_digest(const void *data, size_t len, uint8_t out[16])
{
    /*
     * Use the EVP API instead of the legacy MD5() function, which was
     * deprecated in OpenSSL 3.0. EVP_Digest is available on both 1.x and
     * 3.x and keeps us out of the legacy provider.
     */
    unsigned int out_len = 16;
    if (EVP_Digest(data, len, out, &out_len, EVP_md5(), NULL) != 1) {
        ogs_error("RADIUS: EVP_Digest(MD5) failed");
        memset(out, 0, 16);
    }
}

/* ------------------------------------------------------------------ */
/* Authenticator verification / computation                           */
/* ------------------------------------------------------------------ */

/* Verifies the Response Authenticator for Access-Accept/Reject/Challenge
 * and Accounting-Response / Disconnect-ACK/NAK / CoA-ACK/NAK.
 *   RespAuth = MD5(Code + ID + Length + RequestAuth + ResponseAttrs + Secret)
 */
static int radius_verify_response(const uint8_t *req_auth,
        const uint8_t *pkt, size_t pkt_len, const char *secret)
{
    uint8_t digest[16];
    uint8_t cat[RADIUS_PACKET_MAX + 256];
    size_t cat_len;
    size_t secret_len = strlen(secret);

    if (pkt_len < RADIUS_HDR_LEN)
        return OGS_ERROR;
    if (4 + 16 + (pkt_len - RADIUS_HDR_LEN) + secret_len > sizeof(cat))
        return OGS_ERROR;

    memcpy(cat, pkt, 4);
    memcpy(cat + 4, req_auth, 16);
    memcpy(cat + 20, pkt + RADIUS_HDR_LEN, pkt_len - RADIUS_HDR_LEN);
    cat_len = 4 + 16 + (pkt_len - RADIUS_HDR_LEN);
    memcpy(cat + cat_len, secret, secret_len);
    cat_len += secret_len;

    md5_digest(cat, cat_len, digest);
    return memcmp(digest, pkt + 4, 16) == 0 ? OGS_OK : OGS_ERROR;
}

/* Computes the Request-Authenticator for Accounting-Request (RFC 2866)
 * and Disconnect/CoA-Request (RFC 5176):
 *   ReqAuth = MD5(Code + ID + Length + 0*16 + RequestAttrs + Secret)
 * The packet must have its authenticator field zeroed before computation.
 */
static void radius_fill_request_authenticator(uint8_t *pkt, size_t len,
        const char *secret)
{
    uint8_t digest[16];
    uint8_t cat[RADIUS_PACKET_MAX + 256];
    size_t secret_len = strlen(secret);

    ogs_assert(len >= RADIUS_HDR_LEN);
    ogs_assert(len + secret_len <= sizeof(cat));

    memset(pkt + 4, 0, 16);
    memcpy(cat, pkt, len);
    memcpy(cat + len, secret, secret_len);
    md5_digest(cat, len + secret_len, digest);
    memcpy(pkt + 4, digest, 16);
}

/* ------------------------------------------------------------------ */
/* Attribute scanning helpers                                         */
/* ------------------------------------------------------------------ */

static const uint8_t *radius_find_attr(const uint8_t *attrs, size_t len,
        uint8_t type, uint8_t *out_len)
{
    const uint8_t *p = attrs;
    const uint8_t *end = attrs + len;

    while (p + 2 <= end) {
        uint8_t alen = p[1];

        if (alen < 2 || p + alen > end) return NULL;
        if (p[0] == type) {
            *out_len = alen;
            return p;
        }
        p += alen;
    }
    return NULL;
}

/*
 * Canonicalize a Framed-Route / Framed-IPv6-Route AVP value (RFC 2865
 * §5.22, RFC 3162 §2.4) into the CIDR form ("a.b.c.d/N" or
 * "2001:db8::/64") that lib/pfcp/build.c emits and that open5gs-upfd's
 * parse_framed_route() expects (it strsep()s on '/').
 *
 * Accepts:
 *   "10.0.0.0/24"                        -> "10.0.0.0/24"
 *   "10.0.0.0/24 192.0.2.1 1"            -> "10.0.0.0/24"
 *   "10.0.0.0 255.255.255.0"             -> "10.0.0.0/24"
 *   "10.0.0.0 255.255.255.0 0.0.0.0 1"   -> "10.0.0.0/24"
 *   "2001:db8::/64 fe80::1 1"            -> "2001:db8::/64"
 *
 * Writes the canonical form to out (size out_sz) and returns true.
 * Returns false on unparseable input.
 */
static bool radius_canon_framed_route(const uint8_t *val, size_t vlen,
        bool is_ipv6, char *out, size_t out_sz)
{
    char tmp[256];
    char *p, *tok_addr, *tok_mask, *save = NULL;
    size_t n;

    if (vlen == 0 || vlen >= sizeof(tmp))
        return false;

    memcpy(tmp, val, vlen);
    tmp[vlen] = '\0';

    /* RFC 2865 allows trailing CR/LF or garbage; trim. */
    for (p = tmp + vlen - 1; p >= tmp && (*p == ' ' || *p == '\t' ||
            *p == '\r' || *p == '\n'); p--)
        *p = '\0';
    /* Skip leading whitespace. */
    for (p = tmp; *p == ' ' || *p == '\t'; p++);
    if (!*p) return false;

    tok_addr = strtok_r(p, " \t", &save);
    if (!tok_addr) return false;

    /* Case 1: CIDR form already (contains '/'). Use as-is. */
    if (strchr(tok_addr, '/') != NULL) {
        n = strlen(tok_addr);
        if (n >= out_sz) return false;
        memcpy(out, tok_addr, n + 1);
        return true;
    }

    /* Case 2: legacy form "addr mask [gw [metric ...]]". Only meaningful
     * for IPv4; IPv6 always uses CIDR per RFC 3162. */
    if (is_ipv6) return false;

    tok_mask = strtok_r(NULL, " \t", &save);
    if (!tok_mask) return false;

    {
        struct in_addr mask_addr;
        uint32_t m;
        int prefix = 0;

        if (inet_pton(AF_INET, tok_mask, &mask_addr) != 1)
            return false;
        m = ntohl(mask_addr.s_addr);
        /* Count leading ones and verify the mask is contiguous. */
        while (m & 0x80000000u) { prefix++; m <<= 1; }
        if (m != 0) return false; /* non-contiguous mask */

        n = (size_t)snprintf(out, out_sz, "%s/%d", tok_addr, prefix);
        if (n >= out_sz) return false;
    }
    return true;
}

/* Parse Framed-IP-Address, Framed-IPv6-Prefix, Framed-Route,
 * Framed-IPv6-Route and Class AVPs from Access-Accept attributes
 * into the session. */
static int radius_parse_access_accept(smf_sess_t *sess,
        const uint8_t *attrs, size_t attrs_len)
{
    smf_ue_t *smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    const uint8_t *p = attrs;
    const uint8_t *end = attrs + attrs_len;
    bool got_v4 = false, got_v6 = false;
    /*
     * Framed-IP-Address is kept in network byte order, matching how the
     * rest of Open5GS stores session.ue_ip.addr (see mme-fd-path.c and
     * nudm-handler.c, which copy from sin_addr.s_addr / ipsub.sub[0]).
     * Swapping to host order here used to byte-reverse the assigned UE
     * IP (e.g. 100.70.242.141 came out as 141.242.70.100).
     */
    uint32_t v4_be = 0;
    uint8_t v6[OGS_IPV6_LEN];
    uint8_t class_tmp[1024];
    size_t class_off = 0;
    uint32_t interim_interval = 0;
    /* Collected Framed-Route / Framed-IPv6-Route values, canonicalized to
     * CIDR form. Sized to match the PFCP PDI limit so we can't overflow
     * either store. */
    char *v4_routes[OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI];
    int v4_routes_count = 0;
    char *v6_routes[OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI];
    int v6_routes_count = 0;

    ogs_assert(smf_ue);
    memset(v6, 0, sizeof v6);
    memset(v4_routes, 0, sizeof v4_routes);
    memset(v6_routes, 0, sizeof v6_routes);

    while (p + 2 <= end) {
        uint8_t t = p[0];
        uint8_t alen = p[1];

        if (alen < 2 || p + alen > end)
            break;

        if (t == RADIUS_ATTR_FRAMED_IP_ADDRESS && alen == 6) {
            /* Attribute payload is already network byte order; keep it. */
            memcpy(&v4_be, p + 2, 4);
            if (v4_be != 0)
                got_v4 = true;
        } else if (t == RADIUS_ATTR_FRAMED_IPV6_PREFIX && alen >= 4) {
            uint8_t prefix_len = p[4];
            size_t prefix_octets = (prefix_len + 7) / 8;
            size_t need = 2u + 1u + prefix_octets;

            if (alen >= 2 + need && prefix_octets <= OGS_IPV6_LEN) {
                memset(v6, 0, sizeof v6);
                memcpy(v6, p + 5, prefix_octets);
                got_v6 = true;
            }
        } else if (t == RADIUS_ATTR_CLASS && alen >= 2) {
            size_t vlen = alen - 2;

            if (class_off + vlen <= sizeof(class_tmp)) {
                memcpy(class_tmp + class_off, p + 2, vlen);
                class_off += vlen;
            } else {
                ogs_warn("RADIUS Class attributes exceed %u bytes, truncated",
                        (unsigned)sizeof(class_tmp));
            }
        } else if (t == RADIUS_ATTR_ACCT_INTERIM_INTERVAL && alen == 6) {
            uint32_t nw;

            memcpy(&nw, p + 2, 4);
            interim_interval = be32toh(nw);
        } else if (t == RADIUS_ATTR_FRAMED_ROUTE && alen > 2) {
            char cidr[64];

            if (v4_routes_count >= OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI) {
                ogs_warn("RADIUS: too many Framed-Route AVPs (> %d), "
                        "ignoring extras",
                        OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI);
            } else if (radius_canon_framed_route(p + 2, (size_t)(alen - 2),
                        false, cidr, sizeof cidr)) {
                v4_routes[v4_routes_count++] = ogs_strdup(cidr);
                ogs_info("RADIUS: Framed-Route [%s]", cidr);
            } else {
                char bad[256];
                size_t cp = ogs_min((size_t)(alen - 2), sizeof(bad) - 1);
                memcpy(bad, p + 2, cp);
                bad[cp] = '\0';
                ogs_warn("RADIUS: unparseable Framed-Route '%s'", bad);
            }
        } else if (t == RADIUS_ATTR_FRAMED_IPV6_ROUTE && alen > 2) {
            char cidr[64];

            if (v6_routes_count >= OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI) {
                ogs_warn("RADIUS: too many Framed-IPv6-Route AVPs (> %d), "
                        "ignoring extras",
                        OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI);
            } else if (radius_canon_framed_route(p + 2, (size_t)(alen - 2),
                        true, cidr, sizeof cidr)) {
                v6_routes[v6_routes_count++] = ogs_strdup(cidr);
                ogs_info("RADIUS: Framed-IPv6-Route [%s]", cidr);
            } else {
                char bad[256];
                size_t cp = ogs_min((size_t)(alen - 2), sizeof(bad) - 1);
                memcpy(bad, p + 2, cp);
                bad[cp] = '\0';
                ogs_warn("RADIUS: unparseable Framed-IPv6-Route '%s'", bad);
            }
        }

        p += alen;
    }

    /* Save the Class blob. Any previous one is replaced. */
    if (sess->radius.class_buf) {
        ogs_free(sess->radius.class_buf);
        sess->radius.class_buf = NULL;
        sess->radius.class_len = 0;
    }
    if (class_off) {
        sess->radius.class_buf = ogs_malloc(class_off);
        ogs_assert(sess->radius.class_buf);
        memcpy(sess->radius.class_buf, class_tmp, class_off);
        sess->radius.class_len = class_off;
        ogs_debug("RADIUS: stored %u bytes of Class AVP",
                (unsigned)class_off);
    }

    /*
     * RFC 2869 ?2.1 Acct-Interim-Interval: in this implementation the
     * reporting cadence is driven by the UPF via a PFCP URR Measurement
     * Period (set at session establishment from
     * smf.radius.acct_interim_interval). A per-session override from
     * Access-Accept would require a PFCP Session Modification to update
     * the URR; we log it for now.
     */
    if (interim_interval) {
        ogs_info("RADIUS: Acct-Interim-Interval from server = %u s "
                "(ignored; configured PFCP measurement period in use)",
                (unsigned)interim_interval);
    }

    /*
     * Install Framed-Route / Framed-IPv6-Route into the session. smf_bearer_add
     * (EPC) and npcf-handler (5GC) read these fields and plumb them into the
     * UL/DL PDRs, so the UPF installs routes on Session-Establishment without
     * any further Session-Modification round-trip.
     *
     * Any previous (e.g. subscription-provisioned) routes are freed first so
     * RADIUS takes precedence over UDM/PCF when both are present.
     */
    if (v4_routes_count > 0) {
        int k;
        if (sess->session.ipv4_framed_routes) {
            for (k = 0; k < OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI; k++) {
                if (sess->session.ipv4_framed_routes[k]) {
                    ogs_free(sess->session.ipv4_framed_routes[k]);
                    sess->session.ipv4_framed_routes[k] = NULL;
                }
            }
        } else {
            sess->session.ipv4_framed_routes = ogs_calloc(
                    OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI,
                    sizeof(sess->session.ipv4_framed_routes[0]));
            ogs_assert(sess->session.ipv4_framed_routes);
        }
        for (k = 0; k < v4_routes_count; k++) {
            /* Hand ownership over to the session store, no duplication. */
            sess->session.ipv4_framed_routes[k] = v4_routes[k];
            v4_routes[k] = NULL;
        }
        ogs_info("RADIUS: installed %d Framed-Route(s) on session",
                v4_routes_count);
    } else {
        /* Nothing collected; in case we allocated any tmp strings (shouldn't
         * happen given we only push on success), free them defensively. */
        int k;
        for (k = 0; k < OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI; k++) {
            if (v4_routes[k]) {
                ogs_free(v4_routes[k]);
                v4_routes[k] = NULL;
            }
        }
    }

    if (v6_routes_count > 0) {
        int k;
        if (sess->session.ipv6_framed_routes) {
            for (k = 0; k < OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI; k++) {
                if (sess->session.ipv6_framed_routes[k]) {
                    ogs_free(sess->session.ipv6_framed_routes[k]);
                    sess->session.ipv6_framed_routes[k] = NULL;
                }
            }
        } else {
            sess->session.ipv6_framed_routes = ogs_calloc(
                    OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI,
                    sizeof(sess->session.ipv6_framed_routes[0]));
            ogs_assert(sess->session.ipv6_framed_routes);
        }
        for (k = 0; k < v6_routes_count; k++) {
            sess->session.ipv6_framed_routes[k] = v6_routes[k];
            v6_routes[k] = NULL;
        }
        ogs_info("RADIUS: installed %d Framed-IPv6-Route(s) on session",
                v6_routes_count);
    } else {
        int k;
        for (k = 0; k < OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI; k++) {
            if (v6_routes[k]) {
                ogs_free(v6_routes[k]);
                v6_routes[k] = NULL;
            }
        }
    }

    /* Apply framed addresses into sess->session.ue_ip (PFCP UE address). */
    if (smf_self()->radius.use_framed_ip_for_ue) {
        memset(&sess->session.ue_ip, 0, sizeof(sess->session.ue_ip));

        if (sess->session.session_type == OGS_PDU_SESSION_TYPE_IPV4) {
            if (!got_v4) {
                ogs_error("RADIUS: no Framed-IP-Address for IPv4 session");
                return OGS_ERROR;
            }
            sess->session.ue_ip.addr = v4_be;
        } else if (sess->session.session_type == OGS_PDU_SESSION_TYPE_IPV6) {
            if (!got_v6) {
                ogs_error("RADIUS: no Framed-IPv6-Prefix for IPv6 session");
                return OGS_ERROR;
            }
            memcpy(sess->session.ue_ip.addr6, v6, OGS_IPV6_LEN);
        } else if (sess->session.session_type == OGS_PDU_SESSION_TYPE_IPV4V6) {
            if (!got_v4 || !got_v6) {
                ogs_error("RADIUS: need Framed-IP-Address and "
                        "Framed-IPv6-Prefix for IPv4v6 session");
                return OGS_ERROR;
            }
            sess->session.ue_ip.addr = v4_be;
            memcpy(sess->session.ue_ip.addr6, v6, OGS_IPV6_LEN);
        } else {
            ogs_error("RADIUS: unsupported PDU session type %u",
                    (unsigned)sess->session.session_type);
            return OGS_ERROR;
        }
    } else if (got_v4 || got_v6) {
        ogs_info("RADIUS: ignoring framed UE IP/prefix from Access-Accept "
                "(smf.radius.use_framed_ip_for_ue: false)");
    }

    return OGS_OK;
}

/* ------------------------------------------------------------------ */
/* Request building                                                    */
/* ------------------------------------------------------------------ */

/* Encode 3GPP-User-Location-Info (TS 29.061 ?16.4.7.2) for the given
 * session, into out[] which must be >= 16 bytes. Returns the encoded
 * length, or 0 if no usable location info is available.
 *
 * The on-wire layout of ogs_plmn_id_t already matches the 3-byte packed
 * PLMN-ID the 3GPP ULI expects, so we can memcpy it directly.
 *
 *   EPC session  -> GeoLoc Type 130 (TAI + ECGI), 13 bytes
 *   5GC session  -> GeoLoc Type 136 (TAI + NCGI), 14 bytes
 */
static size_t radius_build_3gpp_uli(const smf_sess_t *sess,
        uint8_t out[16])
{
    uint8_t *p = out;

    if (sess->epc) {
        const ogs_eps_tai_t *tai = &sess->e_tai;
        const ogs_e_cgi_t *ecgi = &sess->e_cgi;
        uint32_t eci;

        /* No ULI available if PLMN is still all-zero. */
        if (!tai->plmn_id.mcc1 && !tai->plmn_id.mcc2 && !tai->plmn_id.mcc3)
            return 0;

        *p++ = RADIUS_3GPP_ULI_TYPE_TAI_ECGI;

        /* TAI: PLMN(3) + TAC(2, big-endian) */
        memcpy(p, &tai->plmn_id, 3); p += 3;
        *p++ = (uint8_t)(tai->tac >> 8);
        *p++ = (uint8_t)(tai->tac & 0xff);

        /* ECGI: PLMN(3) + ECI(4 bytes, 28-bit cell id in low bits). */
        memcpy(p, &ecgi->plmn_id, 3); p += 3;
        eci = ecgi->cell_id & 0x0fffffffu;
        *p++ = (uint8_t)((eci >> 24) & 0x0f);   /* 4 spare MSB bits */
        *p++ = (uint8_t)((eci >> 16) & 0xff);
        *p++ = (uint8_t)((eci >> 8)  & 0xff);
        *p++ = (uint8_t)((eci)       & 0xff);

        return (size_t)(p - out);   /* 13 */
    } else {
        const ogs_5gs_tai_t *tai = &sess->nr_tai;
        const ogs_nr_cgi_t *ncgi = &sess->nr_cgi;
        uint32_t tac;
        uint64_t nci;

        if (!tai->plmn_id.mcc1 && !tai->plmn_id.mcc2 && !tai->plmn_id.mcc3)
            return 0;

        *p++ = RADIUS_3GPP_ULI_TYPE_TAI_NCGI;

        /* TAI: PLMN(3) + TAC(3, 24-bit big-endian). ogs_uint24_t stores
         * the value in host order in the `.v:24` bitfield. */
        memcpy(p, &tai->plmn_id, 3); p += 3;
        tac = tai->tac.v & 0x00ffffffu;
        *p++ = (uint8_t)((tac >> 16) & 0xff);
        *p++ = (uint8_t)((tac >> 8)  & 0xff);
        *p++ = (uint8_t)((tac)       & 0xff);

        /* NCGI: PLMN(3) + NCI(5 bytes, 36-bit cell id in low bits,
         * 4 spare MSB bits in the top nibble of the first byte). */
        memcpy(p, &ncgi->plmn_id, 3); p += 3;
        nci = ncgi->cell_id & 0x0000000fffffffffULL;
        *p++ = (uint8_t)((nci >> 32) & 0x0f);
        *p++ = (uint8_t)((nci >> 24) & 0xff);
        *p++ = (uint8_t)((nci >> 16) & 0xff);
        *p++ = (uint8_t)((nci >> 8)  & 0xff);
        *p++ = (uint8_t)((nci)       & 0xff);

        return (size_t)(p - out);   /* 14 */
    }
}

/* Append per-session 3GPP VSAs shared by Access-Request and Accounting:
 *   - 3GPP-IMEISV (VSA 20)  from smf_ue->imeisv_bcd
 *   - 3GPP-User-Location-Info (VSA 22)  encoded from sess->e_tai / e_cgi
 *     (EPC) or sess->nr_tai / nr_cgi (5GC).
 */
static uint8_t *radius_append_sess_3gpp_attrs(uint8_t *p,
        const smf_sess_t *sess, const smf_ue_t *smf_ue)
{
    uint8_t uli[16];
    size_t uli_len;

    if (smf_ue && smf_ue->imeisv_bcd[0]) {
        ogs_info("RADIUS: appending 3GPP-IMEISV [%s] (len=%d)",
                smf_ue->imeisv_bcd, smf_ue->imeisv_len);
        p = append_attr_vendor_string(p, RADIUS_VENDOR_3GPP,
                RADIUS_3GPP_IMEISV, smf_ue->imeisv_bcd);
    } else {
        ogs_info("RADIUS: 3GPP-IMEISV NOT appended "
                "(smf_ue=%p imeisv_len=%d imeisv_bcd[0]=0x%02x)",
                (const void *)smf_ue,
                smf_ue ? smf_ue->imeisv_len : -1,
                (smf_ue && smf_ue->imeisv_bcd[0]) ?
                        (unsigned)smf_ue->imeisv_bcd[0] : 0);
    }

    if (sess) {
        uli_len = radius_build_3gpp_uli(sess, uli);
        if (uli_len) {
            ogs_info("RADIUS: appending 3GPP-User-Location-Info (len=%zu)",
                    uli_len);
            p = append_attr_vendor_bytes(p, RADIUS_VENDOR_3GPP,
                    RADIUS_3GPP_USER_LOCATION_INFO, uli, uli_len);
        } else {
            ogs_info("RADIUS: 3GPP-User-Location-Info NOT appended "
                    "(uli encode returned 0)");
        }
    }

    return p;
}

static int radius_build_common_attrs(uint8_t *p, const char *user,
        const char *called, const char *calling, const char *nas_id,
        uint32_t nas_ip_be)
{
    uint8_t *base = p;

    p = append_attr_string(p, RADIUS_ATTR_USER_NAME, user);
    if (nas_ip_be)
        p = append_attr_ipv4(p, RADIUS_ATTR_NAS_IP_ADDRESS, nas_ip_be);
    if (nas_id && nas_id[0])
        p = append_attr_string(p, RADIUS_ATTR_NAS_IDENTIFIER, nas_id);
    p = append_attr_u32_be(p, RADIUS_ATTR_SERVICE_TYPE,
            RADIUS_SERVICE_TYPE_FRAMED);
    p = append_attr_u32_be(p, RADIUS_ATTR_FRAMED_PROTOCOL,
            RADIUS_FRAMED_PROTOCOL_PPP);
    p = append_attr_u32_be(p, RADIUS_ATTR_NAS_PORT_TYPE,
            RADIUS_NAS_PORT_TYPE_WIRELESS_OTHER);
    if (called && called[0])
        p = append_attr_string(p, RADIUS_ATTR_CALLED_STATION_ID, called);
    if (calling && calling[0])
        p = append_attr_string(p, RADIUS_ATTR_CALLING_STATION_ID, calling);
    p = append_attr_vendor_string(p, RADIUS_VENDOR_3GPP,
            RADIUS_3GPP_IMSI, user);
    return (int)(p - base);
}

/* ------------------------------------------------------------------ */
/* UDP send/recv client                                                */
/* ------------------------------------------------------------------ */

/*
 * Single-server UDP exchange. Sends `req` to servers[srv_idx] on `port`,
 * retries up to cfg->retry times, waits cfg->timeout_ms for each reply.
 *
 * Returns OGS_OK on a well-formed reply whose code is in acceptable_codes.
 * Returns OGS_TIMEOUT if the server was silent for every attempt (so the
 *   caller can move to the next server in the failover list).
 * Returns OGS_ERROR for anything else (protocol violation, ID mismatch,
 *   unexpected code) ? those are treated as "this server is misbehaving,
 *   stop trying it for this request".
 */
static int radius_udp_exchange(int srv_idx, uint16_t port,
        const uint8_t *req, size_t req_len,
        uint8_t *res, size_t res_max, size_t *res_len,
        const uint8_t *acceptable_codes, unsigned num_codes)
{
    ogs_sockaddr_t *peer = NULL;
    ogs_sock_t *sock = NULL;
    int rv = OGS_ERROR;
    int attempt;
    int successes = 0, timeouts = 0;
    smf_radius_config_t *cfg = &smf_self()->radius;
    smf_radius_server_t *s;

    ogs_assert(req);
    ogs_assert(res);
    ogs_assert(res_len);
    ogs_assert(srv_idx >= 0 && srv_idx < cfg->num_servers);

    s = &cfg->servers[srv_idx];
    if (!s->host || !s->host[0]) {
        ogs_error("RADIUS servers[%d]: no host configured", srv_idx);
        return OGS_ERROR;
    }

    if (ogs_getaddrinfo(&peer, AF_UNSPEC, s->host, port, 0) != OGS_OK ||
        peer == NULL) {
        ogs_error("RADIUS ogs_getaddrinfo(%s) failed", s->host);
        return OGS_ERROR;
    }

    sock = ogs_sock_socket(peer->ogs_sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (!sock) {
        ogs_error("RADIUS ogs_sock_socket() failed");
        ogs_freeaddrinfo(peer);
        return OGS_ERROR;
    }

    sock_set_rcv_timeout(sock->fd, cfg->timeout_ms);

    for (attempt = 0; attempt < cfg->retry; attempt++) {
        ssize_t snd, rcv;
        ogs_sockaddr_t from;

        snd = ogs_sendto(sock->fd, req, req_len, 0, peer);
        if (snd != (ssize_t)req_len) {
            ogs_warn("RADIUS[%s] sendto incomplete (%d vs %u)",
                    s->host, (int)snd, (unsigned)req_len);
            continue;
        }

        rcv = ogs_recvfrom(sock->fd, res, res_max, 0, &from);
        if (rcv < RADIUS_HDR_LEN) {
            if (rcv < 0) {
                /* recv timeout or network error ? count as timeout so the
                 * caller can fail over; all attempts exhausted here mean
                 * the remote is effectively unreachable. */
                timeouts++;
            } else {
                ogs_warn("RADIUS[%s] short response", s->host);
            }
            continue;
        }

        if (res[1] != req[1]) {
            ogs_warn("RADIUS ID mismatch");
            continue;
        }

        {
            uint16_t plen = ((uint16_t)res[2] << 8) | res[3];

            if (plen > (uint16_t)rcv || plen < RADIUS_HDR_LEN) {
                ogs_warn("RADIUS invalid length");
                continue;
            }
            *res_len = plen;
        }

        {
            unsigned n;
            bool ok = false;

            for (n = 0; n < num_codes; n++) {
                if (res[0] == acceptable_codes[n]) {
                    ok = true;
                    break;
                }
            }
            if (!ok) {
                ogs_warn("RADIUS unexpected code %u", (unsigned)res[0]);
                rv = OGS_ERROR;
                break;
            }
        }

        rv = OGS_OK;
        successes++;
        break;
    }

    ogs_sock_destroy(sock);
    ogs_freeaddrinfo(peer);

    /* Update runtime health for the caller's benefit. */
    if (rv == OGS_OK) {
        s->consecutive_failures = 0;
        s->down_since = 0;
    } else if (successes == 0 && timeouts >= cfg->retry) {
        s->consecutive_failures++;
        if (s->consecutive_failures >= SMF_RADIUS_BLACKLIST_THRESHOLD
                && s->down_since == 0) {
            s->down_since = ogs_time_now();
            ogs_warn("RADIUS[%s]: marked DOWN after %d consecutive timeouts",
                    s->host, s->consecutive_failures);
        }
        /* Translate "all attempts timed out" into a distinct return so
         * the caller knows to fail over rather than give up. */
        return OGS_TIMEUP;
    }

    return rv;
}

/* ------------------------------------------------------------------ */
/* Server selection                                                    */
/* ------------------------------------------------------------------ */

/*
 * Produce an ordered list of server indices to try, honoring:
 *   - session stickiness (sticky_idx tried first if healthy)
 *   - select_mode       (primary_failover | hash_imsi)
 *   - health            (down servers go to the end, unless cool-down
 *                        has elapsed in which case they get one probe)
 *
 * Returns the number of servers written into `order[]`. A return of 0
 * means no server is configured.
 */
static int radius_build_try_order(
        int *order, int max_order,
        int sticky_idx, const char *imsi_for_hash)
{
    smf_radius_config_t *cfg = &smf_self()->radius;
    ogs_time_t now = ogs_time_now();
    int n = 0;
    int i;
    bool used[SMF_MAX_RADIUS_SERVERS] = { 0 };

    if (cfg->num_servers == 0) return 0;

    /* 1) Sticky session server first if usable (session coherence). */
    if (sticky_idx >= 0 && sticky_idx < cfg->num_servers) {
        order[n++] = sticky_idx;
        used[sticky_idx] = true;
    }

    /* 2) Preferred server by mode. */
    if (cfg->select_mode == SMF_RADIUS_SELECT_HASH_IMSI
            && imsi_for_hash && imsi_for_hash[0]) {
        uint32_t h = 2166136261u;    /* FNV-1a */
        const char *p;
        for (p = imsi_for_hash; *p; p++) {
            h ^= (uint8_t)*p;
            h *= 16777619u;
        }
        int pref = (int)(h % (uint32_t)cfg->num_servers);
        if (!used[pref]) {
            order[n++] = pref;
            used[pref] = true;
        }
    }

    /* 3) Primaries in declaration order. */
    for (i = 0; i < cfg->num_servers && n < max_order; i++) {
        if (used[i] || !cfg->servers[i].is_primary) continue;
        /* Skip blacklisted servers unless cool-down expired. */
        if (cfg->servers[i].down_since != 0 &&
                (now - cfg->servers[i].down_since) <
                    ogs_time_from_msec(SMF_RADIUS_BLACKLIST_COOLDOWN_MS))
            continue;
        order[n++] = i;
        used[i] = true;
    }

    /* 4) Secondaries in declaration order. */
    for (i = 0; i < cfg->num_servers && n < max_order; i++) {
        if (used[i] || cfg->servers[i].is_primary) continue;
        if (cfg->servers[i].down_since != 0 &&
                (now - cfg->servers[i].down_since) <
                    ogs_time_from_msec(SMF_RADIUS_BLACKLIST_COOLDOWN_MS))
            continue;
        order[n++] = i;
        used[i] = true;
    }

    /* 5) Last resort: any remaining (blacklisted, cooling down) server.
     * Better to try a cold server than drop the request. */
    for (i = 0; i < cfg->num_servers && n < max_order; i++) {
        if (!used[i]) {
            order[n++] = i;
            used[i] = true;
        }
    }

    return n;
}

/*
 * Try each server in `order` until one returns OGS_OK or OGS_ERROR
 * (protocol violation). Timeouts advance to the next server.
 *
 * On success, stores the selected index in *out_idx and the associated
 * secret in *out_secret. This lets the caller verify the response
 * authenticator with the right secret.
 */
static int radius_exchange_with_failover(
        const int *order, int num_order,
        bool is_accounting,
        const uint8_t *req, size_t req_len,
        uint8_t *res, size_t res_max, size_t *res_len,
        const uint8_t *acceptable_codes, unsigned num_codes,
        int *out_idx, const char **out_secret,
        uint8_t *req_authenticator /* for accounting: recomputed per server */)
{
    smf_radius_config_t *cfg = &smf_self()->radius;
    int i, rv = OGS_ERROR;
    uint8_t scratch[RADIUS_PACKET_MAX];

    for (i = 0; i < num_order; i++) {
        int idx = order[i];
        smf_radius_server_t *s = &cfg->servers[idx];
        uint16_t port = is_accounting ? s->acct_port : s->auth_port;
        const uint8_t *send_buf = req;

        /* Accounting and PoD requests need the Request-Authenticator to
         * be computed with *this server's* secret. We build a scratch
         * copy for each try so the caller's buffer stays pristine. */
        if (is_accounting && req_authenticator) {
            memcpy(scratch, req, req_len);
            radius_fill_request_authenticator(scratch, req_len,
                    s->secret ? s->secret : "");
            memcpy(req_authenticator, scratch + 4, 16);
            send_buf = scratch;
        }

        rv = radius_udp_exchange(idx, port,
                send_buf, req_len, res, res_max, res_len,
                acceptable_codes, num_codes);

        if (rv == OGS_OK) {
            if (out_idx)    *out_idx    = idx;
            if (out_secret) *out_secret = s->secret ? s->secret : "";
            return OGS_OK;
        }
        if (rv == OGS_TIMEUP) {
            ogs_info("RADIUS[%s]: timeout, trying next server", s->host);
            continue;
        }
        /* Protocol error on this server ? still try the next one; some
         * farms have a bad actor we want to skip past. */
        ogs_info("RADIUS[%s]: protocol error, trying next server", s->host);
    }

    return rv == OGS_OK ? OGS_OK : OGS_ERROR;
}

/* ------------------------------------------------------------------ */
/* Access-Request (authorization)                                      */
/* ------------------------------------------------------------------ */

int smf_radius_authorize_for_session(smf_sess_t *sess)
{
    uint8_t pkt[RADIUS_PACKET_MAX];
    uint8_t res[RADIUS_PACKET_MAX];
    size_t res_len = 0;
    uint8_t req_auth[16];
    smf_ue_t *smf_ue;
    const char *user;
    const char *called;
    const char *calling;
    const char *nas_id = smf_self()->radius.nas_id;
    uint32_t nas_ip = radius_pick_nas_ipv4();
    uint8_t *p;
    uint16_t total_len;
    smf_radius_config_t *cfg = &smf_self()->radius;
    int order[SMF_MAX_RADIUS_SERVERS];
    int num_order, picked_idx = -1;
    const char *picked_secret = NULL;

    if (!cfg->enabled)
        return OGS_OK;

    ogs_assert(sess);
    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);

    user = radius_username(smf_ue);
    if (!user || !user[0]) {
        ogs_error("RADIUS: no IMSI/User-Name for session");
        return OGS_ERROR;
    }

    called = sess->session.name;
    calling = smf_ue->msisdn_bcd[0] ? smf_ue->msisdn_bcd : NULL;

    memset(pkt, 0, sizeof pkt);
    pkt[0] = RADIUS_CODE_ACCESS_REQUEST;
    pkt[1] = (uint8_t)(ogs_random32() ^ (uint32_t)(sess->index & 0xff));
    ogs_random(pkt + 4, 16);
    memcpy(req_auth, pkt + 4, 16);

    p = pkt + RADIUS_HDR_LEN;
    p += radius_build_common_attrs(p, user, called, calling, nas_id, nas_ip);
    p = radius_append_sess_3gpp_attrs(p, sess, smf_ue);

    total_len = (uint16_t)(p - pkt);
    pkt[2] = (uint8_t)(total_len >> 8);
    pkt[3] = (uint8_t)(total_len);

    num_order = radius_build_try_order(order, SMF_MAX_RADIUS_SERVERS,
            -1 /* no sticky yet */, user);
    if (num_order == 0) {
        ogs_error("RADIUS: no servers configured");
        return OGS_ERROR;
    }

    {
        const uint8_t want[] = {
            RADIUS_CODE_ACCESS_ACCEPT,
            RADIUS_CODE_ACCESS_REJECT
        };

        /* Access-Request has a random 16-byte authenticator in the
         * packet body ? no per-server rewrite needed. */
        if (radius_exchange_with_failover(order, num_order,
                    false /* is_accounting */,
                    pkt, total_len, res, sizeof res, &res_len,
                    want, sizeof want,
                    &picked_idx, &picked_secret, NULL) != OGS_OK) {
            ogs_error("RADIUS Access-Request failed on all %d server(s)",
                    num_order);
            return OGS_ERROR;
        }
    }

    if (radius_verify_response(req_auth, res, res_len,
                picked_secret ? picked_secret : "") != OGS_OK) {
        ogs_warn("RADIUS Access-Accept/Reject authenticator mismatch");
        return OGS_ERROR;
    }
    /* Pin this session to the server that accepted Access-Request so
     * subsequent Interim/Stop go to the same AAA. */
    sess->radius.server_idx = picked_idx;

    if (res[0] == RADIUS_CODE_ACCESS_REJECT) {
        ogs_error("RADIUS Access-Reject for IMSI[%s] DNN[%s]",
                user, called ? called : "");
        return OGS_ERROR;
    }

    if (radius_parse_access_accept(sess, res + RADIUS_HDR_LEN,
                res_len - RADIUS_HDR_LEN) != OGS_OK)
        return OGS_ERROR;

    ogs_info("RADIUS Access-Accept: UE IP from server for IMSI[%s] DNN[%s]",
            user, called ? called : "");
    return OGS_OK;
}

/* ------------------------------------------------------------------ */
/* Accounting-Request builder + sender                                 */
/* ------------------------------------------------------------------ */

static void radius_append_usage_counters(uint8_t **pp, smf_sess_t *sess,
        uint32_t status_type)
{
    uint8_t *p = *pp;
    uint64_t ul = sess->gy.ul_octets;
    uint64_t dl = sess->gy.dl_octets;
    ogs_time_t now = ogs_time_now();
    uint32_t session_time = 0;

    if (sess->radius.start_time && now > sess->radius.start_time)
        session_time = (uint32_t)(
                (now - sess->radius.start_time) / OGS_USEC_PER_SEC);

    /* Acct-Session-Time is sent on Interim and Stop (RFC 2866 ?5.7).
     * We also include it on Start as 0 which is harmless. */
    p = append_attr_u32_be(p, RADIUS_ATTR_ACCT_SESSION_TIME, session_time);

    /* Octet counters:
     *   RADIUS "Input"  = from user to NAS (uplink traffic from UE)
     *   RADIUS "Output" = from NAS to user (downlink traffic to UE)
     * Open5GS stores ul_octets/dl_octets from PFCP URR reports in
     * sess->gy.*; for Stop, the values from the final session-deletion
     * usage report will already be accumulated when we get here.
     */
    p = append_attr_u32_be(p, RADIUS_ATTR_ACCT_INPUT_OCTETS,
            (uint32_t)(ul & 0xFFFFFFFFULL));
    p = append_attr_u32_be(p, RADIUS_ATTR_ACCT_OUTPUT_OCTETS,
            (uint32_t)(dl & 0xFFFFFFFFULL));

    /* Acct-Input/Output-Gigawords (RFC 2869 ?5.1/5.2) when > 4 GiB. */
    if (ul >> 32)
        p = append_attr_u32_be(p, RADIUS_ATTR_ACCT_INPUT_GIGAWORDS,
                (uint32_t)(ul >> 32));
    if (dl >> 32)
        p = append_attr_u32_be(p, RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS,
                (uint32_t)(dl >> 32));

    /* Packet counters are not tracked by Open5GS PFCP URR today;
     * we omit them rather than send zeros that could be misleading.
     * Enable the next block once packet counters become available.
     */
#if 0
    p = append_attr_u32_be(p, RADIUS_ATTR_ACCT_INPUT_PACKETS, 0);
    p = append_attr_u32_be(p, RADIUS_ATTR_ACCT_OUTPUT_PACKETS, 0);
#endif

    if (status_type == RADIUS_ACCT_STATUS_STOP) {
        p = append_attr_u32_be(p, RADIUS_ATTR_ACCT_TERMINATE_CAUSE,
                RADIUS_TERM_NAS_REQUEST);
    }

    *pp = p;
}

static int radius_send_accounting(smf_sess_t *sess, uint32_t status_type)
{
    uint8_t pkt[RADIUS_PACKET_MAX];
    uint8_t res[RADIUS_PACKET_MAX];
    size_t res_len = 0;
    uint8_t req_auth_saved[16];
    smf_ue_t *smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    const char *user;
    const char *called;
    const char *calling;
    const char *nas_id = smf_self()->radius.nas_id;
    uint32_t nas_ip = radius_pick_nas_ipv4();
    uint8_t *p;
    uint16_t total_len;
    smf_radius_config_t *cfg = &smf_self()->radius;
    int order[SMF_MAX_RADIUS_SERVERS];
    int num_order, picked_idx = -1;
    const char *picked_secret = NULL;

    ogs_assert(sess->radius.acct_session_id);
    ogs_assert(smf_ue);

    if (cfg->num_servers == 0)
        return OGS_ERROR;

    user = radius_username(smf_ue);
    called = sess->session.name;
    calling = smf_ue->msisdn_bcd[0] ? smf_ue->msisdn_bcd : NULL;

    memset(pkt, 0, sizeof pkt);
    pkt[0] = RADIUS_CODE_ACCOUNTING_REQUEST;
    pkt[1] = (uint8_t)(ogs_random32() ^
            (uint32_t)((sess->index + status_type) & 0xff));

    p = pkt + RADIUS_HDR_LEN;
    p += radius_build_common_attrs(p, user, called, calling, nas_id, nas_ip);
    p = radius_append_sess_3gpp_attrs(p, sess, smf_ue);
    p = append_attr_u32_be(p, RADIUS_ATTR_ACCT_STATUS_TYPE, status_type);
    p = append_attr_string(p, RADIUS_ATTR_ACCT_SESSION_ID,
            sess->radius.acct_session_id);

    /* Echo the Class AVP(s) received in Access-Accept (RFC 2865 ?5.25). */
    if (sess->radius.class_buf && sess->radius.class_len)
        p = append_class_attrs(p, sess->radius.class_buf,
                sess->radius.class_len);

    if (sess->ipv4) {
        /*
         * sess->ipv4->addr[0] is already in network byte order
         * (it is copied straight into sin_addr.s_addr elsewhere in the
         * stack ? see src/smf/gy-path.c). append_attr_ipv4 also expects
         * network byte order, so pass it through unchanged. A prior
         * htobe32() here double-swapped on little-endian and produced a
         * reversed Framed-IP-Address on the wire.
         */
        p = append_attr_ipv4(p, RADIUS_ATTR_FRAMED_IP_ADDRESS,
                sess->ipv4->addr[0]);
    }
    if (sess->ipv6) {
        uint8_t plen = sess->paa.len ? (uint8_t)sess->paa.len :
                OGS_IPV6_DEFAULT_PREFIX_LEN;

        /*
         * sess->ipv6->addr is uint32_t[4] but the 16-byte network-order
         * representation is what Framed-IPv6-Prefix wants; the in-memory
         * layout already matches, so just reinterpret the bytes.
         */
        p = append_attr_framed_ipv6_prefix(p,
                (const uint8_t *)sess->ipv6->addr, plen);
    }

    radius_append_usage_counters(&p, sess, status_type);

    total_len = (uint16_t)(p - pkt);
    pkt[2] = (uint8_t)(total_len >> 8);
    pkt[3] = (uint8_t)(total_len);

    /* Request-Authenticator is computed per server inside the failover
     * helper because each server has its own shared secret. */
    num_order = radius_build_try_order(order, SMF_MAX_RADIUS_SERVERS,
            sess->radius.server_idx,
            radius_username(smf_ue));
    if (num_order == 0) {
        ogs_warn("RADIUS Accounting: no servers configured");
        return OGS_ERROR;
    }

    {
        const uint8_t want[] = { RADIUS_CODE_ACCOUNTING_RESPONSE };

        if (radius_exchange_with_failover(order, num_order,
                    true /* is_accounting */,
                    pkt, total_len, res, sizeof res, &res_len,
                    want, sizeof want,
                    &picked_idx, &picked_secret, req_auth_saved) != OGS_OK) {
            ogs_warn("RADIUS Accounting-Request (status=%u) failed on all "
                    "%d server(s)", (unsigned)status_type, num_order);
            return OGS_ERROR;
        }
    }

    if (radius_verify_response(req_auth_saved, res, res_len,
                picked_secret ? picked_secret : "") != OGS_OK) {
        ogs_warn("RADIUS Accounting-Response authenticator mismatch");
        return OGS_ERROR;
    }

    /* If the session failed over to a different AAA (primary came back,
     * or secondary took over), update the pin so next Interim stays
     * coherent. */
    if (picked_idx >= 0 && sess->radius.server_idx != picked_idx)
        sess->radius.server_idx = picked_idx;

    ogs_debug("RADIUS Accounting-Response (status=%u) OK from servers[%d]",
            (unsigned)status_type, picked_idx);
    return OGS_OK;
}

/* ------------------------------------------------------------------ */
/* Public accounting lifecycle                                         */
/* ------------------------------------------------------------------ */

void smf_radius_accounting_interim_update(smf_sess_t *sess)
{
    smf_radius_config_t *cfg = &smf_self()->radius;

    if (!cfg->enabled)
        return;
    ogs_assert(sess);

    if (!sess->radius.acct_started || !sess->radius.acct_session_id)
        return;

    (void)radius_send_accounting(sess, RADIUS_ACCT_STATUS_INTERIM_UPDATE);
}

void smf_radius_accounting_session_started(smf_sess_t *sess)
{
    ogs_uuid_t uuid;
    char idbuf[OGS_UUID_FORMATTED_LENGTH + 1];
    smf_radius_config_t *cfg = &smf_self()->radius;

    if (!cfg->enabled)
        return;

    ogs_assert(sess);

    if (sess->radius.acct_session_id)
        return;

    ogs_uuid_get(&uuid);
    ogs_uuid_format(idbuf, &uuid);
    sess->radius.acct_session_id = ogs_strdup(idbuf);
    ogs_assert(sess->radius.acct_session_id);

    sess->radius.start_time = ogs_time_now();

    if (radius_send_accounting(sess, RADIUS_ACCT_STATUS_START) != OGS_OK) {
        ogs_free(sess->radius.acct_session_id);
        sess->radius.acct_session_id = NULL;
        return;
    }
    sess->radius.acct_started = true;
}

void smf_radius_accounting_session_stopping(smf_sess_t *sess)
{
    smf_radius_config_t *cfg = &smf_self()->radius;
    int rc;

    if (!cfg->enabled) {
        ogs_debug("RADIUS Accounting-Stop skipped: radius disabled");
        return;
    }
    ogs_assert(sess);

    if (!sess->radius.acct_started) {
        ogs_warn("RADIUS Accounting-Stop skipped: acct_started=false "
                "(sess_id=%d)", (int)sess->id);
        return;
    }
    if (!sess->radius.acct_session_id) {
        ogs_warn("RADIUS Accounting-Stop skipped: acct_session_id=NULL "
                "(sess_id=%d)", (int)sess->id);
        return;
    }

    ogs_info("RADIUS Accounting-Stop: sending for sess_id=%d "
            "session-id=%s",
            (int)sess->id, sess->radius.acct_session_id);
    rc = radius_send_accounting(sess, RADIUS_ACCT_STATUS_STOP);
    if (rc != OGS_OK)
        ogs_warn("RADIUS Accounting-Stop: send failed (rc=%d) "
                "sess_id=%d", rc, (int)sess->id);
    sess->radius.acct_started = false;
}

void smf_radius_pod_teardown_cancel(smf_sess_t *sess)
{
    ogs_assert(sess);

    if (sess->radius.teardown_timer) {
        ogs_debug("RADIUS PoD: cancelling teardown watchdog "
                "(sess_id=%d)", (int)sess->id);
        ogs_timer_delete(sess->radius.teardown_timer);
        sess->radius.teardown_timer = NULL;
    }
}

void smf_radius_sess_clear(smf_sess_t *sess)
{
    ogs_assert(sess);

    if (sess->radius.teardown_timer) {
        ogs_timer_delete(sess->radius.teardown_timer);
        sess->radius.teardown_timer = NULL;
    }

    if (sess->radius.class_buf) {
        ogs_free(sess->radius.class_buf);
        sess->radius.class_buf = NULL;
        sess->radius.class_len = 0;
    }
    if (sess->radius.acct_session_id) {
        ogs_free(sess->radius.acct_session_id);
        sess->radius.acct_session_id = NULL;
    }
    sess->radius.acct_started = false;
    sess->radius.start_time = 0;
}

/* ------------------------------------------------------------------ */
/* RFC 5176 Disconnect-Message listener                                */
/* ------------------------------------------------------------------ */

static ogs_sock_t *s_pod_sock = NULL;
static ogs_poll_t *s_pod_poll = NULL;

/* Find a session matching the RFC 5176 session identification attrs. */
static smf_sess_t *pod_find_session(const uint8_t *attrs, size_t attrs_len)
{
    smf_ue_t *ue = NULL;
    smf_sess_t *sess = NULL;
    uint8_t alen;
    const uint8_t *v;

    /* 1. Acct-Session-Id (most specific). */
    v = radius_find_attr(attrs, attrs_len, RADIUS_ATTR_ACCT_SESSION_ID,
            &alen);
    if (v && alen > 2) {
        size_t slen = alen - 2;
        char buf[128];

        if (slen >= sizeof buf) slen = sizeof buf - 1;
        memcpy(buf, v + 2, slen);
        buf[slen] = '\0';

        ogs_list_for_each(&smf_self()->smf_ue_list, ue) {
            ogs_list_for_each(&ue->sess_list, sess) {
                if (sess->radius.acct_session_id &&
                        strcmp(sess->radius.acct_session_id, buf) == 0)
                    return sess;
            }
        }
    }

    /* 2. Framed-IP-Address. */
    v = radius_find_attr(attrs, attrs_len, RADIUS_ATTR_FRAMED_IP_ADDRESS,
            &alen);
    if (v && alen == 6) {
        uint32_t nw;

        memcpy(&nw, v + 2, 4);
        sess = smf_sess_find_by_ipv4(nw);
        if (sess) return sess;
    }

    /* 3. Framed-IPv6-Prefix. */
    v = radius_find_attr(attrs, attrs_len, RADIUS_ATTR_FRAMED_IPV6_PREFIX,
            &alen);
    if (v && alen >= 6) {
        uint8_t prefix_len = v[4];
        size_t prefix_octets = (prefix_len + 7) / 8;

        if (prefix_octets >= OGS_IPV6_DEFAULT_PREFIX_LEN / 8) {
            uint32_t addr6_buf[OGS_IPV6_DEFAULT_PREFIX_LEN / 32];

            memset(addr6_buf, 0, sizeof addr6_buf);
            memcpy(addr6_buf, v + 5,
                    OGS_IPV6_DEFAULT_PREFIX_LEN / 8);
            sess = smf_sess_find_by_ipv6(addr6_buf);
            if (sess) return sess;
        }
    }

    /* 4. User-Name (IMSI). Returns first matching session if multiple. */
    v = radius_find_attr(attrs, attrs_len, RADIUS_ATTR_USER_NAME, &alen);
    if (v && alen > 2) {
        size_t slen = alen - 2;
        char username[64];
        const uint8_t *called = NULL;
        uint8_t called_len = 0;

        if (slen >= sizeof username) slen = sizeof username - 1;
        memcpy(username, v + 2, slen);
        username[slen] = '\0';

        v = radius_find_attr(attrs, attrs_len,
                RADIUS_ATTR_CALLED_STATION_ID, &alen);
        if (v) { called = v + 2; called_len = alen - 2; }

        ogs_list_for_each(&smf_self()->smf_ue_list, ue) {
            const char *ue_user;

            ue_user = radius_username(ue);
            if (!ue_user || strcmp(ue_user, username) != 0)
                continue;

            ogs_list_for_each(&ue->sess_list, sess) {
                if (called && called_len && sess->session.name) {
                    size_t dnlen = strlen(sess->session.name);

                    if (dnlen != called_len ||
                            memcmp(sess->session.name, called, dnlen) != 0)
                        continue;
                }
                return sess;
            }
        }
    }

    return NULL;
}

static void pod_send_response(int code, uint8_t id,
        const uint8_t *req_authenticator, ogs_sockaddr_t *to,
        uint32_t error_cause, const char *secret)
{
    uint8_t pkt[RADIUS_PACKET_MAX];
    uint8_t digest[16];
    uint8_t cat[RADIUS_PACKET_MAX + 256];
    uint8_t *p;
    uint16_t total_len;
    size_t secret_len;
    smf_radius_config_t *cfg = &smf_self()->radius;

    /* Fall back to the same candidate list pod_recv_cb uses in case a
     * caller (e.g. early NAK before authenticator validation) didn't
     * pass a specific secret. */
    if (!secret || !secret[0]) {
        if (cfg->pod_secret && cfg->pod_secret[0])
            secret = cfg->pod_secret;
        else if (cfg->num_servers > 0 && cfg->servers[0].secret)
            secret = cfg->servers[0].secret;
        else
            secret = cfg->secret ? cfg->secret : "";
    }
    secret_len = strlen(secret);

    memset(pkt, 0, sizeof pkt);
    pkt[0] = (uint8_t)code;
    pkt[1] = id;

    p = pkt + RADIUS_HDR_LEN;
    if (error_cause)
        p = append_attr_u32_be(p, RADIUS_ATTR_ERROR_CAUSE, error_cause);

    total_len = (uint16_t)(p - pkt);
    pkt[2] = (uint8_t)(total_len >> 8);
    pkt[3] = (uint8_t)(total_len);

    /* Response Authenticator = MD5(Code + ID + Length + ReqAuth +
     * Attributes + Secret). RFC 5176 ?3.2. */
    memcpy(cat, pkt, 4);
    memcpy(cat + 4, req_authenticator, 16);
    memcpy(cat + 20, pkt + RADIUS_HDR_LEN, total_len - RADIUS_HDR_LEN);
    {
        size_t cat_len = 4 + 16 + (total_len - RADIUS_HDR_LEN);

        if (cat_len + secret_len > sizeof cat) return;
        memcpy(cat + cat_len, secret, secret_len);
        md5_digest(cat, cat_len + secret_len, digest);
    }
    memcpy(pkt + 4, digest, 16);

    if (ogs_sendto(s_pod_sock->fd, pkt, total_len, 0, to) != (ssize_t)total_len)
        ogs_warn("RADIUS PoD: failed to send response code=%d", code);
}

/*
 * PoD teardown watchdog.
 *
 * Armed by pod_recv_cb() (EPC path) after we successfully hand a GTPv2
 * Delete Bearer Request to the GTPv2 xact layer. Under normal
 * conditions the MME pages the UE (if idle), tears down the NAS
 * bearer, and replies with a Delete Bearer Response; smf_sess_remove()
 * then fires and this timer is cancelled by smf_radius_sess_clear().
 *
 * If that response never comes (MME bug, race, UE gone, paging
 * timeout not surfaced, ...), this callback fires and we force PFCP
 * Session Deletion locally. The N4 handler / FSM chain then drives the
 * session to smf_sess_remove(), which emits RADIUS Accounting-Stop and
 * cleans up UE state. As a last resort we remove the session directly
 * so Accounting-Stop is guaranteed to go out.
 *
 * Runs in the SMF main thread (ogs_timer_mgr_expire context), so all
 * session operations are safe.
 */
static void pod_teardown_timeout_cb(void *data)
{
    ogs_pool_id_t sess_id = (ogs_pool_id_t)OGS_POINTER_TO_UINT(data);
    smf_sess_t *sess = smf_sess_find_by_id(sess_id);
    int rv;

    if (!sess) {
        /* Already cleaned up via the normal DBR-Response path. */
        ogs_debug("RADIUS PoD teardown timeout: sess_id=%d already gone",
                (int)sess_id);
        return;
    }

    /*
     * The timer is one-shot and a pointer to it is owned by the
     * session; null it out so smf_radius_sess_clear() does not
     * double-free. We still ogs_timer_delete() it below.
     */
    ogs_timer_t *t = sess->radius.teardown_timer;
    sess->radius.teardown_timer = NULL;

    ogs_warn("RADIUS PoD teardown timeout fired "
            "(sess_id=%d, epc=%d, sgw_s5c_teid=0x%x): "
            "MME did not reply to Delete Bearer Request in time, "
            "forcing local teardown",
            (int)sess->id, sess->epc, sess->sgw_s5c_teid);

    /*
     * Emit Accounting-Stop up front. smf_sess_remove() also calls
     * smf_radius_accounting_session_stopping(), but the flag
     * sess->radius.acct_started is cleared here, so a duplicate stop
     * cannot be sent. We do this before anything that could leave
     * the session stuck on a Gx/Gy-dependent FSM branch.
     */
    ogs_info("RADIUS PoD teardown timeout: emitting Accounting-Stop "
            "(sess_id=%d, acct_started=%d, acct_session_id=%s, "
            "cfg_enabled=%d, server=%s)",
            (int)sess->id,
            (int)sess->radius.acct_started,
            sess->radius.acct_session_id ?
                    sess->radius.acct_session_id : "(null)",
            (int)smf_self()->radius.enabled,
            smf_self()->radius.server ?
                    smf_self()->radius.server : "(null)");
    smf_radius_accounting_session_stopping(sess);

    /*
     * Best-effort: ask the UPF to tear down the PFCP session too so
     * we don't leak state there. We intentionally do NOT rely on the
     * normal N4 response cascade to remove the SMF session, because
     * the EPC path (gsm-sm.c) goes through Gx/Gy CCR-T, which in a
     * RADIUS-only deployment never completes and leaves the session
     * wedged in wait_epc_auth_release.
     */
    rv = smf_epc_pfcp_send_session_deletion_request(sess,
            OGS_INVALID_POOL_ID);
    if (rv != OGS_OK) {
        ogs_error("RADIUS PoD teardown timeout: forced PFCP deletion "
                "failed (rv=%d, sess_id=%d), removing session locally",
                rv, (int)sess->id);
    }

    /*
     * Always remove the SMF session locally. A pending PFCP xact
     * whose response arrives after this will simply fail the
     * smf_sess_find_by_id() lookup in the N4 handler and be dropped.
     *
     * Use SMF_SESS_CLEAR rather than smf_sess_remove() directly: the
     * former also removes the smf_ue_t when this was the last session
     * for the UE, so the UE does not linger in the context with an
     * empty pdu list.
     */
    ogs_info("RADIUS PoD teardown timeout: removing SMF session "
            "(sess_id=%d)", (int)sess->id);
    SMF_SESS_CLEAR(sess);

    if (t)
        ogs_timer_delete(t);
}

static void pod_arm_teardown_timer(smf_sess_t *sess)
{
    smf_radius_config_t *cfg = &smf_self()->radius;

    ogs_assert(sess);

    if (!cfg->pod_teardown_timeout_ms) {
        /* Watchdog disabled by config. */
        return;
    }

    /*
     * A previous PoD for the same session may have armed a timer
     * already (e.g. this is a retransmitted Disconnect-Request). In
     * that case we just restart the existing timer so the deadline is
     * measured from the most recent PoD.
     */
    if (!sess->radius.teardown_timer) {
        sess->radius.teardown_timer = ogs_timer_add(
                ogs_app()->timer_mgr, pod_teardown_timeout_cb,
                OGS_UINT_TO_POINTER((unsigned)sess->id));
        if (!sess->radius.teardown_timer) {
            ogs_error("RADIUS PoD: ogs_timer_add() failed for sess_id=%d",
                    (int)sess->id);
            return;
        }
    }

    ogs_timer_start(sess->radius.teardown_timer,
            ogs_time_from_msec(cfg->pod_teardown_timeout_ms));

    ogs_info("RADIUS PoD: teardown watchdog armed "
            "(sess_id=%d, timeout=%ums)",
            (int)sess->id, (unsigned)cfg->pod_teardown_timeout_ms);
}

static void pod_recv_cb(short when, ogs_socket_t fd, void *data)
{
    uint8_t buf[RADIUS_PACKET_MAX];
    ogs_sockaddr_t from;
    ssize_t n;
    uint16_t plen;
    size_t attrs_len;
    const uint8_t *attrs;
    uint8_t saved_auth[16];
    const char *secret;
    size_t secret_len;
    smf_sess_t *sess;
    smf_radius_config_t *cfg = &smf_self()->radius;
    uint8_t packet_copy[RADIUS_PACKET_MAX];

    (void)when;
    (void)data;

    n = ogs_recvfrom(fd, buf, sizeof buf, 0, &from);
    if (n < RADIUS_HDR_LEN) {
        if (n > 0)
            ogs_warn("RADIUS PoD: short packet (%d bytes)", (int)n);
        return;
    }

    plen = ((uint16_t)buf[2] << 8) | buf[3];
    if (plen < RADIUS_HDR_LEN || plen > (uint16_t)n) {
        ogs_warn("RADIUS PoD: bad length %u (recv %d)",
                (unsigned)plen, (int)n);
        return;
    }

    if (buf[0] != RADIUS_CODE_DISCONNECT_REQUEST &&
            buf[0] != RADIUS_CODE_COA_REQUEST) {
        ogs_warn("RADIUS PoD: unexpected code %u", (unsigned)buf[0]);
        return;
    }

    /*
     * Try every configured shared secret, in this order:
     *   1. Explicit `pod_secret` if set (lets operators issue PoDs from
     *      a hosts that don't know the per-server AAA secret).
     *   2. Each server's secret (so PoDs can come directly from any
     *      configured AAA, e.g. in a primary+secondary farm).
     *   3. Legacy `secret` (single-server deployments).
     *
     * The authenticator that matches is remembered so pod_send_response
     * can reply with the same secret; otherwise the requester would see
     * a bad Response-Authenticator.
     */
    memcpy(saved_auth, buf + 4, 16);
    memcpy(packet_copy, buf, plen);
    memset(packet_copy + 4, 0, 16);

    secret = NULL;
    secret_len = 0;
    {
        const char *candidates[SMF_MAX_RADIUS_SERVERS + 2];
        unsigned nc = 0, i;

        if (cfg->pod_secret && cfg->pod_secret[0])
            candidates[nc++] = cfg->pod_secret;
        for (i = 0; i < (unsigned)cfg->num_servers; i++) {
            const char *cs = cfg->servers[i].secret;
            if (cs && cs[0]) candidates[nc++] = cs;
        }
        if (cfg->secret && cfg->secret[0])
            candidates[nc++] = cfg->secret;

        for (i = 0; i < nc; i++) {
            uint8_t digest[16];
            uint8_t cat[RADIUS_PACKET_MAX + 256];
            size_t slen = strlen(candidates[i]);
            size_t cat_len;

            if ((size_t)plen + slen > sizeof cat) continue;
            memcpy(cat, packet_copy, plen);
            memcpy(cat + plen, candidates[i], slen);
            cat_len = plen + slen;
            md5_digest(cat, cat_len, digest);
            if (memcmp(digest, saved_auth, 16) == 0) {
                secret = candidates[i];
                secret_len = slen;
                break;
            }
        }

        if (!secret) {
            char ipbuf[OGS_ADDRSTRLEN];

            ogs_warn("RADIUS PoD: Request-Authenticator mismatch from "
                    "%s (tried %u secret(s))",
                    OGS_ADDR(&from, ipbuf), nc);
            return;
        }
    }
    (void)secret_len;

    attrs = buf + RADIUS_HDR_LEN;
    attrs_len = plen - RADIUS_HDR_LEN;

    /* CoA-Request not implemented: NAK with Unsupported-Service. */
    if (buf[0] == RADIUS_CODE_COA_REQUEST) {
        ogs_info("RADIUS CoA-Request received: unsupported");
        pod_send_response(RADIUS_CODE_COA_NAK, buf[1], saved_auth, &from,
                RADIUS_ERR_CAUSE_UNSUPPORTED_SERVICE, secret);
        return;
    }

    sess = pod_find_session(attrs, attrs_len);
    if (!sess) {
        char ipbuf[OGS_ADDRSTRLEN];

        ogs_info("RADIUS Disconnect-Request: no matching session (from %s)",
                OGS_ADDR(&from, ipbuf));
        pod_send_response(RADIUS_CODE_DISCONNECT_NAK, buf[1], saved_auth,
                &from, RADIUS_ERR_CAUSE_SESSION_NOT_FOUND, secret);
        return;
    }

    {
        smf_ue_t *ue = smf_ue_find_by_id(sess->smf_ue_id);
        char ipbuf[OGS_ADDRSTRLEN];

        ogs_info("RADIUS Disconnect-Request accepted: "
                "IMSI[%s] DNN[%s] session-id[%s] from %s",
                ue ? (ue->imsi_bcd[0] ? ue->imsi_bcd :
                      (ue->supi ? ue->supi : "?")) : "?",
                sess->session.name ? sess->session.name : "",
                sess->radius.acct_session_id ?
                    sess->radius.acct_session_id : "",
                OGS_ADDR(&from, ipbuf));
    }

    pod_send_response(RADIUS_CODE_DISCONNECT_ACK, buf[1], saved_auth, &from,
            0, secret);

    ogs_info("RADIUS PoD: releasing session "
            "(epc=%d, sess_id=%d, sgw_s5c_teid=0x%x)",
            sess->epc, (int)sess->id, sess->sgw_s5c_teid);

    /*
     * EPC (GTPv2 / PGW-C role): send GTPv2 Delete Bearer Request for
     * the default bearer directly. When MME replies with Delete Bearer
     * Response, smf_gsm_state_operational drives the PFCP deletion
     * chain, which culminates in smf_sess_remove() -> RADIUS
     * Accounting-Stop.
     *
     * We are inside the SMF main-loop pollset callback here so it is
     * safe to invoke the GTPv2 send helper synchronously (same thread
     * that runs the GTPv2 xact/state machine).
     */
    if (sess->epc) {
        smf_bearer_t *bearer = smf_default_bearer_in_sess(sess);
        int rv;

        /*
         * Fallback path: the session has no bearers (previous PoD
         * attempt partially tore things down, or the session is in a
         * half-state for some other reason). We can't send a Delete
         * Bearer Request without a bearer, but we MUST still clean the
         * session up so Accounting-Stop is emitted. Trigger PFCP
         * Session Deletion directly; when the UPF replies the N4
         * handler removes the session and emits Accounting-Stop.
         */
        if (!bearer || !sess->gnode) {
            ogs_warn("RADIUS PoD (EPC): session is in a half-state "
                    "(bearer=%p, gnode=%p) sess_id=%d, forcing local "
                    "teardown",
                    bearer, sess->gnode, (int)sess->id);

            /*
             * Emit Accounting-Stop before anything that could wedge
             * the session on a Gx/Gy-dependent FSM branch.
             */
            smf_radius_accounting_session_stopping(sess);

            /* Best-effort UPF cleanup. */
            rv = smf_epc_pfcp_send_session_deletion_request(
                    sess, OGS_INVALID_POOL_ID);
            if (rv != OGS_OK) {
                ogs_error("RADIUS PoD (EPC): forced PFCP deletion "
                        "failed (rv=%d)", rv);
            }

            /*
             * Always remove the session locally so SMF state is
             * cleaned up even when the EPC Gx/Gy cascade would
             * otherwise leave us stuck in wait_epc_auth_release.
             * SMF_SESS_CLEAR also removes the smf_ue_t when this
             * was the last session, avoiding a dangling UE entry.
             */
            SMF_SESS_CLEAR(sess);
            return;
        }

        ogs_info("RADIUS PoD (EPC): sending Delete Bearer Request "
                "EBI=%d SGW-S5C-TEID=0x%x",
                bearer->ebi, sess->sgw_s5c_teid);

        rv = smf_gtp2_send_delete_bearer_request(bearer,
                OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED,
                OGS_GTP2_CAUSE_REACTIVATION_REQUESTED);
        if (rv != OGS_OK) {
            ogs_error("RADIUS PoD (EPC): "
                    "smf_gtp2_send_delete_bearer_request() failed "
                    "(rv=%d), forcing local teardown", rv);

            smf_radius_accounting_session_stopping(sess);

            if (smf_epc_pfcp_send_session_deletion_request(
                        sess, OGS_INVALID_POOL_ID) != OGS_OK) {
                ogs_error("RADIUS PoD (EPC): forced PFCP deletion "
                        "also failed");
            }
            SMF_SESS_CLEAR(sess);
        } else {
            ogs_info("RADIUS PoD (EPC): Delete Bearer Request sent "
                    "successfully, awaiting MME response");
            /*
             * MMEs may never reply (e.g. a bug in the paging /
             * NAS-deactivate path leaves the Delete Bearer procedure
             * hanging). Arm a watchdog so we still emit Accounting-Stop
             * and tear the UPF tunnel down after
             * radius.pod_teardown_timeout_ms milliseconds.
             */
            pod_arm_teardown_timer(sess);
        }
        return;
    }

    /*
     * 5GC (SBI/N1N2): post SMF_EVT_SESSION_RELEASE so the SMF state
     * machine drives the proper Namf_Communication_N1N2MessageTransfer
     * release flow.
     */
    ogs_info("RADIUS PoD (5GC): queuing SMF_EVT_SESSION_RELEASE");
    smf_trigger_session_release(sess, NULL,
            OGS_PFCP_DELETE_TRIGGER_SMF_INITIATED);
}

int smf_radius_pod_open(void)
{
    smf_radius_config_t *cfg = &smf_self()->radius;
    ogs_sockaddr_t *addr = NULL;
    const char *host;

    if (!cfg->enabled || !cfg->pod_enabled)
        return OGS_OK;

    if (!cfg->pod_port)
        cfg->pod_port = RADIUS_DEFAULT_POD_PORT;

    host = (cfg->pod_bind && cfg->pod_bind[0]) ? cfg->pod_bind : NULL;

    if (ogs_getaddrinfo(&addr, AF_UNSPEC, host, cfg->pod_port,
                AI_PASSIVE) != OGS_OK || !addr) {
        ogs_error("RADIUS PoD: cannot resolve pod_bind '%s'",
                host ? host : "*");
        return OGS_ERROR;
    }

    s_pod_sock = ogs_udp_server(addr, NULL);
    if (!s_pod_sock) {
        ogs_error("RADIUS PoD: ogs_udp_server(port=%u) failed",
                (unsigned)cfg->pod_port);
        ogs_freeaddrinfo(addr);
        return OGS_ERROR;
    }

    s_pod_poll = ogs_pollset_add(ogs_app()->pollset, OGS_POLLIN,
            s_pod_sock->fd, pod_recv_cb, s_pod_sock);
    if (!s_pod_poll) {
        ogs_error("RADIUS PoD: ogs_pollset_add failed");
        ogs_sock_destroy(s_pod_sock);
        s_pod_sock = NULL;
        ogs_freeaddrinfo(addr);
        return OGS_ERROR;
    }

    ogs_info("RADIUS PoD listener on %s:%u",
            host ? host : "*", (unsigned)cfg->pod_port);

    ogs_freeaddrinfo(addr);
    return OGS_OK;
}

void smf_radius_pod_close(void)
{
    if (s_pod_poll) {
        ogs_pollset_remove(s_pod_poll);
        s_pod_poll = NULL;
    }
    if (s_pod_sock) {
        ogs_sock_destroy(s_pod_sock);
        s_pod_sock = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Hot reload                                                          */
/* ------------------------------------------------------------------ */

/*
 * String ownership: these pointers hold the heap-allocated copies that
 * back smf_self()->radius.* entries we duplicated from an admin-API
 * payload. We track them out-of-band (rather than marking the config
 * struct with flags) because the YAML parser loads from ogs_app()'s
 * YAML document and its pointers must NOT be freed on hot reload.
 */
static char *g_rad_owned_nas_id;
static char *g_rad_owned_nas_ip;
static char *g_rad_owned_pod_bind;
static char *g_rad_owned_pod_secret;
static char *g_rad_owned_legacy_server;
static char *g_rad_owned_legacy_secret;
static char *g_rad_owned_server_host  [SMF_MAX_RADIUS_SERVERS];
static char *g_rad_owned_server_secret[SMF_MAX_RADIUS_SERVERS];

static void rad_replace_owned(const char **field, char **owned,
        const char *new_value)
{
    char *dup = (new_value && new_value[0]) ? ogs_strdup(new_value) : NULL;
    char *old = *owned;

    /* Null the config slot first so callers on other threads never see
     * a pointer to freed memory. */
    *field = dup;
    *owned = dup;
    if (old) ogs_free(old);
}

int smf_radius_apply_runtime(const smf_radius_config_t *new_cfg)
{
    smf_radius_config_t *cur = &smf_self()->radius;
    bool pod_restart_needed = false;
    int i;

    ogs_assert(new_cfg);

    ogs_info("RADIUS: applying runtime config "
            "(enabled=%d, servers=%d, select_mode=%s)",
            new_cfg->enabled ? 1 : 0,
            new_cfg->num_servers,
            new_cfg->select_mode == SMF_RADIUS_SELECT_HASH_IMSI ?
                "hash_imsi" : "primary_failover");

    /* Decide up front whether the PoD listener needs a bounce. We do
     * this before mutating anything so a string compare against the
     * old state is meaningful. */
    {
        const char *old_bind = cur->pod_bind ? cur->pod_bind : "";
        const char *new_bind = new_cfg->pod_bind ? new_cfg->pod_bind : "";

        if (cur->pod_enabled != new_cfg->pod_enabled ||
                cur->pod_port != new_cfg->pod_port ||
                strcmp(old_bind, new_bind) != 0)
            pod_restart_needed = true;
    }

    /* Scalars + enums first; safe to update without locking because all
     * data-path consumers run on the SMF main thread. */
    cur->enabled               = new_cfg->enabled;
    cur->select_mode           = new_cfg->select_mode;
    cur->timeout_ms            = new_cfg->timeout_ms;
    cur->retry                 = new_cfg->retry;
    cur->acct_interim_interval = new_cfg->acct_interim_interval;
    cur->pod_enabled           = new_cfg->pod_enabled;
    cur->pod_port              = new_cfg->pod_port;
    cur->pod_teardown_timeout_ms = new_cfg->pod_teardown_timeout_ms;
    cur->use_framed_ip_for_ue    = new_cfg->use_framed_ip_for_ue;

    /* Shared-pointer strings. */
    rad_replace_owned(&cur->nas_id,     &g_rad_owned_nas_id,     new_cfg->nas_id);
    rad_replace_owned(&cur->nas_ip,     &g_rad_owned_nas_ip,     new_cfg->nas_ip);
    rad_replace_owned(&cur->pod_bind,   &g_rad_owned_pod_bind,   new_cfg->pod_bind);
    rad_replace_owned(&cur->pod_secret, &g_rad_owned_pod_secret, new_cfg->pod_secret);

    /* Legacy flat server/secret: we null them out so PoD secret
     * selection does not fall back to a stale value. The `servers[]`
     * array is the source of truth once the admin API owns us. */
    rad_replace_owned(&cur->server, &g_rad_owned_legacy_server, NULL);
    rad_replace_owned(&cur->secret, &g_rad_owned_legacy_secret, NULL);

    /* Swap the servers array. Free any heap-owned strings first so the
     * slot is clean, then dup from new_cfg. */
    for (i = 0; i < SMF_MAX_RADIUS_SERVERS; i++) {
        if (g_rad_owned_server_host[i]) {
            ogs_free(g_rad_owned_server_host[i]);
            g_rad_owned_server_host[i] = NULL;
        }
        if (g_rad_owned_server_secret[i]) {
            ogs_free(g_rad_owned_server_secret[i]);
            g_rad_owned_server_secret[i] = NULL;
        }
        memset(&cur->servers[i], 0, sizeof(cur->servers[i]));
    }
    cur->num_servers = 0;
    for (i = 0; i < new_cfg->num_servers && i < SMF_MAX_RADIUS_SERVERS; i++) {
        const smf_radius_server_t *ns = &new_cfg->servers[i];
        smf_radius_server_t *dst = &cur->servers[i];

        if (!ns->host || !ns->host[0]) continue;

        g_rad_owned_server_host[i]   = ogs_strdup(ns->host);
        g_rad_owned_server_secret[i] = ogs_strdup(
                ns->secret ? ns->secret : "");
        dst->host       = g_rad_owned_server_host[i];
        dst->auth_port  = ns->auth_port ? ns->auth_port : 1812;
        dst->acct_port  = ns->acct_port ? ns->acct_port : 1813;
        dst->secret     = g_rad_owned_server_secret[i];
        dst->is_primary = ns->is_primary;
        dst->weight     = ns->weight ? ns->weight : 1;
        /* Clear health so next request gets a fresh chance at this
         * server; admin edits implicitly reset blacklists. */
        dst->consecutive_failures = 0;
        dst->down_since = 0;
        dst->last_probe = 0;
        cur->num_servers++;
    }

    /* Existing sessions may still hold a server_idx that no longer
     * maps to the same AAA. radius_build_try_order() handles this
     * defensively (it clamps and falls back to mode-based selection). */

    /* Finally, (re)start the PoD listener if needed. */
    if (pod_restart_needed) {
        smf_radius_pod_close();
        if (cur->pod_enabled) {
            if (smf_radius_pod_open() != OGS_OK) {
                ogs_error("RADIUS PoD: failed to reopen listener after "
                        "runtime reconfig; PoD disabled until next apply");
            }
        }
    }

    return OGS_OK;
}
