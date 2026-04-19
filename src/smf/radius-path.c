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

/* 3GPP VSAs (TS 29.061 §16.4) */
#define RADIUS_VENDOR_3GPP                  10415
#define RADIUS_3GPP_IMSI                    1
#define RADIUS_3GPP_IMEISV                  20
#define RADIUS_3GPP_USER_LOCATION_INFO      22

/* 3GPP-User-Location-Info Geographic Location Type (TS 29.061 §16.4.7.2). */
#define RADIUS_3GPP_ULI_TYPE_CGI            0
#define RADIUS_3GPP_ULI_TYPE_TAI            128
#define RADIUS_3GPP_ULI_TYPE_ECGI           129
#define RADIUS_3GPP_ULI_TYPE_TAI_ECGI       130
#define RADIUS_3GPP_ULI_TYPE_TAI_NCGI       136

/* Acct-Status-Type values (RFC 2866) */
#define RADIUS_ACCT_STATUS_START            1
#define RADIUS_ACCT_STATUS_STOP             2
#define RADIUS_ACCT_STATUS_INTERIM_UPDATE   3

/* Acct-Terminate-Cause values (RFC 2866 §5.10) */
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
 * RFC 2865 §5.25: Class attributes are opaque and must be echoed
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

/* Parse Framed-IP-Address, Framed-IPv6-Prefix and Class AVPs from
 * Access-Accept attributes into the session. */
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

    ogs_assert(smf_ue);
    memset(v6, 0, sizeof v6);

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
     * RFC 2869 §2.1 Acct-Interim-Interval: in this implementation the
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

    /* Apply framed addresses into sess->session.ue_ip. */
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
            ogs_error("RADIUS: need Framed-IP-Address and Framed-IPv6-Prefix "
                    "for IPv4v6 session");
            return OGS_ERROR;
        }
        sess->session.ue_ip.addr = v4_be;
        memcpy(sess->session.ue_ip.addr6, v6, OGS_IPV6_LEN);
    } else {
        ogs_error("RADIUS: unsupported PDU session type %u",
                (unsigned)sess->session.session_type);
        return OGS_ERROR;
    }

    return OGS_OK;
}

/* ------------------------------------------------------------------ */
/* Request building                                                    */
/* ------------------------------------------------------------------ */

/* Encode 3GPP-User-Location-Info (TS 29.061 §16.4.7.2) for the given
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
        p = append_attr_vendor_string(p, RADIUS_VENDOR_3GPP,
                RADIUS_3GPP_IMEISV, smf_ue->imeisv_bcd);
    }

    if (sess) {
        uli_len = radius_build_3gpp_uli(sess, uli);
        if (uli_len) {
            p = append_attr_vendor_bytes(p, RADIUS_VENDOR_3GPP,
                    RADIUS_3GPP_USER_LOCATION_INFO, uli, uli_len);
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

static int radius_udp_exchange(uint16_t port,
        const uint8_t *req, size_t req_len,
        uint8_t *res, size_t res_max, size_t *res_len,
        const uint8_t *acceptable_codes, unsigned num_codes)
{
    ogs_sockaddr_t *peer = NULL;
    ogs_sock_t *sock = NULL;
    int rv = OGS_ERROR;
    int attempt;
    smf_radius_config_t *cfg = &smf_self()->radius;

    ogs_assert(req);
    ogs_assert(res);
    ogs_assert(res_len);

    if (!cfg->server) {
        ogs_error("RADIUS server not configured");
        return OGS_ERROR;
    }

    if (ogs_getaddrinfo(&peer, AF_UNSPEC, cfg->server, port, 0) != OGS_OK ||
        peer == NULL) {
        ogs_error("RADIUS ogs_getaddrinfo(%s) failed", cfg->server);
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
            ogs_warn("RADIUS sendto incomplete (%d vs %u)",
                    (int)snd, (unsigned)req_len);
            continue;
        }

        rcv = ogs_recvfrom(sock->fd, res, res_max, 0, &from);
        if (rcv < RADIUS_HDR_LEN) {
            if (rcv < 0)
                ogs_warn("RADIUS recvfrom failed");
            else
                ogs_warn("RADIUS short response");
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
        break;
    }

    ogs_sock_destroy(sock);
    ogs_freeaddrinfo(peer);
    return rv;
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

    {
        const uint8_t want[] = {
            RADIUS_CODE_ACCESS_ACCEPT,
            RADIUS_CODE_ACCESS_REJECT
        };

        if (radius_udp_exchange(cfg->auth_port, pkt, total_len,
                    res, sizeof res, &res_len, want, sizeof want) != OGS_OK) {
            ogs_error("RADIUS Access-Request failed after %d attempts",
                    cfg->retry);
            return OGS_ERROR;
        }
    }

    if (radius_verify_response(req_auth, res, res_len,
                cfg->secret ? cfg->secret : "") != OGS_OK) {
        ogs_warn("RADIUS Access-Accept/Reject authenticator mismatch");
        return OGS_ERROR;
    }

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

    /* Acct-Session-Time is sent on Interim and Stop (RFC 2866 §5.7).
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

    /* Acct-Input/Output-Gigawords (RFC 2869 §5.1/5.2) when > 4 GiB. */
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

    ogs_assert(sess->radius.acct_session_id);
    ogs_assert(smf_ue);

    if (!cfg->server)
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

    /* Echo the Class AVP(s) received in Access-Accept (RFC 2865 §5.25). */
    if (sess->radius.class_buf && sess->radius.class_len)
        p = append_class_attrs(p, sess->radius.class_buf,
                sess->radius.class_len);

    if (sess->ipv4) {
        /*
         * sess->ipv4->addr[0] is already in network byte order
         * (it is copied straight into sin_addr.s_addr elsewhere in the
         * stack — see src/smf/gy-path.c). append_attr_ipv4 also expects
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

    radius_fill_request_authenticator(pkt, total_len,
            cfg->secret ? cfg->secret : "");

    memcpy(req_auth_saved, pkt + 4, 16);

    {
        const uint8_t want[] = { RADIUS_CODE_ACCOUNTING_RESPONSE };

        if (radius_udp_exchange(cfg->acct_port, pkt, total_len,
                    res, sizeof res, &res_len, want, sizeof want) != OGS_OK) {
            ogs_warn("RADIUS Accounting-Request (status=%u) failed",
                    (unsigned)status_type);
            return OGS_ERROR;
        }
    }

    if (radius_verify_response(req_auth_saved, res, res_len,
                cfg->secret ? cfg->secret : "") != OGS_OK) {
        ogs_warn("RADIUS Accounting-Response authenticator mismatch");
        return OGS_ERROR;
    }

    ogs_debug("RADIUS Accounting-Response (status=%u) OK",
            (unsigned)status_type);
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
        uint32_t error_cause)
{
    uint8_t pkt[RADIUS_PACKET_MAX];
    uint8_t digest[16];
    uint8_t cat[RADIUS_PACKET_MAX + 256];
    uint8_t *p;
    uint16_t total_len;
    size_t secret_len;
    const char *secret;
    smf_radius_config_t *cfg = &smf_self()->radius;

    secret = (cfg->pod_secret && cfg->pod_secret[0]) ?
            cfg->pod_secret : (cfg->secret ? cfg->secret : "");
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
     * Attributes + Secret). RFC 5176 §3.2. */
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

    secret = (cfg->pod_secret && cfg->pod_secret[0]) ?
            cfg->pod_secret : (cfg->secret ? cfg->secret : "");
    secret_len = strlen(secret);

    /* Verify Request-Authenticator:
     *   ReqAuth == MD5(Code + ID + Length + 0*16 + Attributes + Secret)
     * We do this by saving the authenticator, zeroing it, recomputing and
     * comparing. RFC 5176 §3.5.
     */
    memcpy(saved_auth, buf + 4, 16);
    memcpy(packet_copy, buf, plen);
    {
        uint8_t digest[16];
        uint8_t cat[RADIUS_PACKET_MAX + 256];
        size_t cat_len;

        memset(packet_copy + 4, 0, 16);
        if ((size_t)plen + secret_len > sizeof cat) {
            ogs_warn("RADIUS PoD: packet too large");
            return;
        }
        memcpy(cat, packet_copy, plen);
        memcpy(cat + plen, secret, secret_len);
        cat_len = plen + secret_len;
        md5_digest(cat, cat_len, digest);
        if (memcmp(digest, saved_auth, 16) != 0) {
            char ipbuf[OGS_ADDRSTRLEN];

            ogs_warn("RADIUS PoD: Request-Authenticator mismatch from %s",
                    OGS_ADDR(&from, ipbuf));
            return;
        }
    }

    attrs = buf + RADIUS_HDR_LEN;
    attrs_len = plen - RADIUS_HDR_LEN;

    /* CoA-Request not implemented: NAK with Unsupported-Service. */
    if (buf[0] == RADIUS_CODE_COA_REQUEST) {
        ogs_info("RADIUS CoA-Request received: unsupported");
        pod_send_response(RADIUS_CODE_COA_NAK, buf[1], saved_auth, &from,
                RADIUS_ERR_CAUSE_UNSUPPORTED_SERVICE);
        return;
    }

    sess = pod_find_session(attrs, attrs_len);
    if (!sess) {
        char ipbuf[OGS_ADDRSTRLEN];

        ogs_info("RADIUS Disconnect-Request: no matching session (from %s)",
                OGS_ADDR(&from, ipbuf));
        pod_send_response(RADIUS_CODE_DISCONNECT_NAK, buf[1], saved_auth,
                &from, RADIUS_ERR_CAUSE_SESSION_NOT_FOUND);
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

    pod_send_response(RADIUS_CODE_DISCONNECT_ACK, buf[1], saved_auth, &from, 0);

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
