/*
 * K4 Patch for Open5GS Milenage — for Huawei HSS9860 stored-credential unwrap
 *
 * Matches Huawei HSS9860 storage scheme: K and OPc in MongoDB are stored
 * AES-128-ECB encrypted with a K4 key. This patch decrypts them transparently
 * at each Milenage entry point, so you can paste Huawei-exported ciphertext
 * straight into MongoDB.
 *
 * Apply: replace lib/crypt/milenage.c in your Open5GS source tree with this.
 *
 * K4 is loaded from environment variable OPEN5GS_K4 (32 hex chars) at first
 * Milenage call. If OPEN5GS_K4 is not set or invalid, the compile-time
 * default below is used. If the resulting K4 is all zeros, decryption is
 * skipped entirely (upstream behavior — safe to ship).
 *
 * Security: do NOT commit this file with a real K4 to source control.
 * Prefer the env-var route and keep the compile-time default all zeros.
 */

/*
 * 3GPP AKA - Milenage algorithm (3GPP TS 35.205, .206, .207, .208)
 * Copyright (c) 2006-2007 <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "ogs-crypt.h"

#include "milenage.h"

#include <stdlib.h>
#include <string.h>

#define os_memcpy memcpy
#define os_memcmp memcmp
#define os_memcmp_const memcmp

static void ShiftBits(uint8_t r, uint8_t rijndaelInput[16],
                       uint8_t temp[16], const uint8_t opc[16]);
static uint8_t *bits_shift(uint32_t bit_valid, uint8_t *dst,
                            uint8_t *src, uint32_t numBits);

static int aes_128_encrypt_block(const uint8_t *key,
    const uint8_t *in, uint8_t *out)
{
    const int key_bits = 128;
    unsigned int rk[OGS_AES_RKLENGTH(128)];
    int nrounds;

    nrounds = ogs_aes_setup_enc(rk, key, key_bits);
    ogs_aes_encrypt(rk, nrounds, in, out);

    return 0;
}

/* ==========================================================================
 *                       K4 UNWRAP (Huawei HSS9860)
 * ========================================================================== */

static uint8_t k4_key[16];
static int     k4_ready = 0;    /* 1 once k4_init has run */
static int     k4_enabled = 0;  /* 1 when K4 is non-zero; do decrypt */

/* Compile-time K4 key (HSS9860 K4SNO=1). Can be overridden at runtime
 * with OPEN5GS_K4=<32 hex chars> environment variable. */
static const uint8_t k4_compiled_default[16] = {
    0x5c, 0xf8, 0x77, 0x08, 0x8c, 0x7f, 0xb8, 0xf8,
    0x90, 0x47, 0xb9, 0x96, 0xb3, 0x8d, 0xbf, 0x99
};

static int k4_hex2bin(const char *hex, uint8_t out[16])
{
    int i;
    if (!hex) return -1;
    if (strlen(hex) != 32) return -1;
    for (i = 0; i < 16; i++) {
        unsigned int b;
        if (sscanf(hex + 2*i, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void k4_init(void)
{
    int i, nz;
    const char *env;

    if (k4_ready) return;
    k4_ready = 1;

    env = getenv("OPEN5GS_K4");
    if (env && k4_hex2bin(env, k4_key) == 0) {
        nz = 0;
        for (i = 0; i < 16; i++) if (k4_key[i]) { nz = 1; break; }
        k4_enabled = nz;
        ogs_log_print(OGS_LOG_INFO,
            "Milenage K4: loaded from OPEN5GS_K4 (enabled=%d)\n", k4_enabled);
        return;
    }

    memcpy(k4_key, k4_compiled_default, 16);
    nz = 0;
    for (i = 0; i < 16; i++) if (k4_key[i]) { nz = 1; break; }
    k4_enabled = nz;
    ogs_log_print(OGS_LOG_INFO,
        "Milenage K4: compile-time default (enabled=%d)\n", k4_enabled);
}

/* AES-128-ECB single-block decrypt using Open5GS's built-in AES. */
static void k4_aes_ecb_decrypt_block(const uint8_t *key,
    const uint8_t *in, uint8_t *out)
{
    unsigned int rk[OGS_AES_RKLENGTH(128)];
    int nrounds = ogs_aes_setup_dec(rk, key, 128);
    ogs_aes_decrypt(rk, nrounds, in, out);
}

/* Hex logger with "Milenage" prefix. Safe for up to 32 bytes per call. */
static void milenage_log_hex(const char *tag, const uint8_t *buf, int len)
{
    char hex[65];
    int i;
    if (len > 32) len = 32;
    for (i = 0; i < len; i++)
        snprintf(hex + 2*i, 3, "%02x", buf[i]);
    hex[2*len] = 0;
    ogs_log_print(OGS_LOG_INFO, "Milenage [%s] %s\n", tag, hex);
}

/* Unwrap (K_stored, OPc_stored) -> (K_plain, OPc_plain). Passthrough if disabled. */
static void k4_unwrap(const uint8_t *k_in, const uint8_t *opc_in,
                      uint8_t k_out[16], uint8_t opc_out[16])
{
    k4_init();
    milenage_log_hex("K   input (as stored) ", k_in, 16);
    milenage_log_hex("OPc input (as stored) ", opc_in, 16);
    if (!k4_enabled) {
        ogs_log_print(OGS_LOG_INFO, "Milenage [K4] disabled — passthrough\n");
        memcpy(k_out, k_in, 16);
        memcpy(opc_out, opc_in, 16);
        return;
    }
    ogs_log_print(OGS_LOG_INFO, "Milenage [K4] enabled — decrypting\n");
    milenage_log_hex("K4 key                ", k4_key, 16);
    k4_aes_ecb_decrypt_block(k4_key, k_in, k_out);
    k4_aes_ecb_decrypt_block(k4_key, opc_in, opc_out);
    milenage_log_hex("K   decrypted (plain) ", k_out, 16);
    milenage_log_hex("OPc decrypted (plain) ", opc_out, 16);
}

/* ==========================================================================
 *                        MILENAGE FUNCTIONS
 *   Each public entry point that takes (k, opc) as credentials unwraps
 *   them into local buffers before the actual Milenage math.
 * ========================================================================== */

/**
 * milenage_f1 - Milenage f1 and f1* algorithms
 */
int milenage_f1(const uint8_t *opc, const uint8_t *k,
    const uint8_t *_rand, const uint8_t *sqn,
    const uint8_t *amf, uint8_t *mac_a, uint8_t *mac_s)
{
    uint8_t tmp1[16], tmp2[16], tmp3[16];
    uint8_t k_p[16], opc_p[16];
    int i;
    uint8_t r1 = 64;

    ogs_log_print(OGS_LOG_INFO, "Milenage [f1] ENTER\n");
    milenage_log_hex("f1 RAND               ", _rand, 16);
    milenage_log_hex("f1 SQN                ", sqn, 6);
    milenage_log_hex("f1 AMF                ", amf, 2);
    k4_unwrap(k, opc, k_p, opc_p);

    for (i = 0; i < 16; i++)
        tmp1[i] = _rand[i] ^ opc_p[i];
    if (aes_128_encrypt_block(k_p, tmp1, tmp1))
        return -1;

    /* tmp2 = IN1 = SQN || AMF || SQN || AMF */
    os_memcpy(tmp2, sqn, 6);
    os_memcpy(tmp2 + 6, amf, 2);
    os_memcpy(tmp2 + 8, tmp2, 8);

    /* OUT1 = E_K(TEMP XOR rot(IN1 XOR OP_C, r1) XOR c1) XOR OP_C */
    ShiftBits(r1, tmp3, tmp2, opc_p);
    for (i = 0; i < 16; i++)
        tmp3[i] ^= tmp1[i];
    /* c1 is all zeros, NOP */
    if (aes_128_encrypt_block(k_p, tmp3, tmp1))
        return -1;
    for (i = 0; i < 16; i++)
        tmp1[i] ^= opc_p[i];
    if (mac_a)
        os_memcpy(mac_a, tmp1, 8); /* f1 */
    if (mac_s)
        os_memcpy(mac_s, tmp1 + 8, 8); /* f1* */
    if (mac_a) milenage_log_hex("f1 MAC-A (out)        ", mac_a, 8);
    if (mac_s) milenage_log_hex("f1 MAC-S (out)        ", mac_s, 8);
    ogs_log_print(OGS_LOG_INFO, "Milenage [f1] EXIT ok\n");
    return 0;
}

/**
 * milenage_f2345 - Milenage f2, f3, f4, f5, f5* algorithms
 */
int milenage_f2345(const uint8_t *opc, const uint8_t *k,
    const uint8_t *_rand, uint8_t *res, uint8_t *ck,
    uint8_t *ik, uint8_t *ak, uint8_t *akstar)
{
    uint8_t tmp1[16], tmp2[16], tmp3[16];
    uint8_t k_p[16], opc_p[16];
    int i;
    uint8_t r2 = 0;
    uint8_t r3 = 32;
    uint8_t r4 = 64;
    uint8_t r5 = 96;

    ogs_log_print(OGS_LOG_INFO, "Milenage [f2345] ENTER\n");
    milenage_log_hex("f2345 RAND            ", _rand, 16);
    k4_unwrap(k, opc, k_p, opc_p);

    /* tmp2 = TEMP = E_K(RAND XOR OP_C) */
    for (i = 0; i < 16; i++)
        tmp1[i] = _rand[i] ^ opc_p[i];
    if (aes_128_encrypt_block(k_p, tmp1, tmp2))
        return -1;

    /* f2 and f5 */
    ShiftBits(r2, tmp1, tmp2, opc_p);
    tmp1[15] ^= 1; /* c2 */
    if (aes_128_encrypt_block(k_p, tmp1, tmp3))
        return -1;
    for (i = 0; i < 16; i++)
        tmp3[i] ^= opc_p[i];
    if (res)
        os_memcpy(res, tmp3 + 8, 8); /* f2 */
    if (ak)
        os_memcpy(ak, tmp3, 6); /* f5 */

    /* f3 */
    if (ck) {
        ShiftBits(r3, tmp1, tmp2, opc_p);
        tmp1[15] ^= 2; /* c3 */
        if (aes_128_encrypt_block(k_p, tmp1, ck))
            return -1;
        for (i = 0; i < 16; i++)
            ck[i] ^= opc_p[i];
    }

    /* f4 */
    if (ik) {
        ShiftBits(r4, tmp1, tmp2, opc_p);
        tmp1[15] ^= 4; /* c4 */
        if (aes_128_encrypt_block(k_p, tmp1, ik))
            return -1;
        for (i = 0; i < 16; i++)
            ik[i] ^= opc_p[i];
    }

    /* f5* */
    if (akstar) {
        ShiftBits(r5, tmp1, tmp2, opc_p);
        tmp1[15] ^= 8; /* c5 */
        if (aes_128_encrypt_block(k_p, tmp1, tmp1))
            return -1;
        for (i = 0; i < 6; i++)
            akstar[i] = tmp1[i] ^ opc_p[i];
    }

    if (res)    milenage_log_hex("f2345 RES (out)       ", res, 8);
    if (ck)     milenage_log_hex("f2345 CK  (out)       ", ck, 16);
    if (ik)     milenage_log_hex("f2345 IK  (out)       ", ik, 16);
    if (ak)     milenage_log_hex("f2345 AK  (out)       ", ak, 6);
    if (akstar) milenage_log_hex("f2345 AK* (out)       ", akstar, 6);
    ogs_log_print(OGS_LOG_INFO, "Milenage [f2345] EXIT ok\n");
    return 0;
}

/**
 * milenage_generate - Generate AKA AUTN,IK,CK,RES
 *
 * NOTE: does NOT unwrap k/opc itself — it delegates to milenage_f1 and
 * milenage_f2345, which each unwrap internally. Unwrapping here would
 * cause double-decryption.
 */
void milenage_generate(const uint8_t *opc, const uint8_t *amf,
    const uint8_t *k, const uint8_t *sqn, const uint8_t *_rand,
    uint8_t *autn, uint8_t *ik, uint8_t *ck, uint8_t *ak,
    uint8_t *res, size_t *res_len)
{
    int i;
    uint8_t mac_a[8];

    ogs_log_print(OGS_LOG_INFO, "Milenage [generate] ENTER\n");
    milenage_log_hex("generate RAND         ", _rand, 16);
    milenage_log_hex("generate SQN          ", sqn, 6);
    milenage_log_hex("generate AMF          ", amf, 2);

    if (*res_len < 8) {
        ogs_log_print(OGS_LOG_INFO, "Milenage [generate] EXIT: res_len<8 fail\n");
        *res_len = 0;
        return;
    }
    if (milenage_f1(opc, k, _rand, sqn, amf, mac_a, NULL) ||
        milenage_f2345(opc, k, _rand, res, ck, ik, ak, NULL)) {
        ogs_log_print(OGS_LOG_INFO, "Milenage [generate] EXIT: f1/f2345 fail\n");
        *res_len = 0;
        return;
    }
    *res_len = 8;

    /* AUTN = (SQN ^ AK) || AMF || MAC */
    for (i = 0; i < 6; i++)
        autn[i] = sqn[i] ^ ak[i];
    os_memcpy(autn + 6, amf, 2);
    os_memcpy(autn + 8, mac_a, 8);

    milenage_log_hex("generate AUTN (out)   ", autn, 16);
    milenage_log_hex("generate RES  (out)   ", res, 8);
    ogs_log_print(OGS_LOG_INFO, "Milenage [generate] EXIT ok\n");
}

/**
 * milenage_auts - Milenage AUTS validation
 *
 * Again, delegates to f1/f2345 which handle K4 unwrap.
 */
int milenage_auts(const uint8_t *opc, const uint8_t *k,
    const uint8_t *_rand, const uint8_t *auts, uint8_t *sqn)
{
    uint8_t amf[2] = { 0x00, 0x00 }; /* TS 33.102 v7.0.0, 6.3.3 */
    uint8_t ak[6], mac_s[8];
    int i;

    ogs_log_print(OGS_LOG_INFO, "Milenage [auts] ENTER\n");
    milenage_log_hex("auts RAND             ", _rand, 16);
    milenage_log_hex("auts AUTS (in)        ", auts, 14);

    if (milenage_f2345(opc, k, _rand, NULL, NULL, NULL, NULL, ak)) {
        ogs_log_print(OGS_LOG_INFO, "Milenage [auts] EXIT: f2345 fail\n");
        return -1;
    }
    for (i = 0; i < 6; i++)
        sqn[i] = auts[i] ^ ak[i];
    milenage_log_hex("auts SQN (recovered)  ", sqn, 6);
    if (milenage_f1(opc, k, _rand, sqn, amf, NULL, mac_s) ||
        os_memcmp_const(mac_s, auts + 6, 8) != 0) {
        ogs_log_print(OGS_LOG_INFO, "Milenage [auts] EXIT: MAC-S mismatch\n");
        milenage_log_hex("auts MAC-S computed   ", mac_s, 8);
        milenage_log_hex("auts MAC-S expected   ", auts + 6, 8);
        return -1;
    }
    ogs_log_print(OGS_LOG_INFO, "Milenage [auts] EXIT ok\n");
    return 0;
}

int gsm_milenage(const uint8_t *opc, const uint8_t *k,
    const uint8_t *_rand, uint8_t *sres, uint8_t *kc)
{
    uint8_t res[8], ck[16], ik[16];
    int i;

    if (milenage_f2345(opc, k, _rand, res, ck, ik, NULL, NULL))
        return -1;

    for (i = 0; i < 8; i++)
        kc[i] = ck[i] ^ ck[i + 8] ^ ik[i] ^ ik[i + 8];

#ifdef GSM_MILENAGE_ALT_SRES
    os_memcpy(sres, res, 4);
#else
    for (i = 0; i < 4; i++)
        sres[i] = res[i] ^ res[i + 4];
#endif
    return 0;
}

int milenage_check(const uint8_t *opc, const uint8_t *k,
    const uint8_t *sqn, const uint8_t *_rand, const uint8_t *autn,
    uint8_t *ik, uint8_t *ck, uint8_t *res, size_t *res_len,
    uint8_t *auts)
{
    int i;
    uint8_t mac_a[8], ak[6], rx_sqn[6];
    const uint8_t *amf;

    ogs_log_print(OGS_LOG_INFO, "Milenage: AUTN\n");
    ogs_log_hexdump(OGS_LOG_INFO, autn, 16);
    ogs_log_print(OGS_LOG_INFO, "Milenage: RAND\n");
    ogs_log_hexdump(OGS_LOG_INFO, _rand, 16);

    if (milenage_f2345(opc, k, _rand, res, ck, ik, ak, NULL))
        return -1;

    *res_len = 8;
    ogs_log_print(OGS_LOG_INFO, "Milenage: RES\n");
    ogs_log_hexdump(OGS_LOG_INFO, res, *res_len);
    ogs_log_print(OGS_LOG_INFO, "Milenage: CK\n");
    ogs_log_hexdump(OGS_LOG_INFO, ck, 16);
    ogs_log_print(OGS_LOG_INFO, "Milenage: IK\n");
    ogs_log_hexdump(OGS_LOG_INFO, ik, 16);
    ogs_log_print(OGS_LOG_INFO, "Milenage: AK\n");
    ogs_log_hexdump(OGS_LOG_INFO, ak, 6);

    /* AUTN = (SQN ^ AK) || AMF || MAC */
    for (i = 0; i < 6; i++)
        rx_sqn[i] = autn[i] ^ ak[i];
    ogs_log_print(OGS_LOG_INFO, "Milenage: SQN\n");
    ogs_log_hexdump(OGS_LOG_INFO, rx_sqn, 6);

    if (os_memcmp(rx_sqn, sqn, 6) <= 0) {
        uint8_t auts_amf[2] = { 0x00, 0x00 };
        if (milenage_f2345(opc, k, _rand, NULL, NULL, NULL, NULL, ak))
            return -1;
        ogs_log_print(OGS_LOG_INFO, "Milenage: AK*\n");
        ogs_log_hexdump(OGS_LOG_INFO, ak, 6);
        for (i = 0; i < 6; i++)
            auts[i] = sqn[i] ^ ak[i];
        if (milenage_f1(opc, k, _rand, sqn, auts_amf, NULL, auts + 6))
            return -1;
        ogs_log_print(OGS_LOG_INFO, "Milenage: AUTS*\n");
        ogs_log_hexdump(OGS_LOG_INFO, auts, 14);
        return -2;
    }

    amf = autn + 6;
    ogs_log_print(OGS_LOG_INFO, "Milenage: AMF\n");
    ogs_log_hexdump(OGS_LOG_INFO, amf, 2);
    if (milenage_f1(opc, k, _rand, rx_sqn, amf, mac_a, NULL))
        return -1;

    ogs_log_print(OGS_LOG_INFO, "Milenage: MAC_A\n");
    ogs_log_hexdump(OGS_LOG_INFO, mac_a, 8);

    if (os_memcmp_const(mac_a, autn + 8, 8) != 0) {
        ogs_log_print(OGS_LOG_INFO, "Milenage: MAC mismatch\n");
        ogs_log_print(OGS_LOG_INFO, "Milenage: Received MAC_A\n");
        ogs_log_hexdump(OGS_LOG_INFO, autn + 8, 8);
        return -1;
    }

    return 0;
}

/**
 * milenage_opc - derive OPc from K and OP
 *
 * This is a provisioning helper, NOT an auth hotpath. Inputs are raw plaintext
 * K and OP (not K4-wrapped). We deliberately do NOT unwrap here.
 * If your provisioning pipeline needs to store K4-wrapped OPc in MongoDB,
 * wrap the output of this function externally.
 */
void milenage_opc(const uint8_t *k, const uint8_t *op, uint8_t *opc)
{
    int i;

    aes_128_encrypt_block(k, op, opc);

    for (i = 0; i < 16; i++)
    {
        opc[i] ^= op[i];
    }
}

static void ShiftBits(uint8_t r, uint8_t rijndaelInput[16],
                       uint8_t temp[16], const uint8_t opc[16])
{
    uint32_t deltlen = 16 - (r / 8);
    uint32_t leftout = r % 8;
    uint32_t i;

    if (leftout == 0) {
        for (i = 0; i < 16; i++) {
            rijndaelInput[(i+deltlen) % 16] = temp[i] ^ opc[i];
        }
    } else {
        uint8_t temp1[16];
        uint32_t move_bits;
        uint8_t temp2;

        for (i = 0; i < 16; i++) {
            temp1[(i + deltlen) % 16] = temp[i] ^ opc[i];
        }
        rijndaelInput[15] = 0;
        move_bits = 8 - leftout;
        bits_shift(move_bits, &rijndaelInput[0], temp1, (128 - leftout));
        temp2 = temp1[0] >> (8-leftout);
        rijndaelInput[15] |= temp2;
    }
}

static uint8_t *bits_shift(uint32_t bit_valid, uint8_t *dst,
                            uint8_t *src, uint32_t numBits)
{
    uint32_t bit_used = bit_valid;
    uint32_t bit_empty = 8 - bit_used;
    uint32_t numBytes = numBits >> 3;
    uint32_t leftBits = numBits & 0x7;
    uint32_t i = 0;
    uint8_t *newDst = 0;

    for (i = 0; i < numBytes; i++) {
        dst[i] = (src[i] << bit_empty) | (src[i+1] >> bit_used);
    }

    if (leftBits) {
        if (leftBits == bit_used) {
            dst[numBytes] = src[numBytes] << bit_empty;
            bit_valid = 8;
            newDst = &src[numBytes+1];
        } else if (leftBits < bit_used) {
            dst[numBytes] = src[numBytes] << bit_empty;
            bit_valid = bit_used - leftBits;
            newDst = &src[numBytes];
        } else {
            dst[numBytes] = src[numBytes] << bit_empty |
                            (src[numBytes+1] >> bit_used);
            bit_valid = 8 - (leftBits - bit_used);
            newDst = &src[numBytes+1];
        }
    } else {
        bit_valid = bit_used;
        newDst = &src[numBytes];
    }

    return newDst;
}
