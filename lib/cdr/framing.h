/*
 * Copyright (C) 2026 by Open5GS Contributors
 *
 * Shared on-disk CDR spool framing (SMF PGW-CDR, SGW-C SGW-CDR, open5gs-cgfd).
 *
 * Each record is prefixed with:
 *   4 B  magic       "O5CD"
 *   1 B  version     OGS_CDR_FILE_VERSION
 *   1 B  format      OGS_CDR_FORMAT_* (BER record subtype)
 *   2 B  length N    big-endian BER length
 *   N B  ASN.1 BER
 *
 * The format byte distinguishes PGWRecord vs SGWRecord payloads for operators
 * and cgfd logging. The CGF receives opaque BER either way.
 */

#ifndef OGS_CDR_FRAMING_H
#define OGS_CDR_FRAMING_H

#define OGS_CDR_FILE_MAGIC           "O5CD"
#define OGS_CDR_FILE_VERSION         0x01

/* Legacy SMF writer used 0x01 for any BER PGW record. */
#define OGS_CDR_FORMAT_BER_PGW       0x01
#define OGS_CDR_FORMAT_BER_SGW       0x02

#define OGS_CDR_RECORD_HDR_LEN       8

static inline int ogs_cdr_format_is_valid(uint8_t format)
{
    return format == OGS_CDR_FORMAT_BER_PGW ||
           format == OGS_CDR_FORMAT_BER_SGW;
}

static inline const char *ogs_cdr_format_name(uint8_t format)
{
    switch (format) {
    case OGS_CDR_FORMAT_BER_PGW: return "PGW-CDR";
    case OGS_CDR_FORMAT_BER_SGW: return "SGW-CDR";
    default: return "unknown";
    }
}

#endif /* OGS_CDR_FRAMING_H */
