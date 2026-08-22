/*
 * Copyright (C) 2026 by Pretty5GS Contributors
 */

#include "ogs-dbi.h"

int ogs_dbi_imei_tracker_get(const char *imsi,
        char *imei_out, size_t imei_out_size)
{
    mongoc_cursor_t *cursor = NULL;
    bson_t *query = NULL;
    const bson_t *document;
    bson_iter_t iter;
    bson_error_t error;
    int rv = OGS_ERROR;
    const char *imei;
    uint32_t len = 0;

    ogs_assert(imsi);
    ogs_assert(imei_out);
    ogs_assert(imei_out_size > OGS_DBI_IMEI_TRACKER_IMEI_LEN);

    imei_out[0] = '\0';

    if (!ogs_mongoc()->collection.imei_tracker) {
        ogs_error("imei_tracker collection not initialized");
        return OGS_ERROR;
    }

    query = BCON_NEW(OGS_IMSI_STRING, BCON_UTF8(imsi));
#if MONGOC_CHECK_VERSION(1, 5, 0)
    cursor = mongoc_collection_find_with_opts(
            ogs_mongoc()->collection.imei_tracker, query, NULL, NULL);
#else
    cursor = mongoc_collection_find(ogs_mongoc()->collection.imei_tracker,
            MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
#endif

    if (!mongoc_cursor_next(cursor, &document)) {
        rv = OGS_ERROR;
        goto out;
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ogs_error("imei_tracker cursor: %s", error.message);
        rv = OGS_ERROR;
        goto out;
    }

    if (!bson_iter_init_find(&iter, document, "imei") ||
            !BSON_ITER_HOLDS_UTF8(&iter)) {
        ogs_error("imei_tracker: no imei field for IMSI %s", imsi);
        rv = OGS_ERROR;
        goto out;
    }

    imei = bson_iter_utf8(&iter, &len);
    if (!imei || len < OGS_DBI_IMEI_TRACKER_IMEI_LEN) {
        rv = OGS_ERROR;
        goto out;
    }

    ogs_cpystrn(imei_out, imei, imei_out_size);
    imei_out[OGS_DBI_IMEI_TRACKER_IMEI_LEN] = '\0';
    rv = OGS_OK;

out:
    if (query)
        bson_destroy(query);
    if (cursor)
        mongoc_cursor_destroy(cursor);
    return rv;
}

int ogs_dbi_imei_tracker_set(const char *imsi, const char *imei)
{
    bson_t *query = NULL;
    bson_t *update = NULL;
    bson_error_t error;
    int rv = OGS_OK;

    ogs_assert(imsi);
    ogs_assert(imei);

    if (!ogs_mongoc()->collection.imei_tracker) {
        ogs_error("imei_tracker collection not initialized");
        return OGS_ERROR;
    }

    query = BCON_NEW(OGS_IMSI_STRING, BCON_UTF8(imsi));
    update = BCON_NEW("$set",
            "{",
                OGS_IMSI_STRING, BCON_UTF8(imsi),
                "imei", BCON_UTF8(imei),
            "}");

    if (!mongoc_collection_update(ogs_mongoc()->collection.imei_tracker,
            MONGOC_UPDATE_UPSERT, query, update, NULL, &error)) {
        ogs_error("imei_tracker upsert IMSI %s: %s", imsi, error.message);
        rv = OGS_ERROR;
    }

    if (query)
        bson_destroy(query);
    if (update)
        bson_destroy(update);

    return rv;
}
