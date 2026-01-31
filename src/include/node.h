#ifndef NODE_H
#define NODE_H

#include "constants.h"
#include "database.h"
#include "lmdb.h"
#include "log.h"
#include "node/nodekeys.h"
#include "node/pkhash.h"
#include "node/era.h"
#include "types.h"
#include <stdint.h>
#include <sys/endian.h>

static inline int nodekeys_keys_get_last(
        const char *label,
        oritlsf_pool_t *pool,
        MDB_env *env,
        MDB_dbi dbi,
        nodekeys_t **nodekeys_keys
        )
{
    MDB_txn *txn = NULL;
    MDB_cursor *cur = NULL;
    MDB_val k, v;
    int rc;
    rc = database_txn_begin(label, env, &txn);
    if (rc != MDB_SUCCESS) return rc;
    rc = database_cursor_open(label, txn, dbi, &cur);
    if (rc != MDB_SUCCESS) {
        database_txn_abort(&txn);
        return rc;
    }
    rc = database_cursor_get_last(cur, &k, &v);
    if (rc != MDB_SUCCESS) {
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return rc;
    }
    *nodekeys_keys = (nodekeys_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(nodekeys_t));
    if (!*nodekeys_keys) {
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return ENOMEM;
    }
    if (k.mv_size != NODEKEYS_KEYS_KEY_SIZE || v.mv_size != NODEKEYS_KEYS_DATA_SIZE) {
        LOG_ERROR("%sKEYS: Size mismatch! K:%zu V:%zu", label, k.mv_size, v.mv_size);
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return MDB_CORRUPTED;
    }
    status_t st = nodekeys_deserialize(label, k.mv_data, k.mv_size, v.mv_data, v.mv_size, *nodekeys_keys);
    database_cursor_close(&cur);
    database_txn_abort(&txn);
    return (st == SUCCESS) ? MDB_SUCCESS : FAILURE;
}

static inline int nodekeys_keys_append(
        const char *label,
        oritlsf_pool_t *pool,
        MDB_env *env,
        MDB_dbi dbi,
        const nodekeys_t *keys
        )
{
    MDB_txn *txn = NULL;
    MDB_cursor *cur = NULL;
    MDB_val k, v;
    uint64_t next_no = 0;
    int rc;
    rc = database_txn_begin(label, env, &txn);
    if (rc != MDB_SUCCESS) return rc;
    rc = database_cursor_open(label, txn, dbi, &cur);
    if (rc != MDB_SUCCESS) {
        database_txn_abort(&txn);
        return rc;
    }
    rc = database_cursor_get_last(cur, &k, &v);
    if (rc == MDB_NOTFOUND) {
        next_no = 0;
    } else if (rc == MDB_SUCCESS) {
        uint64_t last_no_be;
        memcpy(&last_no_be, k.mv_data, sizeof(uint64_t));
        next_no = be64toh(last_no_be) + 1;
    } else {
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return rc;
    }
    database_cursor_close(&cur);
    uint8_t *k_buf = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, NODEKEYS_KEYS_KEY_SIZE);
    if (!k_buf) {
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return ENOMEM;
    }
    uint8_t *v_buf = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, NODEKEYS_KEYS_DATA_SIZE);
    if (!v_buf) {
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return ENOMEM;
    }
    nodekeys_t tmp = *keys;
    tmp.no = next_no;
    if (nodekeys_serialize(label, &tmp, k_buf, NODEKEYS_KEYS_KEY_SIZE, v_buf, NODEKEYS_KEYS_DATA_SIZE) != SUCCESS) {
        database_txn_abort(&txn);
        return FAILURE;
    }
    rc = database_txn_put(label, txn, dbi, k_buf, NODEKEYS_KEYS_KEY_SIZE, v_buf, NODEKEYS_KEYS_DATA_SIZE, 0);
    memset(k_buf, 0, NODEKEYS_KEYS_KEY_SIZE);
    memset(v_buf, 0, NODEKEYS_KEYS_DATA_SIZE);
    oritlsf_free(pool, (void **)&k_buf);
    oritlsf_free(pool, (void **)&v_buf);
    if (rc == MDB_SUCCESS) {
        return database_txn_commit(label, &txn);
    } else {
        database_txn_abort(&txn);
        return rc;
    }
}

static inline int database_pkhash_find(
        const char *label,
        oritlsf_pool_t *pool,
        MDB_env *env,
        MDB_dbi dbi,
        uint8_t *hash,
        pkhash_t **database_pkhash
        )
{
    MDB_txn *txn = NULL;
    MDB_cursor *cur = NULL;
    MDB_val k, v;
    int rc;
    rc = database_txn_begin(label, env, &txn);
    if (rc != MDB_SUCCESS) return rc;
    rc = database_cursor_open(label, txn, dbi, &cur);
    if (rc != MDB_SUCCESS) {
        database_txn_abort(&txn);
        return rc;
    }
    rc = database_cursor_find(cur, hash, HASHES_BYTES, &k, &v);
    if (rc != MDB_SUCCESS) {
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return rc;
    }
    *database_pkhash = (pkhash_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(pkhash_t));
    if (!*database_pkhash) {
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return ENOMEM;
    }
    if (k.mv_size != DATABASE_PKHASH_KEY_SIZE || v.mv_size != DATABASE_PKHASH_DATA_SIZE) {
        LOG_ERROR("%sPKHASH: Size mismatch! K:%zu V:%zu", label, k.mv_size, v.mv_size);
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return MDB_CORRUPTED;
    }
    status_t st = pkhash_deserialize(label, k.mv_data, k.mv_size, v.mv_data, v.mv_size, *database_pkhash);
    database_cursor_close(&cur);
    database_txn_abort(&txn);
    return (st == SUCCESS) ? MDB_SUCCESS : FAILURE;
}

static inline int database_pkhash_append(
        const char *label,
        oritlsf_pool_t *pool,
        MDB_env *env,
        MDB_dbi dbi,
        const pkhash_t *pkhash
        )
{
    MDB_txn *txn = NULL;
    int rc;
    rc = database_txn_begin(label, env, &txn);
    if (rc != MDB_SUCCESS) return rc;
    uint8_t *k_buf = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, DATABASE_PKHASH_KEY_SIZE);
    if (!k_buf) {
        database_txn_abort(&txn);
        return ENOMEM;
    }
    uint8_t *v_buf = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, DATABASE_PKHASH_DATA_SIZE);
    if (!v_buf) {
        database_txn_abort(&txn);
        return ENOMEM;
    }
    if (pkhash_serialize(label, pkhash, k_buf, DATABASE_PKHASH_KEY_SIZE, v_buf, DATABASE_PKHASH_DATA_SIZE) != SUCCESS) {
        database_txn_abort(&txn);
        return FAILURE;
    }
    rc = database_txn_put(label, txn, dbi, k_buf, DATABASE_PKHASH_KEY_SIZE, v_buf, DATABASE_PKHASH_DATA_SIZE, 0);
    memset(k_buf, 0, DATABASE_PKHASH_KEY_SIZE);
    memset(v_buf, 0, DATABASE_PKHASH_DATA_SIZE);
    oritlsf_free(pool, (void **)&k_buf);
    oritlsf_free(pool, (void **)&v_buf);
    if (rc == MDB_SUCCESS) {
        return database_txn_commit(label, &txn);
    } else {
        database_txn_abort(&txn);
        return rc;
    }
}

static inline int database_era_get_last(
        const char *label,
        oritlsf_pool_t *pool,
        MDB_env *env,
        MDB_dbi dbi,
        era_t **database_era
        )
{
    MDB_txn *txn = NULL;
    MDB_cursor *cur = NULL;
    MDB_val k, v;
    int rc;
    rc = database_txn_begin(label, env, &txn);
    if (rc != MDB_SUCCESS) return rc;
    rc = database_cursor_open(label, txn, dbi, &cur);
    if (rc != MDB_SUCCESS) {
        database_txn_abort(&txn);
        return rc;
    }
    rc = database_cursor_get_last(cur, &k, &v);
    if (rc != MDB_SUCCESS) {
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return rc;
    }
    *database_era = (era_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(era_t));
    if (!*database_era) {
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return ENOMEM;
    }
    if (k.mv_size != DATABASE_ERA_KEY_SIZE || v.mv_size != DATABASE_ERA_DATA_SIZE) {
        LOG_ERROR("%sERA: Size mismatch! K:%zu V:%zu", label, k.mv_size, v.mv_size);
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return MDB_CORRUPTED;
    }
    status_t st = era_deserialize(label, k.mv_data, k.mv_size, v.mv_data, v.mv_size, *database_era);
    database_cursor_close(&cur);
    database_txn_abort(&txn);
    return (st == SUCCESS) ? MDB_SUCCESS : FAILURE;
}

static inline int database_era_append(
        const char *label,
        oritlsf_pool_t *pool,
        MDB_env *env,
        MDB_dbi dbi,
        const era_t *era
        )
{
    MDB_txn *txn = NULL;
    MDB_cursor *cur = NULL;
    MDB_val k, v;
    uint64_t next_no = 0;
    int rc;
    rc = database_txn_begin(label, env, &txn);
    if (rc != MDB_SUCCESS) return rc;
    rc = database_cursor_open(label, txn, dbi, &cur);
    if (rc != MDB_SUCCESS) {
        database_txn_abort(&txn);
        return rc;
    }
    rc = database_cursor_get_last(cur, &k, &v);
    if (rc == MDB_NOTFOUND) {
        next_no = 0;
    } else if (rc == MDB_SUCCESS) {
        uint64_t last_no_be;
        memcpy(&last_no_be, k.mv_data, sizeof(uint64_t));
        next_no = be64toh(last_no_be) + 1;
    } else {
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return rc;
    }
    database_cursor_close(&cur);
    uint8_t *k_buf = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, DATABASE_ERA_KEY_SIZE);
    if (!k_buf) {
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return ENOMEM;
    }
    uint8_t *v_buf = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, DATABASE_ERA_DATA_SIZE);
    if (!v_buf) {
        database_cursor_close(&cur);
        database_txn_abort(&txn);
        return ENOMEM;
    }
    era_t tmp = *era;
    tmp.no = next_no;
    if (era_serialize(label, &tmp, k_buf, DATABASE_ERA_KEY_SIZE, v_buf, DATABASE_ERA_DATA_SIZE) != SUCCESS) {
        database_txn_abort(&txn);
        return FAILURE;
    }
    rc = database_txn_put(label, txn, dbi, k_buf, DATABASE_ERA_KEY_SIZE, v_buf, DATABASE_ERA_DATA_SIZE, 0);
    memset(k_buf, 0, DATABASE_ERA_KEY_SIZE);
    memset(v_buf, 0, DATABASE_ERA_DATA_SIZE);
    oritlsf_free(pool, (void **)&k_buf);
    oritlsf_free(pool, (void **)&v_buf);
    if (rc == MDB_SUCCESS) {
        return database_txn_commit(label, &txn);
    } else {
        database_txn_abort(&txn);
        return rc;
    }
}

#endif
