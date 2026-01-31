#ifndef NODE_H
#define NODE_H

#include "constants.h"
#include "database.h"
#include "lmdb.h"
#include "log.h"
#include "pqc.h"
#include "types.h"
#include "utilities.h"
#include <stdint.h>
#include <sys/endian.h>

typedef struct {
	uint64_t no;
	uint8_t vermaj;
	uint8_t vermin;
	uint8_t sgn_privatekey[SIGN_PRIVATEKEY_BYTES];
	uint8_t sgn_publickey[SIGN_PUBLICKEY_BYTES];
	uint8_t kem_privatekey[KEM_PRIVATEKEY_BYTES];
	uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
} nodekeys_t;

static inline status_t nodekeys_serialize(const char *label, const nodekeys_t *src, uint8_t *key, size_t key_len, uint8_t *value, size_t value_len) {
    if (!src || !key || !value) {
        LOG_ERROR("%sInvalid src pointers.", label);
        return FAILURE;
    }
    size_t current_offset = 0;
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint64_t), key_len) != SUCCESS) return FAILURE_OOBUF;
    uint64_t key_be = htobe64(src->no);
    memcpy(key + current_offset, &key_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    current_offset = 0;
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint8_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, &src->vermaj, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint8_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, &src->vermin, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, SIGN_PRIVATEKEY_BYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->sgn_privatekey, SIGN_PRIVATEKEY_BYTES);
    current_offset += SIGN_PRIVATEKEY_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset, SIGN_PUBLICKEY_BYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->sgn_publickey, SIGN_PUBLICKEY_BYTES);
    current_offset += SIGN_PUBLICKEY_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset, KEM_PRIVATEKEY_BYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->kem_privatekey, KEM_PRIVATEKEY_BYTES);
    current_offset += KEM_PRIVATEKEY_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset, KEM_PUBLICKEY_BYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->kem_publickey, KEM_PUBLICKEY_BYTES);
    current_offset += KEM_PUBLICKEY_BYTES;
    return SUCCESS;
}

static inline status_t nodekeys_deserialize(const char *label, const uint8_t *key, size_t key_len, const uint8_t *value, size_t value_len, nodekeys_t *dst) {
    if (!dst || !key || !value) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = 0;
    size_t total_buffer_len = key_len;
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading key.", label);
        return FAILURE_OOBUF;
    }
    uint64_t key_be;
    memcpy(&key_be, key + current_offset, sizeof(uint64_t));
    dst->no = be64toh(key_be);
    current_offset += sizeof(uint64_t);
    current_offset = 0;
    total_buffer_len = value_len;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading vermaj.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&dst->vermaj, value + current_offset, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading vermin.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&dst->vermin, value + current_offset, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (current_offset + SIGN_PRIVATEKEY_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading sgnpvkey.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->sgn_privatekey, value + current_offset, SIGN_PRIVATEKEY_BYTES);
    current_offset += SIGN_PRIVATEKEY_BYTES;
    if (current_offset + SIGN_PUBLICKEY_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading sgnpbkey.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->sgn_publickey, value + current_offset, SIGN_PUBLICKEY_BYTES);
    current_offset += SIGN_PUBLICKEY_BYTES;
    if (current_offset + KEM_PRIVATEKEY_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading kempvkey.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->kem_privatekey, value + current_offset, KEM_PRIVATEKEY_BYTES);
    current_offset += KEM_PRIVATEKEY_BYTES;
    if (current_offset + KEM_PUBLICKEY_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading kempbkey.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->kem_publickey, value + current_offset, KEM_PUBLICKEY_BYTES);
    current_offset += KEM_PUBLICKEY_BYTES;
    return SUCCESS;
}

#define NODEKEYS_KEYS_KEY_SIZE ( \
        sizeof(uint64_t) \
        )

#define NODEKEYS_KEYS_DATA_SIZE ( \
        (2 * sizeof(uint8_t)) + \
        SIGN_PRIVATEKEY_BYTES + \
        SIGN_PUBLICKEY_BYTES + \
        KEM_PRIVATEKEY_BYTES + \
        KEM_PUBLICKEY_BYTES \
        )

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

typedef struct {
	uint64_t no;
    uint8_t pkhash[HASHES_BYTES];
	uint8_t vermaj;
	uint8_t vermin;
    uint64_t updateno;
    double hb_interval;
    double sum_hb_interval;
    double count_ack;
    uint64_t last_ack;
    uint64_t last_checkhealthy;
    uint64_t last_task_started;
    uint64_t last_task_finished;
    uint64_t longest_task_time;
    uint8_t ipstatic;
    double healthy;
    long double avgtt;
    uint8_t prevhash[HASHES_BYTES];
    uint8_t hash[HASHES_BYTES];
    uint8_t signature[SIGN_GENERATE_SIGNATURE_BBYTES];
} metrics_t;

static inline status_t metrics_serialize(const char *label, const metrics_t *src, uint8_t *key, size_t key_len, uint8_t *value, size_t value_len) {
    if (!src || !key || !value) {
        LOG_ERROR("%sInvalid src pointers.", label);
        return FAILURE;
    }
    size_t current_offset = 0;
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint64_t), key_len) != SUCCESS) return FAILURE_OOBUF;
    uint64_t key_be = htobe64(src->no);
    memcpy(key + current_offset, &key_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, HASHES_BYTES, key_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(key + current_offset, src->pkhash, HASHES_BYTES);
    current_offset += HASHES_BYTES;
    current_offset = 0;
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint8_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, &src->vermaj, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint8_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, &src->vermin, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint64_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    uint64_t updateno_be = htobe64(src->updateno);
    memcpy(value + current_offset, &updateno_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, DOUBLE_ARRAY_SIZE, value_len) != SUCCESS) return FAILURE_OOBUF;
    uint8_t hbinterval_be[DOUBLE_ARRAY_SIZE];
    double_to_uint8_be(src->hb_interval, hbinterval_be);
    memcpy(value + current_offset, hbinterval_be, DOUBLE_ARRAY_SIZE);
    current_offset += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset, DOUBLE_ARRAY_SIZE, value_len) != SUCCESS) return FAILURE_OOBUF;
    uint8_t sum_hbinterval_be[DOUBLE_ARRAY_SIZE];
    double_to_uint8_be(src->sum_hb_interval, sum_hbinterval_be);
    memcpy(value + current_offset, sum_hbinterval_be, DOUBLE_ARRAY_SIZE);
    current_offset += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset, DOUBLE_ARRAY_SIZE, value_len) != SUCCESS) return FAILURE_OOBUF;
    uint8_t count_ack_be[DOUBLE_ARRAY_SIZE];
    double_to_uint8_be(src->count_ack, count_ack_be);
    memcpy(value + current_offset, count_ack_be, DOUBLE_ARRAY_SIZE);
    current_offset += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint64_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    uint64_t last_ack_be = htobe64(src->last_ack);
    memcpy(value + current_offset, &last_ack_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint64_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    uint64_t last_checkhealthy_be = htobe64(src->last_checkhealthy);
    memcpy(value + current_offset, &last_checkhealthy_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint64_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    uint64_t last_task_started_be = htobe64(src->last_task_started);
    memcpy(value + current_offset, &last_task_started_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint64_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    uint64_t last_task_finished_be = htobe64(src->last_task_finished);
    memcpy(value + current_offset, &last_task_finished_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint64_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    uint64_t longest_task_time_be = htobe64(src->longest_task_time);
    memcpy(value + current_offset, &longest_task_time_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint8_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, &src->ipstatic, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, DOUBLE_ARRAY_SIZE, value_len) != SUCCESS) return FAILURE_OOBUF;
    uint8_t healthy_be[DOUBLE_ARRAY_SIZE];
    double_to_uint8_be(src->healthy, healthy_be);
    memcpy(value + current_offset, healthy_be, DOUBLE_ARRAY_SIZE);
    current_offset += DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset, LONG_DOUBLE_ARRAY_SIZE, value_len) != SUCCESS) return FAILURE_OOBUF;
    uint8_t avgtt_be[LONG_DOUBLE_ARRAY_SIZE];
    long_double_to_uint8_be(src->avgtt, avgtt_be);
    memcpy(value + current_offset, avgtt_be, LONG_DOUBLE_ARRAY_SIZE);
    current_offset += LONG_DOUBLE_ARRAY_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset, HASHES_BYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->prevhash, HASHES_BYTES);
    current_offset += HASHES_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset, HASHES_BYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->hash, HASHES_BYTES);
    current_offset += HASHES_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset, SIGN_GENERATE_SIGNATURE_BBYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->signature, SIGN_GENERATE_SIGNATURE_BBYTES);
    current_offset += SIGN_GENERATE_SIGNATURE_BBYTES;
    return SUCCESS;
}

static inline status_t metrics_deserialize(const char *label, const uint8_t *key, size_t key_len, const uint8_t *value, size_t value_len, metrics_t *dst) {
    if (!dst || !key || !value) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = 0;
    size_t total_buffer_len = key_len;
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading key.", label);
        return FAILURE_OOBUF;
    }
    uint64_t key_be;
    memcpy(&key_be, key + current_offset, sizeof(uint64_t));
    dst->no = be64toh(key_be);
    current_offset += sizeof(uint64_t);
    if (current_offset + HASHES_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading pkhash.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->pkhash, key + current_offset, HASHES_BYTES);
    current_offset += HASHES_BYTES;
    current_offset = 0;
    total_buffer_len = value_len;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading vermaj.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&dst->vermaj, value + current_offset, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading vermin.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&dst->vermin, value + current_offset, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    return SUCCESS;
}

#define DATAAB_METRICS_KEY_SIZE ( \
        sizeof(uint64_t) + \
        HASHES_BYTES \
        )

#define DATAAB_METRICS_DATA_SIZE ( \
        (2 * sizeof(uint8_t)) + \
        sizeof(uint64_t) + \
        (3 * DOUBLE_ARRAY_SIZE) + \
        (5 * sizeof(uint64_t)) + \
        sizeof(uint8_t) + \
        DOUBLE_ARRAY_SIZE + \
        LONG_DOUBLE_ARRAY_SIZE + \
        (2 * HASHES_BYTES) + \
        SIGN_GENERATE_SIGNATURE_BBYTES \
        )

typedef struct {
	uint8_t hash[HASHES_BYTES];
	uint8_t vermaj;
	uint8_t vermin;
	uint8_t sgn_publickey[SIGN_PUBLICKEY_BYTES];
    uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
	uint8_t signature[SIGN_GENERATE_SIGNATURE_BBYTES];
    uint64_t saldo1;
    uint64_t saldo2;
    uint64_t txno;
    uint8_t lasttxid[HASHES_BYTES];
} pkhash_t;

static inline status_t pkhash_serialize(const char *label, const pkhash_t *src, uint8_t *key, size_t key_len, uint8_t *value, size_t value_len) {
    if (!src || !key || !value) {
        LOG_ERROR("%sInvalid src pointers.", label);
        return FAILURE;
    }
    size_t current_offset = 0;
    if (CHECK_BUFFER_BOUNDS(current_offset, HASHES_BYTES, key_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(key + current_offset, &src->hash, HASHES_BYTES);
    current_offset += HASHES_BYTES;
    current_offset = 0;
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint8_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, &src->vermaj, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint8_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, &src->vermin, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, SIGN_PUBLICKEY_BYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->sgn_publickey, SIGN_PUBLICKEY_BYTES);
    current_offset += SIGN_PUBLICKEY_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset, KEM_PUBLICKEY_BYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->kem_publickey, SIGN_PUBLICKEY_BYTES);
    current_offset += SIGN_PUBLICKEY_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset, SIGN_GENERATE_SIGNATURE_BBYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->signature, SIGN_GENERATE_SIGNATURE_BBYTES);
    current_offset += SIGN_GENERATE_SIGNATURE_BBYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint64_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    uint64_t saldo1_be = htobe64(src->saldo1);
    memcpy(key + current_offset, &saldo1_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint64_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    uint64_t saldo2_be = htobe64(src->saldo2);
    memcpy(key + current_offset, &saldo2_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    uint64_t txno_be = htobe64(src->txno);
    memcpy(key + current_offset, &txno_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, HASHES_BYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->lasttxid, HASHES_BYTES);
    current_offset += HASHES_BYTES;
    return SUCCESS;
}

static inline status_t pkhash_deserialize(const char *label, const uint8_t *key, size_t key_len, const uint8_t *value, size_t value_len, pkhash_t *dst) {
    if (!dst || !key || !value) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = 0;
    size_t total_buffer_len = key_len;
    if (current_offset + HASHES_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading key.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->hash, key + current_offset, HASHES_BYTES);
    current_offset += HASHES_BYTES;
    current_offset = 0;
    total_buffer_len = value_len;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading vermaj.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&dst->vermaj, value + current_offset, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading vermin.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&dst->vermin, value + current_offset, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (current_offset + SIGN_PUBLICKEY_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading sgnpbkey.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->sgn_publickey, value + current_offset, SIGN_PUBLICKEY_BYTES);
    current_offset += SIGN_PUBLICKEY_BYTES;
    if (current_offset + KEM_PUBLICKEY_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading kempbkey.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->kem_publickey, value + current_offset, KEM_PUBLICKEY_BYTES);
    current_offset += KEM_PUBLICKEY_BYTES;
    if (current_offset + SIGN_GENERATE_SIGNATURE_BBYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading signature.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->signature, value + current_offset, SIGN_GENERATE_SIGNATURE_BBYTES);
    current_offset += SIGN_GENERATE_SIGNATURE_BBYTES;
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading saldo1.", label);
        return FAILURE_OOBUF;
    }
    uint64_t saldo1_be;
    memcpy(&saldo1_be, value + current_offset, sizeof(uint64_t));
    dst->saldo1 = be64toh(saldo1_be);
    current_offset += sizeof(uint64_t);
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading saldo2.", label);
        return FAILURE_OOBUF;
    }
    uint64_t saldo2_be;
    memcpy(&saldo2_be, value + current_offset, sizeof(uint64_t));
    dst->saldo2 = be64toh(saldo2_be);
    current_offset += sizeof(uint64_t);
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading txno.", label);
        return FAILURE_OOBUF;
    }
    uint64_t txno_be;
    memcpy(&txno_be, value + current_offset, sizeof(uint64_t));
    dst->txno = be64toh(txno_be);
    current_offset += sizeof(uint64_t);
    if (current_offset + HASHES_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading lasttxid.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->lasttxid, value + current_offset, HASHES_BYTES);
    current_offset += HASHES_BYTES;
    return SUCCESS;
}

#define DATABASE_PKHASH_KEY_SIZE ( \
        HASHES_BYTES \
        )

#define DATABASE_PKHASH_DATA_SIZE ( \
        (2 * sizeof(uint8_t)) + \
        SIGN_PUBLICKEY_BYTES + \
        KEM_PUBLICKEY_BYTES + \
        KEM_PRIVATEKEY_BYTES + \
        SIGN_GENERATE_SIGNATURE_BBYTES + \
        (3 * sizeof(uint64_t)) + \
        HASHES_BYTES \
        )

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

static inline status_t serialize_node_pkhash(const char *label, const uint8_t *src, uint8_t *current_buffer, size_t buffer_size, size_t *offset) {
    if (!src || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, HASHES_BYTES, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, src, HASHES_BYTES);
    current_offset_local += HASHES_BYTES;
    *offset = current_offset_local;
    return SUCCESS;
}

static inline status_t deserialize_node_pkhash(const char *label, uint8_t *dst, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!dst || !buffer || !offset_ptr) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    if (current_offset + HASHES_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading pkhash.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst, cursor, HASHES_BYTES);
    cursor += HASHES_BYTES;
    current_offset += HASHES_BYTES;
    *offset_ptr = current_offset;
    return SUCCESS;
}

typedef struct {
	uint8_t men[HASHES_BYTES];
	uint8_t wamen[HASHES_BYTES];
	uint8_t dprkemen[HASHES_BYTES][DPR_COUNT];
} node_men_t;

static inline status_t serialize_node_men(const char *label, const node_men_t *src, uint8_t *current_buffer, size_t buffer_size, size_t *offset) {
    if (!src || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    if (serialize_node_pkhash(label, src->men, current_buffer, buffer_size, offset) != SUCCESS) return FAILURE;
    if (serialize_node_pkhash(label, src->wamen, current_buffer, buffer_size, offset) != SUCCESS) return FAILURE;
    for (uint8_t iii=0;iii<DPR_COUNT;++iii) {
        if (serialize_node_pkhash(label, src->dprkemen[iii], current_buffer, buffer_size, offset) != SUCCESS) return FAILURE;
    }
    return SUCCESS;
}

static inline status_t deserialize_node_men(const char *label, node_men_t *dst, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!dst || !buffer || !offset_ptr) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    if (deserialize_node_pkhash(label, dst->men, buffer, total_buffer_len, offset_ptr) != SUCCESS) return FAILURE;
    if (deserialize_node_pkhash(label, dst->wamen, buffer, total_buffer_len, offset_ptr) != SUCCESS) return FAILURE;
    for (uint8_t iii=0;iii<DPR_COUNT;++iii) {
        if (deserialize_node_pkhash(label, dst->dprkemen[iii], buffer, total_buffer_len, offset_ptr) != SUCCESS) return FAILURE;
    }
    return SUCCESS;
}

typedef struct {
	uint64_t no;
	uint8_t vermaj;
	uint8_t vermin;
    uint64_t updateno;
	uint8_t presiden[HASHES_BYTES];
	uint8_t wapres[HASHES_BYTES];
	node_men_t mendagri;
	node_men_t menlu;
	node_men_t menhan;
	node_men_t menkeu;
	node_men_t menkumham;
	node_men_t menkominfo;
	node_men_t mensos;
	node_men_t menperin;
	node_men_t menperdag;
	node_men_t menristek;
	node_men_t menpanrb;
	node_men_t menag;
	uint8_t irjen[HASHES_BYTES];
	uint8_t ab[IPV6_ADDRESS_LEN][AB_COUNT];
	uint8_t prevhash[HASHES_BYTES];
	uint8_t hash[HASHES_BYTES];
	uint8_t signature[SIGN_GENERATE_SIGNATURE_BBYTES];
} era_t;

static inline status_t era_serialize(const char *label, const era_t *src, uint8_t *key, size_t key_len, uint8_t *value, size_t value_len) {
    if (!src || !key || !value) {
        LOG_ERROR("%sInvalid src pointers.", label);
        return FAILURE;
    }
    size_t current_offset = 0;
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint64_t), key_len) != SUCCESS) return FAILURE_OOBUF;
    uint64_t key_be = htobe64(src->no);
    memcpy(key + current_offset, &key_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    current_offset = 0;
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint8_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, &src->vermaj, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint8_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, &src->vermin, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset, sizeof(uint64_t), value_len) != SUCCESS) return FAILURE_OOBUF;
    uint64_t updateno_be = htobe64(src->updateno);
    memcpy(value + current_offset, &updateno_be, sizeof(uint64_t));
    current_offset += sizeof(uint64_t);
    if (serialize_node_pkhash(label, src->presiden, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_pkhash(label, src->wapres, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_men(label, &src->mendagri, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_men(label, &src->menlu, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_men(label, &src->menhan, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_men(label, &src->menkeu, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_men(label, &src->menkumham, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_men(label, &src->menkominfo, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_men(label, &src->mensos, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_men(label, &src->menperin, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_men(label, &src->menperdag, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_men(label, &src->menristek, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_men(label, &src->menpanrb, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_men(label, &src->menag, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    if (serialize_node_pkhash(label, src->irjen, value, value_len, &current_offset) != SUCCESS) return FAILURE;
    for (uint8_t iii=0;iii<AB_COUNT;++iii) {
        if (CHECK_BUFFER_BOUNDS(current_offset, IPV6_ADDRESS_LEN, value_len) != SUCCESS) return FAILURE_OOBUF;
        memcpy(value + current_offset, src->ab[iii], IPV6_ADDRESS_LEN);
        current_offset += IPV6_ADDRESS_LEN;
    }
    if (CHECK_BUFFER_BOUNDS(current_offset, HASHES_BYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->prevhash, HASHES_BYTES);
    current_offset += HASHES_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset, HASHES_BYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->hash, HASHES_BYTES);
    current_offset += HASHES_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset, SIGN_GENERATE_SIGNATURE_BBYTES, value_len) != SUCCESS) return FAILURE_OOBUF;
    memcpy(value + current_offset, src->signature, SIGN_GENERATE_SIGNATURE_BBYTES);
    current_offset += SIGN_GENERATE_SIGNATURE_BBYTES;
    return SUCCESS;
}

static inline status_t era_deserialize(const char *label, const uint8_t *key, size_t key_len, const uint8_t *value, size_t value_len, era_t *dst) {
    if (!dst || !key || !value) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = 0;
    size_t total_buffer_len = key_len;
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading key.", label);
        return FAILURE_OOBUF;
    }
    uint64_t key_be;
    memcpy(&key_be, key + current_offset, sizeof(uint64_t));
    dst->no = be64toh(key_be);
    current_offset += sizeof(uint64_t);
    current_offset = 0;
    total_buffer_len = value_len;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading vermaj.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&dst->vermaj, value + current_offset, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading vermin.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&dst->vermin, value + current_offset, sizeof(uint8_t));
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading updateno.", label);
        return FAILURE_OOBUF;
    }
    uint64_t updateno_be;
    memcpy(&updateno_be, value + current_offset, sizeof(uint64_t));
    dst->updateno = be64toh(updateno_be);
    current_offset += sizeof(uint64_t);
    if (deserialize_node_pkhash(label, dst->presiden, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_pkhash(label, dst->wapres, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_men(label, &dst->mendagri, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_men(label, &dst->menlu, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_men(label, &dst->menhan, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_men(label, &dst->menkeu, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_men(label, &dst->menkumham, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_men(label, &dst->menkominfo, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_men(label, &dst->mensos, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_men(label, &dst->menperin, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_men(label, &dst->menperdag, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_men(label, &dst->menristek, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_men(label, &dst->menpanrb, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_men(label, &dst->menag, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    if (deserialize_node_pkhash(label, dst->irjen, value, total_buffer_len, &current_offset) != SUCCESS) return FAILURE;
    for (uint8_t iii=0;iii<AB_COUNT;++iii) {
        if (current_offset + IPV6_ADDRESS_LEN > total_buffer_len) {
            LOG_ERROR("%sOut of bounds reading ab[%d].", label, iii);
            return FAILURE_OOBUF;
        }
        memcpy(dst->ab[iii], value + current_offset, IPV6_ADDRESS_LEN);
        current_offset += IPV6_ADDRESS_LEN;
    }
    if (current_offset + HASHES_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading prevhash.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->prevhash, value + current_offset, HASHES_BYTES);
    current_offset += HASHES_BYTES;
    if (current_offset + HASHES_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading hash.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->hash, value + current_offset, HASHES_BYTES);
    current_offset += HASHES_BYTES;
    if (current_offset + SIGN_GENERATE_SIGNATURE_BBYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading signature.", label);
        return FAILURE_OOBUF;
    }
    memcpy(dst->signature, value + current_offset, SIGN_GENERATE_SIGNATURE_BBYTES);
    current_offset += SIGN_GENERATE_SIGNATURE_BBYTES;
    return SUCCESS;
}

#define DATABASE_ERA_KEY_SIZE ( \
        sizeof(uint64_t) \
        )

#define DATABASE_ERA_DATA_SIZE ( \
        (2 * sizeof(uint8_t)) + \
        sizeof(uint64_t) + \
        (2 * HASHES_BYTES)  + \
        (2 * 12 * HASHES_BYTES) + \
        (DPR_COUNT * 12 * HASHES_BYTES) + \
        (1 * HASHES_BYTES) + \
        (AB_COUNT * IPV6_ADDRESS_LEN) + \
        (2 * HASHES_BYTES) + \
        SIGN_GENERATE_SIGNATURE_BBYTES \
        )

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
