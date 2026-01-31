#ifndef NODE_METRICS_H
#define NODE_METRICS_H

#include "constants.h"
#include "log.h"
#include "pqc.h"
#include "types.h"
#include "utilities.h"
#include <stdint.h>
#include <sys/endian.h>

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

#endif

