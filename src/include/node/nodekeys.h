#ifndef NODE_NODEKEYS_H
#define NODE_NODEKEYS_H

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

#endif

