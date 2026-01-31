#ifndef NODE_PKHASH_H
#define NODE_PKHASH_H

#include "constants.h"
#include "log.h"
#include "pqc.h"
#include "types.h"
#include "utilities.h"
#include <stdint.h>
#include <sys/endian.h>

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

#endif

