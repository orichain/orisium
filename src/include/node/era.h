#ifndef NODE_ERA_H
#define NODE_ERA_H

#include "constants.h"
#include "log.h"
#include "pqc.h"
#include "types.h"
#include "utilities.h"
#include <stdint.h>
#include <sys/endian.h>

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

#endif

