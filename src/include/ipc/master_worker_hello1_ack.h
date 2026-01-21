#ifndef IPC_MASTER_WORKER_HELLO1_ACK_H
#define IPC_MASTER_WORKER_HELLO1_ACK_H

#if defined(__clang__)
#if __clang_major__ < 21
#include <stdio.h>
#endif
#endif

#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "ipc/master_worker_hello1_ack.h"
#include "constants.h"
#include "pqc.h"
#include "oritlsf.h"

static inline status_t ipc_serialize_master_worker_hello1_ack(const char *label, const ipc_master_worker_hello1_ack_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, AES_NONCE_BYTES, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->nonce, AES_NONCE_BYTES);
    current_offset_local += AES_NONCE_BYTES;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, KEM_CIPHERTEXT_BYTES, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->kem_ciphertext, KEM_CIPHERTEXT_BYTES);
    current_offset_local += KEM_CIPHERTEXT_BYTES;
    *offset = current_offset_local;
    return SUCCESS;
}

static inline status_t ipc_deserialize_master_worker_hello1_ack(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_master_worker_hello1_ack) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_master_worker_hello1_ack_t *payload = p->payload.ipc_master_worker_hello1_ack;
    if (current_offset + AES_NONCE_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading nonce.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->nonce, cursor, AES_NONCE_BYTES);
    cursor += AES_NONCE_BYTES;
    current_offset += AES_NONCE_BYTES;
    if (current_offset + KEM_CIPHERTEXT_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading kem_ciphertext.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->kem_ciphertext, cursor, KEM_CIPHERTEXT_BYTES);
    cursor += KEM_CIPHERTEXT_BYTES;
    current_offset += KEM_CIPHERTEXT_BYTES;
    *offset_ptr = current_offset;
    return SUCCESS;
}

static inline ipc_protocol_t_status_t ipc_prepare_cmd_master_worker_hello1_ack(const char *label, oritlsf_pool_t *pool, worker_type_t wot, uint8_t index, uint8_t *nonce, uint8_t *kem_ciphertext) {
	ipc_protocol_t_status_t result;
	result.r_ipc_protocol_t = (ipc_protocol_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_protocol_t));
	result.status = FAILURE;
	if (!result.r_ipc_protocol_t) {
		LOG_ERROR("%sFailed to allocate ipc_protocol_t. %s", label, strerror(errno));
		return result;
	}
	result.r_ipc_protocol_t->version[0] = IPC_VERSION_MAJOR;
	result.r_ipc_protocol_t->version[1] = IPC_VERSION_MINOR;
    result.r_ipc_protocol_t->wot = wot;
    result.r_ipc_protocol_t->index = index;
	result.r_ipc_protocol_t->type = IPC_MASTER_WORKER_HELLO1_ACK;
	ipc_master_worker_hello1_ack_t *payload = (ipc_master_worker_hello1_ack_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_master_worker_hello1_ack_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_master_worker_hello1_ack_t payload. %s", label, strerror(errno));
		CLOSE_IPC_PROTOCOL(pool, &result.r_ipc_protocol_t);
		return result;
	}
    memcpy(payload->nonce, nonce, AES_NONCE_BYTES);
    memcpy(payload->kem_ciphertext, kem_ciphertext, KEM_CIPHERTEXT_BYTES);
	result.r_ipc_protocol_t->payload.ipc_master_worker_hello1_ack = payload;
	result.status = SUCCESS;
	return result;
}

#endif
