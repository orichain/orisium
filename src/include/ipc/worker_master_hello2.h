#ifndef IPC_WORKER_MASTER_HELLO2_H
#define IPC_WORKER_MASTER_HELLO2_H

#include "ipc/protocol.h"
#include "log.h"
#include "types.h"
#include "utilities.h"

static inline status_t ipc_serialize_worker_master_hello2(const char *label, const ipc_worker_master_hello2_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->encrypted_wot_index, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES);
    current_offset_local += AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES;
    *offset = current_offset_local;
    return SUCCESS;
}

static inline status_t ipc_deserialize_worker_master_hello2(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_worker_master_hello2) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_worker_master_hello2_t *payload = p->payload.ipc_worker_master_hello2;
    if (current_offset + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading encrypted_wot_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->encrypted_wot_index, cursor, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES);
    cursor += AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES;
    current_offset += AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES;
    *offset_ptr = current_offset;
    return SUCCESS;
}

static inline ipc_protocol_t_status_t ipc_prepare_cmd_worker_master_hello2(const char *label, oritlsf_pool_t *pool, worker_type_t wot, uint8_t index, uint8_t *encrypted_wot_index) {
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
	result.r_ipc_protocol_t->type = IPC_WORKER_MASTER_HELLO2;
	ipc_worker_master_hello2_t *payload = (ipc_worker_master_hello2_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_worker_master_hello2_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_worker_master_hello2_t payload. %s", label, strerror(errno));
		CLOSE_IPC_PROTOCOL(pool, &result.r_ipc_protocol_t);
		return result;
	}
    memcpy(payload->encrypted_wot_index, encrypted_wot_index, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES);
	result.r_ipc_protocol_t->payload.ipc_worker_master_hello2 = payload;
	result.status = SUCCESS;
	return result;
}

#endif
