#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "ipc/master_worker_hello1_ack.h"
#include "constants.h"
#include "pqc.h"

status_t ipc_serialize_master_worker_hello1_ack(const char *label, const ipc_master_worker_hello1_ack_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->wot, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->index, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, KEM_CIPHERTEXT_BYTES, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->kem_ciphertext, KEM_CIPHERTEXT_BYTES);
    current_offset_local += KEM_CIPHERTEXT_BYTES;
    *offset = current_offset_local;
    return SUCCESS;
}

status_t ipc_deserialize_master_worker_hello1_ack(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_master_worker_hello1_ack) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_master_worker_hello1_ack_t *payload = p->payload.ipc_master_worker_hello1_ack;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading wot.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->wot, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading index.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
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

ipc_protocol_t_status_t ipc_prepare_cmd_master_worker_hello1_ack(const char *label, worker_type_t wot, uint8_t index, uint8_t *kem_ciphertext) {
	ipc_protocol_t_status_t result;
	result.r_ipc_protocol_t = (ipc_protocol_t *)malloc(sizeof(ipc_protocol_t));
	result.status = FAILURE;
	if (!result.r_ipc_protocol_t) {
		LOG_ERROR("%sFailed to allocate ipc_protocol_t. %s", label, strerror(errno));
		return result;
	}
	memset(result.r_ipc_protocol_t, 0, sizeof(ipc_protocol_t));
	result.r_ipc_protocol_t->version[0] = IPC_VERSION_MAJOR;
	result.r_ipc_protocol_t->version[1] = IPC_VERSION_MINOR;
	result.r_ipc_protocol_t->type = IPC_MASTER_WORKER_HELLO1_ACK;
	ipc_master_worker_hello1_ack_t *payload = (ipc_master_worker_hello1_ack_t *)calloc(1, sizeof(ipc_master_worker_hello1_ack_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_master_worker_hello1_ack_t payload. %s", label, strerror(errno));
		CLOSE_IPC_PROTOCOL(&result.r_ipc_protocol_t);
		return result;
	}
	payload->wot = wot;
    payload->index = index;
    memcpy(payload->kem_ciphertext, kem_ciphertext, KEM_CIPHERTEXT_BYTES);
	result.r_ipc_protocol_t->payload.ipc_master_worker_hello1_ack = payload;
	result.status = SUCCESS;
	return result;
}
