#ifndef IPC_WORKER_WORKER_INFO_H
#define IPC_WORKER_WORKER_INFO_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "constants.h"
#include "oritlsf.h"

static inline status_t ipc_serialize_worker_worker_info(const char *label, const ipc_worker_worker_info_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->src_wot, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, &payload->src_index, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, &payload->src_session_index, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->dst_wot, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, &payload->dst_index, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, &payload->dst_session_index, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->flag, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    *offset = current_offset_local;
    return SUCCESS;
}

static inline status_t ipc_deserialize_worker_worker_info(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_worker_worker_info) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_worker_worker_info_t *payload = p->payload.ipc_worker_worker_info;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading src_wot.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->src_wot, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading src_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&payload->src_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading src_session_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&payload->src_session_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading dst_wot.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->dst_wot, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading dst_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&payload->dst_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading dst_session_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&payload->dst_session_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading flag.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->flag, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    *offset_ptr = current_offset;
    return SUCCESS;
}

static inline ipc_protocol_t_status_t ipc_prepare_cmd_worker_worker_info(
	    const char *label,
	    oritlsf_pool_t *pool,
	    worker_type_t wot,
	    uint8_t index,
	    worker_type_t src_wot,
	    uint8_t src_index,
	    uint8_t src_session_index,
	    worker_type_t dst_wot,
	    uint8_t dst_index,
	    uint8_t dst_session_index,
	    info_type_t flag
        )
{
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
	result.r_ipc_protocol_t->type = IPC_WORKER_WORKER_INFO;
	ipc_worker_worker_info_t *payload = (ipc_worker_worker_info_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_worker_worker_info_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_worker_worker_info_t payload. %s", label, strerror(errno));
		CLOSE_IPC_PROTOCOL(pool, &result.r_ipc_protocol_t);
		return result;
	}
	payload->src_wot = src_wot;
	payload->src_index = src_index;
    payload->src_session_index = src_session_index;
    payload->dst_wot = dst_wot;
	payload->dst_index = dst_index;
    payload->dst_session_index = dst_session_index;
	payload->flag = flag;
	result.r_ipc_protocol_t->payload.ipc_worker_worker_info = payload;
	result.status = SUCCESS;
	return result;
}

#endif
