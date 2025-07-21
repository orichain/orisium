#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "ipc/worker_master_heartbeat.h"
#include "constants.h"

status_t ipc_serialize_worker_master_heartbeat(const char *label, const ipc_worker_master_heartbeat_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
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
    if (CHECK_BUFFER_BOUNDS(current_offset_local, DOUBLE_ARRAY_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t hbtime_be[8];
    double_to_uint8_be(payload->hbtime, hbtime_be);
    memcpy(current_buffer + current_offset_local, hbtime_be, DOUBLE_ARRAY_SIZE);
    current_offset_local += DOUBLE_ARRAY_SIZE;
    *offset = current_offset_local;
    return SUCCESS;
}

status_t ipc_deserialize_worker_master_heartbeat(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_worker_master_heartbeat) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_worker_master_heartbeat_t *payload = p->payload.ipc_worker_master_heartbeat;
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
    if (current_offset + DOUBLE_ARRAY_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading hbtime.", label);
        return FAILURE_OOBUF;
    }
    uint8_t hbtime_be[8];
    memcpy(hbtime_be, cursor, DOUBLE_ARRAY_SIZE);
    payload->hbtime = uint8_be_to_double(hbtime_be);
    cursor += DOUBLE_ARRAY_SIZE;
    current_offset += DOUBLE_ARRAY_SIZE;
    *offset_ptr = current_offset;
    return SUCCESS;
}

ipc_protocol_t_status_t ipc_prepare_cmd_worker_master_heartbeat(const char *label, worker_type_t wot, uint8_t index, double hbtime) {
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
	result.r_ipc_protocol_t->type = IPC_WORKER_MASTER_HEARTBEAT;
	ipc_worker_master_heartbeat_t *payload = (ipc_worker_master_heartbeat_t *)calloc(1, sizeof(ipc_worker_master_heartbeat_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_worker_master_heartbeat_t payload. %s", label, strerror(errno));
		CLOSE_IPC_PROTOCOL(&result.r_ipc_protocol_t);
		return result;
	}
	payload->wot = wot;
    payload->index = index;
    payload->hbtime = hbtime;
	result.r_ipc_protocol_t->payload.ipc_worker_master_heartbeat = payload;
	result.status = SUCCESS;
	return result;
}
