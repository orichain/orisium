#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "ipc/heartbeat.h"
#include "constants.h"

status_t ipc_serialize_heartbeat(const char *label, const ipc_heartbeat_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, 1, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->wot, 1);
    current_offset_local += 1;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, 1, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->index, 1);
    current_offset_local += 1;
    *offset = current_offset_local;
    return SUCCESS;
}

status_t ipc_deserialize_heartbeat(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_heartbeat) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_heartbeat_t *payload = p->payload.ipc_heartbeat;
    if (current_offset + 1 > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading wot.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->wot, cursor, 1);
    cursor += 1;
    current_offset += 1;
    if (current_offset + 1 > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->index, cursor, 1);
    cursor += 1;
    current_offset += 1;
    *offset_ptr = current_offset;
    return SUCCESS;
}

ipc_protocol_t_status_t ipc_prepare_cmd_heartbeat(const char *label, int *fd_to_close, worker_type_t wot, uint8_t index) {
	ipc_protocol_t_status_t result;
	result.r_ipc_protocol_t = (ipc_protocol_t *)malloc(sizeof(ipc_protocol_t));
	result.status = FAILURE;
	if (!result.r_ipc_protocol_t) {
		LOG_ERROR("%sFailed to allocate ipc_protocol_t. %s", label, strerror(errno));
		CLOSE_FD(fd_to_close);
		return result;
	}
	memset(result.r_ipc_protocol_t, 0, sizeof(ipc_protocol_t));
	result.r_ipc_protocol_t->version[0] = IPC_VERSION_MAJOR;
	result.r_ipc_protocol_t->version[1] = IPC_VERSION_MINOR;
	result.r_ipc_protocol_t->type = IPC_HEARTBEAT;
	ipc_heartbeat_t *payload = (ipc_heartbeat_t *)calloc(1, sizeof(ipc_heartbeat_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_heartbeat_t payload. %s", label, strerror(errno));
		CLOSE_FD(fd_to_close);
		CLOSE_IPC_PROTOCOL(&result.r_ipc_protocol_t);
		return result;
	}
	payload->wot[0] = (uint8_t)wot;
    payload->index[0] = (uint8_t)index;
	result.r_ipc_protocol_t->payload.ipc_heartbeat = payload;
	result.status = SUCCESS;
	return result;
}
