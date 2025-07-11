#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "ipc/shutdown.h"
#include "constants.h"

status_t ipc_serialize_shutdown(const char *label, const ipc_shutdown_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(shutdown_type_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    current_buffer[current_offset_local] = (uint8_t)payload->flag;
    current_offset_local += sizeof(shutdown_type_t);
    *offset = current_offset_local;
    return SUCCESS;
}

status_t ipc_deserialize_shutdown(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_shutdown) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_shutdown_t *payload = p->payload.ipc_shutdown;
    if (current_offset + sizeof(shutdown_type_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading flag.", label);
        return FAILURE_OOBUF;
    }
    payload->flag = *cursor;
    cursor += sizeof(shutdown_type_t);
    current_offset += sizeof(shutdown_type_t);
    *offset_ptr = current_offset;
    return SUCCESS;
}

ipc_protocol_t_status_t ipc_prepare_cmd_shutdown(const char *label, int *fd_to_close) {
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
	result.r_ipc_protocol_t->type = IPC_SHUTDOWN;
	ipc_shutdown_t *payload = (ipc_shutdown_t *)calloc(1, sizeof(ipc_shutdown_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_shutdown_t payload. %s", label, strerror(errno));
		CLOSE_FD(fd_to_close);
		CLOSE_IPC_PROTOCOL(&result.r_ipc_protocol_t);
		return result;
	}
	payload->flag = IMMEDIATELY;
	result.r_ipc_protocol_t->payload.ipc_shutdown = payload;
	result.status = SUCCESS;
	return result;
}
