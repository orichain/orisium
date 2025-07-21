#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <endian.h>

#include "utilities.h"
#include "orilink/protocol.h"
#include "types.h"
#include "log.h"
#include "orilink/heartbeat_ping_end.h"
#include "constants.h"

status_t orilink_serialize_heartbeat_ping_end(const char *label, const orilink_heartbeat_ping_end_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint64_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint64_t id_be = htobe64(payload->id);
    memcpy(current_buffer + current_offset_local, &id_be, sizeof(uint64_t));
    current_offset_local += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint64_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint64_t pid_be = htobe64(payload->pid);
    memcpy(current_buffer + current_offset_local, &pid_be, sizeof(uint64_t));
    current_offset_local += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->trycount, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    *offset = current_offset_local;
    return SUCCESS;
}

status_t orilink_deserialize_heartbeat_ping_end(const char *label, orilink_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.orilink_heartbeat_ping_end) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    orilink_heartbeat_ping_end_t *payload = p->payload.orilink_heartbeat_ping_end;
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading id.", label);
        return FAILURE_OOBUF;
    }
    uint64_t id_be;
    memcpy(&id_be, cursor, sizeof(uint64_t));
    payload->id = be64toh(id_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading pid.", label);
        return FAILURE_OOBUF;
    }
    uint64_t pid_be;
    memcpy(&pid_be, cursor, sizeof(uint64_t));
    payload->pid = be64toh(pid_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading trycount.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->trycount, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    *offset_ptr = current_offset;
    return SUCCESS;
}

orilink_protocol_t_status_t orilink_prepare_cmd_heartbeat_ping_end(const char *label, uint64_t id, uint64_t pid, uint8_t trycount) {
	orilink_protocol_t_status_t result;
	result.r_orilink_protocol_t = (orilink_protocol_t *)malloc(sizeof(orilink_protocol_t));
	result.status = FAILURE;
	if (!result.r_orilink_protocol_t) {
		LOG_ERROR("%sFailed to allocate orilink_protocol_t. %s", label, strerror(errno));
		return result;
	}
	memset(result.r_orilink_protocol_t, 0, sizeof(orilink_protocol_t));
	result.r_orilink_protocol_t->version[0] = ORILINK_VERSION_MAJOR;
	result.r_orilink_protocol_t->version[1] = ORILINK_VERSION_MINOR;
	result.r_orilink_protocol_t->type = ORILINK_HEARTBEAT_PING_END;
	orilink_heartbeat_ping_end_t *payload = (orilink_heartbeat_ping_end_t *)calloc(1, sizeof(orilink_heartbeat_ping_end_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate orilink_heartbeat_ping_end_t payload. %s", label, strerror(errno));
		CLOSE_ORILINK_PROTOCOL(&result.r_orilink_protocol_t);
		return result;
	}
    payload->id = id;
    payload->pid = pid;
    payload->trycount = trycount;
	result.r_orilink_protocol_t->payload.orilink_heartbeat_ping_end = payload;
	result.status = SUCCESS;
	return result;
}
