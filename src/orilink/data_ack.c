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
#include "orilink/data_ack.h"
#include "constants.h"

status_t orilink_serialize_data_ack(const char *label, const orilink_data_ack_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
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
    uint64_t sid_be = htobe64(payload->sid);
    memcpy(current_buffer + current_offset_local, &sid_be, sizeof(uint64_t));
    current_offset_local += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint16_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint16_t spktnum_be = htobe16(payload->sid);
    memcpy(current_buffer + current_offset_local, &spktnum_be, sizeof(uint16_t));
    current_offset_local += sizeof(uint16_t);    
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint16_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint16_t arw_be = htobe16(payload->arw);
    memcpy(current_buffer + current_offset_local, &arw_be, sizeof(uint16_t));
    current_offset_local += sizeof(uint16_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint16_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint16_t len_be = htobe16(payload->len);
    memcpy(current_buffer + current_offset_local, &len_be, sizeof(uint16_t));
    current_offset_local += sizeof(uint16_t);
    if (payload->len > 0) {
        if (CHECK_BUFFER_BOUNDS(current_offset_local, payload->len, buffer_size) != SUCCESS) return FAILURE_OOBUF;
        memcpy(current_buffer + current_offset_local, payload->data, payload->len);
        current_offset_local += payload->len;
    }
    *offset = current_offset_local;
    return SUCCESS;
}

status_t orilink_deserialize_data_ack(const char *label, orilink_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.orilink_data_ack) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    orilink_data_ack_t *payload = p->payload.orilink_data_ack;
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
        LOG_ERROR("%sOut of bounds reading sid.", label);
        return FAILURE_OOBUF;
    }
    uint64_t sid_be;
    memcpy(&sid_be, cursor, sizeof(uint64_t));
    payload->sid = be64toh(sid_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);
    if (current_offset + sizeof(uint16_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading spktnum.", label);
        return FAILURE_OOBUF;
    }
    uint16_t spktnum_be;
    memcpy(&spktnum_be, cursor, sizeof(uint16_t));
    payload->spktnum = be16toh(spktnum_be);
    cursor += sizeof(uint16_t);
    current_offset += sizeof(uint16_t);
    if (current_offset + sizeof(uint16_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading arw.", label);
        return FAILURE_OOBUF;
    }
    uint16_t arw_be;
    memcpy(&arw_be, cursor, sizeof(uint16_t));
    payload->arw = be16toh(arw_be);
    cursor += sizeof(uint16_t);
    current_offset += sizeof(uint16_t);
    if (current_offset + sizeof(uint16_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading len.", label);
        return FAILURE_OOBUF;
    }
    uint16_t len_be;
    memcpy(&len_be, cursor, sizeof(uint16_t));
    payload->len = be16toh(len_be);
    cursor += sizeof(uint16_t);
    current_offset += sizeof(uint16_t);
    if (payload->len > 0) {
        if (current_offset + payload->len > total_buffer_len) {
            LOG_ERROR("%sInsufficient buffer for actual data. Expected %hu, available %zu.",
                    label, payload->len, total_buffer_len - current_offset);
            return FAILURE_OOBUF;
        }
        memcpy(payload->data, cursor, payload->len);
        cursor += payload->len;
        current_offset += payload->len;
    }
    *offset_ptr = current_offset;
    return SUCCESS;
}

orilink_protocol_t_status_t orilink_prepare_cmd_data_ack(const char *label, uint64_t id, uint64_t sid, uint16_t spktnum, uint16_t arw, uint16_t data_len, uint8_t *data) {
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
	result.r_orilink_protocol_t->type = ORILINK_DATA_ACK;
	orilink_data_ack_t *payload = (orilink_data_ack_t *)calloc(1, sizeof(orilink_data_ack_t) + data_len);
	if (!payload) {
		LOG_ERROR("%sFailed to allocate orilink_data_ack_t payload. %s", label, strerror(errno));
		CLOSE_ORILINK_PROTOCOL(&result.r_orilink_protocol_t);
		return result;
	}
    payload->id = id;
    payload->sid = sid;
    payload->spktnum = spktnum;
    payload->arw = arw;
    payload->len = data_len;
    if (data_len > 0 && data) memcpy(payload->data, data, data_len);   
	result.r_orilink_protocol_t->payload.orilink_data_ack = payload;
	result.status = SUCCESS;
	return result;
}
