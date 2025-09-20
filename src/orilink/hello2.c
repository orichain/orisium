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
#include "orilink/hello2.h"
#include "constants.h"
#include "pqc.h"

status_t orilink_serialize_hello2(const char *label, const orilink_hello2_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint64_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint64_t local_id_be = htobe64(payload->local_id);
    memcpy(current_buffer + current_offset_local, &local_id_be, sizeof(uint64_t));
    current_offset_local += sizeof(uint64_t);    
    if (CHECK_BUFFER_BOUNDS(current_offset_local, KEM_PUBLICKEY_BYTES / 2, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->publickey2, KEM_PUBLICKEY_BYTES / 2);
    current_offset_local += KEM_PUBLICKEY_BYTES / 2;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->trycount, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);    
    *offset = current_offset_local;
    return SUCCESS;
}

status_t orilink_deserialize_hello2(const char *label, orilink_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.orilink_hello2) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    orilink_hello2_t *payload = p->payload.orilink_hello2;
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading local_id.", label);
        return FAILURE_OOBUF;
    }
    uint64_t local_id_be;
    memcpy(&local_id_be, cursor, sizeof(uint64_t));
    payload->local_id = be64toh(local_id_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);
    if (current_offset + (KEM_PUBLICKEY_BYTES / 2) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading publickey2.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->publickey2, cursor, KEM_PUBLICKEY_BYTES / 2);
    cursor += KEM_PUBLICKEY_BYTES / 2;
    current_offset += KEM_PUBLICKEY_BYTES / 2;
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

orilink_protocol_t_status_t orilink_prepare_cmd_hello2(
    const char *label, 
    uint8_t inc_ctr, 
    worker_type_t remote_wot, 
    uint8_t remote_index, 
    uint8_t remote_session_index, 
    worker_type_t local_wot, 
    uint8_t local_index, 
    uint8_t local_session_index, 
    uint64_t local_id, 
    uint8_t *publickey, 
    uint8_t trycount
)
{
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
    result.r_orilink_protocol_t->inc_ctr = inc_ctr;
    result.r_orilink_protocol_t->remote_wot = remote_wot;
    result.r_orilink_protocol_t->remote_index = remote_index;
    result.r_orilink_protocol_t->remote_session_index = remote_session_index;
    result.r_orilink_protocol_t->local_wot = local_wot;
    result.r_orilink_protocol_t->local_index = local_index;
    result.r_orilink_protocol_t->local_session_index = local_session_index;
	result.r_orilink_protocol_t->type = ORILINK_HELLO2;
	orilink_hello2_t *payload = (orilink_hello2_t *)calloc(1, sizeof(orilink_hello2_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate orilink_hello2_t payload. %s", label, strerror(errno));
		CLOSE_ORILINK_PROTOCOL(&result.r_orilink_protocol_t);
		return result;
	}
    payload->local_id = local_id;
    memcpy(payload->publickey2, publickey + (KEM_PUBLICKEY_BYTES / 2), KEM_PUBLICKEY_BYTES / 2);
    payload->trycount = trycount;
	result.r_orilink_protocol_t->payload.orilink_hello2 = payload;
	result.status = SUCCESS;
	return result;
}
