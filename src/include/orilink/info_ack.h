#ifndef ORILINK_INFO_ACK_H
#define ORILINK_INFO_ACK_H

#if defined(__clang__)
#if __clang_major__ < 21
#include <stdio.h>
#endif
#endif

#include <string.h>
#include <stdint.h>

#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#include "utilities.h"
#include "orilink/protocol.h"
#include "types.h"
#include "log.h"
#include "constants.h"
#include "oritlsf.h"

static inline status_t orilink_serialize_info_ack(const char *label, const orilink_info_ack_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint64_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint64_t local_id_be = htobe64(payload->local_id);
    memcpy(current_buffer + current_offset_local, &local_id_be, sizeof(uint64_t));
    current_offset_local += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint64_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint64_t remote_id_be = htobe64(payload->remote_id);
    memcpy(current_buffer + current_offset_local, &remote_id_be, sizeof(uint64_t));
    current_offset_local += sizeof(uint64_t);
    *offset = current_offset_local;
    return SUCCESS;
}

static inline status_t orilink_deserialize_info_ack(const char *label, orilink_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.orilink_info_ack) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    orilink_info_ack_t *payload = p->payload.orilink_info_ack;
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading local_id.", label);
        return FAILURE_OOBUF;
    }
    uint64_t local_id_be;
    memcpy(&local_id_be, cursor, sizeof(uint64_t));
    payload->local_id = be64toh(local_id_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading remote_id.", label);
        return FAILURE_OOBUF;
    }
    uint64_t remote_id_be;
    memcpy(&remote_id_be, cursor, sizeof(uint64_t));
    payload->remote_id = be64toh(remote_id_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);
    *offset_ptr = current_offset;
    return SUCCESS;
}

static inline orilink_protocol_t_status_t orilink_prepare_cmd_info_ack(
        const char *label,
        oritlsf_pool_t *pool,
        uint8_t inc_ctr,
        worker_type_t remote_wot,
        uint8_t remote_index,
        uint8_t remote_session_index,
        worker_type_t local_wot,
        uint8_t local_index,
        uint8_t local_session_index,
        uint64_t id_connection,
        uint64_t local_id,
        uint64_t remote_id,
        uint8_t trycount
        )
{
	orilink_protocol_t_status_t result;
	result.r_orilink_protocol_t = (orilink_protocol_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(orilink_protocol_t));
	result.status = FAILURE;
	if (!result.r_orilink_protocol_t) {
		LOG_ERROR("%sFailed to allocate orilink_protocol_t. %s", label, strerror(errno));
		return result;
	}
	result.r_orilink_protocol_t->version[0] = ORILINK_VERSION_MAJOR;
	result.r_orilink_protocol_t->version[1] = ORILINK_VERSION_MINOR;
    result.r_orilink_protocol_t->inc_ctr = inc_ctr;
    result.r_orilink_protocol_t->remote_wot = remote_wot;
    result.r_orilink_protocol_t->remote_index = remote_index;
    result.r_orilink_protocol_t->remote_session_index = remote_session_index;
    result.r_orilink_protocol_t->local_wot = local_wot;
    result.r_orilink_protocol_t->local_index = local_index;
    result.r_orilink_protocol_t->local_session_index = local_session_index;
    result.r_orilink_protocol_t->id_connection = id_connection;
    result.r_orilink_protocol_t->trycount = trycount;
	result.r_orilink_protocol_t->type = ORILINK_INFO_ACK;
	orilink_info_ack_t *payload = (orilink_info_ack_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(orilink_info_ack_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate orilink_info_ack_t payload. %s", label, strerror(errno));
		CLOSE_ORILINK_PROTOCOL(pool, &result.r_orilink_protocol_t);
		return result;
	}
    payload->local_id = local_id;
    payload->remote_id = remote_id;
	result.r_orilink_protocol_t->payload.orilink_info_ack = payload;
	result.status = SUCCESS;
	return result;
}


#endif
