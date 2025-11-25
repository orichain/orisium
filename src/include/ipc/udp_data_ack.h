#ifndef IPC_UDP_DATA_ACK_H
#define IPC_UDP_DATA_ACK_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "ipc/udp_data_ack.h"
#include "constants.h"
#include "oritlsf.h"

static inline status_t ipc_serialize_udp_data_ack(const char *label, const ipc_udp_data_ack_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, &payload->session_index, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, &payload->orilink_protocol, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, &payload->trycount, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, (uint8_t *)&payload->status, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    *offset = current_offset_local;
    return SUCCESS;
}

static inline status_t ipc_deserialize_udp_data_ack(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_udp_data_ack) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_udp_data_ack_t *payload = p->payload.ipc_udp_data_ack;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading session_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&payload->session_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading orilink_protocol.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&payload->orilink_protocol, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading trycount.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&payload->trycount, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading status.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&payload->status, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    *offset_ptr = current_offset;
    return SUCCESS;
}

static inline ipc_protocol_t_status_t ipc_prepare_cmd_udp_data_ack(const char *label, oritlsf_pool_t *pool, worker_type_t wot, uint8_t index, uint8_t session_index, uint8_t orilink_protocol, uint8_t trycount, status_t status) {
	ipc_protocol_t_status_t result;
	result.r_ipc_protocol_t = (ipc_protocol_t *)oritlsf_calloc(pool, 1, sizeof(ipc_protocol_t));
	result.status = FAILURE;
	if (!result.r_ipc_protocol_t) {
		LOG_ERROR("%sFailed to allocate ipc_protocol_t. %s", label, strerror(errno));
		return result;
	}
	result.r_ipc_protocol_t->version[0] = IPC_VERSION_MAJOR;
	result.r_ipc_protocol_t->version[1] = IPC_VERSION_MINOR;
    result.r_ipc_protocol_t->wot = wot;
    result.r_ipc_protocol_t->index = index;
	result.r_ipc_protocol_t->type = IPC_UDP_DATA_ACK;
	ipc_udp_data_ack_t *payload = (ipc_udp_data_ack_t *)oritlsf_calloc(pool, 1, sizeof(ipc_udp_data_ack_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_udp_data_ack_t payload. %s", label, strerror(errno));
		CLOSE_IPC_PROTOCOL(pool, &result.r_ipc_protocol_t);
		return result;
	}
    payload->session_index = session_index;
    payload->orilink_protocol = orilink_protocol;
    payload->trycount = trycount;
    payload->status = status;
	result.r_ipc_protocol_t->payload.ipc_udp_data_ack = payload;
	result.status = SUCCESS;
	return result;
}


#endif
