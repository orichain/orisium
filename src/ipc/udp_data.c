#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <endian.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "ipc/udp_data.h"
#include "constants.h"

struct sockaddr_in6;

status_t ipc_serialize_udp_data(const char *label, const ipc_udp_data_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, &payload->session_index, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, SOCKADDR_IN6_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t remote_addr_be[SOCKADDR_IN6_SIZE];
    serialize_sockaddr_in6(&payload->remote_addr, remote_addr_be);    
    memcpy(current_buffer + current_offset_local, remote_addr_be, SOCKADDR_IN6_SIZE);
    current_offset_local += SOCKADDR_IN6_SIZE;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint16_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint16_t len_be = htobe16(payload->len);
    memcpy(current_buffer + current_offset_local, &len_be, sizeof(uint16_t));
    current_offset_local += sizeof(uint16_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, payload->len, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->data, payload->len);
    current_offset_local += payload->len;
    *offset = current_offset_local;
    return SUCCESS;
}

status_t ipc_deserialize_udp_data(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_udp_data) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_udp_data_t *payload = p->payload.ipc_udp_data;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading session_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&payload->session_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + SOCKADDR_IN6_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading remote_addr.", label);
        return FAILURE_OOBUF;
    }
    uint8_t remote_addr_be[SOCKADDR_IN6_SIZE];
    memcpy(remote_addr_be, cursor, SOCKADDR_IN6_SIZE);
    deserialize_sockaddr_in6(remote_addr_be, &payload->remote_addr);
    cursor += SOCKADDR_IN6_SIZE;
    current_offset += SOCKADDR_IN6_SIZE;
    if (current_offset + sizeof(uint16_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading len.", label);
        return FAILURE_OOBUF;
    }
    uint16_t len_be;
    memcpy(&len_be, cursor, sizeof(uint16_t));
    payload->len = be16toh(len_be);
    cursor += sizeof(uint16_t);
    current_offset += sizeof(uint16_t);
    if (current_offset + payload->len > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading data.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->data, cursor, payload->len);
    cursor += payload->len;
    current_offset += payload->len;
    *offset_ptr = current_offset;
    return SUCCESS;
}

ipc_protocol_t_status_t ipc_prepare_cmd_udp_data(const char *label, worker_type_t wot, uint8_t index, uint8_t session_index, struct sockaddr_in6 *remote_addr, uint16_t len, uint8_t *data) {
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
    result.r_ipc_protocol_t->wot = wot;
    result.r_ipc_protocol_t->index = index;
	result.r_ipc_protocol_t->type = IPC_UDP_DATA;
	ipc_udp_data_t *payload = (ipc_udp_data_t *)calloc(1, sizeof(ipc_udp_data_t) + len);
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_udp_data_t payload. %s", label, strerror(errno));
		CLOSE_IPC_PROTOCOL(&result.r_ipc_protocol_t);
		return result;
	}
    payload->session_index = session_index;
    memcpy(&payload->remote_addr, remote_addr, SOCKADDR_IN6_SIZE);
    payload->len = len;
    memcpy(&payload->data, data, len);
	result.r_ipc_protocol_t->payload.ipc_udp_data = payload;
	result.status = SUCCESS;
	return result;
}
