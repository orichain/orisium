#ifndef IPC_MASTER_COW_CONNECT_H
#define IPC_MASTER_COW_CONNECT_H

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
#include "ipc/master_cow_connect.h"
#include "constants.h"

struct sockaddr_in6;

static inline status_t ipc_serialize_master_cow_connect(const char *label, const ipc_master_cow_connect_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint8_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, &payload->session_index, sizeof(uint8_t));
    current_offset_local += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint64_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint64_t id_connection_be = htobe64(payload->id_connection);
    memcpy(current_buffer + current_offset_local, &id_connection_be, sizeof(uint64_t));
    current_offset_local += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(current_offset_local, SOCKADDR_IN6_SIZE, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint8_t remote_addr_be[SOCKADDR_IN6_SIZE];
    serialize_sockaddr_in6(&payload->remote_addr, remote_addr_be);    
    memcpy(current_buffer + current_offset_local, remote_addr_be, SOCKADDR_IN6_SIZE);
    current_offset_local += SOCKADDR_IN6_SIZE;
    *offset = current_offset_local;
    return SUCCESS;
}

static inline status_t ipc_deserialize_master_cow_connect(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_master_cow_connect) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_master_cow_connect_t *payload = p->payload.ipc_master_cow_connect;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading session_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&payload->session_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading id_connection.", label);
        return FAILURE_OOBUF;
    }
    uint64_t id_connection_be;
    memcpy(&id_connection_be, cursor, sizeof(uint64_t));
    payload->id_connection = be64toh(id_connection_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);
    if (current_offset + SOCKADDR_IN6_SIZE > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading remote_addr.", label);
        return FAILURE_OOBUF;
    }
    uint8_t remote_addr_be[SOCKADDR_IN6_SIZE];
    memcpy(remote_addr_be, cursor, SOCKADDR_IN6_SIZE);
    deserialize_sockaddr_in6(remote_addr_be, &payload->remote_addr);
    cursor += SOCKADDR_IN6_SIZE;
    current_offset += SOCKADDR_IN6_SIZE;
    *offset_ptr = current_offset;
    return SUCCESS;
}

static inline ipc_protocol_t_status_t ipc_prepare_cmd_master_cow_connect(const char *label, worker_type_t wot, uint8_t index, uint8_t session_index, uint64_t id_connection, struct sockaddr_in6 *remote_addr) {
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
	result.r_ipc_protocol_t->type = IPC_MASTER_COW_CONNECT;
	ipc_master_cow_connect_t *payload = (ipc_master_cow_connect_t *)calloc(1, sizeof(ipc_master_cow_connect_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_master_cow_connect_t payload. %s", label, strerror(errno));
		CLOSE_IPC_PROTOCOL(&result.r_ipc_protocol_t);
		return result;
	}
    payload->session_index = session_index;
    payload->id_connection = id_connection;
    memcpy(&payload->remote_addr, remote_addr, SOCKADDR_IN6_SIZE);
	result.r_ipc_protocol_t->payload.ipc_master_cow_connect = payload;
	result.status = SUCCESS;
	return result;
}


#endif
