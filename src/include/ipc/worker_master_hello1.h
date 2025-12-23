#ifndef IPC_WORKER_MASTER_HELLO1_H
#define IPC_WORKER_MASTER_HELLO1_H

#if defined(__clang__)
    #if __clang_major__ < 21
        #include <stdio.h>
    #endif
#endif

#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "ipc/worker_master_hello1.h"
#include "constants.h"
#include "pqc.h"
#include "oritlsf.h"

static inline status_t ipc_serialize_worker_master_hello1(const char *label, const ipc_worker_master_hello1_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, KEM_PUBLICKEY_BYTES, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->kem_publickey, KEM_PUBLICKEY_BYTES);
    current_offset_local += KEM_PUBLICKEY_BYTES;
    *offset = current_offset_local;
    return SUCCESS;
}

static inline status_t ipc_deserialize_worker_master_hello1(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_worker_master_hello1) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_worker_master_hello1_t *payload = p->payload.ipc_worker_master_hello1;
    if (current_offset + KEM_PUBLICKEY_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading kem_publickey.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->kem_publickey, cursor, KEM_PUBLICKEY_BYTES);
    cursor += KEM_PUBLICKEY_BYTES;
    current_offset += KEM_PUBLICKEY_BYTES;
    *offset_ptr = current_offset;
    return SUCCESS;
}

static inline ipc_protocol_t_status_t ipc_prepare_cmd_worker_master_hello1(const char *label, oritlsf_pool_t *pool, worker_type_t wot, uint8_t index, uint8_t *kem_publickey) {
	ipc_protocol_t_status_t result;
	result.r_ipc_protocol_t = (ipc_protocol_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_protocol_t));
	result.status = FAILURE;
	if (!result.r_ipc_protocol_t) {
		LOG_ERROR("%sFailed to allocate ipc_protocol_t. %s", label, strerror(errno));
		return result;
	}
	result.r_ipc_protocol_t->version[0] = IPC_VERSION_MAJOR;
	result.r_ipc_protocol_t->version[1] = IPC_VERSION_MINOR;
    result.r_ipc_protocol_t->wot = wot;
    result.r_ipc_protocol_t->index = index;
	result.r_ipc_protocol_t->type = IPC_WORKER_MASTER_HELLO1;
	ipc_worker_master_hello1_t *payload = (ipc_worker_master_hello1_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_worker_master_hello1_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_worker_master_hello1_t payload. %s", label, strerror(errno));
		CLOSE_IPC_PROTOCOL(pool, &result.r_ipc_protocol_t);
		return result;
	}
    memcpy(payload->kem_publickey, kem_publickey, KEM_PUBLICKEY_BYTES);
	result.r_ipc_protocol_t->payload.ipc_worker_master_hello1 = payload;
	result.status = SUCCESS;
	return result;
}

#endif
