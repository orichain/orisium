#ifndef ORILINK_HELLO4_H
#define ORILINK_HELLO4_H

#if defined(__clang__)
    #if __clang_major__ < 21
        #include <stdio.h>
    #endif
#endif

#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "utilities.h"
#include "orilink/protocol.h"
#include "types.h"
#include "log.h"
#include "constants.h"
#include "oritlsf.h"

static inline status_t orilink_serialize_hello4(const char *label, const orilink_hello4_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(
            current_offset_local, 
            AES_NONCE_BYTES +
            sizeof(uint8_t) +
            sizeof(uint8_t) +
            sizeof(uint8_t) +
            sizeof(uint64_t) +
            AES_TAG_BYTES, 
            buffer_size
        ) != SUCCESS
    ) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->encrypted_local_identity,
        AES_NONCE_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint64_t) +
        AES_TAG_BYTES
    );
    current_offset_local +=
        AES_NONCE_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint64_t) +
        AES_TAG_BYTES;
    *offset = current_offset_local;
    return SUCCESS;
}

static inline status_t orilink_deserialize_hello4(const char *label, orilink_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.orilink_hello4) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    orilink_hello4_t *payload = p->payload.orilink_hello4;
    if (current_offset + 
        AES_NONCE_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint64_t) +
        AES_TAG_BYTES
        >
        total_buffer_len
    )
    {
        LOG_ERROR("%sOut of bounds reading encrypted_local_identity.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->encrypted_local_identity, cursor,
        AES_NONCE_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint64_t) +
        AES_TAG_BYTES
    );
    cursor +=
        AES_NONCE_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint64_t) +
        AES_TAG_BYTES;
    current_offset += 
        AES_NONCE_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint64_t) +
        AES_TAG_BYTES;
    *offset_ptr = current_offset;
    return SUCCESS;
}

static inline orilink_protocol_t_status_t orilink_prepare_cmd_hello4(
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
    uint8_t *encrypted_local_identity,
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
	result.r_orilink_protocol_t->type = ORILINK_HELLO4;
	orilink_hello4_t *payload = (orilink_hello4_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(orilink_hello4_t));
	if (!payload) {
		LOG_ERROR("%sFailed to allocate orilink_hello4_t payload. %s", label, strerror(errno));
		CLOSE_ORILINK_PROTOCOL(pool, &result.r_orilink_protocol_t);
		return result;
	}
    memcpy(payload->encrypted_local_identity, encrypted_local_identity, 
        AES_NONCE_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint64_t) +
        AES_TAG_BYTES
    );
	result.r_orilink_protocol_t->payload.orilink_hello4 = payload;
	result.status = SUCCESS;
	return result;
}


#endif
