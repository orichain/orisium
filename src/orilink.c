#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>

#include "utilities.h"
#include "orilink/protocol.h"
#include "orilink/hello1.h"
#include "orilink/hello1_ack.h"
#include "orilink/hello2.h"
#include "orilink/hello2_ack.h"
#include "orilink/hello3.h"
#include "orilink/hello3_ack.h"
#include "orilink/hello4.h"
#include "orilink/hello4_ack.h"
#include "orilink/heartbeat.h"
#include "orilink/heartbeat_ack.h"
#include "orilink/info.h"
#include "orilink/info_ack.h"
#include "types.h"
#include "log.h"
#include "constants.h"
#include "pqc.h"
#include "xorshiro128plus.h"

size_t calculate_orilink_payload_fixed_size(const char *label, orilink_protocol_type_t type, bool plus_header) {
	size_t payload_fixed_size = 0;
    switch (type) {
        case ORILINK_HELLO1: {
            payload_fixed_size = sizeof(uint64_t) + 
                                 (KEM_PUBLICKEY_BYTES / 2);
            break;
        }
        case ORILINK_HELLO1_ACK: {
            payload_fixed_size = sizeof(uint64_t);
            break;
        }
        case ORILINK_HELLO2: {
            payload_fixed_size = sizeof(uint64_t) + 
                                 (KEM_PUBLICKEY_BYTES / 2);
            break;
        }
        case ORILINK_HELLO2_ACK: {
            payload_fixed_size = sizeof(uint64_t) + 
                                 (KEM_CIPHERTEXT_BYTES / 2);
            break;
        }
        case ORILINK_HELLO3: {
            payload_fixed_size = sizeof(uint64_t);
            break;
        }
        case ORILINK_HELLO3_ACK: {
            payload_fixed_size = sizeof(uint64_t) + 
                                 AES_NONCE_BYTES + 
                                 (KEM_CIPHERTEXT_BYTES / 2);
            break;
        }
        case ORILINK_HELLO4: {
            payload_fixed_size = AES_NONCE_BYTES +
                                 sizeof(uint8_t) +
                                 sizeof(uint8_t) +
                                 sizeof(uint8_t) +
                                 sizeof(uint64_t) +
                                 AES_TAG_BYTES;
            break;
        }
        case ORILINK_HELLO4_ACK: {
            payload_fixed_size = sizeof(uint8_t) +
                                 sizeof(uint8_t) +
                                 sizeof(uint8_t) +
                                 sizeof(uint64_t) +
                                 AES_TAG_BYTES +
                                 sizeof(uint8_t) +
                                 sizeof(uint8_t) +
                                 sizeof(uint8_t) +
                                 sizeof(uint64_t) +
                                 AES_TAG_BYTES;
            break;
        }
        case ORILINK_HEARTBEAT: {
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + DOUBLE_ARRAY_SIZE;
            break;
        }
        case ORILINK_HEARTBEAT_ACK: {
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t);
            break;
        }
        case ORILINK_INFO: {
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t);
            break;
        }
        case ORILINK_INFO_ACK: {
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t);
            break;
        }
        default:
            LOG_ERROR("%sUnknown protocol type: %d", label, type);
            return 0;
    }
    if (!plus_header) {
        return payload_fixed_size;
    }
    return AES_TAG_BYTES + 
           sizeof(uint32_t) + 
           ORILINK_VERSION_BYTES +
           sizeof(uint8_t) + 
           sizeof(uint8_t) + 
           sizeof(uint8_t) + 
           sizeof(uint8_t) + 
           
           sizeof(uint64_t) + 
           
           sizeof(uint8_t) + 
           sizeof(uint8_t) + 
           sizeof(uint8_t) + 
           sizeof(uint8_t) + 
           sizeof(uint8_t) + 
           payload_fixed_size;
}

size_t_status_t calculate_orilink_payload_size(const char *label, const orilink_protocol_t *p) {
	size_t_status_t result;
    result.r_size_t = 0;
    result.status = FAILURE;
    size_t payload_fixed_size = calculate_orilink_payload_fixed_size(label, p->type, true);
    if (payload_fixed_size == 0) {
        LOG_ERROR("%sInvalid Orilink Payload Size.", label);
        result.status = FAILURE;
        return result;
    }
    size_t payload_dynamic_size = 0;
    result.r_size_t = payload_fixed_size + payload_dynamic_size;
    result.status = SUCCESS;
    return result;
}

ssize_t_status_t orilink_serialize(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint8_t* nonce, uint32_t *ctr, const orilink_protocol_t* p, uint8_t** ptr_buffer, size_t* buffer_size) {
    ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;

    if (!p || !ptr_buffer || !buffer_size) {
        return result;
    }
    size_t_status_t psize = calculate_orilink_payload_size(label, p);
    if (psize.status != SUCCESS) {
		result.status = psize.status;
		return result;
	}
    size_t total_required_size = psize.r_size_t;
    if (total_required_size > ORILINK_MAX_PACKET_SIZE) {
        LOG_ERROR("%sorilink_serialize error. Total_required_size: %d, ORILINK_MAX_PACKET_SIZE %d.", label, total_required_size, ORILINK_MAX_PACKET_SIZE);
        result.status = FAILURE;
        return result;
    }
    if (total_required_size == 0) {
        LOG_ERROR("%sCalculated required size is 0.", label);
        result.status = FAILURE;
        return result;
    }
    uint8_t* current_buffer = *ptr_buffer;
    if (current_buffer == NULL || *buffer_size < total_required_size) {
        LOG_DEBUG("%sAllocating/resizing buffer. Old size: %zu, Required: %zu", label, *buffer_size, total_required_size);
        uint8_t* new_buffer = realloc(current_buffer, total_required_size);
        if (!new_buffer) {
            LOG_ERROR("%sError reallocating buffer for serialization: %s", label, strerror(errno));
            result.status = FAILURE_NOMEM;
            return result;
        }
        *ptr_buffer = new_buffer;
        current_buffer = new_buffer;
        *buffer_size = total_required_size;
    } else {
        LOG_DEBUG("%sBuffer size %zu is sufficient for %zu bytes. No reallocation needed.", label, *buffer_size, total_required_size);
    }
    size_t offset = 0;
//----------------------------------------------------------------------
// Mac
//---------------------------------------------------------------------- 
    if (CHECK_BUFFER_BOUNDS(offset, AES_TAG_BYTES, *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memset(current_buffer + offset, 0, AES_TAG_BYTES);
    offset += AES_TAG_BYTES;
//----------------------------------------------------------------------
// Counter
//----------------------------------------------------------------------    
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint32_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memset(current_buffer + offset, 0, sizeof(uint32_t));
    offset += sizeof(uint32_t);
//----------------------------------------------------------------------
// Version
//----------------------------------------------------------------------
    if (CHECK_BUFFER_BOUNDS(offset, ORILINK_VERSION_BYTES, *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, p->version, ORILINK_VERSION_BYTES);
    offset += ORILINK_VERSION_BYTES;
//----------------------------------------------------------------------
// Inc Ctr
//---------------------------------------------------------------------- 
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, &p->inc_ctr, sizeof(uint8_t));
    offset += sizeof(uint8_t);
//----------------------------------------------------------------------
// Local Index
//---------------------------------------------------------------------- 
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, &p->local_index, sizeof(uint8_t));
    offset += sizeof(uint8_t);
//----------------------------------------------------------------------
// Local Session Index
//---------------------------------------------------------------------- 
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, &p->local_session_index, sizeof(uint8_t));
    offset += sizeof(uint8_t);
//----------------------------------------------------------------------
// Local Wot
//---------------------------------------------------------------------- 
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, (uint8_t *)&p->local_wot, sizeof(uint8_t));
    offset += sizeof(uint8_t);
//----------------------------------------------------------------------
// Id Connection
//----------------------------------------------------------------------    
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint64_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    uint64_t id_connection_be = htobe64(p->id_connection);
    memcpy(current_buffer + offset, &id_connection_be, sizeof(uint64_t));
    offset += sizeof(uint64_t);
//----------------------------------------------------------------------
// Remote Wot
//---------------------------------------------------------------------- 
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, (uint8_t *)&p->remote_wot, sizeof(uint8_t));
    offset += sizeof(uint8_t);
//----------------------------------------------------------------------
// Remote Index
//---------------------------------------------------------------------- 
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, &p->remote_index, sizeof(uint8_t));
    offset += sizeof(uint8_t);
//----------------------------------------------------------------------
// Remote Session Index
//---------------------------------------------------------------------- 
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, &p->remote_session_index, sizeof(uint8_t));
    offset += sizeof(uint8_t);
//----------------------------------------------------------------------
// Type
//---------------------------------------------------------------------- 
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, (uint8_t *)&p->type, sizeof(uint8_t));
    offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Try Count
//----------------------------------------------------------------------    
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, &p->trycount, sizeof(uint8_t));
    offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
    status_t result_pyld = FAILURE;
    switch (p->type) {
        case ORILINK_HELLO1:
            result_pyld = orilink_serialize_hello1(label, p->payload.orilink_hello1, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_HELLO1_ACK:
            result_pyld = orilink_serialize_hello1_ack(label, p->payload.orilink_hello1_ack, current_buffer, *buffer_size, &offset);
            break;            
        case ORILINK_HELLO2:
            result_pyld = orilink_serialize_hello2(label, p->payload.orilink_hello2, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_HELLO2_ACK:
            result_pyld = orilink_serialize_hello2_ack(label, p->payload.orilink_hello2_ack, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_HELLO3:
            result_pyld = orilink_serialize_hello3(label, p->payload.orilink_hello3, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_HELLO3_ACK:
            result_pyld = orilink_serialize_hello3_ack(label, p->payload.orilink_hello3_ack, current_buffer, *buffer_size, &offset);
            break;            
        case ORILINK_HELLO4:
            result_pyld = orilink_serialize_hello4(label, p->payload.orilink_hello4, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_HELLO4_ACK:
            result_pyld = orilink_serialize_hello4_ack(label, p->payload.orilink_hello4_ack, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_HEARTBEAT:
            result_pyld = orilink_serialize_heartbeat(label, p->payload.orilink_heartbeat, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_HEARTBEAT_ACK:
            result_pyld = orilink_serialize_heartbeat_ack(label, p->payload.orilink_heartbeat_ack, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_INFO:
            result_pyld = orilink_serialize_info(label, p->payload.orilink_info, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_INFO_ACK:
            result_pyld = orilink_serialize_info_ack(label, p->payload.orilink_info_ack, current_buffer, *buffer_size, &offset);
            break;
        default:
            LOG_ERROR("%sUnknown protocol type for serialization: 0x%02x", label, p->type);
            result.status = FAILURE_OPYLD;
            return result;
    }
    if (result_pyld != SUCCESS) {
        LOG_ERROR("%sPayload serialization failed with status %d.", label, result_pyld);
        result.status = FAILURE_OPYLD;
        return result;
    }
    uint8_t *key0 = (uint8_t *)calloc(1, HASHES_BYTES * sizeof(uint8_t));
    if (memcmp(
            key_aes, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        uint32_t ctr_be = htobe32(*(uint32_t *)ctr);
        memcpy(current_buffer + AES_TAG_BYTES, &ctr_be, sizeof(uint32_t));
        const size_t data_offset = AES_TAG_BYTES + 
                                   sizeof(uint32_t) + 
                                   ORILINK_VERSION_BYTES + 
                                   sizeof(uint8_t) + 
                                   sizeof(uint8_t) + 
                                   sizeof(uint8_t) + 
                                   sizeof(uint8_t) + 
                                   
                                   sizeof(uint64_t) + 
                                   
                                   sizeof(uint8_t) + 
                                   sizeof(uint8_t) + 
                                   sizeof(uint8_t) + 
                                   sizeof(uint8_t) + 
                                   sizeof(uint8_t);
                                   
        const size_t data_len = offset - data_offset;
        uint8_t *data = current_buffer + data_offset;
        uint8_t *encrypted_data = current_buffer + data_offset;
        if (encrypt_decrypt_256(
                label,
                key_aes,
                nonce,
                ctr,
                data,
                encrypted_data,
                data_len
            ) != SUCCESS
        )
        {
            free(key0);
            result.status = FAILURE;
            return result;
        }
    }
    if (memcmp(
            key_mac, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        #if defined(ORILINK_DECRYPT_HEADER)
            const size_t header_offset = AES_TAG_BYTES;
            const size_t header_len = sizeof(uint32_t) +
                                      ORILINK_VERSION_BYTES +
                                      sizeof(uint8_t) +
                                      sizeof(uint8_t) +
                                      sizeof(uint8_t);
            uint8_t *header = current_buffer + header_offset;
            uint8_t *encrypted_header = current_buffer + header_offset;
            if (encrypt_decrypt_128(
                    label,
                    key_mac,
                    nonce,
                    ctr,
                    header,
                    encrypted_header,
                    header_len
                ) != SUCCESS
            )
            {
                free(key0);
                result.status = FAILURE;
                return result;
            }
        #endif
        const size_t data_4mac_offset = AES_TAG_BYTES;
        const size_t data_4mac_len = offset - AES_TAG_BYTES;
        uint8_t *data_4mac = current_buffer + data_4mac_offset;
        uint8_t mac[AES_TAG_BYTES];
        calculate_mac(key_mac, data_4mac, mac, data_4mac_len);
        memcpy(current_buffer, mac, AES_TAG_BYTES);
    } else {
        uint8_t rendom_mac[AES_TAG_BYTES];
        generate_fast_salt(rendom_mac, AES_TAG_BYTES);
        memcpy(current_buffer, rendom_mac, AES_TAG_BYTES);
    }
    if (memcmp(
            key_aes, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        if (p->inc_ctr != 0xFF) {
            increment_ctr(ctr, nonce);
        }
    }
    free(key0);
    result.r_ssize_t = (ssize_t)offset;
    result.status = SUCCESS;
    return result;
}

orilink_protocol_t_status_t orilink_deserialize(const char *label, uint8_t* key_aes, uint8_t* nonce, uint32_t *ctr, uint8_t* buffer, size_t len) {
    orilink_protocol_t_status_t result;
    result.r_orilink_protocol_t = NULL;
    result.status = FAILURE;
    const size_t data_offset = AES_TAG_BYTES + 
                               sizeof(uint32_t) +  
                               ORILINK_VERSION_BYTES + 
                               sizeof(uint8_t) + 
                               sizeof(uint8_t) + 
                               sizeof(uint8_t) + 
                               sizeof(uint8_t) + 
                               
                               sizeof(uint64_t) +
                                
                               sizeof(uint8_t) + 
                               sizeof(uint8_t) + 
                               sizeof(uint8_t) + 
                               sizeof(uint8_t) + 
                               sizeof(uint8_t);
                               
    if (!buffer || len < data_offset) {
        LOG_ERROR("%sBuffer terlalu kecil untuk Mac, Version dan Type Etc. Len: %zu", label, len);
        result.status = FAILURE_OOBUF;
        return result;
    }
    if (len > ORILINK_MAX_PACKET_SIZE) {
        LOG_ERROR("%sorilink_deserialize error. Len: %d, ORILINK_MAX_PACKET_SIZE %d.", label, len, ORILINK_MAX_PACKET_SIZE);
        result.status = FAILURE;
        return result;
    }
    orilink_protocol_t* p = (orilink_protocol_t*)calloc(1, sizeof(orilink_protocol_t));
    if (!p) {
        LOG_ERROR("%sFailed to allocate orilink_protocol_t. %s", label, strerror(errno));
        result.status = FAILURE_NOMEM;
        return result;
    }
    LOG_DEBUG("%sAllocating orilink_protocol_t struct: %zu bytes.", label, sizeof(orilink_protocol_t));
    size_t current_buffer_offset = 0;
//----------------------------------------------------------------------    
// Mac
//----------------------------------------------------------------------    
    memcpy(p->mac, buffer + current_buffer_offset, AES_TAG_BYTES);
    current_buffer_offset += AES_TAG_BYTES;
//----------------------------------------------------------------------    
// Ctr
//----------------------------------------------------------------------    
    uint32_t data_ctr_be;
    memcpy(&data_ctr_be, buffer + current_buffer_offset, sizeof(uint32_t));
    p->ctr = be32toh(data_ctr_be);
    current_buffer_offset += sizeof(uint32_t);
//----------------------------------------------------------------------    
// Version
//----------------------------------------------------------------------    
    memcpy(p->version, buffer + current_buffer_offset, ORILINK_VERSION_BYTES);
    current_buffer_offset += ORILINK_VERSION_BYTES;
//----------------------------------------------------------------------    
// Inc Ctr
//----------------------------------------------------------------------    
    memcpy(&p->inc_ctr, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Local Index
//----------------------------------------------------------------------    
    memcpy(&p->local_index, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Local Session Index
//----------------------------------------------------------------------    
    memcpy(&p->local_session_index, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Local Wot
//----------------------------------------------------------------------    
    memcpy((uint8_t *)&p->local_wot, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Id Connection
//----------------------------------------------------------------------    
    uint64_t id_connection_be;
    memcpy(&id_connection_be, buffer + current_buffer_offset, sizeof(uint64_t));
    p->id_connection = be64toh(id_connection_be);
    current_buffer_offset += sizeof(uint64_t);
//----------------------------------------------------------------------    
// Remote Wot
//----------------------------------------------------------------------    
    memcpy((uint8_t *)&p->remote_wot, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Remote Index
//----------------------------------------------------------------------    
    memcpy(&p->remote_index, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Remote Session Index
//----------------------------------------------------------------------    
    memcpy(&p->remote_session_index, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Type
//----------------------------------------------------------------------    
    memcpy((uint8_t *)&p->type, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Trycount
//----------------------------------------------------------------------    
    memcpy(&p->trycount, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
//----------------------------------------------------------------------
    uint8_t *key0 = (uint8_t *)calloc(1, HASHES_BYTES * sizeof(uint8_t));
    if (memcmp(
            key_aes, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        const size_t data_len = len - data_offset;
        uint8_t *data = buffer + data_offset;
        uint8_t *decrypted_data = buffer + data_offset;
        if (encrypt_decrypt_256(
                label,
                key_aes,
                nonce,
                ctr,
                data,
                decrypted_data,
                data_len
            ) != SUCCESS
        )
        {
            CLOSE_ORILINK_PROTOCOL(&p);
            free(key0);
            result.status = FAILURE;
            return result;
        }
    }
    size_t fixed_payload_size = calculate_orilink_payload_fixed_size(label, p->type, false);
    LOG_DEBUG("%sDeserializing type 0x%02x. Current offset: %zu", label, p->type, current_buffer_offset);
    status_t result_pyld = FAILURE;
    switch (p->type) {
        case ORILINK_HELLO1: {
			if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HELLO1 fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_hello1_t *payload = (orilink_hello1_t*) calloc(1, sizeof(orilink_hello1_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_hello1_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_hello1 = payload;
            result_pyld = orilink_deserialize_hello1(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HELLO1_ACK: {
			if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HELLO1_ACK fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_hello1_ack_t *payload = (orilink_hello1_ack_t*) calloc(1, sizeof(orilink_hello1_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_hello1_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_hello1_ack = payload;
            result_pyld = orilink_deserialize_hello1_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HELLO2: {
			if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HELLO2 fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_hello2_t *payload = (orilink_hello2_t*) calloc(1, sizeof(orilink_hello2_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_hello2_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_hello2 = payload;
            result_pyld = orilink_deserialize_hello2(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HELLO2_ACK: {
			if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HELLO2_ACK fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_hello2_ack_t *payload = (orilink_hello2_ack_t*) calloc(1, sizeof(orilink_hello2_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_hello2_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_hello2_ack = payload;
            result_pyld = orilink_deserialize_hello2_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HELLO3: {
			if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HELLO3 fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_hello3_t *payload = (orilink_hello3_t*) calloc(1, sizeof(orilink_hello3_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_hello3_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_hello3 = payload;
            result_pyld = orilink_deserialize_hello3(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HELLO3_ACK: {
			if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HELLO3_ACK fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_hello3_ack_t *payload = (orilink_hello3_ack_t*) calloc(1, sizeof(orilink_hello3_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_hello3_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_hello3_ack = payload;
            result_pyld = orilink_deserialize_hello3_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HELLO4: {
			if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HELLO4 fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_hello4_t *payload = (orilink_hello4_t*) calloc(1, sizeof(orilink_hello4_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_hello4_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_hello4 = payload;
            result_pyld = orilink_deserialize_hello4(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HELLO4_ACK: {
			if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HELLO4_ACK fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_hello4_ack_t *payload = (orilink_hello4_ack_t*) calloc(1, sizeof(orilink_hello4_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_hello4_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_hello4_ack = payload;
            result_pyld = orilink_deserialize_hello4_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HEARTBEAT: {
			if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HEARTBEAT fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_heartbeat_t *payload = (orilink_heartbeat_t*) calloc(1, sizeof(orilink_heartbeat_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_heartbeat_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_heartbeat = payload;
            result_pyld = orilink_deserialize_heartbeat(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HEARTBEAT_ACK: {
			if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HEARTBEAT_ACK fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_heartbeat_ack_t *payload = (orilink_heartbeat_ack_t*) calloc(1, sizeof(orilink_heartbeat_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_heartbeat_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_heartbeat_ack = payload;
            result_pyld = orilink_deserialize_heartbeat_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_INFO: {
			if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_INFO fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_info_t *payload = (orilink_info_t*) calloc(1, sizeof(orilink_info_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_info_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_info = payload;
            result_pyld = orilink_deserialize_info(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_INFO_ACK: {
			if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_INFO_ACK fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_info_ack_t *payload = (orilink_info_ack_t*) calloc(1, sizeof(orilink_info_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_info_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_info_ack = payload;
            result_pyld = orilink_deserialize_info_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        default:
            LOG_ERROR("%sUnknown protocol type for deserialization: 0x%02x", label, p->type);
            result.status = FAILURE_OPYLD;
            CLOSE_ORILINK_PROTOCOL(&p);
            free(key0);
            return result;
    }
    if (result_pyld != SUCCESS) {
        LOG_ERROR("%sPayload deserialization failed with status %d.", label, result_pyld);
        CLOSE_ORILINK_PROTOCOL(&p);
        free(key0);
        result.status = FAILURE_OPYLD;
        return result;
    }
    if (memcmp(
            key_aes, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        if (p->inc_ctr != 0xFF) {
            increment_ctr(ctr, nonce);
        }
    }
    free(key0);
    result.r_orilink_protocol_t = p;
    result.status = SUCCESS;
    LOG_DEBUG("%sorilink_deserialize BERHASIL.", label);
    return result;
}

puint8_t_size_t_status_t create_orilink_raw_protocol_packet(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint8_t* nonce, uint32_t *ctr, const orilink_protocol_t* p) {
	puint8_t_size_t_status_t result;
    result.r_puint8_t = NULL;
    result.r_size_t = 0;
    result.status = FAILURE;
    ssize_t_status_t serialize_result = orilink_serialize(label, key_aes, key_mac, nonce, ctr, p, &result.r_puint8_t, &result.r_size_t);
    if (serialize_result.status != SUCCESS) {
        LOG_ERROR("%sError serializing ORILINK protocol: %d", label, serialize_result.status);
        if (result.r_puint8_t) {
            free(result.r_puint8_t);
            result.r_puint8_t = NULL;
            result.r_size_t = 0;
        }
        return result;
    }
    if (result.r_size_t > ORILINK_MAX_PACKET_SIZE) {
        LOG_ERROR("%sError packet size %d ORILINK_MAX_PACKET_SIZE %d", label, result.r_size_t, ORILINK_MAX_PACKET_SIZE);
        if (result.r_puint8_t) {
            free(result.r_puint8_t);
            result.r_puint8_t = NULL;
            result.r_size_t = 0;
        }
        return result;
    }
    LOG_DEBUG("%sTotal pesan untuk dikirim: %zu byte.", label, result.r_size_t);
    result.status = SUCCESS;
    return result;
}
