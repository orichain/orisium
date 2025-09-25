#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

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
#include "types.h"
#include "log.h"
#include "constants.h"
#include "pqc.h"
#include "poly1305-donna.h"
#include "aes.h"
#include "ipc/protocol.h"

static inline size_t_status_t calculate_orilink_payload_size(const char *label, const orilink_protocol_t* p, bool checkfixheader) {
	size_t_status_t result;
    result.r_size_t = 0;
    result.status = FAILURE;
    size_t payload_fixed_size = 0;
    size_t payload_dynamic_size = 0;
    
    switch (p->type) {
        case ORILINK_HELLO1: {
            if (!checkfixheader) {
                if (!p->payload.orilink_hello1) {
                    LOG_ERROR("%sORILINK_HELLO1 payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + 
                                 (KEM_PUBLICKEY_BYTES / 2) + 
                                 sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_HELLO1_ACK: {
            if (!checkfixheader) {
                if (!p->payload.orilink_hello1_ack) {
                    LOG_ERROR("%sORILINK_HELLO1_ACK payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + 
                                 sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_HELLO2: {
            if (!checkfixheader) {
                if (!p->payload.orilink_hello2) {
                    LOG_ERROR("%sORILINK_HELLO2 payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + 
                                 (KEM_PUBLICKEY_BYTES / 2) + 
                                 sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_HELLO2_ACK: {
            if (!checkfixheader) {
                if (!p->payload.orilink_hello2_ack) {
                    LOG_ERROR("%sORILINK_HELLO2_ACK payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + 
                                 (KEM_CIPHERTEXT_BYTES / 2) + 
                                 sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_HELLO3: {
            if (!checkfixheader) {
                if (!p->payload.orilink_hello3) {
                    LOG_ERROR("%sORILINK_HELLO3 payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + 
                                 sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_HELLO3_ACK: {
            if (!checkfixheader) {
                if (!p->payload.orilink_hello3_ack) {
                    LOG_ERROR("%sORILINK_HELLO3_ACK payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + 
                                 AES_NONCE_BYTES + 
                                 (KEM_CIPHERTEXT_BYTES / 2) + 
                                 sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_HELLO4: {
            if (!checkfixheader) {
                if (!p->payload.orilink_hello4) {
                    LOG_ERROR("%sORILINK_HELLO4 payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = AES_NONCE_BYTES +
                                 sizeof(uint8_t) +
                                 sizeof(uint8_t) +
                                 sizeof(uint8_t) +
                                 sizeof(uint64_t) +
                                 AES_TAG_BYTES +
                                 sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_HELLO4_ACK: {
            if (!checkfixheader) {
                if (!p->payload.orilink_hello4_ack) {
                    LOG_ERROR("%sORILINK_HELLO4_ACK payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint8_t) +
                                 sizeof(uint8_t) +
                                 sizeof(uint8_t) +
                                 sizeof(uint64_t) +
                                 AES_TAG_BYTES +
                                 sizeof(uint8_t) +
                                 sizeof(uint8_t) +
                                 sizeof(uint8_t) +
                                 sizeof(uint64_t) +
                                 AES_TAG_BYTES +
                                 sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        default:
            LOG_ERROR("%sUnknown protocol type for serialization: 0x%02x", label, p->type);
            result.status = FAILURE_OPYLD;
            return result;
    }
    if (checkfixheader) {
        result.r_size_t = payload_fixed_size;
    } else {
        result.r_size_t = AES_TAG_BYTES + 
                          sizeof(uint32_t) + 
                          ORILINK_VERSION_BYTES + 
                          sizeof(uint8_t) + 
                          sizeof(uint8_t) + 
                          sizeof(uint8_t) + 
                          sizeof(uint8_t) + 
                          sizeof(uint8_t) + 
                          sizeof(uint8_t) + 
                          sizeof(uint8_t) + 
                          sizeof(uint64_t) + 
                          sizeof(uint8_t) + 
                          payload_fixed_size + 
                          payload_dynamic_size;
    }
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
    size_t_status_t psize = calculate_orilink_payload_size(label, p, false);
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
    if (CHECK_BUFFER_BOUNDS(offset, ORILINK_VERSION_BYTES, *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, p->version, ORILINK_VERSION_BYTES);
    offset += ORILINK_VERSION_BYTES;
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, &p->inc_ctr, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, (uint8_t *)&p->remote_wot, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, &p->remote_index, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, &p->remote_session_index, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, (uint8_t *)&p->local_wot, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, &p->local_index, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, &p->local_session_index, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint64_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    uint64_t id_connection_be = htobe64(p->id_connection);
    memcpy(current_buffer + offset, &id_connection_be, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, (uint8_t *)&p->type, sizeof(uint8_t));
    offset += sizeof(uint8_t);
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
        size_t data_len = offset - 
                          AES_TAG_BYTES -
                          sizeof(uint32_t) -
                          ORILINK_VERSION_BYTES -
                          sizeof(uint8_t) -
                          sizeof(uint8_t) - 
                          sizeof(uint8_t) - 
                          sizeof(uint8_t) - 
                          sizeof(uint8_t) - 
                          sizeof(uint8_t) - 
                          sizeof(uint8_t) - 
                          sizeof(uint64_t) - 
                          sizeof(uint8_t);
        size_t data_4mac_len = offset - AES_TAG_BYTES;
        uint8_t *data = (uint8_t *)calloc(1, data_len);
        if (!data) {
            LOG_ERROR("%sError calloc data for encryption: %s", label, strerror(errno));
            free(key0);
            result.status = FAILURE_NOMEM;
            return result;
        }
        uint8_t *data_4mac = (uint8_t *)calloc(1, data_4mac_len);
        if (!data_4mac) {
            LOG_ERROR("%sError calloc data_4mac for encryption: %s", label, strerror(errno));
            free(key0);
            free(data);
            result.status = FAILURE_NOMEM;
            return result;
        }
        uint8_t *encrypted_data = (uint8_t *)calloc(1, data_len);
        if (!encrypted_data) {
            LOG_ERROR("%sError calloc encrypted_data for encryption: %s", label, strerror(errno));
            free(key0);
            free(data);
            free(data_4mac);
            result.status = FAILURE_NOMEM;
            return result;
        }
        uint8_t *keystream_buffer = (uint8_t *)calloc(1, data_len);
        if (!keystream_buffer) {
            LOG_ERROR("%sError calloc keystream_buffer for encryption: %s", label, strerror(errno));
            free(key0);
            free(data);
            free(data_4mac);
            free(encrypted_data);
            result.status = FAILURE_NOMEM;
            return result;
        }
        memcpy(
            data, 
            current_buffer +
                AES_TAG_BYTES + 
                sizeof(uint32_t) + 
                ORILINK_VERSION_BYTES + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint64_t) +
                sizeof(uint8_t),
            data_len
        );
        aes256ctx aes_ctx;
        aes256_ctr_keyexp(&aes_ctx, key_aes);
        uint8_t iv[AES_IV_BYTES];
        memcpy(iv, nonce, AES_NONCE_BYTES);
        uint32_t local_ctr_be = htobe32(*(uint32_t *)ctr);
        memcpy(iv + AES_NONCE_BYTES, &local_ctr_be, sizeof(uint32_t));
        aes256_ctr(keystream_buffer, data_len, iv, &aes_ctx);
        for (size_t i = 0; i < data_len; i++) {
            encrypted_data[i] = data[i] ^ keystream_buffer[i];
        }
        aes256_ctx_release(&aes_ctx);
        memcpy(
            current_buffer +
                AES_TAG_BYTES + 
                sizeof(uint32_t) + 
                ORILINK_VERSION_BYTES + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint64_t) +
                sizeof(uint8_t),
            encrypted_data,
            data_len
        );  
        memcpy(data_4mac,
            current_buffer +
                AES_TAG_BYTES,
            data_4mac_len
        );
        uint8_t mac[AES_TAG_BYTES];
        poly1305_context ctx;
        poly1305_init(&ctx, key_mac);
        poly1305_update(&ctx, data_4mac, data_4mac_len);
        poly1305_finish(&ctx, mac);
        memcpy(current_buffer, mac, AES_TAG_BYTES);
        free(data);
        free(data_4mac);
        free(encrypted_data);
        free(keystream_buffer);
        if (p->inc_ctr != 0xFF) {
            increment_ctr(ctr, nonce);
        }
    } else {
        size_t data_4mac_len = offset - AES_TAG_BYTES;
        uint8_t *data_4mac = (uint8_t *)calloc(1, data_4mac_len);
        if (!data_4mac) {
            LOG_ERROR("%sError calloc data_4mac for mac: %s", label, strerror(errno));
            free(key0);
            result.status = FAILURE_NOMEM;
            return result;
        }
        memcpy(data_4mac, current_buffer + AES_TAG_BYTES, data_4mac_len);
        uint8_t mac[AES_TAG_BYTES];
        poly1305_context ctx;
        poly1305_init(&ctx, key_mac);
        poly1305_update(&ctx, data_4mac, data_4mac_len);
        poly1305_finish(&ctx, mac);
        memcpy(current_buffer, mac, AES_TAG_BYTES);
        free(data_4mac);
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

    if (!buffer || len < (
            AES_TAG_BYTES + 
            sizeof(uint32_t) + 
            ORILINK_VERSION_BYTES + 
            sizeof(uint8_t) + 
            sizeof(uint8_t) + 
            sizeof(uint8_t) + 
            sizeof(uint8_t) + 
            sizeof(uint8_t) + 
            sizeof(uint8_t) + 
            sizeof(uint8_t) + 
            sizeof(uint64_t) +
            sizeof(uint8_t)
        )
    )
    {
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
    memcpy(p->mac, buffer + current_buffer_offset, AES_TAG_BYTES);
    current_buffer_offset += AES_TAG_BYTES;
    uint32_t data_ctr_be;
    memcpy(&data_ctr_be, buffer + current_buffer_offset, sizeof(uint32_t));
    current_buffer_offset += sizeof(uint32_t);
    memcpy(p->version, buffer, ORILINK_VERSION_BYTES);
    current_buffer_offset += ORILINK_VERSION_BYTES;
    memcpy(&p->inc_ctr, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    memcpy((uint8_t *)&p->remote_wot, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    memcpy(&p->remote_index, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    memcpy(&p->remote_session_index, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    memcpy((uint8_t *)&p->local_wot, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    memcpy(&p->local_index, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    memcpy(&p->local_session_index, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    uint64_t id_connection_be;
    memcpy(&id_connection_be, buffer + current_buffer_offset, sizeof(uint64_t));
    p->id_connection = be64toh(id_connection_be);
    current_buffer_offset += sizeof(uint64_t);
    memcpy((uint8_t *)&p->type, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    uint8_t *key0 = (uint8_t *)calloc(1, HASHES_BYTES * sizeof(uint8_t));
    if (memcmp(
            key_aes, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        uint32_t data_ctr = be32toh(data_ctr_be);
        if (data_ctr != *(uint32_t *)ctr) {
            LOG_ERROR("%sCounter tidak cocok. data_ctr: %ul, *ctr: %ul", label, data_ctr, *(uint32_t *)ctr);
            CLOSE_ORILINK_PROTOCOL(&p);
            free(key0);
            result.status = FAILURE_CTRMSMTCH;
            return result;
        }
        size_t data_len = len -
                          AES_TAG_BYTES -
                          sizeof(uint32_t) -
                          ORILINK_VERSION_BYTES -
                          sizeof(uint8_t) -
                          sizeof(uint8_t) - 
                          sizeof(uint8_t) - 
                          sizeof(uint8_t) - 
                          sizeof(uint8_t) - 
                          sizeof(uint8_t) - 
                          sizeof(uint8_t) - 
                          sizeof(uint64_t) -
                          sizeof(uint8_t);
        uint8_t *data = (uint8_t *)calloc(1, data_len);
        if (!data) {
            LOG_ERROR("%sError calloc data for encryption: %s", label, strerror(errno));
            CLOSE_ORILINK_PROTOCOL(&p);
            free(key0);
            result.status = FAILURE_NOMEM;
            return result;
        }
        uint8_t *decrypted_data = (uint8_t *)calloc(1, data_len);
        if (!decrypted_data) {
            LOG_ERROR("%sError calloc decrypted_data for encryption: %s", label, strerror(errno));
            CLOSE_ORILINK_PROTOCOL(&p);
            free(key0);
            free(data);
            result.status = FAILURE_NOMEM;
            return result;
        }
        uint8_t *keystream_buffer = (uint8_t *)calloc(1, data_len);
        if (!keystream_buffer) {
            LOG_ERROR("%sError calloc keystream_buffer for encryption: %s", label, strerror(errno));
            CLOSE_ORILINK_PROTOCOL(&p);
            free(key0);
            free(data);
            free(decrypted_data);
            result.status = FAILURE_NOMEM;
            return result;
        }
        memcpy(
            data, 
            buffer +
                AES_TAG_BYTES + 
                sizeof(uint32_t) + 
                ORILINK_VERSION_BYTES + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint64_t) +
                sizeof(uint8_t), 
            data_len
        );
        aes256ctx aes_ctx;
        aes256_ctr_keyexp(&aes_ctx, key_aes);
        uint8_t iv[AES_IV_BYTES];
        memcpy(iv, nonce, AES_NONCE_BYTES);
        uint32_t local_ctr_be = htobe32(*(uint32_t *)ctr);
        memcpy(iv + AES_NONCE_BYTES, &local_ctr_be, sizeof(uint32_t));
        aes256_ctr(keystream_buffer, data_len, iv, &aes_ctx);
        for (size_t i = 0; i < data_len; i++) {
            decrypted_data[i] = data[i] ^ keystream_buffer[i];
        }
        aes256_ctx_release(&aes_ctx);
        memcpy(
            buffer + 
                AES_TAG_BYTES + 
                sizeof(uint32_t) + 
                ORILINK_VERSION_BYTES + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint64_t) +
                sizeof(uint8_t), 
            decrypted_data, 
            data_len
        );
        free(data);
        free(decrypted_data);
        free(keystream_buffer);
    }
    size_t_status_t psize = calculate_orilink_payload_size(label, p, true);
    if (psize.status != SUCCESS) {
        CLOSE_ORILINK_PROTOCOL(&p);
        free(key0);
		result.status = psize.status;
		return result;
	}
    size_t fixed_header_size = psize.r_size_t;
    LOG_DEBUG("%sDeserializing type 0x%02x. Current offset: %zu", label, p->type, current_buffer_offset);
    status_t result_pyld = FAILURE;
    switch (p->type) {
        case ORILINK_HELLO1: {
			if (current_buffer_offset + fixed_header_size > len) {
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
			if (current_buffer_offset + fixed_header_size > len) {
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
			if (current_buffer_offset + fixed_header_size > len) {
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
			if (current_buffer_offset + fixed_header_size > len) {
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
			if (current_buffer_offset + fixed_header_size > len) {
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
			if (current_buffer_offset + fixed_header_size > len) {
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
			if (current_buffer_offset + fixed_header_size > len) {
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
			if (current_buffer_offset + fixed_header_size > len) {
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

ssize_t_status_t send_orilink_raw_protocol_packet(const char *label, puint8_t_size_t_status_t *r, int *sock_fd, const struct sockaddr_in6 *dest_addr) {
	ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;
    socklen_t dest_addr_len = sizeof(struct sockaddr_in6);
    result.r_ssize_t = sendto(*sock_fd, r->r_puint8_t, r->r_size_t, 0, (const struct sockaddr *)dest_addr, dest_addr_len);
    if (result.r_ssize_t != (ssize_t)r->r_size_t) {
        LOG_ERROR("%ssendto failed to send_orilink_protocol_packet. %s", label, strerror(errno));
        if (r->r_puint8_t) {
            free(r->r_puint8_t);
            r->r_puint8_t = NULL;
            r->r_size_t = 0;
        }
        result.status = FAILURE;
        return result;
    }
    if (r->r_puint8_t) {
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
    }
    result.status = SUCCESS;
    return result;
}

status_t orilink_check_mac_ctr(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint32_t* ctr, orilink_raw_protocol_t *r) {
	uint8_t *key0 = (uint8_t *)calloc(1, HASHES_BYTES * sizeof(uint8_t));
    if (memcmp(
            key_aes, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        if (r->ctr != *(uint32_t *)ctr) {
            LOG_ERROR("%sOrilink Counter tidak cocok. data_ctr: %ul, *ctr: %ul", label, r->ctr, *(uint32_t *)ctr);
            free(key0);
            return FAILURE_CTRMSMTCH;
        }
    }
    free(key0);
    uint8_t *data_4mac = (uint8_t*) calloc(1, AES_TAG_BYTES);
    if (!data_4mac) {
        LOG_ERROR("%sFailed to allocate data_4mac buffer. %s", label, strerror(errno));
        return FAILURE_NOMEM;
    }
    uint8_t *dt = (uint8_t*) calloc(1, r->n - AES_TAG_BYTES);
    if (!dt) {
        LOG_ERROR("%sFailed to allocate dt buffer. %s", label, strerror(errno));
        free(data_4mac);
        return FAILURE_NOMEM;
    }
    memcpy(data_4mac, r->recv_buffer, AES_TAG_BYTES);
    memcpy(dt, r->recv_buffer + AES_TAG_BYTES, r->n - AES_TAG_BYTES);
    uint8_t mac[AES_TAG_BYTES];
    poly1305_context ctx;
    poly1305_init(&ctx, key_mac);
    poly1305_update(&ctx, dt, r->n - AES_TAG_BYTES);
    poly1305_finish(&ctx, mac);
    if (poly1305_verify(mac, data_4mac)) {
        LOG_DEBUG("%sMac cocok", label);
        free(data_4mac);
        free(dt);
        return SUCCESS;
    } else {
        LOG_ERROR("%sOrilink Mac mismatch!", label);
        free(data_4mac);
        free(dt);
        return FAILURE_MACMSMTCH;
    }
}

orilink_raw_protocol_t_status_t receive_orilink_raw_protocol_packet(const char *label, int *sock_fd, struct sockaddr_in6 *source_addr) {
    orilink_raw_protocol_t_status_t result;
    result.status = FAILURE;
    result.r_orilink_raw_protocol_t = NULL;
    uint8_t *full_orilink_payload_buffer = (uint8_t *)calloc(1, ORILINK_MAX_PACKET_SIZE * sizeof(uint8_t));
    socklen_t source_addr_len = sizeof(struct sockaddr_in6);
    ssize_t bytes_read_payload = recvfrom(*sock_fd, full_orilink_payload_buffer, ORILINK_MAX_PACKET_SIZE, 0, (struct sockaddr * restrict)source_addr, &source_addr_len);
    if (bytes_read_payload < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
			LOG_ERROR("%sreceive_orilink_raw_protocol_packet failed: %s", label, strerror(errno));
			free(full_orilink_payload_buffer);
            result.status = FAILURE_EAGNEWBLK;
            return result;
        } else {
            LOG_ERROR("%sreceive_orilink_raw_protocol_packet failed: %s", label, strerror(errno));
            free(full_orilink_payload_buffer);
            result.status = FAILURE;
            return result;
        }
    } else if (bytes_read_payload < (ssize_t)(AES_TAG_BYTES + sizeof(uint32_t) + ORILINK_VERSION_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t))) {
        LOG_ERROR("%sreceive_orilink_raw_protocol_packet received 0 bytes (unexpected for UDP).", label);
        free(full_orilink_payload_buffer);
        result.status = FAILURE_OOBUF;
        return result;
    }
    orilink_raw_protocol_t* r = (orilink_raw_protocol_t*)calloc(1, sizeof(orilink_raw_protocol_t));
    if (!r) {
        LOG_ERROR("%sFailed to allocate orilink_raw_protocol_t. %s", label, strerror(errno));
        free(full_orilink_payload_buffer);
        result.status = FAILURE_NOMEM;
        return result;
    }
    uint8_t *b = (uint8_t*) calloc(1, bytes_read_payload);
    if (!b) {
        LOG_ERROR("%sFailed to allocate orilink_raw_protocol_t buffer. %s", label, strerror(errno));
        free(full_orilink_payload_buffer);
        CLOSE_ORILINK_RAW_PROTOCOL(&r);
        result.status = FAILURE_NOMEM;
        return result;
    }
    memcpy(b, full_orilink_payload_buffer, bytes_read_payload);
    free(full_orilink_payload_buffer);
    r->recv_buffer = b;
    r->n = (uint32_t)bytes_read_payload;
    memcpy(r->mac, b, AES_TAG_BYTES);
    uint32_t ctr_be;
    memcpy(&ctr_be,
        b + 
        AES_TAG_BYTES,
        sizeof(uint32_t)
    );
    r->ctr = be32toh(ctr_be);
    memcpy(r->version,
        b + 
        AES_TAG_BYTES + 
        sizeof(uint32_t), 
        ORILINK_VERSION_BYTES
    );
    memcpy(&r->inc_ctr,
        b +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES,
        sizeof(uint8_t)
    );
    memcpy((uint8_t *)&r->remote_wot,
        b +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t),
        sizeof(uint8_t)
    );
    memcpy(&r->remote_index,
        b +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t),
        sizeof(uint8_t)
    );
    memcpy(&r->remote_session_index,
        b +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t),
        sizeof(uint8_t)
    );
    memcpy((uint8_t *)&r->local_wot,
        b +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t),
        sizeof(uint8_t)
    );
    memcpy(&r->local_index,
        b +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t),
        sizeof(uint8_t)
    );
    memcpy(&r->local_session_index,
        b +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t),
        sizeof(uint8_t)
    );
    uint64_t id_connection_be;
    memcpy(&id_connection_be,
        b +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t),
        sizeof(uint64_t)
    );
    r->id_connection = be64toh(id_connection_be);
    memcpy((uint8_t *)&r->type,
        b +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint64_t),
        sizeof(uint8_t)
    );
    result.r_orilink_raw_protocol_t = r;
    result.status = SUCCESS;
    return result;
}

status_t udp_data_to_orilink_raw_protocol_packet(const char *label, ipc_udp_data_t *iudp_datai, orilink_raw_protocol_t *oudp_datao) {
    oudp_datao->recv_buffer = (uint8_t *)calloc(1, iudp_datai->len);
    if (!oudp_datao->recv_buffer) {
        LOG_ERROR("%sFailed to allocate orilink_raw_protocol_t buffer. %s", label, strerror(errno));
        return FAILURE_NOMEM;
    }
    memcpy(oudp_datao->recv_buffer, iudp_datai->data, iudp_datai->len);
    oudp_datao->n = iudp_datai->len;
    memcpy(oudp_datao->mac, oudp_datao->recv_buffer, AES_TAG_BYTES);
    uint32_t ctr_be;
    memcpy(&ctr_be,
        oudp_datao->recv_buffer + 
        AES_TAG_BYTES,
        sizeof(uint32_t)
    );
    oudp_datao->ctr = be32toh(ctr_be);
    memcpy(oudp_datao->version,
        oudp_datao->recv_buffer + 
        AES_TAG_BYTES + 
        sizeof(uint32_t), 
        ORILINK_VERSION_BYTES
    );
    memcpy(&oudp_datao->inc_ctr,
        oudp_datao->recv_buffer +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES,
        sizeof(uint8_t)
    );
    memcpy((uint8_t *)&oudp_datao->remote_wot,
        oudp_datao->recv_buffer +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t),
        sizeof(uint8_t)
    );
    memcpy(&oudp_datao->remote_index,
        oudp_datao->recv_buffer +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t),
        sizeof(uint8_t)
    );
    memcpy(&oudp_datao->remote_session_index,
        oudp_datao->recv_buffer +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t),
        sizeof(uint8_t)
    );
    memcpy((uint8_t *)&oudp_datao->local_wot,
        oudp_datao->recv_buffer +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t),
        sizeof(uint8_t)
    );
    memcpy(&oudp_datao->local_index,
        oudp_datao->recv_buffer +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t),
        sizeof(uint8_t)
    );
    memcpy(&oudp_datao->local_session_index,
        oudp_datao->recv_buffer +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t),
        sizeof(uint8_t)
    );
    
    uint64_t id_connection_be;
    memcpy(&id_connection_be,
        oudp_datao->recv_buffer +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t),
        sizeof(uint64_t)
    );
    oudp_datao->id_connection = be64toh(id_connection_be);
    memcpy((uint8_t *)&oudp_datao->type,
        oudp_datao->recv_buffer +
        AES_TAG_BYTES +
        sizeof(uint32_t) +
        ORILINK_VERSION_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint64_t),
        sizeof(uint8_t)
    );
    return SUCCESS;
}
