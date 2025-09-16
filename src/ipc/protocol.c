#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <endian.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/uio.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "ipc/master_worker_info.h"
#include "ipc/worker_master_heartbeat.h"
#include "ipc/master_cow_connect.h"
#include "ipc/worker_master_hello1.h"
#include "ipc/worker_master_hello2.h"
#include "ipc/master_worker_hello1_ack.h"
#include "ipc/master_worker_hello2_ack.h"
#include "constants.h"
#include "pqc.h"
#include "poly1305-donna.h"
#include "aes.h"

static inline size_t_status_t calculate_ipc_payload_size(const char *label, const ipc_protocol_t* p, bool checkfixheader) {
	size_t_status_t result;
    result.r_size_t = 0;
    result.status = FAILURE;
    size_t payload_fixed_size = 0;
    size_t payload_dynamic_size = 0;
    
    switch (p->type) {
		case IPC_MASTER_WORKER_INFO: {
            if (!checkfixheader) {
                if (!p->payload.ipc_master_worker_info) {
                    LOG_ERROR("%sIPC_MASTER_WORKER_INFO payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case IPC_WORKER_MASTER_HEARTBEAT: {
            if (!checkfixheader) {
                if (!p->payload.ipc_worker_master_heartbeat) {
                    LOG_ERROR("%sIPC_WORKER_MASTER_HEARTBEAT payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = DOUBLE_ARRAY_SIZE;
            payload_dynamic_size = 0;
            break;
        }
        case IPC_MASTER_COW_CONNECT: {
            if (!checkfixheader) {
                if (!p->payload.ipc_master_cow_connect) {
                    LOG_ERROR("%sIPC_MASTER_COW_CONNECT payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = SOCKADDR_IN6_SIZE;
            payload_dynamic_size = 0;
            break;
        }
        case IPC_WORKER_MASTER_HELLO1: {
            if (!checkfixheader) {
                if (!p->payload.ipc_worker_master_hello1) {
                    LOG_ERROR("%sIPC_WORKER_MASTER_HELLO1 payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = KEM_PUBLICKEY_BYTES;
            payload_dynamic_size = 0;
            break;
        }
        case IPC_WORKER_MASTER_HELLO2: {
            if (!checkfixheader) {
                if (!p->payload.ipc_worker_master_hello2) {
                    LOG_ERROR("%sIPC_WORKER_MASTER_HELLO2 payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES;
            payload_dynamic_size = 0;
            break;
        }
        case IPC_MASTER_WORKER_HELLO1_ACK: {
            if (!checkfixheader) {
                if (!p->payload.ipc_master_worker_hello1_ack) {
                    LOG_ERROR("%sIPC_MASTER_WORKER_HELLO1_ACK payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = AES_NONCE_BYTES + KEM_CIPHERTEXT_BYTES;
            payload_dynamic_size = 0;
            break;
        }
        case IPC_MASTER_WORKER_HELLO2_ACK: {
            if (!checkfixheader) {
                if (!p->payload.ipc_master_worker_hello2_ack) {
                    LOG_ERROR("%sIPC_MASTER_WORKER_HELLO2_ACK payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES;
            payload_dynamic_size = 0;
            break;
        }
        default:
            LOG_ERROR("%sUnknown protocol type for serialization: 0x%02x", label, p->type);
            result.status = FAILURE_IPYLD;
            return result;
    }
    if (checkfixheader) {
        result.r_size_t = payload_fixed_size;
    } else {
        result.r_size_t = AES_TAG_BYTES + sizeof(uint32_t) + IPC_VERSION_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + payload_fixed_size + payload_dynamic_size;
    }
    result.status = SUCCESS;
    return result;
}

ssize_t_status_t ipc_serialize(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint8_t* nonce, uint32_t *ctr, const ipc_protocol_t* p, uint8_t** ptr_buffer, size_t* buffer_size) {
    ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;
    if (!p || !ptr_buffer || !buffer_size) {
        return result;
    }
    size_t_status_t psize = calculate_ipc_payload_size(label, p, false);
    if (psize.status != SUCCESS) {
		result.status = psize.status;
		return result;
	}
    size_t total_required_size = psize.r_size_t;
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
    if (CHECK_BUFFER_BOUNDS(offset, IPC_VERSION_BYTES, *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, p->version, IPC_VERSION_BYTES);
    offset += IPC_VERSION_BYTES;
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, (uint8_t *)&p->wot, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, (uint8_t *)&p->index, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, (uint8_t *)&p->type, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    status_t result_pyld = FAILURE;
    switch (p->type) {
        case IPC_MASTER_WORKER_INFO:
            result_pyld = ipc_serialize_master_worker_info(label, p->payload.ipc_master_worker_info, current_buffer, *buffer_size, &offset);
            break;
        case IPC_WORKER_MASTER_HEARTBEAT:
            result_pyld = ipc_serialize_worker_master_heartbeat(label, p->payload.ipc_worker_master_heartbeat, current_buffer, *buffer_size, &offset);
            break;
        case IPC_MASTER_COW_CONNECT:
            result_pyld = ipc_serialize_master_cow_connect(label, p->payload.ipc_master_cow_connect, current_buffer, *buffer_size, &offset);
            break;
        case IPC_WORKER_MASTER_HELLO1:
            result_pyld = ipc_serialize_worker_master_hello1(label, p->payload.ipc_worker_master_hello1, current_buffer, *buffer_size, &offset);
            break;
        case IPC_WORKER_MASTER_HELLO2:
            result_pyld = ipc_serialize_worker_master_hello2(label, p->payload.ipc_worker_master_hello2, current_buffer, *buffer_size, &offset);
            break;
        case IPC_MASTER_WORKER_HELLO1_ACK:
            result_pyld = ipc_serialize_master_worker_hello1_ack(label, p->payload.ipc_master_worker_hello1_ack, current_buffer, *buffer_size, &offset);
            break;
        case IPC_MASTER_WORKER_HELLO2_ACK:
            result_pyld = ipc_serialize_master_worker_hello2_ack(label, p->payload.ipc_master_worker_hello2_ack, current_buffer, *buffer_size, &offset);
            break;
            
        default:
            LOG_ERROR("%sUnknown protocol type for serialization: 0x%02x", label, p->type);
            result.status = FAILURE_IPYLD;
            return result;
    }
    if (result_pyld != SUCCESS) {
        LOG_ERROR("%sPayload serialization failed with status %d.", label, result_pyld);
        result.status = FAILURE_IPYLD;
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
                          IPC_VERSION_BYTES -
                          sizeof(uint8_t) -
                          sizeof(uint8_t) -
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
                IPC_VERSION_BYTES +
                sizeof(uint8_t) +
                sizeof(uint8_t) +
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
                IPC_VERSION_BYTES +
                sizeof(uint8_t) +
                sizeof(uint8_t) +
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
        increment_ctr(ctr, nonce);
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

ipc_protocol_t_status_t ipc_deserialize(const char *label, uint8_t* key_aes, uint8_t* nonce, uint32_t *ctr, uint8_t* buffer, size_t len) {
    ipc_protocol_t_status_t result;
    result.r_ipc_protocol_t = NULL;
    result.status = FAILURE;
    if (!buffer || len < (IPC_VERSION_BYTES + sizeof(uint8_t))) {
        LOG_ERROR("%sBuffer terlalu kecil untuk Version dan Type. Len: %zu", label, len);
        result.status = FAILURE_OOBUF;
        return result;
    }
    ipc_protocol_t* p = (ipc_protocol_t*)calloc(1, sizeof(ipc_protocol_t));
    if (!p) {
        LOG_ERROR("%sFailed to allocate ipc_protocol_t. %s", label, strerror(errno));
        result.status = FAILURE_NOMEM;
        return result;
    }
    LOG_DEBUG("%sAllocating ipc_protocol_t struct: %zu bytes.", label, sizeof(ipc_protocol_t));
    size_t current_buffer_offset = 0;
    memcpy(p->mac, buffer + current_buffer_offset, AES_TAG_BYTES);
    current_buffer_offset += AES_TAG_BYTES;
    uint32_t data_ctr_be;
    memcpy(&data_ctr_be, buffer + current_buffer_offset, sizeof(uint32_t));
    current_buffer_offset += sizeof(uint32_t);
    memcpy(p->version, buffer + current_buffer_offset, IPC_VERSION_BYTES);
    current_buffer_offset += IPC_VERSION_BYTES;
    memcpy((uint8_t *)&p->wot, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    memcpy((uint8_t *)&p->index, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
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
            CLOSE_IPC_PROTOCOL(&p);
            free(key0);
            result.status = FAILURE_CTRMSMTCH;
            return result;
        }
        size_t data_len = len -
                          AES_TAG_BYTES -
                          sizeof(uint32_t) - 
                          IPC_VERSION_BYTES - 
                          sizeof(uint8_t) - 
                          sizeof(uint8_t) - 
                          sizeof(uint8_t);
        uint8_t *data = (uint8_t *)calloc(1, data_len);
        if (!data) {
            LOG_ERROR("%sError calloc data for encryption: %s", label, strerror(errno));
            CLOSE_IPC_PROTOCOL(&p);
            free(key0);
            result.status = FAILURE_NOMEM;
            return result;
        }
        uint8_t *decrypted_data = (uint8_t *)calloc(1, data_len);
        if (!decrypted_data) {
            LOG_ERROR("%sError calloc decrypted_data for encryption: %s", label, strerror(errno));
            CLOSE_IPC_PROTOCOL(&p);
            free(key0);
            free(data);
            result.status = FAILURE_NOMEM;
            return result;
        }
        uint8_t *keystream_buffer = (uint8_t *)calloc(1, data_len);
        if (!keystream_buffer) {
            LOG_ERROR("%sError calloc keystream_buffer for encryption: %s", label, strerror(errno));
            CLOSE_IPC_PROTOCOL(&p);
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
                IPC_VERSION_BYTES + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
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
                IPC_VERSION_BYTES + 
                sizeof(uint8_t) + 
                sizeof(uint8_t) + 
                sizeof(uint8_t), 
            decrypted_data, 
            data_len
        );
        free(data);
        free(decrypted_data);
        free(keystream_buffer);
    }
    size_t_status_t psize = calculate_ipc_payload_size(label, p, true);
    if (psize.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&p);
        free(key0);
		result.status = psize.status;
		return result;
	}
    size_t fixed_header_size = psize.r_size_t;
    LOG_DEBUG("%sDeserializing type 0x%02x. Current offset: %zu", label, p->type, current_buffer_offset);
    status_t result_pyld = FAILURE;
    switch (p->type) {
        case IPC_MASTER_WORKER_INFO: {
            if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_MASTER_WORKER_INFO fixed header.", label);
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_master_worker_info_t *payload = (ipc_master_worker_info_t*) calloc(1, sizeof(ipc_master_worker_info_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_master_worker_info_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_master_worker_info = payload;
            result_pyld = ipc_deserialize_master_worker_info(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_WORKER_MASTER_HEARTBEAT: {
            if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_WORKER_MASTER_HEARTBEAT fixed header.", label);
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_worker_master_heartbeat_t *payload = (ipc_worker_master_heartbeat_t*) calloc(1, sizeof(ipc_worker_master_heartbeat_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_worker_master_heartbeat_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_worker_master_heartbeat = payload;
            result_pyld = ipc_deserialize_worker_master_heartbeat(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_MASTER_COW_CONNECT: {
            if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_MASTER_COW_CONNECT fixed header.", label);
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_master_cow_connect_t *payload = (ipc_master_cow_connect_t*) calloc(1, sizeof(ipc_master_cow_connect_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_master_cow_connect_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_master_cow_connect = payload;
            result_pyld = ipc_deserialize_master_cow_connect(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_WORKER_MASTER_HELLO1: {
            if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_WORKER_MASTER_HELLO1 fixed header.", label);
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_worker_master_hello1_t *payload = (ipc_worker_master_hello1_t*) calloc(1, sizeof(ipc_worker_master_hello1_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_worker_master_hello1_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_worker_master_hello1 = payload;
            result_pyld = ipc_deserialize_worker_master_hello1(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_WORKER_MASTER_HELLO2: {
            if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_WORKER_MASTER_HELLO1 fixed header.", label);
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_worker_master_hello2_t *payload = (ipc_worker_master_hello2_t*) calloc(1, sizeof(ipc_worker_master_hello2_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_worker_master_hello2_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_worker_master_hello2 = payload;
            result_pyld = ipc_deserialize_worker_master_hello2(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_MASTER_WORKER_HELLO1_ACK: {
            if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_MASTER_WORKER_HELLO1_ACK fixed header.", label);
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_master_worker_hello1_ack_t *payload = (ipc_master_worker_hello1_ack_t*) calloc(1, sizeof(ipc_master_worker_hello1_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_master_worker_hello1_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_master_worker_hello1_ack = payload;
            result_pyld = ipc_deserialize_master_worker_hello1_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_MASTER_WORKER_HELLO2_ACK: {
            if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_MASTER_WORKER_HELLO2_ACK fixed header.", label);
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_master_worker_hello2_ack_t *payload = (ipc_master_worker_hello2_ack_t*) calloc(1, sizeof(ipc_master_worker_hello2_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_master_worker_hello2_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_master_worker_hello2_ack = payload;
            result_pyld = ipc_deserialize_master_worker_hello2_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        default:
            LOG_ERROR("%sUnknown protocol type for deserialization: 0x%02x", label, p->type);
            result.status = FAILURE_IPYLD;
            CLOSE_IPC_PROTOCOL(&p);
            free(key0);
            return result;
    }
    if (result_pyld != SUCCESS) {
        LOG_ERROR("%sPayload deserialization failed with status %d.", label, result_pyld);
        CLOSE_IPC_PROTOCOL(&p);
        free(key0);
        result.status = FAILURE_IPYLD;
        return result;
    }
    if (memcmp(
            key_aes, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        increment_ctr(ctr, nonce);
    }
    free(key0);
    result.r_ipc_protocol_t = p;
    result.status = SUCCESS;
    LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
    return result;
}

ssize_t_status_t send_ipc_protocol_message(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint8_t* nonce, uint32_t *ctr, int *uds_fd, const ipc_protocol_t* p) {
	ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;
    uint8_t* serialized_ipc_data_buffer = NULL;
    size_t serialized_ipc_data_len = 0;

    ssize_t_status_t serialize_result = ipc_serialize(label, key_aes, key_mac, nonce, ctr, p, &serialized_ipc_data_buffer, &serialized_ipc_data_len);
    if (serialize_result.status != SUCCESS) {
        LOG_ERROR("%sError serializing IPC protocol: %d", serialize_result.status);
        if (serialized_ipc_data_buffer) {
            free(serialized_ipc_data_buffer);
        }
        return result;
    }
    size_t total_message_len_to_send = IPC_LENGTH_PREFIX_BYTES + serialized_ipc_data_len;
    uint8_t *final_send_buffer = (uint8_t *)malloc(total_message_len_to_send);
    if (!final_send_buffer) {
        LOG_ERROR("%smalloc failed for final_send_buffer. %s", label, strerror(errno));
        if (serialized_ipc_data_buffer) {
            free(serialized_ipc_data_buffer);
        }
        return result;
    }
    size_t offset = 0;
    uint32_t ipc_protocol_data_len_be = htobe32((uint32_t)serialized_ipc_data_len);
    memcpy(final_send_buffer + offset, &ipc_protocol_data_len_be, IPC_LENGTH_PREFIX_BYTES);
    offset += IPC_LENGTH_PREFIX_BYTES;
    memcpy(final_send_buffer + offset, serialized_ipc_data_buffer, serialized_ipc_data_len);
    LOG_DEBUG("%sTotal pesan untuk dikirim: %zu byte (Prefix %zu + IPC Data %zu).",
            label, total_message_len_to_send, IPC_LENGTH_PREFIX_BYTES, serialized_ipc_data_len);
    struct msghdr msg = {0};
    struct iovec iov[1];
    iov[0].iov_base = final_send_buffer;
    iov[0].iov_len = total_message_len_to_send;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    result.r_ssize_t = sendmsg(*uds_fd, &msg, 0);
    if (result.r_ssize_t == -1) {
        LOG_ERROR("%ssend_ipc_protocol_message sendmsg. %s", label, strerror(errno));
        free(final_send_buffer);
        if (serialized_ipc_data_buffer) {
            free(serialized_ipc_data_buffer);
        }
        return result;
    } else if (result.r_ssize_t != (ssize_t)total_message_len_to_send) {
        LOG_ERROR("%sendmsg hanya mengirim %zd dari %zu byte!",
                label, result.r_ssize_t, total_message_len_to_send);
        free(final_send_buffer);
        if (serialized_ipc_data_buffer) {
            free(serialized_ipc_data_buffer);
        }
        return result;
    } else {
        LOG_DEBUG("%sBerhasil mengirim %zd byte.\n", label, result.r_ssize_t);
    }    
    free(final_send_buffer);
    if (serialized_ipc_data_buffer) {
        free(serialized_ipc_data_buffer);
    }
    result.status = SUCCESS;
    return result;
}

status_t ipc_check_mac_ctr(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint32_t* ctr, ipc_raw_protocol_t *r) {
	uint8_t *key0 = (uint8_t *)calloc(1, HASHES_BYTES * sizeof(uint8_t));
    if (memcmp(
            key_aes, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        if (r->ctr != *(uint32_t *)ctr) {
            LOG_ERROR("%sCounter tidak cocok. data_ctr: %ul, *ctr: %ul", label, r->ctr, *(uint32_t *)ctr);
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
        LOG_ERROR("%sMac mismatch!", label);
        free(data_4mac);
        free(dt);
        return FAILURE_MACMSMTCH;
    }
}

ipc_raw_protocol_t_status_t receive_ipc_raw_protocol_message(const char *label, int *uds_fd) {
    ipc_raw_protocol_t_status_t result;
    result.status = FAILURE;
    result.r_ipc_raw_protocol_t = NULL;
    uint32_t total_ipc_payload_len_be;
    char temp_len_prefix_buf[IPC_LENGTH_PREFIX_BYTES];
    struct msghdr msg_prefix = {0};
    struct iovec iov_prefix[1];
    iov_prefix[0].iov_base = temp_len_prefix_buf;
    iov_prefix[0].iov_len = IPC_LENGTH_PREFIX_BYTES;
    msg_prefix.msg_iov = iov_prefix;
    msg_prefix.msg_iovlen = 1;
    char cmsgbuf_prefix[CMSG_SPACE(sizeof(int))];
    msg_prefix.msg_control = cmsgbuf_prefix;
    msg_prefix.msg_controllen = sizeof(cmsgbuf_prefix);
    LOG_DEBUG("%sTahap 1: Membaca length prefix dan potensi FD (%zu byte).", label, IPC_LENGTH_PREFIX_BYTES);
    ssize_t bytes_read_prefix_and_fd = recvmsg(*uds_fd, &msg_prefix, MSG_WAITALL);
    if (bytes_read_prefix_and_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("%sreceive_ipc_raw_protocol_message recvmsg (length prefix + FD). %s", label, strerror(errno));
        }
        return result;
    }
    if (bytes_read_prefix_and_fd != (ssize_t)IPC_LENGTH_PREFIX_BYTES) {
        LOG_ERROR("%sGagal membaca length prefix sepenuhnya. Diharapkan %zu byte, diterima %zd.",
                label, IPC_LENGTH_PREFIX_BYTES, bytes_read_prefix_and_fd);
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(&total_ipc_payload_len_be, temp_len_prefix_buf, IPC_LENGTH_PREFIX_BYTES);
    uint32_t total_ipc_payload_len = be32toh(total_ipc_payload_len_be);
    LOG_DEBUG("%sDitemukan panjang payload IPC: %u byte.", label, total_ipc_payload_len);
    if (total_ipc_payload_len == 0) {
        LOG_ERROR("%sPanjang payload IPC adalah 0. Tidak ada data untuk dibaca.", label);
        result.status = FAILURE_BAD_PROTOCOL;
        return result;
    }
    uint8_t *full_ipc_payload_buffer = (uint8_t *)malloc(total_ipc_payload_len);
    if (!full_ipc_payload_buffer) {
        LOG_ERROR("%sreceive_ipc_raw_protocol_message: malloc failed for full_ipc_payload_buffer. %s", label, strerror(errno));
        result.status = FAILURE_NOMEM;
        return result;
    }
    struct msghdr msg_payload = {0};
    struct iovec iov_payload[1];
    iov_payload[0].iov_base = full_ipc_payload_buffer;
    iov_payload[0].iov_len = total_ipc_payload_len;
    msg_payload.msg_iov = iov_payload;
    msg_payload.msg_iovlen = 1;
    msg_payload.msg_control = NULL;
    msg_payload.msg_controllen = 0;
    LOG_DEBUG("%sTahap 2: Membaca %u byte payload IPC.", label, total_ipc_payload_len);
    ssize_t bytes_read_payload = recvmsg(*uds_fd, &msg_payload, MSG_WAITALL);
    if (bytes_read_payload < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
			LOG_ERROR("%sreceive_ipc_raw_protocol_message recvmsg (payload). %s", label, strerror(errno));
			free(full_ipc_payload_buffer);
			result.status = FAILURE_EAGNEWBLK;
            return result;
        } else {
			LOG_ERROR("%sreceive_ipc_raw_protocol_message recvmsg (payload). %s", label, strerror(errno));
			free(full_ipc_payload_buffer);
			result.status = FAILURE;
			return result;
		}
    } else if (bytes_read_payload < (ssize_t)(AES_TAG_BYTES + sizeof(uint32_t) + IPC_VERSION_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t))) {
        LOG_ERROR("%sreceive_ipc_raw_protocol_message received 0 bytes (unexpected for IPC).", label);
        free(full_ipc_payload_buffer);
        result.status = FAILURE_OOBUF;
        return result;
    } else if (bytes_read_payload != (ssize_t)total_ipc_payload_len) {
        LOG_ERROR("%sPayload IPC tidak lengkap. Diharapkan %u byte, diterima %zd.", label, total_ipc_payload_len, bytes_read_payload);
        free(full_ipc_payload_buffer);
        result.status = FAILURE_OOBUF;
        return result;
    }
    ipc_raw_protocol_t* r = (ipc_raw_protocol_t*)calloc(1, sizeof(ipc_raw_protocol_t));
    if (!r) {
        LOG_ERROR("%sFailed to allocate ipc_raw_protocol_t. %s", label, strerror(errno));
        free(full_ipc_payload_buffer);
        result.status = FAILURE_NOMEM;
        return result;
    }
    uint8_t *b = (uint8_t*) calloc(1, bytes_read_payload);
    if (!b) {
        LOG_ERROR("%sFailed to allocate ipc_raw_protocol_t buffer. %s", label, strerror(errno));
        free(full_ipc_payload_buffer);
        CLOSE_IPC_RAW_PROTOCOL(&r);
        result.status = FAILURE_NOMEM;
        return result;
    }
    memcpy(b, full_ipc_payload_buffer, bytes_read_payload);
    free(full_ipc_payload_buffer);
    r->recv_buffer = b;
    r->n = (uint32_t)bytes_read_payload;
    uint32_t ctr_be;
    memcpy(&ctr_be, b + AES_TAG_BYTES, sizeof(uint32_t));
    r->ctr = be32toh(ctr_be);
    memcpy(r->version, b + AES_TAG_BYTES + sizeof(uint32_t), IPC_VERSION_BYTES);
    memcpy((uint8_t *)&r->wot, b + AES_TAG_BYTES + sizeof(uint32_t) + IPC_VERSION_BYTES, sizeof(uint8_t));
    memcpy((uint8_t *)&r->index, b + AES_TAG_BYTES + sizeof(uint32_t) + IPC_VERSION_BYTES + sizeof(uint8_t), sizeof(uint8_t));
    memcpy((uint8_t *)&r->type, b + AES_TAG_BYTES + sizeof(uint32_t) + IPC_VERSION_BYTES + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint8_t));
    result.r_ipc_raw_protocol_t = r;
    result.status = SUCCESS;
    return result;
}
/*
ssize_t_status_t send_ipc_protocol_message_wfdtopass(const char *label, int *uds_fd, const ipc_protocol_t* p, int *fd_to_pass) {
	ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;
    uint8_t* serialized_ipc_data_buffer = NULL;
    size_t serialized_ipc_data_len = 0;

    ssize_t_status_t serialize_result = ipc_serialize(label, p, &serialized_ipc_data_buffer, &serialized_ipc_data_len);
    if (serialize_result.status != SUCCESS) {
        LOG_ERROR("%sError serializing IPC protocol: %d", serialize_result.status);
        if (serialized_ipc_data_buffer) {
            free(serialized_ipc_data_buffer);
        }
        return result;
    }
    size_t total_message_len_to_send = IPC_LENGTH_PREFIX_BYTES + serialized_ipc_data_len;
    uint8_t *final_send_buffer = (uint8_t *)malloc(total_message_len_to_send);
    if (!final_send_buffer) {
        LOG_ERROR("%smalloc failed for final_send_buffer. %s", label, strerror(errno));
        if (serialized_ipc_data_buffer) {
            free(serialized_ipc_data_buffer);
        }
        return result;
    }
    size_t offset = 0;
    uint32_t ipc_protocol_data_len_be = htobe32((uint32_t)serialized_ipc_data_len);
    memcpy(final_send_buffer + offset, &ipc_protocol_data_len_be, IPC_LENGTH_PREFIX_BYTES);
    offset += IPC_LENGTH_PREFIX_BYTES;
    memcpy(final_send_buffer + offset, serialized_ipc_data_buffer, serialized_ipc_data_len);
    LOG_DEBUG("%sTotal pesan untuk dikirim: %zu byte (Prefix %zu + IPC Data %zu).",
            label, total_message_len_to_send, IPC_LENGTH_PREFIX_BYTES, serialized_ipc_data_len);
    struct msghdr msg = {0};
    struct iovec iov[1];
    iov[0].iov_base = final_send_buffer;
    iov[0].iov_len = total_message_len_to_send;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    if (*fd_to_pass != -1) {
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *((int *) CMSG_DATA(cmsg)) = *fd_to_pass;
        LOG_DEBUG("%sMengirim FD: %d\n", label, *fd_to_pass);
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
    }
    result.r_ssize_t = sendmsg(*uds_fd, &msg, 0);
    if (result.r_ssize_t == -1) {
        LOG_ERROR("%ssend_ipc_protocol_message sendmsg. %s", label, strerror(errno));
        free(final_send_buffer);
        if (serialized_ipc_data_buffer) {
            free(serialized_ipc_data_buffer);
        }
        return result;
    } else if (result.r_ssize_t != (ssize_t)total_message_len_to_send) {
        LOG_ERROR("%sendmsg hanya mengirim %zd dari %zu byte!",
                label, result.r_ssize_t, total_message_len_to_send);
        free(final_send_buffer);
        if (serialized_ipc_data_buffer) {
            free(serialized_ipc_data_buffer);
        }
        return result;
    } else {
        LOG_DEBUG("%sBerhasil mengirim %zd byte.\n", label, result.r_ssize_t);
    }
    free(final_send_buffer);
    if (serialized_ipc_data_buffer) {
        free(serialized_ipc_data_buffer);
    }
    result.status = SUCCESS;
    return result;
}

ipc_raw_protocol_t_status_t receive_ipc_raw_protocol_message_wfdrcvd(const char *label, int *uds_fd, int *fd_received) {
    ipc_raw_protocol_t_status_t result;
    result.status = FAILURE;
    result.r_ipc_raw_protocol_t = NULL;
    if (fd_received) {
        *fd_received = -1;
    }
    uint32_t total_ipc_payload_len_be;
    char temp_len_prefix_buf[IPC_LENGTH_PREFIX_BYTES];
    struct msghdr msg_prefix = {0};
    struct iovec iov_prefix[1];
    iov_prefix[0].iov_base = temp_len_prefix_buf;
    iov_prefix[0].iov_len = IPC_LENGTH_PREFIX_BYTES;
    msg_prefix.msg_iov = iov_prefix;
    msg_prefix.msg_iovlen = 1;
    char cmsgbuf_prefix[CMSG_SPACE(sizeof(int))];
    msg_prefix.msg_control = cmsgbuf_prefix;
    msg_prefix.msg_controllen = sizeof(cmsgbuf_prefix);
    LOG_DEBUG("%sTahap 1: Membaca length prefix dan potensi FD (%zu byte).", label, IPC_LENGTH_PREFIX_BYTES);
    ssize_t bytes_read_prefix_and_fd = recvmsg(*uds_fd, &msg_prefix, MSG_WAITALL);
    if (bytes_read_prefix_and_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("%sreceive_and_deserialize_ipc_message recvmsg (length prefix + FD). %s", label, strerror(errno));
        }
        return result;
    }
    if (bytes_read_prefix_and_fd != (ssize_t)IPC_LENGTH_PREFIX_BYTES) {
        LOG_ERROR("%sGagal membaca length prefix sepenuhnya. Diharapkan %zu byte, diterima %zd.",
                label, IPC_LENGTH_PREFIX_BYTES, bytes_read_prefix_and_fd);
        result.status = FAILURE_OOBUF;
        return result;
    }
    struct cmsghdr *cmsg_prefix = CMSG_FIRSTHDR(&msg_prefix);
    if (cmsg_prefix && cmsg_prefix->cmsg_level == SOL_SOCKET && cmsg_prefix->cmsg_type == SCM_RIGHTS && cmsg_prefix->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (fd_received) {
            *fd_received = *((int *) CMSG_DATA(cmsg_prefix));
        }
        LOG_DEBUG("%sFD diterima: %d", label, *fd_received);
    } else {
        LOG_DEBUG("%sTidak ada FD yang diterima dengan length prefix.", label);
    }
    memcpy(&total_ipc_payload_len_be, temp_len_prefix_buf, IPC_LENGTH_PREFIX_BYTES);
    uint32_t total_ipc_payload_len = be32toh(total_ipc_payload_len_be);
    LOG_DEBUG("%sDitemukan panjang payload IPC: %u byte.", label, total_ipc_payload_len);
    if (total_ipc_payload_len == 0) {
        LOG_ERROR("%sPanjang payload IPC adalah 0. Tidak ada data untuk dibaca.", label);
        result.status = FAILURE_BAD_PROTOCOL;
        return result;
    }
    uint8_t *full_ipc_payload_buffer = (uint8_t *)malloc(total_ipc_payload_len);
    if (!full_ipc_payload_buffer) {
        LOG_ERROR("%sreceive_and_deserialize_ipc_message: malloc failed for full_ipc_payload_buffer. %s", label, strerror(errno));
        result.status = FAILURE_NOMEM;
        return result;
    }
    struct msghdr msg_payload = {0};
    struct iovec iov_payload[1];
    iov_payload[0].iov_base = full_ipc_payload_buffer;
    iov_payload[0].iov_len = total_ipc_payload_len;
    msg_payload.msg_iov = iov_payload;
    msg_payload.msg_iovlen = 1;
    msg_payload.msg_control = NULL;
    msg_payload.msg_controllen = 0;
    LOG_DEBUG("%sTahap 2: Membaca %u byte payload IPC.", label, total_ipc_payload_len);
    ssize_t bytes_read_payload = recvmsg(*uds_fd, &msg_payload, MSG_WAITALL);
    if (bytes_read_payload == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("%sreceive_and_deserialize_ipc_message recvmsg (payload). %s", label, strerror(errno));
        }
        free(full_ipc_payload_buffer);
        result.status = FAILURE;
        return result;
    } else if (bytes_read_payload < (ssize_t)(IPC_VERSION_BYTES + sizeof(uint8_t))) {
        LOG_ERROR("%sreceive_ipc_raw_protocol_message received 0 bytes (unexpected for IPC).", label);
        free(full_ipc_payload_buffer);
        result.status = FAILURE_OOBUF;
        return result;
    } else if (bytes_read_payload != (ssize_t)total_ipc_payload_len) {
        LOG_ERROR("%sPayload IPC tidak lengkap. Diharapkan %u byte, diterima %zd.", label, total_ipc_payload_len, bytes_read_payload);
        free(full_ipc_payload_buffer);
        result.status = FAILURE_OOBUF;
        return result;
    }
    ipc_raw_protocol_t* r = (ipc_raw_protocol_t*)calloc(1, sizeof(ipc_raw_protocol_t));
    if (!r) {
        LOG_ERROR("%sFailed to allocate ipc_raw_protocol_t. %s", label, strerror(errno));
        free(full_ipc_payload_buffer);
        result.status = FAILURE_NOMEM;
        return result;
    }
    uint8_t *b = (uint8_t*) calloc(1, bytes_read_payload);
    if (!b) {
        LOG_ERROR("%sFailed to allocate ipc_raw_protocol_t buffer. %s", label, strerror(errno));
        free(full_ipc_payload_buffer);
        CLOSE_IPC_RAW_PROTOCOL(&r);
        result.status = FAILURE_NOMEM;
        return result;
    }
    memcpy(b, full_ipc_payload_buffer, bytes_read_payload);
    free(full_ipc_payload_buffer);
    r->recv_buffer = b;
    r->n = (uint32_t)bytes_read_payload;
    memcpy(r->version, b, IPC_VERSION_BYTES);
    memcpy((uint8_t *)&r->type, b + IPC_VERSION_BYTES, sizeof(uint8_t));
    result.r_ipc_raw_protocol_t = r;
    result.status = SUCCESS;
    return result;
}
*/
