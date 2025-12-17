#ifndef IPC_H
#define IPC_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/uio.h>

#ifdef __NetBSD__
    #include <sys/endian.h>
    #include <sys/errno.h>
#else
    #include <endian.h>
#endif

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "ipc/master_worker_info.h"
#include "ipc/worker_master_task_info.h"
#include "ipc/worker_master_heartbeat.h"
#include "ipc/master_cow_connect.h"
#include "ipc/udp_data.h"
#include "ipc/udp_data_ack.h"
#include "ipc/worker_master_hello1.h"
#include "ipc/worker_master_hello2.h"
#include "ipc/master_worker_hello1_ack.h"
#include "ipc/master_worker_hello2_ack.h"
#include "constants.h"
#include "pqc.h"
#include "xorshiro128plus.h"
#include "oritlsf.h"

static inline size_t calculate_ipc_payload_fixed_size(const char *label, ipc_protocol_type_t type, bool plus_header) {
	size_t payload_fixed_size = 0;
    switch (type) {
        case IPC_MASTER_WORKER_INFO: {
            payload_fixed_size = sizeof(uint8_t);
            break;
        }
        case IPC_WORKER_MASTER_TASK_INFO: {
            payload_fixed_size = sizeof(uint8_t) + sizeof(uint8_t);
            break;
        }
        case IPC_WORKER_MASTER_HEARTBEAT: {
            payload_fixed_size = DOUBLE_ARRAY_SIZE;
            break;
        }
        case IPC_MASTER_COW_CONNECT: {
            payload_fixed_size = sizeof(uint8_t) + sizeof(uint64_t) + SOCKADDR_IN6_SIZE;
            break;
        }
        case IPC_UDP_DATA: {
            payload_fixed_size = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + SOCKADDR_IN6_SIZE + sizeof(uint16_t);
            break;
        }
        case IPC_UDP_DATA_ACK: {
            payload_fixed_size = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t);
            break;
        }
        case IPC_WORKER_MASTER_HELLO1: {
            payload_fixed_size = KEM_PUBLICKEY_BYTES;
            break;
        }
        case IPC_WORKER_MASTER_HELLO2: {
            payload_fixed_size = AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES;
            break;
        }
        case IPC_MASTER_WORKER_HELLO1_ACK: {
            payload_fixed_size = AES_NONCE_BYTES + KEM_CIPHERTEXT_BYTES;
            break;
        }
        case IPC_MASTER_WORKER_HELLO2_ACK: {
            payload_fixed_size = sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES;
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
           IPC_VERSION_BYTES + 
           sizeof(uint8_t) + 
           sizeof(uint8_t) + 
           sizeof(uint8_t) + 
           payload_fixed_size;
}

static inline size_t_status_t calculate_ipc_payload_size(const char *label, const ipc_protocol_t* p) {
	size_t_status_t result;
    result.r_size_t = 0;
    result.status = FAILURE;
    size_t payload_fixed_size = calculate_ipc_payload_fixed_size(label, p->type, true);
    if (payload_fixed_size == 0) {
        LOG_ERROR("%sInvalid Ipc Payload Size.", label);
        result.status = FAILURE;
        return result;
    }
    size_t payload_dynamic_size = 0;
    switch (p->type) {
		case IPC_UDP_DATA: {
            if (!p->payload.ipc_udp_data) {
                LOG_ERROR("%sIPC_UDP_DATA payload is NULL.", label);
                result.status = FAILURE;
                return result;
            }
            payload_dynamic_size = p->payload.ipc_udp_data->len;
            break;
        }
        default:
            payload_dynamic_size = 0;
    }
    result.r_size_t = payload_fixed_size + payload_dynamic_size;
    result.status = SUCCESS;
    return result;
}

static inline ssize_t_status_t ipc_serialize(const char *label, oritlsf_pool_t *pool, uint8_t* key_aes, uint8_t* key_mac, uint8_t* nonce, uint32_t *ctr, const ipc_protocol_t *p, uint8_t **ptr_buffer, size_t buffer_size) {
    ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;
    if (!p || !ptr_buffer) {
        return result;
    }
    uint8_t *current_buffer = *ptr_buffer;
    size_t offset = 0;
//----------------------------------------------------------------------
// Mac
//----------------------------------------------------------------------    
    if (CHECK_BUFFER_BOUNDS(offset, AES_TAG_BYTES, buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memset(current_buffer + offset, 0, AES_TAG_BYTES);
    offset += AES_TAG_BYTES;
//----------------------------------------------------------------------
// Counter
//----------------------------------------------------------------------    
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint32_t), buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    uint32_t pctr = *(uint32_t *)ctr;
    uint32_t ctr_be = htobe32(pctr);
    memcpy(current_buffer + offset, &ctr_be, sizeof(uint32_t));
    offset += sizeof(uint32_t);
//----------------------------------------------------------------------    
    if (CHECK_BUFFER_BOUNDS(offset, IPC_VERSION_BYTES, buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, p->version, IPC_VERSION_BYTES);
    offset += IPC_VERSION_BYTES;
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, (uint8_t *)&p->type, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, (uint8_t *)&p->wot, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint8_t), buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, &p->index, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    status_t result_pyld = FAILURE;
    switch (p->type) {
        case IPC_MASTER_WORKER_INFO:
            result_pyld = ipc_serialize_master_worker_info(label, p->payload.ipc_master_worker_info, current_buffer, buffer_size, &offset);
            break;
        case IPC_WORKER_MASTER_TASK_INFO:
            result_pyld = ipc_serialize_worker_master_task_info(label, p->payload.ipc_worker_master_task_info, current_buffer, buffer_size, &offset);
            break;
        case IPC_WORKER_MASTER_HEARTBEAT:
            result_pyld = ipc_serialize_worker_master_heartbeat(label, p->payload.ipc_worker_master_heartbeat, current_buffer, buffer_size, &offset);
            break;
        case IPC_MASTER_COW_CONNECT:
            result_pyld = ipc_serialize_master_cow_connect(label, p->payload.ipc_master_cow_connect, current_buffer, buffer_size, &offset);
            break;
        case IPC_UDP_DATA:
            result_pyld = ipc_serialize_udp_data(label, p->payload.ipc_udp_data, current_buffer, buffer_size, &offset);
            break;
        case IPC_UDP_DATA_ACK:
            result_pyld = ipc_serialize_udp_data_ack(label, p->payload.ipc_udp_data_ack, current_buffer, buffer_size, &offset);
            break;
        case IPC_WORKER_MASTER_HELLO1:
            result_pyld = ipc_serialize_worker_master_hello1(label, p->payload.ipc_worker_master_hello1, current_buffer, buffer_size, &offset);
            break;
        case IPC_WORKER_MASTER_HELLO2:
            result_pyld = ipc_serialize_worker_master_hello2(label, p->payload.ipc_worker_master_hello2, current_buffer, buffer_size, &offset);
            break;
        case IPC_MASTER_WORKER_HELLO1_ACK:
            result_pyld = ipc_serialize_master_worker_hello1_ack(label, p->payload.ipc_master_worker_hello1_ack, current_buffer, buffer_size, &offset);
            break;
        case IPC_MASTER_WORKER_HELLO2_ACK:
            result_pyld = ipc_serialize_master_worker_hello2_ack(label, p->payload.ipc_master_worker_hello2_ack, current_buffer, buffer_size, &offset);
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
    uint8_t key0[HASHES_BYTES];
    memset(key0, 0, HASHES_BYTES);
    if (memcmp(
            key_aes, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        const size_t data_offset = AES_TAG_BYTES +
                                   sizeof(uint32_t) +
                                   IPC_VERSION_BYTES +
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t) +
                                   sizeof(uint8_t);
        const size_t data_len = offset - data_offset;
        uint8_t *data = current_buffer + data_offset;
        uint8_t *encrypted_data = current_buffer + data_offset;
        if (encrypt_decrypt_256(
                label,
                pool,
                key_aes,
                nonce,
                &pctr,
                data,
                encrypted_data,
                data_len
            ) != SUCCESS
        )
        {
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
        if (pctr == *(uint32_t *)ctr) {
            increment_ctr(ctr, nonce);
        }
    }
    result.r_ssize_t = (ssize_t)offset;
    result.status = SUCCESS;
    return result;
}

static inline ipc_protocol_t_status_t ipc_deserialize(const char *label, oritlsf_pool_t *pool, uint8_t* key_aes, uint8_t* nonce, uint32_t *ctr, uint8_t* buffer, size_t len) {
    ipc_protocol_t_status_t result;
    result.r_ipc_protocol_t = NULL;
    result.status = FAILURE;
    const size_t data_offset = AES_TAG_BYTES + 
                               sizeof(uint32_t) + 
                               IPC_VERSION_BYTES + 
                               sizeof(uint8_t) + 
                               sizeof(uint8_t) + 
                               sizeof(uint8_t);
    if (!buffer || len < data_offset) {
        LOG_ERROR("%sBuffer terlalu kecil untuk Version dan Type. Len: %zu", label, len);
        result.status = FAILURE_OOBUF;
        return result;
    }
    ipc_protocol_t* p = (ipc_protocol_t*)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_protocol_t));
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
    p->ctr = be32toh(data_ctr_be);
    current_buffer_offset += sizeof(uint32_t);
    memcpy(p->version, buffer + current_buffer_offset, IPC_VERSION_BYTES);
    current_buffer_offset += IPC_VERSION_BYTES;
    memcpy((uint8_t *)&p->type, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    memcpy((uint8_t *)&p->wot, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    memcpy(&p->index, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    uint8_t key0[HASHES_BYTES];
    memset(key0, 0, HASHES_BYTES);
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
                pool,
                key_aes,
                nonce,
                &p->ctr,
                data,
                decrypted_data,
                data_len
            ) != SUCCESS
        )
        {
            CLOSE_IPC_PROTOCOL(pool, &p);
            result.status = FAILURE;
            return result;
        }
    }
//----------------------------------------------------------------------
    size_t fixed_payload_size = calculate_ipc_payload_fixed_size(label, p->type, false);
    LOG_DEBUG("%sDeserializing type 0x%02x. Current offset: %zu", label, p->type, current_buffer_offset);
    status_t result_pyld = FAILURE;
    switch (p->type) {
        case IPC_MASTER_WORKER_INFO: {
            if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_MASTER_WORKER_INFO fixed header.", label);
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_master_worker_info_t *payload = (ipc_master_worker_info_t*)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_master_worker_info_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_master_worker_info_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_master_worker_info = payload;
            result_pyld = ipc_deserialize_master_worker_info(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_WORKER_MASTER_TASK_INFO: {
            if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_WORKER_MASTER_TASK_INFO fixed header.", label);
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_worker_master_task_info_t *payload = (ipc_worker_master_task_info_t*)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_worker_master_task_info_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_worker_master_task_info_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_worker_master_task_info = payload;
            result_pyld = ipc_deserialize_worker_master_task_info(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_WORKER_MASTER_HEARTBEAT: {
            if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_WORKER_MASTER_HEARTBEAT fixed header.", label);
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_worker_master_heartbeat_t *payload = (ipc_worker_master_heartbeat_t*)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_worker_master_heartbeat_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_worker_master_heartbeat_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_worker_master_heartbeat = payload;
            result_pyld = ipc_deserialize_worker_master_heartbeat(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_MASTER_COW_CONNECT: {
            if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_MASTER_COW_CONNECT fixed header.", label);
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_master_cow_connect_t *payload = (ipc_master_cow_connect_t*)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_master_cow_connect_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_master_cow_connect_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_master_cow_connect = payload;
            result_pyld = ipc_deserialize_master_cow_connect(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_UDP_DATA: {
            if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_UDP_DATA fixed header.", label);
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            size_t fixed_header_blen_size = fixed_payload_size - sizeof(uint16_t);
            uint16_t actual_data_len_be;
            memcpy(&actual_data_len_be, buffer + current_buffer_offset + fixed_header_blen_size, sizeof(uint16_t));
            uint16_t actual_data_len = be16toh(actual_data_len_be);
            ipc_udp_data_t *payload = (ipc_udp_data_t*)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_udp_data_t) + actual_data_len);
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_udp_data_t with FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_udp_data = payload;
            result_pyld = ipc_deserialize_udp_data(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_UDP_DATA_ACK: {
            if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_UDP_DATA_ACK fixed header.", label);
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_udp_data_ack_t *payload = (ipc_udp_data_ack_t*)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_udp_data_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_udp_data_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_udp_data_ack = payload;
            result_pyld = ipc_deserialize_udp_data_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_WORKER_MASTER_HELLO1: {
            if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_WORKER_MASTER_HELLO1 fixed header.", label);
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_worker_master_hello1_t *payload = (ipc_worker_master_hello1_t*)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_worker_master_hello1_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_worker_master_hello1_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_worker_master_hello1 = payload;
            result_pyld = ipc_deserialize_worker_master_hello1(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_WORKER_MASTER_HELLO2: {
            if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_WORKER_MASTER_HELLO1 fixed header.", label);
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_worker_master_hello2_t *payload = (ipc_worker_master_hello2_t*)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_worker_master_hello2_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_worker_master_hello2_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_worker_master_hello2 = payload;
            result_pyld = ipc_deserialize_worker_master_hello2(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_MASTER_WORKER_HELLO1_ACK: {
            if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_MASTER_WORKER_HELLO1_ACK fixed header.", label);
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_master_worker_hello1_ack_t *payload = (ipc_master_worker_hello1_ack_t*)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_master_worker_hello1_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_master_worker_hello1_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_master_worker_hello1_ack = payload;
            result_pyld = ipc_deserialize_master_worker_hello1_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_MASTER_WORKER_HELLO2_ACK: {
            if (current_buffer_offset + fixed_payload_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_MASTER_WORKER_HELLO2_ACK fixed header.", label);
                CLOSE_IPC_PROTOCOL(pool, &p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_master_worker_hello2_ack_t *payload = (ipc_master_worker_hello2_ack_t*)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_master_worker_hello2_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_master_worker_hello2_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(pool, &p);
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
            CLOSE_IPC_PROTOCOL(pool, &p);
            return result;
    }
    if (result_pyld != SUCCESS) {
        LOG_ERROR("%sPayload deserialization failed with status %d.", label, result_pyld);
        CLOSE_IPC_PROTOCOL(pool, &p);
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
        if (p->ctr == *(uint32_t *)ctr) {
            increment_ctr(ctr, nonce);
        }
    }
    result.r_ipc_protocol_t = p;
    result.status = SUCCESS;
    LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
    return result;
}

static inline et_result_t write_ipc_protocol_message(
    oritlsf_pool_t *oritlsf_pool, 
    int *uds_fd,
    et_buffer_t *buffer, 
    size_t len,
    uint8_t *data,
    bool on_out_ready
)
{
    et_result_t wetr;
    wetr.failure = false;
    wetr.partial = true;
    wetr.status = FAILURE;
    if (on_out_ready && buffer->out_size_tb == 0) {
        wetr.failure = false;
        wetr.partial = false;
        wetr.status = SUCCESS;
        return wetr;
    }
    if (!on_out_ready) {
        if (buffer->out_size_tb == 0) {
            buffer->out_size_tb = len;
            buffer->buffer_out = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, 
                oritlsf_pool,
                buffer->out_size_tb,
                sizeof(uint8_t)
            );
            if (!buffer->buffer_out) {
                buffer->read_step = 0;
                buffer->out_size_tb = 0;
                buffer->out_size_c = 0;
                wetr.failure = true;
                wetr.partial = true;
                wetr.status = FAILURE_NOMEM;
                return wetr;
            }
            memcpy(buffer->buffer_out, data, len);
        } else {
            buffer->out_size_tb += len;
            buffer->buffer_out = (uint8_t *)oritlsf_realloc(__FILE__, __LINE__, 
                oritlsf_pool,
                buffer->buffer_out,
                buffer->out_size_tb * sizeof(uint8_t)
            );
            if (!buffer->buffer_out) {
                buffer->read_step = 0;
                buffer->out_size_tb = 0;
                buffer->out_size_c = 0;
                wetr.failure = true;
                wetr.partial = true;
                wetr.status = FAILURE_NOMEM;
                return wetr;
            }
            memcpy(buffer->buffer_out + len, data, len);
        }
    }
    while (true) {
        struct msghdr msg = {0};
        struct iovec iov[1];
        iov[0].iov_base = buffer->buffer_out + buffer->out_size_c;
        iov[0].iov_len = buffer->out_size_tb - buffer->out_size_c;
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        ssize_t wsize = sendmsg(*uds_fd, &msg, 0);
        if (wsize < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (buffer->out_size_tb == buffer->out_size_c) {
                    wetr.failure = false;
                    wetr.partial = false;
                    wetr.status = SUCCESS_EAGNEWBLK;
                } else {
                    wetr.failure = false;
                    wetr.partial = true;
                    wetr.status = FAILURE_EAGNEWBLK;
                }
                break;
            } else {
                oritlsf_free(oritlsf_pool, (void **)&buffer->buffer_out);
                buffer->read_step = 0;
                buffer->out_size_tb = 0;
                buffer->out_size_c = 0;
                wetr.failure = true;
                wetr.partial = true;
                wetr.status = FAILURE;
                break;
            }
        } 
        if (wsize > 0) {
            buffer->out_size_c += wsize;
        }
        if (wsize == 0) {
            oritlsf_free(oritlsf_pool, (void **)&buffer->buffer_out);
            buffer->read_step = 0;
            buffer->out_size_tb = 0;
            buffer->out_size_c = 0;
            wetr.failure = true;
            wetr.partial = true;
            wetr.status = FAILURE;
            break;
        }
        if (buffer->out_size_tb == buffer->out_size_c) {
            wetr.failure = false;
            wetr.partial = false;
            wetr.status = SUCCESS;
            break;
        }
    }
    return wetr;
}

static inline ssize_t_status_t send_ipc_protocol_message(const char *label, oritlsf_pool_t *pool, uint8_t* key_aes, uint8_t* key_mac, uint8_t* nonce, uint32_t *ctr, int *uds_fd, et_buffer_t *buffer, const ipc_protocol_t* p) {
	ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;
    size_t_status_t psize = calculate_ipc_payload_size(label, p);
    if (psize.status != SUCCESS) {
		return result;
	}
    size_t serialized_ipc_data_len = psize.r_size_t;
    if (serialized_ipc_data_len > IPC_MAX_PACKET_SIZE) {
        LOG_ERROR("%sipc_serialize error. Serialized_ipc_data_len: %d, IPC_MAX_PACKET_SIZE %d.", label, serialized_ipc_data_len, IPC_MAX_PACKET_SIZE);
        return result;
    }
    if (serialized_ipc_data_len == 0) {
        LOG_ERROR("%sCalculated required size is 0.", label);
        return result;
    }
    uint8_t *serialized_ipc_data_buffer = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, serialized_ipc_data_len);
    if (!serialized_ipc_data_buffer) {
		result.status = FAILURE_NOMEM;
		return result;
	}
    ssize_t_status_t serialize_result = ipc_serialize(label, pool, key_aes, key_mac, nonce, ctr, p, &serialized_ipc_data_buffer, serialized_ipc_data_len);
    if (serialize_result.status != SUCCESS) {
        LOG_ERROR("%sError serializing IPC protocol: %d", serialize_result.status, p->type);
        oritlsf_free(pool, (void **)&serialized_ipc_data_buffer);
        return result;
    }
    size_t total_message_len_to_send = IPC_LENGTH_PREFIX_BYTES + serialized_ipc_data_len;
    uint8_t *final_send_buffer = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, total_message_len_to_send);
    if (!final_send_buffer) {
        LOG_ERROR("%smalloc failed for final_send_buffer. %s", label, strerror(errno));
        oritlsf_free(pool, (void **)&serialized_ipc_data_buffer);
        return result;
    }
    size_t offset = 0;
    uint32_t ipc_protocol_data_len_be = htobe32((uint32_t)serialized_ipc_data_len);
    memcpy(final_send_buffer + offset, &ipc_protocol_data_len_be, IPC_LENGTH_PREFIX_BYTES);
    offset += IPC_LENGTH_PREFIX_BYTES;
    memcpy(final_send_buffer + offset, serialized_ipc_data_buffer, serialized_ipc_data_len);
    LOG_DEBUG("%sTotal pesan untuk dikirim: %zu byte (Prefix %zu + IPC Data %zu).", label, total_message_len_to_send, IPC_LENGTH_PREFIX_BYTES, serialized_ipc_data_len);
    et_result_t wetr = write_ipc_protocol_message(
        pool, 
        uds_fd,
        buffer, 
        total_message_len_to_send,
        final_send_buffer,
        false
    );
    oritlsf_free(pool, (void **)&final_send_buffer);
    oritlsf_free(pool, (void **)&serialized_ipc_data_buffer);
    if (!wetr.failure) {
        if (!wetr.partial) {
            oritlsf_free(pool, (void **)&buffer->buffer_out);
            buffer->out_size_tb = 0;
            buffer->out_size_c = 0;
        }
    }
    result.r_ssize_t = buffer->out_size_c;
    result.status = SUCCESS;
    return result;
}

static inline status_t ipc_check_mac(const char *label, uint8_t* key_mac, ipc_raw_protocol_t *r) {
    uint8_t key0[HASHES_BYTES];
    memset(key0, 0, HASHES_BYTES);
    if (memcmp(
            key_mac, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        uint8_t *data_4mac = r->recv_buffer;
        const size_t data_offset = AES_TAG_BYTES;
        const size_t data_len = r->n - AES_TAG_BYTES;
        uint8_t *data = r->recv_buffer + data_offset;
        if (compare_mac(
                key_mac,
                data,
                data_len,
                data_4mac
            ) != SUCCESS
        )
        {
            LOG_ERROR("%sIpc Mac mismatch!", label);
            return FAILURE_MACMSMTCH;
        }
    }
    return SUCCESS;
}

static inline status_t ipc_check_ctr(const char *label, uint8_t* key_aes, uint32_t* ctr, ipc_raw_protocol_t *r) {
    uint8_t key0[HASHES_BYTES];
    memset(key0, 0, HASHES_BYTES);
    if (memcmp(
            key_aes, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        if (r->ctr != *(uint32_t *)ctr) {
            LOG_ERROR("%sIpc Counter not match. Protocol %d, data_ctr: %u, *ctr: %u", label, r->type, r->ctr, *(uint32_t *)ctr);
            return FAILURE_CTRMSMTCH;
        }
    }
    return SUCCESS;
}

static inline status_t ipc_read_header(const char *label, uint8_t* key_mac, uint8_t* nonce, ipc_raw_protocol_t *r) {
    size_t current_offset = 0;
    size_t total_buffer_len = (size_t)r->n;
    uint8_t *cursor = r->recv_buffer + current_offset;
    uint8_t key0[HASHES_BYTES];
    memset(key0, 0, HASHES_BYTES);
    if (memcmp(
            key_mac, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        
    }
    if (current_offset + AES_TAG_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading mac.", label);
        return FAILURE_OOBUF;
    }
    memcpy(r->mac, cursor, AES_TAG_BYTES);
    cursor += AES_TAG_BYTES;
    current_offset += AES_TAG_BYTES;
    if (current_offset + sizeof(uint32_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading ctr.", label);
        return FAILURE_OOBUF;
    }
    uint32_t ctr_be;
    memcpy(&ctr_be, cursor, sizeof(uint32_t));
    r->ctr = be32toh(ctr_be);
    cursor += sizeof(uint32_t);
    current_offset += sizeof(uint32_t);
    if (current_offset + IPC_VERSION_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading version.", label);
        return FAILURE_OOBUF;
    }
    memcpy(r->version, cursor, IPC_VERSION_BYTES);
    cursor += IPC_VERSION_BYTES;
    current_offset += IPC_VERSION_BYTES;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading type.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&r->type, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading wot.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&r->wot, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->index, cursor, sizeof(uint8_t));
    return SUCCESS;
}

static inline status_t ipc_read_cleartext_header(const char *label, ipc_raw_protocol_t *r) {
    size_t current_offset = 0;
    size_t total_buffer_len = (size_t)r->n;
    uint8_t *cursor = r->recv_buffer + current_offset;
    if (current_offset + AES_TAG_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading mac.", label);
        return FAILURE_OOBUF;
    }
    cursor += AES_TAG_BYTES;
    current_offset += AES_TAG_BYTES;
    if (current_offset + sizeof(uint32_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading ctr.", label);
        return FAILURE_OOBUF;
    }
    cursor += sizeof(uint32_t);
    current_offset += sizeof(uint32_t);
    if (current_offset + IPC_VERSION_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading version.", label);
        return FAILURE_OOBUF;
    }
    cursor += IPC_VERSION_BYTES;
    current_offset += IPC_VERSION_BYTES;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading type.", label);
        return FAILURE_OOBUF;
    }
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading wot.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&r->wot, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->index, cursor, sizeof(uint8_t));
    return SUCCESS;
}

static inline et_result_t receive_ipc_raw_protocol_message(oritlsf_pool_t *pool, int *uds_fd, et_buffer_t *buffer) {
    et_result_t retr;
    retr.failure = false;
    retr.partial = true;
    retr.status = FAILURE;
    if (buffer->read_step == 0) {
        if (buffer->in_size_tb == 0) {
            buffer->in_size_tb = IPC_LENGTH_PREFIX_BYTES;
            buffer->buffer_in = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, 
                pool,
                buffer->in_size_tb,
                sizeof(uint8_t)
            );
            if (!buffer->buffer_in) {
                buffer->read_step = 0;
                buffer->in_size_tb = 0;
                buffer->in_size_c = 0;
                retr.failure = true;
                retr.partial = true;
                retr.status = FAILURE_NOMEM;
                return retr;
            }
        }
        while (true) {
            struct msghdr msg_prefix = {0};
            struct iovec iov_prefix[1];
            iov_prefix[0].iov_base = buffer->buffer_in + buffer->in_size_c;
            iov_prefix[0].iov_len = buffer->in_size_tb - buffer->in_size_c;
            msg_prefix.msg_iov = iov_prefix;
            msg_prefix.msg_iovlen = 1;
            msg_prefix.msg_control = NULL;
            msg_prefix.msg_controllen = 0;
            ssize_t rsize = recvmsg(*uds_fd, &msg_prefix, 0);
            if (rsize < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (buffer->in_size_tb == buffer->in_size_c) {
                        retr.failure = false;
                        retr.partial = false;
                        retr.status = SUCCESS_EAGNEWBLK;
                    } else {
                        retr.failure = false;
                        retr.partial = true;
                        retr.status = FAILURE_EAGNEWBLK;
                    }
                    break;
                } else {
                    oritlsf_free(pool, (void **)&buffer->buffer_in);
                    buffer->read_step = 0;
                    buffer->in_size_tb = 0;
                    buffer->in_size_c = 0;
                    retr.failure = true;
                    retr.partial = true;
                    retr.status = FAILURE;
                    break;
                }
            } 
            if (rsize > 0) {
                buffer->in_size_c += rsize;
            }
            if (rsize == 0) {
                oritlsf_free(pool, (void **)&buffer->buffer_in);
                buffer->read_step = 0;
                buffer->in_size_tb = 0;
                buffer->in_size_c = 0;
                retr.failure = true;
                retr.partial = true;
                retr.status = FAILURE;
                break;
            }
            if (buffer->in_size_tb == buffer->in_size_c) {
                retr.failure = false;
                retr.partial = false;
                retr.status = SUCCESS;
                break;
            }
        }
        if (!retr.failure) {
            if (!retr.partial) {
                uint32_t total_ipc_payload_len_be;
                memcpy(&total_ipc_payload_len_be, buffer->buffer_in, buffer->in_size_tb);
                uint32_t total_ipc_payload_len = be32toh(total_ipc_payload_len_be);                
                const size_t min_size = AES_TAG_BYTES +
                                        sizeof(uint32_t) +
                                        IPC_VERSION_BYTES +
                                        sizeof(uint8_t) +
                                        sizeof(uint8_t) +
                                        sizeof(uint8_t);
                if (total_ipc_payload_len < (uint32_t)min_size) {
                    oritlsf_free(pool, (void **)&buffer->buffer_in);
                    buffer->read_step = 0;
                    buffer->in_size_tb = 0;
                    buffer->in_size_c = 0;
                    retr.failure = true;
                    retr.partial = true;
                    retr.status = FAILURE;
                    return retr;
                } else if (total_ipc_payload_len > (uint32_t)IPC_MAX_PACKET_SIZE) {
                    oritlsf_free(pool, (void **)&buffer->buffer_in);
                    buffer->read_step = 0;
                    buffer->in_size_tb = 0;
                    buffer->in_size_c = 0;
                    retr.failure = true;
                    retr.partial = true;
                    retr.status = FAILURE;
                    return retr;
                }
                oritlsf_free(pool, (void **)&buffer->buffer_in);
                buffer->read_step = 1;
                buffer->in_size_tb = 0;
                buffer->in_size_c = 0;
                buffer->in_size_tb = (ssize_t)total_ipc_payload_len;
                buffer->buffer_in = (uint8_t *)oritlsf_calloc(__FILE__, __LINE__, 
                    pool,
                    buffer->in_size_tb,
                    sizeof(uint8_t)
                );
                if (!buffer->buffer_in) {
                    buffer->read_step = 0;
                    buffer->in_size_tb = 0;
                    buffer->in_size_c = 0;
                    retr.failure = true;
                    retr.partial = true;
                    retr.status = FAILURE_NOMEM;
                    return retr;
                }
            }
        }
    }
    if (buffer->read_step == 1) {
        if (buffer->in_size_tb == 0) {
            oritlsf_free(pool, (void **)&buffer->buffer_in);
            buffer->read_step = 0;
            buffer->in_size_tb = 0;
            buffer->in_size_c = 0;
            retr.failure = true;
            retr.partial = true;
            retr.status = FAILURE;
            return retr;
        }
        while (true) {
            struct msghdr msg_payload = {0};
            struct iovec iov_payload[1];
            iov_payload[0].iov_base = buffer->buffer_in + buffer->in_size_c;
            iov_payload[0].iov_len = buffer->in_size_tb - buffer->in_size_c;
            msg_payload.msg_iov = iov_payload;
            msg_payload.msg_iovlen = 1;
            msg_payload.msg_control = NULL;
            msg_payload.msg_controllen = 0;
            ssize_t rsize = recvmsg(*uds_fd, &msg_payload, 0);
            if (rsize < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (buffer->in_size_tb == buffer->in_size_c) {
                        retr.failure = false;
                        retr.partial = false;
                        retr.status = SUCCESS_EAGNEWBLK;
                    } else {
                        retr.failure = false;
                        retr.partial = true;
                        retr.status = FAILURE_EAGNEWBLK;
                    }
                    break;
                } else {
                    oritlsf_free(pool, (void **)&buffer->buffer_in);
                    buffer->read_step = 0;
                    buffer->in_size_tb = 0;
                    buffer->in_size_c = 0;
                    retr.failure = true;
                    retr.partial = true;
                    retr.status = FAILURE;
                    break;
                }
            } 
            if (rsize > 0) {
                buffer->in_size_c += rsize;
            }
            if (rsize == 0) {
                oritlsf_free(pool, (void **)&buffer->buffer_in);
                buffer->read_step = 0;
                buffer->in_size_tb = 0;
                buffer->in_size_c = 0;
                retr.failure = true;
                retr.partial = true;
                retr.status = FAILURE;
                break;
            }
            if (buffer->in_size_tb == buffer->in_size_c) {
                retr.failure = false;
                retr.partial = false;
                retr.status = SUCCESS;
                break;
            }
        }
    }
    return retr;
}

static inline status_t ipc_add_tail_protocol_queue_internal(
    ipc_protocol_queue_t **head,
    ipc_protocol_queue_t **tail,
    ipc_protocol_queue_t *new_queue
)
{
    new_queue->next = NULL;
    new_queue->prev = *tail;
    if (*tail) {
        (*tail)->next = new_queue;
    } else {
        *head = new_queue;
    }
    *tail = new_queue;
    return SUCCESS;
}

static inline status_t ipc_add_tail_protocol_queue(
    const char *label,
    oritlsf_pool_t *pool, 
    worker_type_t wot,
    uint8_t index,
    int *uds_fd,
    et_buffer_t *buffer,
    ipc_protocol_t *p,
    ipc_protocol_queue_t **head,
    ipc_protocol_queue_t **tail
)
{
    ipc_protocol_queue_t *new_queue = (ipc_protocol_queue_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_protocol_queue_t));
    if (!new_queue) {
        LOG_ERROR("%sFailed to allocate ipc_protocol_queue_t buffer. %s", label, strerror(errno));
        return FAILURE;
    }
    new_queue->wot = wot;
    new_queue->index = index;
    new_queue->uds_fd = uds_fd;
    new_queue->buffer = buffer;
    new_queue->p = p;
    return ipc_add_tail_protocol_queue_internal(head, tail, new_queue);
}

static inline status_t ipc_add_head_protocol_queue_internal(
    ipc_protocol_queue_t **head,
    ipc_protocol_queue_t **tail,
    ipc_protocol_queue_t *new_queue
)
{
    new_queue->prev = NULL;
    new_queue->next = *head;
    if (*head) {
        (*head)->prev = new_queue;
    } else {
        *tail = new_queue;
    }
    *head = new_queue;
    return SUCCESS;
}

static inline status_t ipc_add_head_protocol_queue(
    const char *label,
    oritlsf_pool_t *pool, 
    worker_type_t wot,
    uint8_t index,
    int *uds_fd,
    et_buffer_t *buffer,
    ipc_protocol_t *p,
    ipc_protocol_queue_t **head,
    ipc_protocol_queue_t **tail
)
{
    ipc_protocol_queue_t *new_queue = (ipc_protocol_queue_t *)oritlsf_calloc(__FILE__, __LINE__, pool, 1, sizeof(ipc_protocol_queue_t));
    if (!new_queue) {
        LOG_ERROR("%sFailed to allocate ipc_protocol_queue_t buffer. %s", label, strerror(errno));
        return FAILURE;
    }
    new_queue->wot = wot;
    new_queue->index = index;
    new_queue->uds_fd = uds_fd;
    new_queue->buffer = buffer;
    new_queue->p = p;
    return ipc_add_head_protocol_queue_internal(head, tail, new_queue);
}

static inline status_t ipc_insert_before_protocol_queue(
    ipc_protocol_queue_t **head,
    ipc_protocol_queue_t **tail,
    ipc_protocol_queue_t *pos,
    ipc_protocol_queue_t *new_queue
)
{
    if (!pos) {
        ipc_add_tail_protocol_queue_internal(head, tail, new_queue);
        return SUCCESS;
    }
    new_queue->next = pos;
    new_queue->prev = pos->prev;
    if (pos->prev) {
        pos->prev->next = new_queue;
    } else {
        *head = new_queue;
    }
    pos->prev = new_queue;
    return SUCCESS;
}

static inline status_t ipc_insert_after_protocol_queue(
    ipc_protocol_queue_t **head,
    ipc_protocol_queue_t **tail,
    ipc_protocol_queue_t *pos,
    ipc_protocol_queue_t *new_queue
)
{
    if (!pos) {
        ipc_add_head_protocol_queue_internal(head, tail, new_queue);
        return SUCCESS;
    }
    new_queue->prev = pos;
    new_queue->next = pos->next;
    if (pos->next) {
        pos->next->prev = new_queue;
    } else {
        *tail = new_queue;
    }
    pos->next = new_queue;
    return SUCCESS;
}

static inline void ipc_remove_protocol_queue(
	oritlsf_pool_t *pool, 
    ipc_protocol_queue_t **head,
    ipc_protocol_queue_t **tail,
    ipc_protocol_queue_t *queue
)
{
    if (!queue) return;
    if (queue->prev)
        queue->prev->next = queue->next;
    else
        *head = queue->next;

    if (queue->next)
        queue->next->prev = queue->prev;
    else
        *tail = queue->prev;
    CLOSE_IPC_PROTOCOL(pool, &queue->p);
    queue->next = NULL;
    queue->prev = NULL;
    free(queue);
}

static inline ipc_protocol_queue_t *ipc_pop_head_protocol_queue(
    ipc_protocol_queue_t **head,
    ipc_protocol_queue_t **tail
)
{
    if (!(*head)) return NULL;
    ipc_protocol_queue_t *pqueue = *head;
    *head = pqueue->next;
    if (*head)
        (*head)->prev = NULL;
    else
        *tail = NULL;
    pqueue->next = pqueue->prev = NULL;
    return pqueue;
}

static inline ipc_protocol_queue_t *ipc_pop_tail_protocol_queue(
    ipc_protocol_queue_t **head,
    ipc_protocol_queue_t **tail
)
{
    if (!(*tail)) return NULL;
    ipc_protocol_queue_t *pqueue = *tail;
    *tail = pqueue->prev;
    if (*tail)
        (*tail)->next = NULL;
    else
        *head = NULL;
    pqueue->next = pqueue->prev = NULL;
    return pqueue;
}

static inline void ipc_cleanup_protocol_queue(
	oritlsf_pool_t *pool, 
    ipc_protocol_queue_t **head,
    ipc_protocol_queue_t **tail
)
{
    ipc_protocol_queue_t *cur = *head;
    while (cur) {
        ipc_protocol_queue_t *next = cur->next;
        CLOSE_IPC_PROTOCOL(pool, &cur->p);
        free(cur);
        cur = next;
    }
    *head = *tail = NULL;
}

#endif
