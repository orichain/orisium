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
#include "orilink/hello_end.h"
#include "orilink/sock_ready.h"
#include "orilink/syn.h"
#include "orilink/syn_ack.h"
#include "orilink/syn_end.h"
#include "orilink/heartbeat_ping.h"
#include "orilink/heartbeat_pong.h"
#include "orilink/heartbeat_pong_ack.h"
#include "orilink/heartbeat_ping_end.h"
#include "orilink/syndt.h"
#include "orilink/syndt_ack.h"
#include "orilink/syndt_end.h"
#include "orilink/data.h"
#include "orilink/data_ack.h"
#include "orilink/data_end.h"
#include "orilink/findt.h"
#include "orilink/findt_ack.h"
#include "orilink/findt_end.h"
#include "orilink/fin.h"
#include "orilink/fin_ack.h"
#include "orilink/fin_end.h"
#include "types.h"
#include "log.h"
#include "constants.h"
#include "pqc.h"
#include "poly1305-donna.h"
#include "aes.h"

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
            payload_fixed_size = sizeof(uint64_t) + (KEM_PUBLICKEY_BYTES / 2) + sizeof(uint8_t);
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
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint8_t);
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
            payload_fixed_size = sizeof(uint64_t) + (KEM_PUBLICKEY_BYTES / 2) + sizeof(uint8_t);
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
            payload_fixed_size = sizeof(uint64_t) + (KEM_CIPHERTEXT_BYTES / 2) + sizeof(uint8_t);
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
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint8_t);
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
            payload_fixed_size = sizeof(uint64_t) + (KEM_CIPHERTEXT_BYTES / 2) + (AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t) + AES_TAG_BYTES) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_HELLO_END: {
            if (!checkfixheader) {
                if (!p->payload.orilink_hello_end) {
                    LOG_ERROR("%sORILINK_HELLO_END payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + (AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint64_t) + AES_TAG_BYTES) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_SOCK_READY: {
            if (!checkfixheader) {
                if (!p->payload.orilink_sock_ready) {
                    LOG_ERROR("%sORILINK_SOCK_READY payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
		case ORILINK_SYN: {
            if (!checkfixheader) {
                if (!p->payload.orilink_syn) {
                    LOG_ERROR("%sORILINK_SYN payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_SYN_ACK: {
            if (!checkfixheader) {
                if (!p->payload.orilink_syn_ack) {
                    LOG_ERROR("%sORILINK_SYN_ACK payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_SYN_END: {
            if (!checkfixheader) {
                if (!p->payload.orilink_syn_end) {
                    LOG_ERROR("%sORILINK_SYN_END payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_HEARTBEAT_PING: {
            if (!checkfixheader) {
                if (!p->payload.orilink_heartbeat_ping) {
                    LOG_ERROR("%sORILINK_HEARTBEAT_PING payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_HEARTBEAT_PONG: {
            if (!checkfixheader) {
                if (!p->payload.orilink_heartbeat_pong) {
                    LOG_ERROR("%sORILINK_HEARTBEAT_PONG payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_HEARTBEAT_PONG_ACK: {
            if (!checkfixheader) {
                if (!p->payload.orilink_heartbeat_pong_ack) {
                    LOG_ERROR("%sORILINK_HEARTBEAT_PONG_ACK payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_HEARTBEAT_PING_END: {
            if (!checkfixheader) {
                if (!p->payload.orilink_heartbeat_ping_end) {
                    LOG_ERROR("%sORILINK_HEARTBEAT_PING_END payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_SYNDT: {
            if (!checkfixheader) {
                if (!p->payload.orilink_syndt) {
                    LOG_ERROR("%sORILINK_SYNDT payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_SYNDT_ACK: {
            if (!checkfixheader) {
                if (!p->payload.orilink_syndt_ack) {
                    LOG_ERROR("%sORILINK_SYNDT_ACK payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_SYNDT_END: {
            if (!checkfixheader) {
                if (!p->payload.orilink_syndt_end) {
                    LOG_ERROR("%sORILINK_SYNDT_END payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_DATA: {
            if (!checkfixheader) {
                if (!p->payload.orilink_data) {
                    LOG_ERROR("%sORILINK_DATA payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint16_t);
            payload_dynamic_size = p->payload.orilink_data->len;
            break;
        }
        case ORILINK_DATA_ACK: {
            if (!checkfixheader) {
                if (!p->payload.orilink_data_ack) {
                    LOG_ERROR("%sORILINK_DATA_ACK payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_DATA_END: {
            if (!checkfixheader) {
                if (!p->payload.orilink_data_end) {
                    LOG_ERROR("%sORILINK_DATA_END payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_FINDT: {
            if (!checkfixheader) {
                if (!p->payload.orilink_findt) {
                    LOG_ERROR("%sORILINK_FINDT payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_FINDT_ACK: {
            if (!checkfixheader) {
                if (!p->payload.orilink_findt_ack) {
                    LOG_ERROR("%sORILINK_FINDT_ACK payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_FINDT_END: {
            if (!checkfixheader) {
                if (!p->payload.orilink_findt_end) {
                    LOG_ERROR("%sORILINK_FINDT_END payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_FIN: {
            if (!checkfixheader) {
                if (!p->payload.orilink_fin) {
                    LOG_ERROR("%sORILINK_FIN payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_FIN_ACK: {
            if (!checkfixheader) {
                if (!p->payload.orilink_fin_ack) {
                    LOG_ERROR("%sORILINK_FIN_ACK payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint8_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_FIN_END: {
            if (!checkfixheader) {
                if (!p->payload.orilink_fin_end) {
                    LOG_ERROR("%sORILINK_FIN_END payload is NULL.", label);
                    result.status = FAILURE;
                    return result;
                }
            }
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint8_t);
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
        result.r_size_t = AES_TAG_BYTES + sizeof(uint32_t) + ORILINK_VERSION_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t) + payload_fixed_size + payload_dynamic_size;
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
    memcpy(current_buffer + offset, (uint8_t *)&p->c_index, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint16_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    uint16_t sid_be = htobe16(p->sid);
    memcpy(current_buffer + offset, &sid_be, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint16_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    uint16_t sseq_be = htobe16(p->sseq);
    memcpy(current_buffer + offset, &sseq_be, sizeof(uint16_t));
    offset += sizeof(uint16_t);
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
        case ORILINK_HELLO_END:
            result_pyld = orilink_serialize_hello_end(label, p->payload.orilink_hello_end, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_SOCK_READY:
            result_pyld = orilink_serialize_sock_ready(label, p->payload.orilink_sock_ready, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_SYN:
            result_pyld = orilink_serialize_syn(label, p->payload.orilink_syn, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_SYN_ACK:
            result_pyld = orilink_serialize_syn_ack(label, p->payload.orilink_syn_ack, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_SYN_END:
            result_pyld = orilink_serialize_syn_end(label, p->payload.orilink_syn_end, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_HEARTBEAT_PING:
            result_pyld = orilink_serialize_heartbeat_ping(label, p->payload.orilink_heartbeat_ping, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_HEARTBEAT_PONG:
            result_pyld = orilink_serialize_heartbeat_pong(label, p->payload.orilink_heartbeat_pong, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_HEARTBEAT_PONG_ACK:
            result_pyld = orilink_serialize_heartbeat_pong_ack(label, p->payload.orilink_heartbeat_pong_ack, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_HEARTBEAT_PING_END:
            result_pyld = orilink_serialize_heartbeat_ping_end(label, p->payload.orilink_heartbeat_ping_end, current_buffer, *buffer_size, &offset);
            break;            
        case ORILINK_SYNDT:
            result_pyld = orilink_serialize_syndt(label, p->payload.orilink_syndt, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_SYNDT_ACK:
            result_pyld = orilink_serialize_syndt_ack(label, p->payload.orilink_syndt_ack, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_SYNDT_END:
            result_pyld = orilink_serialize_syndt_end(label, p->payload.orilink_syndt_end, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_DATA:
            result_pyld = orilink_serialize_data(label, p->payload.orilink_data, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_DATA_ACK:
            result_pyld = orilink_serialize_data_ack(label, p->payload.orilink_data_ack, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_DATA_END:
            result_pyld = orilink_serialize_data_end(label, p->payload.orilink_data_end, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_FINDT:
            result_pyld = orilink_serialize_findt(label, p->payload.orilink_findt, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_FINDT_ACK:
            result_pyld = orilink_serialize_findt_ack(label, p->payload.orilink_findt_ack, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_FINDT_END:
            result_pyld = orilink_serialize_findt_end(label, p->payload.orilink_findt_end, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_FIN:
            result_pyld = orilink_serialize_fin(label, p->payload.orilink_fin, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_FIN_ACK:
            result_pyld = orilink_serialize_fin_ack(label, p->payload.orilink_fin_ack, current_buffer, *buffer_size, &offset);
            break;
        case ORILINK_FIN_END:
            result_pyld = orilink_serialize_fin_end(label, p->payload.orilink_fin_end, current_buffer, *buffer_size, &offset);
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
                          sizeof(uint16_t) -
                          sizeof(uint16_t) -
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
                sizeof(uint16_t) +
                sizeof(uint16_t) +
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
                sizeof(uint16_t) +
                sizeof(uint16_t) +
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

orilink_protocol_t_status_t orilink_deserialize(const char *label, uint8_t* key_aes, uint8_t* nonce, uint32_t *ctr, uint8_t* buffer, size_t len) {
    orilink_protocol_t_status_t result;
    result.r_orilink_protocol_t = NULL;
    result.status = FAILURE;

    if (!buffer || len < (AES_TAG_BYTES + ORILINK_VERSION_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint8_t))) {
        LOG_ERROR("%sBuffer terlalu kecil untuk Mac, Version dan Type. Len: %zu", label, len);
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
    memcpy((uint8_t *)&p->wot, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    memcpy((uint8_t *)&p->index, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    memcpy((uint8_t *)&p->c_index, buffer + current_buffer_offset, sizeof(uint8_t));
    current_buffer_offset += sizeof(uint8_t);
    uint16_t sid_be;
    memcpy(&sid_be, buffer + current_buffer_offset, sizeof(uint16_t));
    p->sid = be16toh(sid_be);
    current_buffer_offset += sizeof(uint16_t);
    uint16_t sseq_be;
    memcpy(&sseq_be, buffer + current_buffer_offset, sizeof(uint16_t));
    p->sseq = be16toh(sseq_be);
    current_buffer_offset += sizeof(uint16_t);
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
                          sizeof(uint16_t) -
						  sizeof(uint16_t) -
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
                sizeof(uint16_t) +
                sizeof(uint16_t) +
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
                sizeof(uint16_t) +
                sizeof(uint16_t) +
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
        case ORILINK_HELLO_END: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HELLO_END fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_hello_end_t *payload = (orilink_hello_end_t*) calloc(1, sizeof(orilink_hello_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_hello_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_hello_end = payload;
            result_pyld = orilink_deserialize_hello_end(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_SOCK_READY: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_SOCK_READY fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_sock_ready_t *payload = (orilink_sock_ready_t*) calloc(1, sizeof(orilink_sock_ready_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_sock_ready_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_sock_ready = payload;
            result_pyld = orilink_deserialize_sock_ready(label, p, buffer, len, &current_buffer_offset);
            break;
		}
		case ORILINK_SYN: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_SYN fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syn_t *payload = (orilink_syn_t*) calloc(1, sizeof(orilink_syn_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_syn_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_syn = payload;
            result_pyld = orilink_deserialize_syn(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_SYN_ACK: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_SYN_ACK fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syn_ack_t *payload = (orilink_syn_ack_t*) calloc(1, sizeof(orilink_syn_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_syn_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_syn_ack = payload;
            result_pyld = orilink_deserialize_syn_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_SYN_END: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_SYN_END fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syn_end_t *payload = (orilink_syn_end_t*) calloc(1, sizeof(orilink_syn_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_syn_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_syn_end = payload;
            result_pyld = orilink_deserialize_syn_end(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HEARTBEAT_PING: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HEARTBEAT_PING fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_heartbeat_ping_t *payload = (orilink_heartbeat_ping_t*) calloc(1, sizeof(orilink_heartbeat_ping_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_heartbeat_ping_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_heartbeat_ping = payload;
            result_pyld = orilink_deserialize_heartbeat_ping(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HEARTBEAT_PONG: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HEARTBEAT_PONG fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_heartbeat_pong_t *payload = (orilink_heartbeat_pong_t*) calloc(1, sizeof(orilink_heartbeat_pong_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_heartbeat_pong_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_heartbeat_pong = payload;
            result_pyld = orilink_deserialize_heartbeat_pong(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HEARTBEAT_PONG_ACK: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HEARTBEAT_PONG_ACK fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_heartbeat_pong_ack_t *payload = (orilink_heartbeat_pong_ack_t*) calloc(1, sizeof(orilink_heartbeat_pong_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_heartbeat_pong_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_heartbeat_pong_ack = payload;
            result_pyld = orilink_deserialize_heartbeat_pong_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_HEARTBEAT_PING_END: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_HEARTBEAT_PING_END fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_heartbeat_ping_end_t *payload = (orilink_heartbeat_ping_end_t*) calloc(1, sizeof(orilink_heartbeat_ping_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_heartbeat_ping_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_heartbeat_ping_end = payload;
            result_pyld = orilink_deserialize_heartbeat_ping_end(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_SYNDT: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_SYNDT fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syndt_t *payload = (orilink_syndt_t*) calloc(1, sizeof(orilink_syndt_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_syndt_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_syndt = payload;
            result_pyld = orilink_deserialize_syndt(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_SYNDT_ACK: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_SYNDT_ACK fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syndt_ack_t *payload = (orilink_syndt_ack_t*) calloc(1, sizeof(orilink_syndt_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_syndt_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_syndt_ack = payload;
            result_pyld = orilink_deserialize_syndt_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_SYNDT_END: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_SYNDT_END fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syndt_end_t *payload = (orilink_syndt_end_t*) calloc(1, sizeof(orilink_syndt_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_syndt_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_syndt_end = payload;
            result_pyld = orilink_deserialize_syndt_end(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_DATA: {
            if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_DATA fixed header.");
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            size_t fixed_header_blen_size = fixed_header_size - sizeof(uint16_t);
            uint16_t raw_data_len_be;
            memcpy(&raw_data_len_be, buffer + current_buffer_offset + fixed_header_blen_size, sizeof(uint16_t));
            uint16_t actual_data_len = be16toh(raw_data_len_be);
            orilink_data_t *payload = (orilink_data_t*) calloc(1, sizeof(orilink_data_t) + actual_data_len);
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_data_t with FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_data = payload;
            result_pyld = orilink_deserialize_data(label, p, buffer, len, &current_buffer_offset);
            break;
        }
        case ORILINK_DATA_ACK: {
            if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_DATA_ACK fixed header.");
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_data_ack_t *payload = (orilink_data_ack_t*) calloc(1, sizeof(orilink_data_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_data_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_data_ack = payload;
            result_pyld = orilink_deserialize_data_ack(label, p, buffer, len, &current_buffer_offset);
            break;
        }
        case ORILINK_DATA_END: {
            if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_DATA_END fixed header.");
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_data_end_t *payload = (orilink_data_end_t*) calloc(1, sizeof(orilink_data_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_data_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_data_end = payload;
            result_pyld = orilink_deserialize_data_end(label, p, buffer, len, &current_buffer_offset);
            break;
        }
        case ORILINK_FINDT: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_FINDT fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_findt_t *payload = (orilink_findt_t*) calloc(1, sizeof(orilink_findt_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_findt_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_findt = payload;
            result_pyld = orilink_deserialize_findt(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_FINDT_ACK: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_FINDT_ACK fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_findt_ack_t *payload = (orilink_findt_ack_t*) calloc(1, sizeof(orilink_findt_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_findt_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_findt_ack = payload;
            result_pyld = orilink_deserialize_findt_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_FINDT_END: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_FINDT_END fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_findt_end_t *payload = (orilink_findt_end_t*) calloc(1, sizeof(orilink_findt_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_findt_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_findt_end = payload;
            result_pyld = orilink_deserialize_findt_end(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_FIN: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_FIN fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_fin_t *payload = (orilink_fin_t*) calloc(1, sizeof(orilink_fin_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_fin_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_fin = payload;
            result_pyld = orilink_deserialize_fin(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_FIN_ACK: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_FIN_ACK fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_fin_ack_t *payload = (orilink_fin_ack_t*) calloc(1, sizeof(orilink_fin_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_fin_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_fin_ack = payload;
            result_pyld = orilink_deserialize_fin_ack(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_FIN_END: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_FIN_END fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_fin_end_t *payload = (orilink_fin_end_t*) calloc(1, sizeof(orilink_fin_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_fin_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                free(key0);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_fin_end = payload;
            result_pyld = orilink_deserialize_fin_end(label, p, buffer, len, &current_buffer_offset);
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
        increment_ctr(ctr, nonce);
    }
    free(key0);
    result.r_orilink_protocol_t = p;
    result.status = SUCCESS;
    LOG_DEBUG("%sorilink_deserialize BERHASIL.", label);
    return result;
}

ssize_t_status_t send_orilink_protocol_packet(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint8_t* nonce, uint32_t *ctr, int *sock_fd, const struct sockaddr *dest_addr, const orilink_protocol_t* p) {
	ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;
    uint8_t* serialized_orilink_data_buffer = NULL;
    size_t serialized_orilink_data_len = 0;
    ssize_t_status_t serialize_result = orilink_serialize(label, key_aes, key_mac, nonce, ctr, p, &serialized_orilink_data_buffer, &serialized_orilink_data_len);
    if (serialize_result.status != SUCCESS) {
        LOG_ERROR("%sError serializing ORILINK protocol: %d", label, serialize_result.status);
        if (serialized_orilink_data_buffer) {
            free(serialized_orilink_data_buffer);
        }
        return result;
    }
    if (serialized_orilink_data_len > ORILINK_MAX_PACKET_SIZE) {
        LOG_ERROR("%sError packet size %d ORILINK_MAX_PACKET_SIZE %d", label, serialized_orilink_data_len, ORILINK_MAX_PACKET_SIZE);
        if (serialized_orilink_data_buffer) {
            free(serialized_orilink_data_buffer);
        }
        return result;
    }
    LOG_DEBUG("%sTotal pesan untuk dikirim: %zu byte.", label, serialized_orilink_data_len);
    socklen_t dest_addr_len = sizeof(struct sockaddr_in6);
    result.r_ssize_t = sendto(*sock_fd, serialized_orilink_data_buffer, serialized_orilink_data_len, 0, dest_addr, dest_addr_len);
    if (result.r_ssize_t != (ssize_t)serialized_orilink_data_len) {
        LOG_ERROR("%ssendto failed to send_orilink_protocol_packet. %s", label, strerror(errno));
        if (serialized_orilink_data_buffer) {
            free(serialized_orilink_data_buffer);
        }
        result.status = FAILURE;
        return result;
    }
    if (serialized_orilink_data_buffer) {
        free(serialized_orilink_data_buffer);
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

orilink_raw_protocol_t_status_t receive_orilink_raw_protocol_packet(const char *label, int *sock_fd, struct sockaddr *source_addr) {
    orilink_raw_protocol_t_status_t result;
    result.status = FAILURE;
    result.r_orilink_raw_protocol_t = NULL;
    uint8_t *full_orilink_payload_buffer = (uint8_t *)calloc(1, ORILINK_MAX_PACKET_SIZE * sizeof(uint8_t));
    socklen_t source_addr_len = sizeof(struct sockaddr_in6);
    ssize_t bytes_read_payload = recvfrom(*sock_fd, full_orilink_payload_buffer, ORILINK_MAX_PACKET_SIZE, 0, source_addr, &source_addr_len);
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
    uint32_t ctr_be;
    memcpy(&ctr_be, b + AES_TAG_BYTES, sizeof(uint32_t));
    r->ctr = be32toh(ctr_be);
    memcpy(r->version, b + AES_TAG_BYTES + sizeof(uint32_t), ORILINK_VERSION_BYTES);
    memcpy((uint8_t *)&r->wot, b + AES_TAG_BYTES + sizeof(uint32_t) + ORILINK_VERSION_BYTES, sizeof(uint8_t));
    memcpy((uint8_t *)&r->index, b + AES_TAG_BYTES + sizeof(uint32_t) + ORILINK_VERSION_BYTES + sizeof(uint8_t), sizeof(uint8_t));
    memcpy((uint8_t *)&r->c_index, b + AES_TAG_BYTES + sizeof(uint32_t) + ORILINK_VERSION_BYTES + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint8_t));
    uint16_t sid_be;
    memcpy(&sid_be, b + AES_TAG_BYTES + sizeof(uint32_t) + ORILINK_VERSION_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint16_t));
    r->sid = be16toh(sid_be);
    uint16_t sseq_be;
    memcpy(&sseq_be, b + AES_TAG_BYTES + sizeof(uint32_t) + ORILINK_VERSION_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t), sizeof(uint16_t));
    r->sseq = be16toh(sseq_be);
    memcpy((uint8_t *)&r->type, b + AES_TAG_BYTES + sizeof(uint32_t) + ORILINK_VERSION_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t), sizeof(uint8_t));
    result.r_orilink_raw_protocol_t = r;
    result.status = SUCCESS;
    return result;
}
