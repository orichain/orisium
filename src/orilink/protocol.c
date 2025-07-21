#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>

#include "utilities.h"
#include "orilink/protocol.h"
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

static inline size_t_status_t calculate_orilink_payload_size(const char *label, const orilink_protocol_t* p, bool checkfixheader) {
	size_t_status_t result;
    result.r_size_t = 0;
    result.status = FAILURE;
    size_t payload_fixed_size = 0;
    size_t payload_dynamic_size = 0;
    
    switch (p->type) {
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
        result.r_size_t = ORILINK_VERSION_BYTES + sizeof(uint8_t) + sizeof(uint32_t) + payload_fixed_size + payload_dynamic_size;
    }
    result.status = SUCCESS;
    return result;
}

ssize_t_status_t orilink_serialize(const char *label, const orilink_protocol_t* p, uint8_t** ptr_buffer, size_t* buffer_size) {
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
    size_t offset_chksum = 0;
    size_t offset_payload = 0;
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
    memcpy(current_buffer + offset, (uint8_t *)&p->type, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(uint32_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    offset_chksum = offset;
    memset(current_buffer + offset, 0, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    offset_payload = offset;
    status_t result_pyld = FAILURE;
    switch (p->type) {
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
    uint32_t chksum_be = htobe32(orilink_hash32(current_buffer + offset_payload, offset - offset_payload));
    memcpy(current_buffer + offset_chksum, &chksum_be, sizeof(uint32_t));
    result.r_ssize_t = (ssize_t)offset;
    result.status = SUCCESS;
    return result;
}

orilink_protocol_t_status_t orilink_deserialize(const char *label, const uint8_t* buffer, size_t len) {
    orilink_protocol_t_status_t result;
    result.r_orilink_protocol_t = NULL;
    result.status = FAILURE;

    if (!buffer || len < (ORILINK_VERSION_BYTES + sizeof(uint8_t) + sizeof(uint32_t))) {
        LOG_ERROR("%sBuffer terlalu kecil untuk Version, Type dan Chksum. Len: %zu", label, len);
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
    memcpy(p->version, buffer, ORILINK_VERSION_BYTES);
    memcpy((uint8_t *)&p->type, buffer + ORILINK_VERSION_BYTES, sizeof(uint8_t));
    size_t current_buffer_offset = ORILINK_VERSION_BYTES + sizeof(uint8_t);
    uint32_t chksum_be;
    memcpy(&chksum_be, buffer + current_buffer_offset, sizeof(uint32_t));
    p->chksum = be32toh(chksum_be);
    current_buffer_offset += sizeof(uint32_t);
    size_t offset_payload = current_buffer_offset;
    size_t_status_t psize = calculate_orilink_payload_size(label, p, true);
    if (psize.status != SUCCESS) {
		result.status = psize.status;
		return result;
	}
    size_t fixed_header_size = psize.r_size_t;
    LOG_DEBUG("%sDeserializing type 0x%02x. Current offset: %zu", label, p->type, current_buffer_offset);
    status_t result_pyld = FAILURE;
    switch (p->type) {
		case ORILINK_SYN: {
			if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_SYN fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syn_t *payload = (orilink_syn_t*) calloc(1, sizeof(orilink_syn_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_syn_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syn_ack_t *payload = (orilink_syn_ack_t*) calloc(1, sizeof(orilink_syn_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_syn_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syn_end_t *payload = (orilink_syn_end_t*) calloc(1, sizeof(orilink_syn_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_syn_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_heartbeat_ping_t *payload = (orilink_heartbeat_ping_t*) calloc(1, sizeof(orilink_heartbeat_ping_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_heartbeat_ping_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_heartbeat_pong_t *payload = (orilink_heartbeat_pong_t*) calloc(1, sizeof(orilink_heartbeat_pong_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_heartbeat_pong_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_heartbeat_pong_ack_t *payload = (orilink_heartbeat_pong_ack_t*) calloc(1, sizeof(orilink_heartbeat_pong_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_heartbeat_pong_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_heartbeat_ping_end_t *payload = (orilink_heartbeat_ping_end_t*) calloc(1, sizeof(orilink_heartbeat_ping_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_heartbeat_ping_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syndt_t *payload = (orilink_syndt_t*) calloc(1, sizeof(orilink_syndt_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_syndt_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syndt_ack_t *payload = (orilink_syndt_ack_t*) calloc(1, sizeof(orilink_syndt_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_syndt_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syndt_end_t *payload = (orilink_syndt_end_t*) calloc(1, sizeof(orilink_syndt_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_syndt_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_data_ack_t *payload = (orilink_data_ack_t*) calloc(1, sizeof(orilink_data_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_data_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_data_end_t *payload = (orilink_data_end_t*) calloc(1, sizeof(orilink_data_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_data_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_findt_t *payload = (orilink_findt_t*) calloc(1, sizeof(orilink_findt_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_findt_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_findt_ack_t *payload = (orilink_findt_ack_t*) calloc(1, sizeof(orilink_findt_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_findt_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_findt_end_t *payload = (orilink_findt_end_t*) calloc(1, sizeof(orilink_findt_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_findt_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_fin_t *payload = (orilink_fin_t*) calloc(1, sizeof(orilink_fin_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_fin_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_fin_ack_t *payload = (orilink_fin_ack_t*) calloc(1, sizeof(orilink_fin_ack_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_fin_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_fin_end_t *payload = (orilink_fin_end_t*) calloc(1, sizeof(orilink_fin_end_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate orilink_fin_end_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
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
            return result;
    }
    if (result_pyld != SUCCESS) {
        LOG_ERROR("%sPayload deserialization failed with status %d.", label, result_pyld);
        CLOSE_ORILINK_PROTOCOL(&p);
        result.status = FAILURE_OPYLD;
        return result;
    }
    uint32_t calculated_chksum = orilink_hash32(buffer + offset_payload, current_buffer_offset - offset_payload);
    if (calculated_chksum != p->chksum) {
        LOG_ERROR("%sChecksum mismatch! Received: 0x%08x, Calculated: 0x%08x", label, p->chksum, calculated_chksum);
        CLOSE_ORILINK_PROTOCOL(&p);
        result.status = FAILURE_CHKSUM;
        return result;
    } else {
        LOG_DEBUG("%sChecksum cocok: 0x%08x", label, p->chksum);
    }
    result.r_orilink_protocol_t = p;
    result.status = SUCCESS;
    LOG_DEBUG("%sorilink_deserialize BERHASIL.", label);
    return result;
}

ssize_t_status_t send_orilink_protocol_packet(const char *label, int *sock_fd, const struct sockaddr *dest_addr, socklen_t *dest_addr_len, const orilink_protocol_t* p) {
	ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;
    uint8_t* serialized_orilink_data_buffer = NULL;
    size_t serialized_orilink_data_len = 0;

    ssize_t_status_t serialize_result = orilink_serialize(label, p, &serialized_orilink_data_buffer, &serialized_orilink_data_len);
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
    result.r_ssize_t = sendto(*sock_fd, serialized_orilink_data_buffer, serialized_orilink_data_len, 0, dest_addr, *dest_addr_len);
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

orilink_protocol_t_status_t receive_and_deserialize_orilink_packet(const char *label, int *sock_fd, struct sockaddr *source_addr, socklen_t *source_addr_len) {
    orilink_protocol_t_status_t deserialized_result;
    deserialized_result.r_orilink_protocol_t = NULL;
    deserialized_result.status = FAILURE;
    uint8_t recv_buffer[ORILINK_MAX_PACKET_SIZE];
    ssize_t n = recvfrom(*sock_fd, recv_buffer, ORILINK_MAX_PACKET_SIZE, 0, source_addr, source_addr_len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            deserialized_result.status = FAILURE_EAGNEWBLK;
            return deserialized_result;
        } else {
            LOG_ERROR("%sreceive_and_deserialize_orilink_packet failed: %s", label, strerror(errno));
            deserialized_result.status = FAILURE;
            return deserialized_result;
        }
    } else if (n == 0) {
        LOG_ERROR("%sreceive_and_deserialize_orilink_packet received 0 bytes (unexpected for UDP).", label);
        deserialized_result.status = FAILURE;
        return deserialized_result;
    }
    deserialized_result = orilink_deserialize(label, (const uint8_t*)recv_buffer, n);
    if (deserialized_result.status != SUCCESS) {
        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", label, deserialized_result.status);
        deserialized_result.status = FAILURE;
        return deserialized_result;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", label);
    }
    deserialized_result.status = SUCCESS;
    return deserialized_result;
}
