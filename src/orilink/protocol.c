#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <endian.h>
#include <stdint.h>

#include "utilities.h"
#include "orilink/protocol.h"
#include "orilink/syn.h"
#include "orilink/syn_ack.h"
#include "types.h"
#include "log.h"
#include "constants.h"

static inline size_t_status_t calculate_orilink_payload_size(const char *label, const orilink_protocol_t* p) {
	size_t_status_t result;
    result.r_size_t = 0;
    result.status = FAILURE;
    size_t payload_fixed_size = 0;
    size_t payload_dynamic_size = 0;
    
    switch (p->type) {
		case ORILINK_SYN: {
            if (!p->payload.orilink_syn) {
                LOG_ERROR("%sORILINK_SYN payload is NULL.", label);
                result.status = FAILURE;
                return result;
            }
            payload_fixed_size = sizeof(uint64_t);
            payload_dynamic_size = 0;
            break;
        }
        case ORILINK_SYN_ACK: {
            if (!p->payload.orilink_syn_ack) {
                LOG_ERROR("%sORILINK_SYN_ACK payload is NULL.", label);
                result.status = FAILURE;
                return result;
            }
            payload_fixed_size = sizeof(uint64_t);
            payload_dynamic_size = 0;
            break;
        }
        default:
            LOG_ERROR("%sUnknown protocol type for serialization: 0x%02x", label, p->type);
            result.status = FAILURE_OPYLD;
            return result;
    }
    result.r_size_t = ORILINK_VERSION_BYTES + sizeof(orilink_protocol_type_t) + sizeof(uint32_t) + payload_fixed_size + payload_dynamic_size;
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
    size_t_status_t psize = calculate_orilink_payload_size(label, p);
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
    size_t offset_chksum = 0;
    size_t offset_payload = 0;
    if (CHECK_BUFFER_BOUNDS(offset, ORILINK_VERSION_BYTES, *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, p->version, ORILINK_VERSION_BYTES);
    offset += ORILINK_VERSION_BYTES;
    if (CHECK_BUFFER_BOUNDS(offset, sizeof(orilink_protocol_type_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    current_buffer[offset] = (uint8_t)p->type;
    offset += sizeof(orilink_protocol_type_t);
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

    if (!buffer || len < (ORILINK_VERSION_BYTES + sizeof(orilink_protocol_type_t) + sizeof(uint32_t))) {
        LOG_ERROR("%sBuffer terlalu kecil untuk Version, Type dan Chksum. Len: %zu", label, len);
        result.status = FAILURE_OOBUF;
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
    p->type = (orilink_protocol_type_t)buffer[ORILINK_VERSION_BYTES];    
    size_t current_buffer_offset = ORILINK_VERSION_BYTES + sizeof(orilink_protocol_type_t);
    uint32_t chksum_be;
    memcpy(&chksum_be, buffer + current_buffer_offset, sizeof(uint32_t));
    p->chksum = be32toh(chksum_be);
    current_buffer_offset += sizeof(uint32_t);
    size_t offset_payload = current_buffer_offset;
    LOG_DEBUG("%sDeserializing type 0x%02x. Current offset: %zu", label, p->type, current_buffer_offset);
    status_t result_pyld = FAILURE;
    switch (p->type) {
		case ORILINK_SYN: {
			if (current_buffer_offset + sizeof(uint64_t) > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_SYN fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syn_t *task_payload = (orilink_syn_t*) calloc(1, sizeof(orilink_syn_t));
            if (!task_payload) {
                LOG_ERROR("%sFailed to allocate orilink_syn_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_syn = task_payload;
            result_pyld = orilink_deserialize_syn(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case ORILINK_SYN_ACK: {
			if (current_buffer_offset + sizeof(uint64_t) > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk ORILINK_SYN_ACK fixed header.", label);
                CLOSE_ORILINK_PROTOCOL(&p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            orilink_syn_ack_t *task_payload = (orilink_syn_ack_t*) calloc(1, sizeof(orilink_syn_ack_t));
            if (!task_payload) {
                LOG_ERROR("%sFailed to allocate orilink_syn_ack_t without FAM. %s", label, strerror(errno));
                CLOSE_ORILINK_PROTOCOL(&p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.orilink_syn_ack = task_payload;
            result_pyld = orilink_deserialize_syn_ack(label, p, buffer, len, &current_buffer_offset);
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
    if (n <= 0 ) {
        LOG_ERROR("%sreceive_and_deserialize_orilink_packet failed: %s", label, strerror(errno));
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
