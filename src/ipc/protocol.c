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
#include "ipc/master_worker_shutdown.h"
#include "ipc/worker_master_heartbeat.h"
#include "constants.h"

static inline size_t_status_t calculate_ipc_payload_size(const char *label, const ipc_protocol_t* p, bool checkfixheader) {
	size_t_status_t result;
    result.r_size_t = 0;
    result.status = FAILURE;
    size_t payload_fixed_size = 0;
    size_t payload_dynamic_size = 0;
    
    switch (p->type) {
		case IPC_MASTER_WORKER_SHUTDOWN: {
            if (!checkfixheader) {
                if (!p->payload.ipc_master_worker_shutdown) {
                    LOG_ERROR("%sIPC_MASTER_WORKER_SHUTDOWN payload is NULL.", label);
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
            payload_fixed_size = sizeof(uint8_t) + sizeof(uint8_t) + DOUBLE_ARRAY_SIZE;
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
        result.r_size_t = IPC_VERSION_BYTES + sizeof(uint8_t) + payload_fixed_size + payload_dynamic_size;
    }
    result.status = SUCCESS;
    return result;
}

ssize_t_status_t ipc_serialize(const char *label, const ipc_protocol_t* p, uint8_t** ptr_buffer, size_t* buffer_size) {
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
    memcpy(current_buffer + offset, (uint8_t *)&p->type, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    status_t result_pyld = FAILURE;
    switch (p->type) {
        case IPC_MASTER_WORKER_SHUTDOWN:
            result_pyld = ipc_serialize_master_worker_shutdown(label, p->payload.ipc_master_worker_shutdown, current_buffer, *buffer_size, &offset);
            break;
        case IPC_WORKER_MASTER_HEARTBEAT:
            result_pyld = ipc_serialize_worker_master_heartbeat(label, p->payload.ipc_worker_master_heartbeat, current_buffer, *buffer_size, &offset);
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
    result.r_ssize_t = (ssize_t)offset;
    result.status = SUCCESS;
    print_hex("DEBUG SEND: ", *ptr_buffer, result.r_ssize_t, true);
    return result;
}

ipc_protocol_t_status_t ipc_deserialize(const char *label, const uint8_t* buffer, size_t len) {
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
    memcpy(p->version, buffer, IPC_VERSION_BYTES);
    memcpy((uint8_t *)&p->type, buffer + IPC_VERSION_BYTES, sizeof(uint8_t));
    size_t current_buffer_offset = IPC_VERSION_BYTES + sizeof(uint8_t);
    size_t_status_t psize = calculate_ipc_payload_size(label, p, true);
    if (psize.status != SUCCESS) {
		result.status = psize.status;
		return result;
	}
    size_t fixed_header_size = psize.r_size_t;
    LOG_DEBUG("%sDeserializing type 0x%02x. Current offset: %zu", label, p->type, current_buffer_offset);
    status_t result_pyld = FAILURE;
    switch (p->type) {
        case IPC_MASTER_WORKER_SHUTDOWN: {
            if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_MASTER_WORKER_SHUTDOWN fixed header.", label);
                CLOSE_IPC_PROTOCOL(&p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_master_worker_shutdown_t *payload = (ipc_master_worker_shutdown_t*) calloc(1, sizeof(ipc_master_worker_shutdown_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_master_worker_shutdown_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(&p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_master_worker_shutdown = payload;
            result_pyld = ipc_deserialize_master_worker_shutdown(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_WORKER_MASTER_HEARTBEAT: {
            if (current_buffer_offset + fixed_header_size > len) {
                LOG_ERROR("%sBuffer terlalu kecil untuk IPC_WORKER_MASTER_HEARTBEAT fixed header.", label);
                CLOSE_IPC_PROTOCOL(&p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_worker_master_heartbeat_t *payload = (ipc_worker_master_heartbeat_t*) calloc(1, sizeof(ipc_worker_master_heartbeat_t));
            if (!payload) {
                LOG_ERROR("%sFailed to allocate ipc_worker_master_heartbeat_t without FAM. %s", label, strerror(errno));
                CLOSE_IPC_PROTOCOL(&p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_worker_master_heartbeat = payload;
            result_pyld = ipc_deserialize_worker_master_heartbeat(label, p, buffer, len, &current_buffer_offset);
            break;
		}
        default:
            LOG_ERROR("%sUnknown protocol type for deserialization: 0x%02x", label, p->type);
            result.status = FAILURE_IPYLD;
            CLOSE_IPC_PROTOCOL(&p);
            return result;
    }
    if (result_pyld != SUCCESS) {
        LOG_ERROR("%sPayload deserialization failed with status %d.", label, result_pyld);
        CLOSE_IPC_PROTOCOL(&p);
        result.status = FAILURE_IPYLD;
        return result;
    }
    result.r_ipc_protocol_t = p;
    result.status = SUCCESS;
    LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
    return result;
}

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

ssize_t_status_t send_ipc_protocol_message(const char *label, int *uds_fd, const ipc_protocol_t* p) {
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

ipc_protocol_t_status_t receive_and_deserialize_ipc_message_wfdrcvd(const char *label, int *uds_fd, int *actual_fd_received) {
    ipc_protocol_t_status_t deserialized_result;
    deserialized_result.r_ipc_protocol_t = NULL;
    deserialized_result.status = FAILURE;

    if (actual_fd_received) {
        *actual_fd_received = -1;
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
        return deserialized_result;
    }
    if (bytes_read_prefix_and_fd != (ssize_t)IPC_LENGTH_PREFIX_BYTES) {
        LOG_ERROR("%sGagal membaca length prefix sepenuhnya. Diharapkan %zu byte, diterima %zd.",
                label, IPC_LENGTH_PREFIX_BYTES, bytes_read_prefix_and_fd);
        deserialized_result.status = FAILURE_OOBUF;
        return deserialized_result;
    }
    struct cmsghdr *cmsg_prefix = CMSG_FIRSTHDR(&msg_prefix);
    if (cmsg_prefix && cmsg_prefix->cmsg_level == SOL_SOCKET && cmsg_prefix->cmsg_type == SCM_RIGHTS && cmsg_prefix->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (actual_fd_received) {
            *actual_fd_received = *((int *) CMSG_DATA(cmsg_prefix));
        }
        LOG_DEBUG("%sFD diterima: %d", label, *actual_fd_received);
    } else {
        LOG_DEBUG("%sTidak ada FD yang diterima dengan length prefix.", label);
    }
    memcpy(&total_ipc_payload_len_be, temp_len_prefix_buf, IPC_LENGTH_PREFIX_BYTES);
    uint32_t total_ipc_payload_len = be32toh(total_ipc_payload_len_be);
    LOG_DEBUG("%sDitemukan panjang payload IPC: %u byte.", label, total_ipc_payload_len);
    if (total_ipc_payload_len == 0) {
        LOG_ERROR("%sPanjang payload IPC adalah 0. Tidak ada data untuk dibaca.", label);
        deserialized_result.status = FAILURE_BAD_PROTOCOL;
        return deserialized_result;
    }
    uint8_t *full_ipc_payload_buffer = (uint8_t *)malloc(total_ipc_payload_len);
    if (!full_ipc_payload_buffer) {
        LOG_ERROR("%sreceive_and_deserialize_ipc_message: malloc failed for full_ipc_payload_buffer. %s", label, strerror(errno));
        deserialized_result.status = FAILURE_NOMEM;
        return deserialized_result;
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
        deserialized_result.status = FAILURE;
        return deserialized_result;
    }
    if (bytes_read_payload != (ssize_t)total_ipc_payload_len) {
        LOG_ERROR("%sPayload IPC tidak lengkap. Diharapkan %u byte, diterima %zd.",
                label, total_ipc_payload_len, bytes_read_payload);
        free(full_ipc_payload_buffer);
        deserialized_result.status = FAILURE_OOBUF;
        return deserialized_result;
    }
    LOG_DEBUG("%sipc_deserialize dengan buffer %p dan panjang %u.",
            label, (void*)full_ipc_payload_buffer, total_ipc_payload_len);
    deserialized_result = ipc_deserialize(label, (const uint8_t*)full_ipc_payload_buffer, total_ipc_payload_len);
    if (deserialized_result.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", label, deserialized_result.status);
        free(full_ipc_payload_buffer);
        deserialized_result.status = FAILURE;
        return deserialized_result;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
    }
    free(full_ipc_payload_buffer);
    deserialized_result.status = SUCCESS;
    return deserialized_result;
}

ipc_protocol_t_status_t receive_and_deserialize_ipc_message(const char *label, int *uds_fd) {
    ipc_protocol_t_status_t deserialized_result;
    deserialized_result.r_ipc_protocol_t = NULL;
    deserialized_result.status = FAILURE;

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
        return deserialized_result;
    }
    if (bytes_read_prefix_and_fd != (ssize_t)IPC_LENGTH_PREFIX_BYTES) {
        LOG_ERROR("%sGagal membaca length prefix sepenuhnya. Diharapkan %zu byte, diterima %zd.",
                label, IPC_LENGTH_PREFIX_BYTES, bytes_read_prefix_and_fd);
        deserialized_result.status = FAILURE_OOBUF;
        return deserialized_result;
    }
    memcpy(&total_ipc_payload_len_be, temp_len_prefix_buf, IPC_LENGTH_PREFIX_BYTES);
    uint32_t total_ipc_payload_len = be32toh(total_ipc_payload_len_be);
    LOG_DEBUG("%sDitemukan panjang payload IPC: %u byte.", label, total_ipc_payload_len);
    if (total_ipc_payload_len == 0) {
        LOG_ERROR("%sPanjang payload IPC adalah 0. Tidak ada data untuk dibaca.", label);
        deserialized_result.status = FAILURE_BAD_PROTOCOL;
        return deserialized_result;
    }
    uint8_t *full_ipc_payload_buffer = (uint8_t *)malloc(total_ipc_payload_len);
    if (!full_ipc_payload_buffer) {
        LOG_ERROR("%sreceive_and_deserialize_ipc_message: malloc failed for full_ipc_payload_buffer. %s", label, strerror(errno));
        deserialized_result.status = FAILURE_NOMEM;
        return deserialized_result;
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
        deserialized_result.status = FAILURE;
        return deserialized_result;
    }
    if (bytes_read_payload != (ssize_t)total_ipc_payload_len) {
        LOG_ERROR("%sPayload IPC tidak lengkap. Diharapkan %u byte, diterima %zd.",
                label, total_ipc_payload_len, bytes_read_payload);
        free(full_ipc_payload_buffer);
        deserialized_result.status = FAILURE_OOBUF;
        return deserialized_result;
    }
    LOG_DEBUG("%sipc_deserialize dengan buffer %p dan panjang %u.",
            label, (void*)full_ipc_payload_buffer, total_ipc_payload_len);
    deserialized_result = ipc_deserialize(label, (const uint8_t*)full_ipc_payload_buffer, total_ipc_payload_len);
    if (deserialized_result.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", label, deserialized_result.status);
        free(full_ipc_payload_buffer);
        deserialized_result.status = FAILURE;
        return deserialized_result;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", label);
    }
    free(full_ipc_payload_buffer);
    deserialized_result.status = SUCCESS;
    return deserialized_result;
}
