#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "log.h"
#include "ipc/client_request_task.h"
#include "constants.h"

status_t ipc_serialize_client_request_task(const char *label, const ipc_client_request_task_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset_local = *offset;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, IP_ADDRESS_LEN, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->ip, IP_ADDRESS_LEN);
    current_offset_local += IP_ADDRESS_LEN;
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint16_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint16_t len_be = htobe16(payload->len);
    memcpy(current_buffer + current_offset_local, &len_be, sizeof(uint16_t));
    current_offset_local += sizeof(uint16_t);
    if (payload->len > 0) {
        if (CHECK_BUFFER_BOUNDS(current_offset_local, payload->len, buffer_size) != SUCCESS) return FAILURE_OOBUF;
        memcpy(current_buffer + current_offset_local, payload->data, payload->len);
        current_offset_local += payload->len;
    }
    *offset = current_offset_local;
    return SUCCESS;
}

status_t ipc_deserialize_client_request_task(const char *label, ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_client_request_task) {
        LOG_ERROR("%sInvalid input pointers.", label);
        return FAILURE;
    }
    size_t current_offset = *offset_ptr;
    const uint8_t *cursor = buffer + current_offset;
    ipc_client_request_task_t *payload = p->payload.ipc_client_request_task;
    if (current_offset + IP_ADDRESS_LEN > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading ip.", label);
        return FAILURE_OOBUF;
    }
    memcpy(payload->ip, cursor, IP_ADDRESS_LEN);
    cursor += IP_ADDRESS_LEN;
    current_offset += IP_ADDRESS_LEN;
    if (current_offset + sizeof(uint16_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading len.", label);
        return FAILURE_OOBUF;
    }
    uint16_t len_be;
    memcpy(&len_be, cursor, sizeof(uint16_t));
    payload->len = be16toh(len_be);
    cursor += sizeof(uint16_t);
    current_offset += sizeof(uint16_t);
//======================================================================
// Penjelasan tentang FAM dalam protocol ipc hanya akan ada di file ini
// Karena IPC_CLIENT_REQUEST_TASK adalah ipc protocol pertama yang memakai FAM
// Tujuan: Untuk memahami/memudahkan/konsistensi team dalam pengembangan protocol ipc
// 1. len adalah panjang dari data
// 2. data adalah FAM / Flexible Array Member
// 3. Member FAM harus berada di akhir struct
// 4. Untuk memudahkan/konsistensi team dalam pengembangan protocol ipc. dibuat aturan
//    - setiap FAM diberi nama data
//    - setiap FAM harus di awali dengan len
//    - jika FAM adalah gabungan data, harus ada len(2 byte/uint16_t) sebagai totalpanjang
//    - diikuti len_xxx sebagai len detail. contoh:
//
//      uint16_t len;
//      uint16_t len_publickey;
//      uint16_t len_signature;
//      uint8_t data[]; <============ Flexible
//======================================================================
// typedef struct {
//     uint8_t ip[IP_ADDRESS_LEN];
//     uint16_t len;
//     uint8_t data[]; <============ Flexible
// } ipc_client_request_task_t;
//======================================================================
    if (payload->len > 0) {
        if (current_offset + payload->len > total_buffer_len) {
            LOG_ERROR("%sInsufficient buffer for actual data. Expected %hu, available %zu.",
                    label, payload->len, total_buffer_len - current_offset);
            return FAILURE_OOBUF;
        }
        memcpy(payload->data, cursor, payload->len);
        cursor += payload->len;
        current_offset += payload->len;
    }
    *offset_ptr = current_offset;
    return SUCCESS;
}

ipc_protocol_t_status_t ipc_prepare_cmd_client_request_task(const char *label, int *fd_to_close, uint8_t client_ip_for_request[], uint16_t data_len, uint8_t *data) {
	ipc_protocol_t_status_t result;
	result.r_ipc_protocol_t = (ipc_protocol_t *)malloc(sizeof(ipc_protocol_t));
	result.status = FAILURE;
	if (!result.r_ipc_protocol_t) {
		LOG_ERROR("%sFailed to allocate ipc_protocol_t. %s", label, strerror(errno));
		CLOSE_FD(fd_to_close);
		return result;
	}
	memset(result.r_ipc_protocol_t, 0, sizeof(ipc_protocol_t));
	result.r_ipc_protocol_t->version[0] = IPC_VERSION_MAJOR;
	result.r_ipc_protocol_t->version[1] = IPC_VERSION_MINOR;
	result.r_ipc_protocol_t->type = IPC_CLIENT_REQUEST_TASK;
	ipc_client_request_task_t *payload = (ipc_client_request_task_t *)calloc(1, sizeof(ipc_client_request_task_t) + data_len);
	if (!payload) {
		LOG_ERROR("%sFailed to allocate ipc_client_request_task_t payload. %s", label, strerror(errno));
		CLOSE_FD(fd_to_close);
		CLOSE_IPC_PROTOCOL(&result.r_ipc_protocol_t);
		return result;
	}
	memcpy(payload->ip, client_ip_for_request, IP_ADDRESS_LEN);
	payload->len = data_len;
	if (data_len > 0 && data) memcpy(payload->data, data, data_len);
	result.r_ipc_protocol_t->payload.ipc_client_request_task = payload;
	result.status = SUCCESS;
	return result;
}
