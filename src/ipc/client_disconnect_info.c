#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy
#include <stdint.h>
#include <stdlib.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "ipc/client_disconnect_info.h"
#include "constants.h"

status_t ipc_serialize_client_disconnect_info(const ipc_client_disconnect_info_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        return FAILURE;
    }

    size_t current_offset_local = *offset;

    if (CHECK_BUFFER_BOUNDS(current_offset_local, IP_ADDRESS_LEN, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->ip, IP_ADDRESS_LEN);
    current_offset_local += IP_ADDRESS_LEN;

    *offset = current_offset_local;
    return SUCCESS;
}

status_t ipc_deserialize_client_disconnect_info(ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    // Validasi Pointer Input
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_client_disconnect_info) {
        fprintf(stderr, "[ipc_deserialize_client_disconnect_info Error]: Invalid input pointers.\n");
        return FAILURE;
    }

    size_t current_offset = *offset_ptr; // Ambil offset dari pointer input
    const uint8_t *cursor = buffer + current_offset;
    ipc_client_disconnect_info_t *payload = p->payload.ipc_client_disconnect_info; // Payload spesifik yang akan diisi (STRUCT DENGAN FAM)

    fprintf(stderr, "==========================================================Panjang offset_ptr AWAL: %ld\n", (long)(cursor - buffer));

    // 2. Deserialisasi ip (IP_ADDRESS_LEN)
    if (current_offset + IP_ADDRESS_LEN > total_buffer_len) {
        fprintf(stderr, "[ipc_deserialize_client_disconnect_info Error]: Out of bounds reading correlation_id.\n");
        return FAILURE_OOBUF;
    }
    memcpy(payload->ip, cursor, IP_ADDRESS_LEN);
    cursor += IP_ADDRESS_LEN;
    current_offset += IP_ADDRESS_LEN;
    *offset_ptr = current_offset;

    fprintf(stderr, "==========================================================Panjang offset_ptr AKHIR: %ld\n", (long)*offset_ptr);
    
    return SUCCESS;
}

ipc_protocol_t_status_t ipc_prepare_cmd_client_disconnect_info(int *fd_to_close, uint8_t disconnected_client_ip[]) {
	ipc_protocol_t_status_t result;
	result.r_ipc_protocol_t = (ipc_protocol_t *)malloc(sizeof(ipc_protocol_t));
	result.status = FAILURE;
	if (!result.r_ipc_protocol_t) {
		perror("Failed to allocate ipc_protocol_t protocol");
		CLOSE_FD(fd_to_close);
		return result;
	}
	memset(result.r_ipc_protocol_t, 0, sizeof(ipc_protocol_t)); // Inisialisasi dengan nol
	result.r_ipc_protocol_t->version[0] = IPC_VERSION_MAJOR;
	result.r_ipc_protocol_t->version[1] = IPC_VERSION_MINOR;
	result.r_ipc_protocol_t->type = IPC_CLIENT_DISCONNECTED;
	ipc_client_disconnect_info_t *payload = (ipc_client_disconnect_info_t *)calloc(1, sizeof(ipc_client_disconnect_info_t));
	if (!payload) {
		perror("Failed to allocate ipc_client_disconnect_info_t payload");
		CLOSE_FD(fd_to_close);
		CLOSE_IPC_PROTOCOL(&result.r_ipc_protocol_t);
		return result;
	}
	memcpy(payload->ip, disconnected_client_ip, IP_ADDRESS_LEN);				
	result.r_ipc_protocol_t->payload.ipc_client_disconnect_info = payload;
	result.status = SUCCESS;
	return result;
}
