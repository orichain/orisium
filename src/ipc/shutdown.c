#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy
#include <stdint.h>
#include <stdlib.h>

#include "commons.h"
#include "ipc/protocol.h"
#include "types.h"
#include "ipc/shutdown.h"

status_t ipc_serialize_shutdown(const ipc_shutdown_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        return FAILURE;
    }

    size_t current_offset_local = *offset;

    // Salin type
    if (CHECK_BUFFER_BOUNDS_NO_RETURN(current_offset_local, 1, buffer_size)) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->flag, 1);
    current_offset_local += 1;

    *offset = current_offset_local;
    return SUCCESS;
}

status_t ipc_deserialize_shutdown(ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    // Validasi Pointer Input
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_shutdown) {
        fprintf(stderr, "[ipc_deserialize_shutdown Error]: Invalid input pointers.\n");
        return FAILURE;
    }

    size_t current_offset = *offset_ptr; // Ambil offset dari pointer input
    const uint8_t *cursor = buffer + current_offset;
    ipc_shutdown_t *payload = p->payload.ipc_shutdown; // Payload spesifik yang akan diisi (STRUCT DENGAN FAM)

    fprintf(stderr, "==========================================================Panjang offset_ptr AWAL: %ld\n", (long)(cursor - buffer));

    // 1. Deserialisasi type
    if (current_offset + 1 > total_buffer_len) {
        fprintf(stderr, "[ipc_deserialize_shutdown Error]: Out of bounds reading correlation_id.\n");
        return FAILURE_OOBUF;
    }
    memcpy(payload->flag, cursor, 1);
    cursor += 1;
    current_offset += 1;
    
    *offset_ptr = current_offset;

    fprintf(stderr, "==========================================================Panjang offset_ptr AKHIR: %ld\n", (long)*offset_ptr);
    
    return SUCCESS;
}

ipc_protocol_t_status_t ipc_prepare_cmd_shutdown(int *fd_to_close) {
	ipc_protocol_t_status_t result;
	result.r_ipc_protocol_t = (ipc_protocol_t *)malloc(sizeof(ipc_protocol_t));
	result.status = FAILURE;
	if (!result.r_ipc_protocol_t) {
		perror("Failed to allocate ipc_protocol_t protocol");
		//CLOSE_FD(client_sock);
		CLOSE_FD(*fd_to_close);
		return result;
	}
	memset(result.r_ipc_protocol_t, 0, sizeof(ipc_protocol_t)); // Inisialisasi dengan nol
	result.r_ipc_protocol_t->version[0] = VERSION_MAJOR;
	result.r_ipc_protocol_t->version[1] = VERSION_MINOR;
	result.r_ipc_protocol_t->type = IPC_SHUTDOWN;
	ipc_shutdown_t *payload = (ipc_shutdown_t *)calloc(1, sizeof(ipc_shutdown_t));
	if (!payload) {
		perror("Failed to allocate ipc_shutdown_t payload");
		//CLOSE_FD(client_sock);
		CLOSE_FD(*fd_to_close);
		CLOSE_IPC_PROTOCOL(result.r_ipc_protocol_t);
		return result;
	}
	payload->flag[0] = (uint8_t)0x01;
	result.r_ipc_protocol_t->payload.ipc_shutdown = payload;
	result.status = SUCCESS;
	return result;
}
