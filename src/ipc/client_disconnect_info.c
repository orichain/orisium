#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>

#include "commons.h"
#include "ipc/protocol.h"
#include "types.h"
#include "ipc/client_disconnect_info.h"

status_t ipc_deserialize_client_disconnect_info(ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    // Validasi Pointer Input
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_client_request_task) {
        fprintf(stderr, "[ipc_deserialize_client_disconnect_info Error]: Invalid input pointers.\n");
        return FAILURE;
    }

    size_t current_offset = *offset_ptr; // Ambil offset dari pointer input
    const uint8_t *cursor = buffer + current_offset;
    ipc_client_disconnect_info_t *payload = p->payload.ipc_client_disconnect_info; // Payload spesifik yang akan diisi (STRUCT DENGAN FAM)

    fprintf(stderr, "==========================================================Panjang offset_ptr AWAL: %ld\n", (long)(cursor - buffer));

    // 1. Deserialisasi correlation_id (uint64_t)
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        fprintf(stderr, "[ipc_deserialize_client_disconnect_info Error]: Out of bounds reading correlation_id.\n");
        return FAILURE_OOBUF;
    }
    uint64_t correlation_id_be;
    memcpy(&correlation_id_be, cursor, sizeof(uint64_t));
    payload->correlation_id = be64toh(correlation_id_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);
    
    // 2. Deserialisasi ip (INET6_ADDRSTRLEN)
    if (current_offset + INET6_ADDRSTRLEN > total_buffer_len) {
        fprintf(stderr, "[ipc_deserialize_client_disconnect_info Error]: Out of bounds reading correlation_id.\n");
        return FAILURE_OOBUF;
    }
    memcpy(payload->ip, cursor, INET6_ADDRSTRLEN);
    cursor += INET6_ADDRSTRLEN;
    current_offset += INET6_ADDRSTRLEN;
    *offset_ptr = current_offset;

    fprintf(stderr, "==========================================================Panjang offset_ptr AKHIR: %ld\n", (long)*offset_ptr);
    
    return SUCCESS;
}

status_t ipc_serialize_client_disconnect_info(const ipc_client_disconnect_info_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        return FAILURE;
    }

    size_t current_offset_local = *offset;

    // Salin Correlation ID (big-endian)
    if (CHECK_BUFFER_BOUNDS_NO_RETURN(current_offset_local, sizeof(uint64_t), buffer_size)) return FAILURE_OOBUF;
    uint64_t correlation_id_be = htobe64(payload->correlation_id);
    memcpy(current_buffer + current_offset_local, &correlation_id_be, sizeof(uint64_t));
    current_offset_local += sizeof(uint64_t);
    
    // Salin ip (INET6_ADDRSTRLEN)
    if (CHECK_BUFFER_BOUNDS_NO_RETURN(current_offset_local, INET6_ADDRSTRLEN, buffer_size)) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->ip, INET6_ADDRSTRLEN);
    current_offset_local += INET6_ADDRSTRLEN;

    *offset = current_offset_local;
    return SUCCESS;
}

ipc_protocol_t_status_t ipc_prepare_cmd_client_disconnect_info(int *fd_to_close, uint64_t *correlation_id, uint8_t disconnected_client_ip[]) {
	ipc_protocol_t *p = (ipc_protocol_t *)malloc(sizeof(ipc_protocol_t));
	ipc_protocol_t_status_t result;
	result.status = FAILURE;
	result.r_ipc_protocol_t = p;
	if (!p) {
		perror("Failed to allocate ipc_protocol_t protocol");
		//CLOSE_FD(client_sock);
		CLOSE_FD(*fd_to_close);
		return result;
	}
	memset(p, 0, sizeof(ipc_protocol_t)); // Inisialisasi dengan nol
	p->version[0] = VERSION_MAJOR;
	p->version[1] = VERSION_MINOR;
	p->type = IPC_CLIENT_DISCONNECTED;
	ipc_client_disconnect_info_t *payload = (ipc_client_disconnect_info_t *)calloc(1, sizeof(ipc_client_disconnect_info_t));
	if (!payload) {
		perror("Failed to allocate ipc_client_disconnect_info_t payload");
		//CLOSE_FD(client_sock);
		CLOSE_FD(*fd_to_close);
		CLOSE_IPC_PROTOCOL(p);
		return result;
	}
	payload->correlation_id = *correlation_id; // Cast ke uint64_t
	memcpy(payload->ip, disconnected_client_ip, INET6_ADDRSTRLEN);				
	p->payload.ipc_client_disconnect_info = payload;
	result.status = SUCCESS;
	return result;
}
