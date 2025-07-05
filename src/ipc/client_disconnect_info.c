#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy
#include <endian.h>
#include <stdint.h>

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
