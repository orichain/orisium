#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "ipc/client_request_task.h"
#include "constants.h"

status_t ipc_serialize_client_request_task(const ipc_client_request_task_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        return FAILURE;
    }

    size_t current_offset_local = *offset;

    // Salin ip (IP_ADDRESS_LEN)
    if (CHECK_BUFFER_BOUNDS(current_offset_local, IP_ADDRESS_LEN, buffer_size) != SUCCESS) return FAILURE_OOBUF;
    memcpy(current_buffer + current_offset_local, payload->ip, IP_ADDRESS_LEN);
    current_offset_local += IP_ADDRESS_LEN;

    // Salin Len
    if (CHECK_BUFFER_BOUNDS(current_offset_local, sizeof(uint16_t), buffer_size) != SUCCESS) return FAILURE_OOBUF;
    uint16_t len_be = htobe16(payload->len);
    memcpy(current_buffer + current_offset_local, &len_be, sizeof(uint16_t));
    current_offset_local += sizeof(uint16_t);

    // Salin Data
    if (payload->len > 0) {
        if (CHECK_BUFFER_BOUNDS(current_offset_local, payload->len, buffer_size) != SUCCESS) return FAILURE_OOBUF;
        memcpy(current_buffer + current_offset_local, payload->data, payload->len);
        current_offset_local += payload->len;
    }

    *offset = current_offset_local;
    return SUCCESS;
}

status_t ipc_deserialize_client_request_task(ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    // Validasi Pointer Input
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_client_request_task) {
        fprintf(stderr, "[ipc_deserialize_client_request_task Error]: Invalid input pointers.\n");
        return FAILURE;
    }

    size_t current_offset = *offset_ptr; // Ambil offset dari pointer input
    const uint8_t *cursor = buffer + current_offset;
    ipc_client_request_task_t *payload = p->payload.ipc_client_request_task; // Payload spesifik yang akan diisi (STRUCT DENGAN FAM)

    fprintf(stderr, "==========================================================Panjang offset_ptr AWAL: %ld\n", (long)(cursor - buffer));

    // 2. Deserialisasi ip (IP_ADDRESS_LEN)
    if (current_offset + IP_ADDRESS_LEN > total_buffer_len) {
        fprintf(stderr, "[ipc_deserialize_client_request_task Error]: Out of bounds reading correlation_id.\n");
        return FAILURE_OOBUF;
    }
    memcpy(payload->ip, cursor, IP_ADDRESS_LEN);
    cursor += IP_ADDRESS_LEN;
    current_offset += IP_ADDRESS_LEN;

    // 3. Deserialisasi len (uint16_t - panjang data aktual)
    if (current_offset + sizeof(uint16_t) > total_buffer_len) {
        fprintf(stderr, "[ipc_deserialize_client_request_task Error]: Out of bounds reading data length.\n");
        return FAILURE_OOBUF;
    }
    uint16_t len_be;
    memcpy(&len_be, cursor, sizeof(uint16_t));
    payload->len = be16toh(len_be);
    cursor += sizeof(uint16_t);
    current_offset += sizeof(uint16_t);

    // 4. Salin data aktual (variable length) ke FAM
    if (payload->len > 0) {
        // PERIKSA ruang yang tersisa di buffer input.
        // TIDAK perlu `malloc` di sini karena `payload->data` adalah FAM
        // dan memori untuknya sudah dialokasikan oleh `ipc_deserialize`.
        if (current_offset + payload->len > total_buffer_len) {
            fprintf(stderr, "[ipc_deserialize_client_request_task Error]: Insufficient buffer for actual data. Expected %hu, available %zu.\n",
                    payload->len, total_buffer_len - current_offset);
            // Karena ini FAM, tidak bisa di-NULL-kan. Cukup kembalikan error.
            return FAILURE_OOBUF;
        }

        // Salin data aktual dari buffer input ke FAM `payload->data`
        memcpy(payload->data, cursor, payload->len);
        cursor += payload->len;
        current_offset += payload->len;
    } else {
        // Jika payload->len adalah 0, tidak ada data untuk disalin.
        // Tidak perlu mengatur `payload->data = NULL;` karena itu adalah FAM, bukan pointer.
    }

    *offset_ptr = current_offset; // Perbarui offset pointer untuk pemanggil (ipc_deserialize)

    fprintf(stderr, "==========================================================Panjang offset_ptr AKHIR: %ld\n", (long)*offset_ptr);

    return SUCCESS;
}

ipc_protocol_t_status_t ipc_prepare_cmd_client_request_task(int *fd_to_close, uint8_t client_ip_for_request[], uint16_t data_len, uint8_t *data) {
	ipc_protocol_t_status_t result;
	result.r_ipc_protocol_t = (ipc_protocol_t *)malloc(sizeof(ipc_protocol_t));
	result.status = FAILURE;
	if (!result.r_ipc_protocol_t) {
		perror("Failed to allocate ipc_protocol_t protocol");
		if (*fd_to_close != -1) {
			CLOSE_FD(fd_to_close);
		}
		return result;
	}
	memset(result.r_ipc_protocol_t, 0, sizeof(ipc_protocol_t)); // Inisialisasi dengan nol
	result.r_ipc_protocol_t->version[0] = IPC_VERSION_MAJOR;
	result.r_ipc_protocol_t->version[1] = IPC_VERSION_MINOR;
	result.r_ipc_protocol_t->type = IPC_CLIENT_REQUEST_TASK;
	ipc_client_request_task_t *payload = (ipc_client_request_task_t *)calloc(1, sizeof(ipc_client_request_task_t) + data_len);
	if (!payload) {
		perror("Failed to allocate ipc_client_request_task_t payload");
		if (*fd_to_close != -1) {
			CLOSE_FD(fd_to_close);
		}
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
