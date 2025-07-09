#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <string.h>      // for memset, strncpy
#include <endian.h>
#include <stdint.h>

#include "commons.h"
#include "ipc/protocol.h"
#include "types.h"
#include "ipc/logic_response.h"

status_t ipc_serialize_logic_response(const ipc_logic_response_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        return FAILURE;
    }

    size_t current_offset_local = *offset;

    // Salin Len
    if (CHECK_BUFFER_BOUNDS_NO_RETURN(current_offset_local, sizeof(uint16_t), buffer_size)) return FAILURE_OOBUF;
    uint16_t len_be = htobe16(payload->len);
    memcpy(current_buffer + current_offset_local, &len_be, sizeof(uint16_t));
    current_offset_local += sizeof(uint16_t);

    // Salin Data
    if (payload->len > 0) {
        if (CHECK_BUFFER_BOUNDS_NO_RETURN(current_offset_local, payload->len, buffer_size)) return FAILURE_OOBUF;
        memcpy(current_buffer + current_offset_local, payload->data, payload->len);
        current_offset_local += payload->len;
    }

    *offset = current_offset_local;
    return SUCCESS;
}

status_t ipc_deserialize_logic_response(ipc_protocol_t *p, const uint8_t *buffer, size_t total_buffer_len, size_t *offset_ptr) {
    // Validasi Pointer Input
    if (!p || !buffer || !offset_ptr || !p->payload.ipc_logic_response) {
        fprintf(stderr, "[ipc_deserialize_logic_response Error]: Invalid input pointers.\n");
        return FAILURE;
    }

    size_t current_offset = *offset_ptr; // Ambil offset dari pointer input
    const uint8_t *cursor = buffer + current_offset;
    ipc_logic_response_t *payload = p->payload.ipc_logic_response; // Payload spesifik yang akan diisi (STRUCT DENGAN FAM)

    fprintf(stderr, "==========================================================Panjang offset_ptr AWAL: %ld\n", (long)(cursor - buffer));

    // 2. Deserialisasi len (uint16_t - panjang data aktual)
    if (current_offset + sizeof(uint16_t) > total_buffer_len) {
        fprintf(stderr, "[ipc_deserialize_logic_response Error]: Out of bounds reading data length.\n");
        return FAILURE_OOBUF;
    }
    uint16_t len_be;
    memcpy(&len_be, cursor, sizeof(uint16_t));
    payload->len = be16toh(len_be);
    cursor += sizeof(uint16_t);
    current_offset += sizeof(uint16_t);

    // 3. Salin data aktual (variable length) ke FAM
    if (payload->len > 0) {
        // PERIKSA ruang yang tersisa di buffer input.
        // TIDAK perlu `malloc` di sini karena `payload->data` adalah FAM
        // dan memori untuknya sudah dialokasikan oleh `ipc_deserialize`.
        if (current_offset + payload->len > total_buffer_len) {
            fprintf(stderr, "[ipc_deserialize_logic_response Error]: Insufficient buffer for actual data. Expected %hu, available %zu.\n",
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
