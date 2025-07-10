#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <string.h>      // for memset, strncpy
#include <sys/socket.h>  // for socketpair, SOCK_STREAM, AF_UNIX, AF_INET, accept
#include <sys/types.h>   // for pid_t, ssize_t
#include <endian.h>
#include <stdint.h>
#include <sys/uio.h>

#include "utilities.h"
#include "ipc/protocol.h"
#include "types.h"
#include "ipc/client_disconnect_info.h"
#include "ipc/client_request_task.h"
#include "ipc/shutdown.h"
#include "ipc/heartbeat.h"
#include "constants.h"

static inline size_t_status_t calculate_ipc_payload_size(const ipc_protocol_t* p) {
	size_t_status_t result;
    result.r_size_t = 0;
    result.status = FAILURE;
    size_t payload_fixed_size = 0;
    size_t payload_dynamic_size = 0;
    // 1. Hitung total_required_size dengan aman
    switch (p->type) {
        case IPC_CLIENT_REQUEST_TASK: {
            if (!p->payload.ipc_client_request_task) {
                fprintf(stderr, "[ipc_serialize Error]: IPC_CLIENT_REQUEST_TASK payload is NULL.\n");
                result.status = FAILURE; // Atur status hasil ke FAILURE
                return result;
            }
            payload_fixed_size = IP_ADDRESS_LEN + sizeof(uint16_t);
            payload_dynamic_size = p->payload.ipc_client_request_task->len;
            break;
        }
        case IPC_CLIENT_DISCONNECTED: {
			if (!p->payload.ipc_client_disconnect_info) {
                fprintf(stderr, "[ipc_serialize Error]: IPC_CLIENT_DISCONNECTED payload is NULL.\n");
                result.status = FAILURE; // Atur status hasil ke FAILURE
                return result;
            }
            payload_fixed_size = IP_ADDRESS_LEN;
            payload_dynamic_size = 0;
            break;
		}
		case IPC_SHUTDOWN: {
            if (!p->payload.ipc_shutdown) {
                fprintf(stderr, "[ipc_serialize Error]: IPC_SHUTDOWN payload is NULL.\n");
                result.status = FAILURE; // Atur status hasil ke FAILURE
                return result;
            }
            payload_fixed_size = 1;
            payload_dynamic_size = 0;
            break;
        }
        case IPC_HEARTBEAT: {
            if (!p->payload.ipc_heartbeat) {
                fprintf(stderr, "[ipc_serialize Error]: IPC_SHUTDOWN payload is NULL.\n");
                result.status = FAILURE; // Atur status hasil ke FAILURE
                return result;
            }
            payload_fixed_size = 2;
            payload_dynamic_size = 0;
            break;
        }
        default:
            fprintf(stderr, "[ipc_serialize Error]: Unknown message type for serialization: 0x%02x.\n", p->type);
            result.status = FAILURE_IPYLD;
            return result;
    }
    result.r_size_t = IPC_VERSION_BYTES + sizeof(ipc_protocol_type_t) + payload_fixed_size + payload_dynamic_size;
    result.status = SUCCESS;
    return result;
}

ssize_t_status_t ipc_serialize(const ipc_protocol_t* p, uint8_t** ptr_buffer, size_t* buffer_size) {
    ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;

    if (!p || !ptr_buffer || !buffer_size) {
        return result;
    }
    
    size_t_status_t psize = calculate_ipc_payload_size(p);
    if (psize.status != SUCCESS) {
		result.status = psize.status;
		return result;
	}

    size_t total_required_size = psize.r_size_t;

    if (total_required_size == 0) {
        fprintf(stderr, "[ipc_serialize Error]: Calculated required size is 0.\n");
        result.status = FAILURE;
        return result;
    }

    uint8_t* current_buffer = *ptr_buffer;
    if (current_buffer == NULL || *buffer_size < total_required_size) {
        printf("Allocating/resizing buffer. Old size: %zu, Required: %zu\n", *buffer_size, total_required_size);
        uint8_t* new_buffer = realloc(current_buffer, total_required_size);
        if (!new_buffer) {
            perror("Error reallocating buffer for serialization");
            result.status = FAILURE_NOMEM; // Set status NOMEM
            return result;
        }
        *ptr_buffer = new_buffer;
        current_buffer = new_buffer;
        *buffer_size = total_required_size;
    } else {
        printf("Buffer size %zu is sufficient for %zu bytes. No reallocation needed.\n", *buffer_size, total_required_size);
    }

    size_t offset = 0;

    if (CHECK_BUFFER_BOUNDS(offset, IPC_VERSION_BYTES, *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, p->version, IPC_VERSION_BYTES);
    offset += IPC_VERSION_BYTES;

    if (CHECK_BUFFER_BOUNDS(offset, sizeof(ipc_protocol_type_t), *buffer_size) != SUCCESS) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    current_buffer[offset] = (uint8_t)p->type;
    offset += sizeof(ipc_protocol_type_t);

    status_t result_pyld = FAILURE;
    switch (p->type) {
        case IPC_CLIENT_REQUEST_TASK:
            // Panggil ipc_serialize_client_request_task tanpa required_size
            result_pyld = ipc_serialize_client_request_task(p->payload.ipc_client_request_task, current_buffer, *buffer_size, &offset);
            break;
        case IPC_CLIENT_DISCONNECTED:
            // Panggil ipc_serialize_client_disconnect_info tanpa required_size
            result_pyld = ipc_serialize_client_disconnect_info(p->payload.ipc_client_disconnect_info, current_buffer, *buffer_size, &offset);
            break;
        case IPC_SHUTDOWN:
            // Panggil ipc_serialize_shutdown tanpa required_size
            result_pyld = ipc_serialize_shutdown(p->payload.ipc_shutdown, current_buffer, *buffer_size, &offset);
            break;
        case IPC_HEARTBEAT:
            // Panggil ipc_serialize_hearbeat tanpa required_size
            result_pyld = ipc_serialize_heartbeat(p->payload.ipc_heartbeat, current_buffer, *buffer_size, &offset);
            break;
        default:
            fprintf(stderr, "[ipc_serialize Error]: Unexpected message type in switch for serialization: 0x%02x.\n", p->type);
            result.status = FAILURE_IPYLD;
            return result;
    }

    if (result_pyld != SUCCESS) {
        fprintf(stderr, "[ipc_serialize Error]: Payload serialization failed with status %d.\n", result_pyld);
        result.status = FAILURE_IPYLD;
        return result;
    }

    result.r_ssize_t = (ssize_t)offset;
    result.status = SUCCESS;
    return result;
}

ipc_protocol_t_status_t ipc_deserialize(const uint8_t* buffer, size_t len) {
    ipc_protocol_t_status_t result;
    result.r_ipc_protocol_t = NULL;
    result.status = FAILURE;

    // Pengecekan dasar buffer
    if (!buffer || len < (IPC_VERSION_BYTES + sizeof(ipc_protocol_type_t))) {
        fprintf(stderr, "[ipc_deserialize Error]: Buffer terlalu kecil untuk Version dan Type. Len: %zu\n", len);
        result.status = FAILURE_OOBUF;
        return result;
    }

    // Alokasikan hanya struktur ipc_protocol_t utama terlebih dahulu.
    // Ini hanya mengalokasikan fixed size dari ipc_protocol_t, termasuk pointer di dalamnya.
    ipc_protocol_t* p = (ipc_protocol_t*)calloc(1, sizeof(ipc_protocol_t));
    if (!p) {
        perror("ipc_deserialize: Failed to allocate ipc_protocol_t");
        result.status = FAILURE_NOMEM;
        return result;
    }
    fprintf(stderr, "Allocating ipc_protocol_t struct: %zu bytes\n", sizeof(ipc_protocol_t));

    // Salin Version dan Type
    memcpy(p->version, buffer, IPC_VERSION_BYTES);
    p->type = (ipc_protocol_type_t)buffer[IPC_VERSION_BYTES];
    size_t current_buffer_offset = IPC_VERSION_BYTES + sizeof(ipc_protocol_type_t); // Offset awal payload

    fprintf(stderr, "[ipc_deserialize Debug]: Deserializing type 0x%02x. Current offset: %zu\n", p->type, current_buffer_offset);

    status_t result_pyld = FAILURE;
    switch (p->type) {
        case IPC_CLIENT_REQUEST_TASK: {
            if (current_buffer_offset + IP_ADDRESS_LEN + sizeof(uint16_t) > len) {
                fprintf(stderr, "[ipc_deserialize Error]: Buffer terlalu kecil untuk IPC_CLIENT_REQUEST_TASK fixed header.\n");
                CLOSE_IPC_PROTOCOL(&p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            uint16_t raw_data_len_be;
            memcpy(&raw_data_len_be, buffer + current_buffer_offset + IP_ADDRESS_LEN, sizeof(uint16_t));
            uint16_t actual_data_len = be16toh(raw_data_len_be);
            ipc_client_request_task_t *task_payload = (ipc_client_request_task_t*) calloc(1, sizeof(ipc_client_request_task_t) + actual_data_len);
            if (!task_payload) {
                perror("ipc_deserialize: Failed to allocate ipc_client_request_task_t with FAM");
                CLOSE_IPC_PROTOCOL(&p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_client_request_task = task_payload;
            result_pyld = ipc_deserialize_client_request_task(p, buffer, len, &current_buffer_offset);
            break;
        }
        case IPC_CLIENT_DISCONNECTED: {
			if (current_buffer_offset + IP_ADDRESS_LEN > len) {
                fprintf(stderr, "[ipc_deserialize Error]: Buffer terlalu kecil untuk IPC_CLIENT_DISCONNECTED fixed header.\n");
                CLOSE_IPC_PROTOCOL(&p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_client_disconnect_info_t *disconnect_info_payload = (ipc_client_disconnect_info_t*) calloc(1, sizeof(ipc_client_disconnect_info_t));
            if (!disconnect_info_payload) {
                perror("ipc_deserialize: Failed to allocate ipc_client_disconnect_info_t without FAM");
                CLOSE_IPC_PROTOCOL(&p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_client_disconnect_info = disconnect_info_payload;
            result_pyld = ipc_deserialize_client_disconnect_info(p, buffer, len, &current_buffer_offset);
            break;
		}
		case IPC_SHUTDOWN: {
			if (current_buffer_offset + 1 > len) {
                fprintf(stderr, "[ipc_deserialize Error]: Buffer terlalu kecil untuk IPC_SHUTDOWN fixed header.\n");
                CLOSE_IPC_PROTOCOL(&p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_shutdown_t *task_payload = (ipc_shutdown_t*) calloc(1, sizeof(ipc_shutdown_t));
            if (!task_payload) {
                perror("ipc_deserialize: Failed to allocate ipc_shutdown_t without FAM");
                CLOSE_IPC_PROTOCOL(&p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_shutdown = task_payload;
            result_pyld = ipc_deserialize_shutdown(p, buffer, len, &current_buffer_offset);
            break;
		}
        case IPC_HEARTBEAT: {
			if (current_buffer_offset + 2 > len) {
                fprintf(stderr, "[ipc_deserialize Error]: Buffer terlalu kecil untuk IPC_HEARTBEAT fixed header.\n");
                CLOSE_IPC_PROTOCOL(&p);
                result.status = FAILURE_OOBUF;
                return result;
            }
            ipc_heartbeat_t *task_payload = (ipc_heartbeat_t*) calloc(1, sizeof(ipc_heartbeat_t));
            if (!task_payload) {
                perror("ipc_deserialize: Failed to allocate ipc_heartbeat_t without FAM");
                CLOSE_IPC_PROTOCOL(&p);
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_heartbeat = task_payload;
            result_pyld = ipc_deserialize_heartbeat(p, buffer, len, &current_buffer_offset);
            break;
		}
        default:
            fprintf(stderr, "[ipc_deserialize Error]: Unknown message type 0x%02x.\n", p->type);
            result.status = FAILURE_IPYLD;
            CLOSE_IPC_PROTOCOL(&p);
            return result;
    }
    if (result_pyld != SUCCESS) {
        fprintf(stderr, "[ipc_deserialize Error]: Payload deserialization failed with status %d.\n", result_pyld);        
        CLOSE_IPC_PROTOCOL(&p);
        result.status = FAILURE_IPYLD;
        return result;
    }
    result.r_ipc_protocol_t = p;
    result.status = SUCCESS;
    fprintf(stderr, "[ipc_deserialize Debug]: ipc_deserialize BERHASIL.\n");
    return result;
}

ssize_t_status_t send_ipc_protocol_message(int *uds_fd, const ipc_protocol_t* p, int *fd_to_pass) {
	ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;
    
    uint8_t* serialized_ipc_data_buffer = NULL; // Ini akan berisi Version + Type + Payload
    size_t serialized_ipc_data_len = 0; // Ini adalah panjang dari buffer di atas

    // 1. Panggil ipc_serialize untuk mendapatkan data yang diserialisasi
    // Hasil dari ipc_serialize adalah data mulai dari IPC_VERSION_BYTES + ipc_protocol_type_t + actual_payload
    ssize_t_status_t serialize_result = ipc_serialize(p, &serialized_ipc_data_buffer, &serialized_ipc_data_len);

    if (serialize_result.status != SUCCESS) {
        fprintf(stderr, "[send_ipc_protocol_message Debug]: Error serializing IPC message: %d\n", serialize_result.status);
        if (serialized_ipc_data_buffer) { // Penting: bebaskan buffer jika ada alokasi yang terjadi sebelum error
            free(serialized_ipc_data_buffer);
        }
        return result;
    }

    // `serialized_ipc_data_len` sekarang adalah panjang data IPC yang sebenarnya (versi + tipe + payload)
    // `serialized_ipc_data_buffer` berisi data mentah tersebut

    // 2. Hitung total panjang buffer yang akan DIKIRIMkan (Length Prefix + Serialized IPC Data)
    size_t total_message_len_to_send = IPC_LENGTH_PREFIX_BYTES + serialized_ipc_data_len;

    // 3. Alokasikan buffer baru untuk seluruh pesan, termasuk length prefix
    uint8_t *final_send_buffer = (uint8_t *)malloc(total_message_len_to_send);
    if (!final_send_buffer) {
        perror("send_ipc_protocol_message: malloc failed for final_send_buffer");
        // Jangan lupa bebaskan buffer dari ipc_serialize
        if (serialized_ipc_data_buffer) {
            free(serialized_ipc_data_buffer);
        }
        return result;
    }

    size_t offset = 0;

    // 4. Tulis Length Prefix (panjang data IPC, dalam big-endian)
    uint32_t ipc_protocol_data_len_be = htobe32((uint32_t)serialized_ipc_data_len); // Cast ke uint32_t
    memcpy(final_send_buffer + offset, &ipc_protocol_data_len_be, IPC_LENGTH_PREFIX_BYTES);
    offset += IPC_LENGTH_PREFIX_BYTES;

    // 5. Salin data IPC yang sudah diserialisasi ke buffer akhir
    memcpy(final_send_buffer + offset, serialized_ipc_data_buffer, serialized_ipc_data_len);
    // offset += serialized_ipc_data_len; // Tidak perlu karena ini adalah bagian terakhir

    fprintf(stderr, "[send_ipc_protocol_message Debug]: Total pesan untuk dikirim: %zu byte (Prefix %zu + IPC Data %zu).\n",
            total_message_len_to_send, IPC_LENGTH_PREFIX_BYTES, serialized_ipc_data_len);

    // 6. Panggil send_ipc_message dengan buffer yang sudah lengkap dan panjangnya
    // send_ipc_message asli Anda akan sangat sederhana, hanya menerima buffer dan panjang
    // dan mengirimkannya. IPC_msg_header_t di send_ipc_message lama Anda tidak lagi diperlukan.
    // Kita harus membuat versi baru send_ipc_message yang lebih sederhana untuk ini.
    // Atau, kita bisa memanggil sendmsg langsung di sini. Mari kita panggil sendmsg langsung
    // untuk menghindari kebingungan dengan send_ipc_message lama Anda.
    
    print_hex("===========DEBUG SEND=========", final_send_buffer, total_message_len_to_send, 1);

    // Mengkonfigurasi sendmsg
    struct msghdr msg = {0};
    struct iovec iov[1]; // Hanya satu iovec untuk seluruh buffer
    iov[0].iov_base = final_send_buffer;
    iov[0].iov_len = total_message_len_to_send;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    // Handle FD passing (logika ini sama seperti sebelumnya)
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    if (*fd_to_pass != -1) {
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *((int *) CMSG_DATA(cmsg)) = *fd_to_pass;
        fprintf(stderr, "[send_ipc_protocol_message Debug]: Mengirim FD: %d\n", *fd_to_pass);
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
    }

    // Kirim pesan
    result.r_ssize_t = sendmsg(*uds_fd, &msg, 0);
    if (result.r_ssize_t == -1) {
		perror("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        perror("send_ipc_protocol_message sendmsg");
    } else if (result.r_ssize_t != (ssize_t)total_message_len_to_send) {
        fprintf(stderr, "[send_ipc_protocol_message Debug]: PERINGATAN: sendmsg hanya mengirim %zd dari %zu byte!\n",
                result.r_ssize_t, total_message_len_to_send);
    } else {
        fprintf(stderr, "[send_ipc_protocol_message Debug]: Berhasil mengirim %zd byte.\n", result.r_ssize_t);
    }

    // 7. Bebaskan buffer yang dialokasikan
    
    free(final_send_buffer);
    free(serialized_ipc_data_buffer); // Juga bebaskan dari ipc_serialize
    
    result.status = SUCCESS;
    return result;
}

ipc_protocol_t_status_t receive_and_deserialize_ipc_message(int *uds_fd, int *actual_fd_received) {
    ipc_protocol_t_status_t deserialized_result;
    deserialized_result.r_ipc_protocol_t = NULL;
    deserialized_result.status = FAILURE;

    // Inisialisasi FD yang diterima
    if (actual_fd_received) {
        *actual_fd_received = -1;
    }

    // --- TAHAP 1: Baca SELURUH pesan (Length Prefix + Payload IPC) + FD dengan recvmsg ---
    // Alokasikan buffer untuk panjang maksimum pesan yang Anda harapkan, atau secara dinamis setelah membaca length prefix.
    // Untuk kesederhanaan, kita akan menggunakan pendekatan buffer dua tahap yang lebih aman:
    // Tahap A: Baca 4 byte pertama untuk mendapatkan panjang total.
    // Tahap B: Alokasikan buffer berdasarkan panjang total, lalu baca sisanya + FD.

    uint32_t total_ipc_payload_len_be; // Panjang payload IPC dalam big-endian

    // Buffer sementara untuk 4 byte length prefix
    char temp_len_prefix_buf[IPC_LENGTH_PREFIX_BYTES];

    // Konfigurasi msghdr untuk membaca length prefix dan ancillary data (FD)
    struct msghdr msg_prefix = {0};
    struct iovec iov_prefix[1];
    iov_prefix[0].iov_base = temp_len_prefix_buf;
    iov_prefix[0].iov_len = IPC_LENGTH_PREFIX_BYTES;

    msg_prefix.msg_iov = iov_prefix;
    msg_prefix.msg_iovlen = 1;

    char cmsgbuf_prefix[CMSG_SPACE(sizeof(int))];
    msg_prefix.msg_control = cmsgbuf_prefix;
    msg_prefix.msg_controllen = sizeof(cmsgbuf_prefix);

    fprintf(stderr, "[receive_and_deserialize_ipc_message Debug]: Tahap 1: Membaca length prefix dan potensi FD (%zu byte).\n", IPC_LENGTH_PREFIX_BYTES);
    ssize_t bytes_read_prefix_and_fd = recvmsg(*uds_fd, &msg_prefix, MSG_WAITALL);

    if (bytes_read_prefix_and_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("receive_and_deserialize_ipc_message recvmsg (length prefix + FD)");
        }
        return deserialized_result;
    }

    if (bytes_read_prefix_and_fd != (ssize_t)IPC_LENGTH_PREFIX_BYTES) {
        fprintf(stderr, "[receive_and_deserialize_ipc_message Debug]: ERROR: Gagal membaca length prefix sepenuhnya. Diharapkan %zu byte, diterima %zd.\n",
                IPC_LENGTH_PREFIX_BYTES, bytes_read_prefix_and_fd);
        deserialized_result.status = FAILURE_OOBUF;
        return deserialized_result;
    }

    // Ekstrak FD jika ada dari tahap pertama ini
    struct cmsghdr *cmsg_prefix = CMSG_FIRSTHDR(&msg_prefix);
    if (cmsg_prefix && cmsg_prefix->cmsg_level == SOL_SOCKET && cmsg_prefix->cmsg_type == SCM_RIGHTS && cmsg_prefix->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (actual_fd_received) {
            *actual_fd_received = *((int *) CMSG_DATA(cmsg_prefix));
        }
        fprintf(stderr, "[receive_and_deserialize_ipc_message Debug]: FD diterima: %d\n", *actual_fd_received);
    } else {
        fprintf(stderr, "[receive_and_deserialize_ipc_message Debug]: Tidak ada FD yang diterima dengan length prefix.\n");
    }

    // Konversi panjang dari big-endian ke host byte order
    memcpy(&total_ipc_payload_len_be, temp_len_prefix_buf, IPC_LENGTH_PREFIX_BYTES);
    uint32_t total_ipc_payload_len = be32toh(total_ipc_payload_len_be);
    fprintf(stderr, "[receive_and_deserialize_ipc_message Debug]: Ditemukan panjang payload IPC: %u byte.\n", total_ipc_payload_len);

    // --- TAHAP 2: Alokasikan buffer dinamis dan baca sisa payload IPC ---
    if (total_ipc_payload_len == 0) {
        fprintf(stderr, "[receive_and_deserialize_ipc_message Debug]: Peringatan: Panjang payload IPC adalah 0. Tidak ada data untuk dibaca.\n");
        deserialized_result.status = FAILURE_BAD_PROTOCOL;
        return deserialized_result;
    }

    uint8_t *full_ipc_payload_buffer = (uint8_t *)malloc(total_ipc_payload_len);
    if (!full_ipc_payload_buffer) {
        perror("receive_and_deserialize_ipc_message: malloc failed for full_ipc_payload_buffer");
        deserialized_result.status = FAILURE_NOMEM;
        return deserialized_result;
    }

    // Konfigurasi recvmsg untuk membaca SISA payload (tanpa FD, karena sudah diambil)
    struct msghdr msg_payload = {0};
    struct iovec iov_payload[1];
    iov_payload[0].iov_base = full_ipc_payload_buffer;
    iov_payload[0].iov_len = total_ipc_payload_len;

    msg_payload.msg_iov = iov_payload;
    msg_payload.msg_iovlen = 1;

    // Untuk memastikan tidak ada ancillary data yang tersisa jika FD tidak dikirim dengan prefix
    // Tapi karena sendmsg pengirim mengirimnya sebagai satu blok, seharusnya tidak ada.
    msg_payload.msg_control = NULL;
    msg_payload.msg_controllen = 0;


    fprintf(stderr, "[receive_and_deserialize_ipc_message Debug]: Tahap 2: Membaca %u byte payload IPC.\n", total_ipc_payload_len);
    ssize_t bytes_read_payload = recvmsg(*uds_fd, &msg_payload, MSG_WAITALL);

    if (bytes_read_payload == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("receive_and_deserialize_ipc_message recvmsg (payload)");
        }
        free(full_ipc_payload_buffer);
        deserialized_result.status = FAILURE;
        return deserialized_result;
    }

    if (bytes_read_payload != (ssize_t)total_ipc_payload_len) {
        fprintf(stderr, "[receive_and_deserialize_ipc_message Debug]: ERROR: Payload IPC tidak lengkap. Diharapkan %u byte, diterima %zd.\n",
                total_ipc_payload_len, bytes_read_payload);
        free(full_ipc_payload_buffer);
        deserialized_result.status = FAILURE_OOBUF;
        return deserialized_result;
    }

    // --- TAHAP 3: Deserialisasi payload IPC ---
    fprintf(stderr, "[receive_and_deserialize_ipc_message Debug]: Memanggil ipc_deserialize dengan buffer %p dan panjang %u.\n",
            (void*)full_ipc_payload_buffer, total_ipc_payload_len);

    deserialized_result = ipc_deserialize((const uint8_t*)full_ipc_payload_buffer, total_ipc_payload_len);

    if (deserialized_result.status != SUCCESS) {
        fprintf(stderr, "[receive_and_deserialize_ipc_message Debug]: ipc_deserialize gagal dengan status %d.\n", deserialized_result.status);
    } else {
        fprintf(stderr, "[receive_and_deserialize_ipc_message Debug]: ipc_deserialize BERHASIL.\n");
    }

    // Bebaskan buffer yang dialokasikan dinamis
    free(full_ipc_payload_buffer);

    return deserialized_result;
}
