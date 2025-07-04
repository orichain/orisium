#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
#include <pthread.h> // for pthread_t
#endif
#include <errno.h>       // for errno, EAGAIN, EWOULDBLOCK
#include <netinet/in.h>  // for sockaddr_in, INADDR_ANY, in_addr
#include <stdbool.h>     // for false, bool, true
#include <stdio.h>       // for printf, perror, fprintf, NULL, stderr
#include <stdlib.h>      // for exit, EXIT_FAILURE, atoi, EXIT_SUCCESS, malloc, free
#include <string.h>      // for memset, strncpy
#include <sys/epoll.h>   // for epoll_event, epoll_ctl, EPOLLET, EPOLLIN
#include <sys/socket.h>  // for socketpair, SOCK_STREAM, AF_UNIX, AF_INET, accept
#include <sys/types.h>   // for pid_t, ssize_t
#include <unistd.h>      // for close, fork, getpid
#include <signal.h>      // for sig_atomic_t, sigaction, SIGINT
#include <arpa/inet.h>   // for inet_ntop, inet_pton
#include <fcntl.h>       // for fcntl, F_GETFL, F_SETFL, O_NONBLOCK
#include <sys/wait.h>    // for waitpid
#include <bits/types/sig_atomic_t.h>
#include <endian.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_types.h>
#include <stdint.h>
#include <sys/uio.h>

#include "log.h"
#include "constants.h"

#define IPC_LENGTH_PREFIX_BYTES sizeof(uint32_t)
// Definisi Makro (di src/include/common_defs.h atau di awal file .c jika hanya digunakan lokal)
#define CHECK_BUFFER_BOUNDS(current_offset, bytes_to_write, total_buffer_size) \
    do { \
        if ((current_offset) + (bytes_to_write) > (total_buffer_size)) { \
            fprintf(stderr, "[SER Error]: Buffer overflow check failed. Offset: %zu, Bytes to write: %zu, Total buffer size: %zu\n", \
                    (size_t)(current_offset), (size_t)(bytes_to_write), (size_t)(total_buffer_size)); /* Explicit cast to size_t */ \
            return FAILURE_OOBUF; /* Mengembalikan status_t */ \
        } \
    } while(0)

// Anda juga perlu memastikan `status_t` didefinisikan sebagai `int` atau `enum` yang sesuai.
// Jika `FAILURE_OOBUF` adalah sebuah `int`, maka `return FAILURE_OOBUF;` di makro akan mengembalikan `int`.
// Ini akan menyebabkan masalah di `ipc_serialize` yang mengharapkan `ssize_t_status_t`.

// Mari kita ubah makro agar hanya melakukan pengecekan dan mencetak pesan,
// lalu pemanggil yang menangani nilai kembalian.

#define CHECK_BUFFER_BOUNDS_NO_RETURN(current_offset, bytes_to_write, total_buffer_size) \
    ((current_offset) + (bytes_to_write) > (total_buffer_size)) ? \
    (fprintf(stderr, "[SER Error]: Buffer overflow check failed. Offset: %zu, Bytes to write: %zu, Total buffer size: %zu\n", \
             (size_t)(current_offset), (size_t)(bytes_to_write), (size_t)(total_buffer_size)), 1) : 0
// Makro ini akan mengembalikan 1 jika ada overflow, 0 jika tidak.
// Ini bisa digunakan untuk pengecekan di dalam fungsi yang berbeda.


// --- Message Types for IPC (Unix Domain Sockets) ---
typedef enum {
    IPC_CLIENT_REQUEST_TASK = (uint8_t)0x01,        // From SIO Worker to Master (new client request)
    IPC_LOGIC_TASK = (uint8_t)0x02,                 // From Master to Logic Worker (forward client request)
    IPC_LOGIC_RESPONSE_TO_SIO = (uint8_t)0x03,      // From Logic Worker to Master (response for original client)
    IPC_OUTBOUND_TASK = (uint8_t)0x04,              // From Logic Worker to Master (request to contact another node)
    IPC_OUTBOUND_RESPONSE = (uint8_t)0x05,          // From Client Outbound Worker to Master (response from another node)
    IPC_MASTER_ACK = (uint8_t)0x06,                 // Generic ACK from Master
    IPC_WORKER_ACK = (uint8_t)0x07,                 // Generic ACK from Worker
    IPC_CLIENT_DISCONNECTED = (uint8_t)0x08         // From SIO Worker to Master (client disconnected)
} message_type_t;

// --- IPC Message Header ---
typedef struct {
    message_type_t type;
    size_t data_len;
} ipc_msg_header_t;

// Send message over UDS, with optional FD passing (from ipc.h/ipc.c)
ssize_t send_ipc_message(int uds_fd, message_type_t type, const void *data, size_t data_len, int fd_to_pass) {
    ipc_msg_header_t header = { .type = type, .data_len = data_len };
    struct iovec iov[2];
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = (void *)data;
    iov[1].iov_len = data_len;

    char cmsgbuf[CMSG_SPACE(sizeof(int))]; // Buffer for control message (for FD)

    struct msghdr msg = {0};
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    if (fd_to_pass != -1) { // If an FD needs to be passed
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *((int *) CMSG_DATA(cmsg)) = fd_to_pass;
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
    }

    ssize_t bytes_sent = sendmsg(uds_fd, &msg, 0);
    if (bytes_sent == -1) {
        perror("send_ipc_message sendmsg"); // Using perror as LOG_ERROR might not be available in all contexts
    }
    return bytes_sent;
}

// Receive message over UDS, with optional FD reception (from ipc.h/ipc.c)
ssize_t recv_ipc_message(int uds_fd, ipc_msg_header_t *header, void *data_buffer, size_t buffer_size, int *actual_fd_received) {
    struct iovec iov[2];
    iov[0].iov_base = header;
    iov[0].iov_len = sizeof(ipc_msg_header_t);
    iov[1].iov_base = data_buffer;
    iov[1].iov_len = buffer_size;

    char cmsgbuf[CMSG_SPACE(sizeof(int))]; // Buffer for control message (for FD)

    struct msghdr msg = {0};
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    *actual_fd_received = -1; // Initialize to -1

    ssize_t bytes_read = recvmsg(uds_fd, &msg, 0);
    if (bytes_read == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recv_ipc_message recvmsg");
        }
        return -1;
    }

    if (bytes_read < (ssize_t)sizeof(ipc_msg_header_t)) {
        fprintf(stderr, "recv_ipc_message: Incomplete header received (%zd bytes)\n", bytes_read);
        return -1;
    }

    if (header->data_len > buffer_size) {
        fprintf(stderr, "recv_ipc_message: Data too large for buffer (expected %zu, got %zu). Truncating.\n",
                header->data_len, buffer_size);
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
        *actual_fd_received = *((int *) CMSG_DATA(cmsg));
    }

    return bytes_read;
}

typedef enum {
    SUCCESS = (uint8_t)0x00,
    FAILURE_BAD_PROTOCOL = (uint8_t)0xfa,
    FAILURE_NOMEM = (uint8_t)0xfb,
    FAILURE_IPYLD = (uint8_t)0xfc,
    FAILURE_OOBUF = (uint8_t)0xfd,
    FAILURE_OOIDX = (uint8_t)0xfe,
    FAILURE = (uint8_t)0xff
} status_t;

typedef struct {
	size_t r_size_t;
	status_t status;
} size_t_status_t;

typedef struct {
	ssize_t r_ssize_t;
	status_t status;
} ssize_t_status_t;

//============================================================================================================================
#define VERSION_BYTES 2

typedef struct {
    uint64_t correlation_id;
    uint16_t len;
    uint8_t data[];
} ipc_client_request_task_t;

typedef struct {
	uint8_t version[VERSION_BYTES];
	message_type_t type;
	union {
		ipc_client_request_task_t *ipc_client_request_task;
	} payload;
} ipc_protocol_t;

typedef struct {
	ipc_protocol_t *r_ipc_protocol_t;
	status_t status;
} ipc_protocol_t_status_t;

size_t_status_t calculate_ipc_payload_size(message_type_t type) {
    size_t_status_t result;
    result.r_size_t = 0;
    result.status = FAILURE;
    switch (type) {
        case IPC_CLIENT_REQUEST_TASK: {
            result.r_size_t = sizeof(uint64_t) + sizeof(uint16_t);
            break;
		}
        default: {
            result.status = FAILURE_OOIDX;
            return result;
		}
    }

    result.status = SUCCESS;
    return result;
}

size_t_status_t calculate_ipc_payload_buffer(const uint8_t* buffer, size_t len) {
	size_t_status_t result;
    result.r_size_t = 0;
    result.status = FAILURE;
    
    if (!buffer || len < VERSION_BYTES + sizeof(message_type_t)) {
		return result;
	}
    size_t offset = VERSION_BYTES;
    message_type_t type = (message_type_t)buffer[offset];
    offset += sizeof(message_type_t);
    switch (type) {
        case IPC_CLIENT_REQUEST_TASK: {
			if (len < offset + sizeof(uint64_t) + sizeof(uint16_t)) {
				return result;
			}
            uint64_t correlation_id = 0;
            uint16_t len = 0;
            memcpy(&correlation_id, buffer + offset, sizeof(uint64_t));
            correlation_id = be64toh(correlation_id);
            offset += sizeof(uint64_t);
            memcpy(&len, buffer + offset, sizeof(uint16_t));
            len = be16toh(len);
            offset += sizeof(uint16_t);
            result.r_size_t = VERSION_BYTES + sizeof(message_type_t) + sizeof(uint64_t) + sizeof(uint16_t) + len;
            result.status = SUCCESS;
            return result;
        }
        default:
            result.r_size_t = 0;
			result.status = FAILURE;
			return result;
    }
}

#define SER_CHECK_SPACE(x) if (x > buffer_size) return FAILURE_OOBUF

status_t ipc_serialize_client_request_task(const ipc_client_request_task_t* payload, uint8_t* current_buffer, size_t buffer_size, size_t* offset) {
    if (!payload || !current_buffer || !offset) {
        return FAILURE;
    }

    size_t current_offset_local = *offset;

    // Salin Correlation ID (big-endian)
    if (CHECK_BUFFER_BOUNDS_NO_RETURN(current_offset_local, sizeof(uint64_t), buffer_size)) return FAILURE_OOBUF;
    uint64_t correlation_id_be = htobe64(payload->correlation_id);
    memcpy(current_buffer + current_offset_local, &correlation_id_be, sizeof(uint64_t));
    current_offset_local += sizeof(uint64_t);

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

ssize_t_status_t ipc_serialize(const ipc_protocol_t* p, uint8_t** ptr_buffer, size_t* buffer_size) {
    ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;

    if (!p || !ptr_buffer || !buffer_size) {
        return result;
    }

    size_t total_required_size = 0;
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
            payload_fixed_size = sizeof(uint64_t) + sizeof(uint16_t);
            payload_dynamic_size = p->payload.ipc_client_request_task->len;
            break;
        }
        default:
            fprintf(stderr, "[ipc_serialize Error]: Unknown message type for serialization: 0x%02x.\n", p->type);
            result.status = FAILURE_IPYLD;
            return result;
    }

    total_required_size = VERSION_BYTES + sizeof(message_type_t) + payload_fixed_size + payload_dynamic_size;

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

    // Gunakan CHECK_BUFFER_BOUNDS_NO_RETURN dan tangani nilai kembaliannya
    if (CHECK_BUFFER_BOUNDS_NO_RETURN(offset, VERSION_BYTES, *buffer_size)) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(current_buffer + offset, p->version, VERSION_BYTES);
    offset += VERSION_BYTES;

    if (CHECK_BUFFER_BOUNDS_NO_RETURN(offset, sizeof(message_type_t), *buffer_size)) {
        result.status = FAILURE_OOBUF;
        return result;
    }
    current_buffer[offset] = (uint8_t)p->type;
    offset += sizeof(message_type_t);

    status_t result_pyld = FAILURE;
    switch (p->type) {
        case IPC_CLIENT_REQUEST_TASK:
            // Panggil ipc_serialize_client_request_task tanpa required_size
            result_pyld = ipc_serialize_client_request_task(p->payload.ipc_client_request_task, current_buffer, *buffer_size, &offset);
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


ssize_t send_ipc_protocol_message(int uds_fd, const ipc_protocol_t* p, int fd_to_pass) {
    uint8_t* serialized_ipc_data_buffer = NULL; // Ini akan berisi Version + Type + Payload
    size_t serialized_ipc_data_len = 0; // Ini adalah panjang dari buffer di atas

    // 1. Panggil ipc_serialize untuk mendapatkan data yang diserialisasi
    // Hasil dari ipc_serialize adalah data mulai dari VERSION_BYTES + message_type_t + actual_payload
    ssize_t_status_t serialize_result = ipc_serialize(p, &serialized_ipc_data_buffer, &serialized_ipc_data_len);

    if (serialize_result.status != SUCCESS) {
        fprintf(stderr, "[send_ipc_protocol_message Debug]: Error serializing IPC message: %d\n", serialize_result.status);
        if (serialized_ipc_data_buffer) { // Penting: bebaskan buffer jika ada alokasi yang terjadi sebelum error
            free(serialized_ipc_data_buffer);
        }
        return -1;
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
        return -1;
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

    // Mengkonfigurasi sendmsg
    struct msghdr msg = {0};
    struct iovec iov[1]; // Hanya satu iovec untuk seluruh buffer
    iov[0].iov_base = final_send_buffer;
    iov[0].iov_len = total_message_len_to_send;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    // Handle FD passing (logika ini sama seperti sebelumnya)
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    if (fd_to_pass != -1) {
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *((int *) CMSG_DATA(cmsg)) = fd_to_pass;
        fprintf(stderr, "[send_ipc_protocol_message Debug]: Mengirim FD: %d\n", fd_to_pass);
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
    }

    // Kirim pesan
    ssize_t bytes_sent = sendmsg(uds_fd, &msg, 0);
    if (bytes_sent == -1) {
        perror("send_ipc_protocol_message sendmsg");
    } else if (bytes_sent != (ssize_t)total_message_len_to_send) {
        fprintf(stderr, "[send_ipc_protocol_message Debug]: PERINGATAN: sendmsg hanya mengirim %zd dari %zu byte!\n",
                bytes_sent, total_message_len_to_send);
    } else {
        fprintf(stderr, "[send_ipc_protocol_message Debug]: Berhasil mengirim %zd byte.\n", bytes_sent);
    }

    // 7. Bebaskan buffer yang dialokasikan
    free(final_send_buffer);
    free(serialized_ipc_data_buffer); // Juga bebaskan dari ipc_serialize

    return bytes_sent;
}

#define DESER_CHECK_SPACE(x) if (len < x) return FAILURE_OOBUF

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

    // 1. Deserialisasi correlation_id (uint64_t)
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        fprintf(stderr, "[ipc_deserialize_client_request_task Error]: Out of bounds reading correlation_id.\n");
        return FAILURE_OOBUF;
    }
    uint64_t correlation_id_be;
    memcpy(&correlation_id_be, cursor, sizeof(uint64_t));
    payload->correlation_id = be64toh(correlation_id_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);

    // 2. Deserialisasi len (uint16_t - panjang data aktual)
    if (current_offset + sizeof(uint16_t) > total_buffer_len) {
        fprintf(stderr, "[ipc_deserialize_client_request_task Error]: Out of bounds reading data length.\n");
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

ipc_protocol_t_status_t ipc_deserialize(const uint8_t* buffer, size_t len) {
    ipc_protocol_t_status_t result;
    result.r_ipc_protocol_t = NULL;
    result.status = FAILURE;

    // Pengecekan dasar buffer
    if (!buffer || len < (VERSION_BYTES + sizeof(message_type_t))) {
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
    memcpy(p->version, buffer, VERSION_BYTES);
    p->type = (message_type_t)buffer[VERSION_BYTES];
    size_t current_buffer_offset = VERSION_BYTES + sizeof(message_type_t); // Offset awal payload

    fprintf(stderr, "[ipc_deserialize Debug]: Deserializing type 0x%02x. Current offset: %zu\n", p->type, current_buffer_offset);

    status_t result_pyld = FAILURE;
    switch (p->type) {
        case IPC_CLIENT_REQUEST_TASK: {
            // Untuk mendeserialisasi IPC_CLIENT_REQUEST_TASK, kita perlu tahu 'len' (panjang data aktual)
            // yang ada di dalam payload itu sendiri. Kita harus membaca bagian fixed dari payload terlebih dahulu.

            // Pastikan ada cukup byte di buffer untuk membaca correlation_id dan len
            if (current_buffer_offset + sizeof(uint64_t) + sizeof(uint16_t) > len) {
                fprintf(stderr, "[ipc_deserialize Error]: Buffer terlalu kecil untuk IPC_CLIENT_REQUEST_TASK fixed header.\n");
                free(p);
                result.status = FAILURE_OOBUF;
                return result;
            }

            // Baca 'len' dari buffer untuk menentukan ukuran FAM
            uint16_t raw_data_len_be;
            memcpy(&raw_data_len_be, buffer + current_buffer_offset + sizeof(uint64_t), sizeof(uint16_t));
            uint16_t actual_data_len = be16toh(raw_data_len_be);

            // Alokasikan memori untuk ipc_client_request_task_t, termasuk ruang untuk FAM 'data[]'
            // Inilah tempat alokasi untuk FAM terjadi!
            ipc_client_request_task_t *task_payload = (ipc_client_request_task_t*)
                calloc(1, sizeof(ipc_client_request_task_t) + actual_data_len);

            if (!task_payload) {
                perror("ipc_deserialize: Failed to allocate ipc_client_request_task_t with FAM");
                free(p); // Bebaskan ipc_protocol_t jika alokasi payload gagal
                result.status = FAILURE_NOMEM;
                return result;
            }
            p->payload.ipc_client_request_task = task_payload; // Set pointer ke alokasi baru

            // Panggil fungsi deserialisasi spesifik payload.
            // Fungsi ini akan MENGISI 'task_payload' dari 'buffer'.
            // Parameter 'required_size' tidak lagi relevan karena kita sudah mengalokasikan
            // ukuran yang tepat dan 'len' adalah batas total buffer.
            result_pyld = ipc_deserialize_client_request_task(p, buffer, len, &current_buffer_offset);
            break;
        }
        // Tambahkan case lain untuk tipe pesan lainnya jika ada
        default:
            fprintf(stderr, "[ipc_deserialize Error]: Unknown message type 0x%02x.\n", p->type);
            result.status = FAILURE_IPYLD;
            free(p); // Bebaskan ipc_protocol_t yang sudah dialokasikan
            return result;
    }

    // Cek hasil deserialisasi payload
    if (result_pyld != SUCCESS) {
        fprintf(stderr, "[ipc_deserialize Error]: Payload deserialization failed with status %d.\n", result_pyld);
        // Penting: Bebaskan task_payload (termasuk FAM-nya) jika sudah dialokasikan sebelum membebaskan 'p'.
        // Jika p->payload.ipc_client_request_task sudah dialokasikan:
        if (p->payload.ipc_client_request_task) {
            free(p->payload.ipc_client_request_task); // Ini membebaskan struct + FAM
        }
        free(p); // Kemudian bebaskan ipc_protocol_t
        result.status = FAILURE_IPYLD;
        return result;
    }

    result.r_ipc_protocol_t = p;
    result.status = SUCCESS;
    fprintf(stderr, "[ipc_deserialize Debug]: ipc_deserialize BERHASIL.\n");
    return result;
}

#define INITIAL_RECV_BUFFER_SIZE 2048 
#define MAX_IPC_MESSAGE_PAYLOAD_SIZE 1024

ipc_protocol_t_status_t receive_and_deserialize_ipc_message(int uds_fd, int *actual_fd_received) {
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
    ssize_t bytes_read_prefix_and_fd = recvmsg(uds_fd, &msg_prefix, MSG_WAITALL);

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
    ssize_t bytes_read_payload = recvmsg(uds_fd, &msg_payload, MSG_WAITALL);

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
//============================================================================================================================

// --- Data Structures for Tasks/Messages (from ipc.h/types.h) ---
typedef struct {
    long client_correlation_id;
    char request_data[MAX_DATA_BUFFER_IN_STRUCT];
    size_t request_data_len;
} client_request_task_t;

typedef struct {
    long client_correlation_id;
    char response_data[MAX_DATA_BUFFER_IN_STRUCT];
    size_t response_data_len;
} logic_response_t;

typedef struct {
    long client_correlation_id;
    char peer_ip[INET6_ADDRSTRLEN];
    int peer_port;
    char request_data[MAX_DATA_BUFFER_IN_STRUCT];
    size_t request_data_len;
} outbound_task_t;

typedef struct {
    long client_correlation_id;
    bool success;
    char response_data[MAX_DATA_BUFFER_IN_STRUCT];
    size_t response_data_len;
} outbound_response_t;

typedef struct {
    long client_correlation_id;
    char client_ip[INET6_ADDRSTRLEN]; // IP dari klien yang terputus
} client_disconnect_info_t;


// --- Struktur Data untuk Konfigurasi Jaringan (Biasanya dari config.h atau global.h) ---
typedef struct {
    char ip[IP_STRLEN];
    int port;
} peer_info_t;

typedef struct {
    char node_id[20]; // ID node ini
    int listen_port;  // Port untuk node ini mendengarkan koneksi masuk

    peer_info_t bootstrap_peers[MAX_PEERS];
    int num_bootstrap_peers;
} node_config_t;

// Global instance of node configuration
node_config_t node_config;


// --- Utility Functions (from utility.h) ---
// Changed set_nonblocking to take a label for consistent logging
static int set_nonblocking(const char* label, int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        LOG_ERROR("%sfcntl F_GETFL: %s", label, strerror(errno));
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG_ERROR("%sfcntl F_SETFL O_NONBLOCK: %s", label, strerror(errno));
        return -1;
    }
    return 0;
}

// --- Worker Functions (from worker.h) ---
// Re-implementing basic worker logic from previous working version

// Client State for Server IO Worker
typedef struct {
    bool in_use;
    int client_fd;
    long correlation_id; // Unique ID for this client session
    char client_ip[INET6_ADDRSTRLEN]; // Added to track client IP in SIO worker
    // For challenge-response or other stateful interactions
    bool awaiting_challenge_response;
    // Buffer for partial reads, if needed
} client_conn_state_t;

client_conn_state_t client_connections[MAX_CLIENTS_PER_SIO_WORKER]; // For SIO workers


// Server IO Worker (handles incoming client TCP connections)
void run_server_io_workerx(int worker_idx, int master_uds_fd) {
    LOG_INFO("[Server IO Worker %d, PID %d]: Started.", worker_idx, getpid());

    for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
        client_connections[i].in_use = false;
        client_connections[i].client_fd = -1;
        client_connections[i].correlation_id = -1;
        memset(client_connections[i].client_ip, 0, sizeof(client_connections[i].client_ip));
        client_connections[i].awaiting_challenge_response = false;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        LOG_ERROR("epoll_create1 (SIO Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET; // Edge-triggered
    event.data.fd = master_uds_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_uds_fd, &event) == -1) {
        LOG_ERROR("epoll_ctl: add master_uds_fd (SIO Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }
    LOG_INFO("[Server IO Worker %d]: Master UDS %d added to epoll.", worker_idx, master_uds_fd);
    LOG_INFO("[Server IO Worker %d]: Entering event loop.", worker_idx);

    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait (SIO)");
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; ++n) {
            int current_fd = events[n].data.fd;

            // Handle UDS from Master
            if (current_fd == master_uds_fd) {
				/*
                ipc_msg_header_t master_msg_header;
                char master_msg_data[sizeof(client_request_task_t) > sizeof(logic_response_t) ?
                                     sizeof(client_request_task_t) : sizeof(logic_response_t)]; // Max size of expected messages
                int received_client_fd = -1;

                ssize_t bytes_read = recv_ipc_message(master_uds_fd, &master_msg_header, master_msg_data, sizeof(master_msg_data), &received_client_fd);
                if (bytes_read == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recv_ipc_message from master (SIO)");
                    }
                    continue;
                }
                */
                int received_client_fd = -1;
                ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(master_uds_fd, &received_client_fd);
                if (deserialized_result.status != SUCCESS) {
                    fprintf(stderr, "[Server IO Worker %d]: Error receiving or deserializing IPC message from Master: %d\n", worker_idx, deserialized_result.status);
                    continue;
                }
                ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;
                printf("[Server IO Worker %d]: Received message type: 0x%02x\n", worker_idx, received_protocol->type);
                printf("[Server IO Worker %d]: Received FD: %d\n", worker_idx, received_client_fd);
                

                if (received_protocol->type == IPC_CLIENT_REQUEST_TASK) {
                    ipc_client_request_task_t *req = received_protocol->payload.ipc_client_request_task;

                    if (received_client_fd == -1) {
                        LOG_ERROR("[Server IO Worker %d]: Error: No client FD received with IPC_CLIENT_REQUEST_TASK for ID %ld. Skipping.", worker_idx, req->correlation_id);
                        continue;
                    }

                    if (set_nonblocking("[SIO Worker]: ", received_client_fd) == -1) {
                        LOG_ERROR("[Server IO Worker %d]: Failed to set non-blocking for FD %d. Closing.", worker_idx, received_client_fd);
                        close(received_client_fd);
                        continue;
                    }

                    event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                    event.data.fd = received_client_fd;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, received_client_fd, &event) == -1) {
                        LOG_ERROR("epoll_ctl: add client FD to SIO worker %d epoll: %s", worker_idx, strerror(errno));
                        close(received_client_fd);
                        continue;
                    }

                    // Get client IP and store client state
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    char client_ip_str[INET6_ADDRSTRLEN];
                    if (getpeername(received_client_fd, (struct sockaddr*)&client_addr, &client_len) == 0) {
                        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, sizeof(client_ip_str));
                    } else {
                        perror("getpeername (SIO Worker)");
                        strncpy(client_ip_str, "UNKNOWN_IP", sizeof(client_ip_str) - 1);
                        client_ip_str[sizeof(client_ip_str) - 1] = '\0';
                    }

                    int slot_found = -1;
                    for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
                        if (!client_connections[i].in_use) {
                            client_connections[i].in_use = true;
                            client_connections[i].client_fd = received_client_fd;
                            client_connections[i].correlation_id = req->correlation_id;
                            strncpy(client_connections[i].client_ip, client_ip_str, sizeof(client_connections[i].client_ip) - 1);
                            client_connections[i].client_ip[sizeof(client_connections[i].client_ip) - 1] = '\0';
                            client_connections[i].awaiting_challenge_response = false;
                            slot_found = i;
                            break;
                        }
                    }

                    if (slot_found != -1) {
                        LOG_INFO("[Server IO Worker %d]: Received client FD %d (ID %ld, IP %s) from Master and added to epoll. Slot %d.",
                               worker_idx, received_client_fd, req->correlation_id, client_ip_str, slot_found);
                    } else {
                        LOG_ERROR("[Server IO Worker %d]: No free slots for new client FD %d. Closing.", worker_idx, received_client_fd);
                        close(received_client_fd);
                    }

                }
                /*
                 else if (master_msg_header.type == IPC_LOGIC_RESPONSE_TO_SIO) {
                    logic_response_t *resp = (logic_response_t *)master_msg_data;
                    int target_client_fd = -1;
                    int client_slot_idx = -1;
                    char client_ip_for_response[INET6_ADDRSTRLEN];
                    memset(client_ip_for_response, 0, sizeof(client_ip_for_response));

                    for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
                        if (client_connections[i].in_use && client_connections[i].correlation_id == resp->client_correlation_id) {
                            target_client_fd = client_connections[i].client_fd;
                            client_slot_idx = i;
                            strncpy(client_ip_for_response, client_connections[i].client_ip, sizeof(client_ip_for_response) - 1);
                            client_ip_for_response[sizeof(client_ip_for_response) - 1] = '\0';
                            break;
                        }
                    }

                    if (target_client_fd != -1) {
                        LOG_INFO("[Server IO Worker %d]: Received logic response for client ID %ld (IP %s, from SIO index %d). Data: '%.*s'",
                               worker_idx, resp->client_correlation_id, client_ip_for_response, client_slot_idx,
                               (int)resp->response_data_len, resp->response_data);

                        ssize_t bytes_written = write(target_client_fd, resp->response_data, resp->response_data_len);
                        if (bytes_written == -1) {
                            perror("write to client (SIO)");
                        } else {
                            LOG_INFO("[Server IO Worker %d]: Sent %zd bytes to client FD %d (ID %ld, IP %s).",
                                   worker_idx, bytes_written, target_client_fd, resp->client_correlation_id, client_ip_for_response);
                        }
                        // Close client connection after response for simple request/response
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, target_client_fd, NULL);
                        close(target_client_fd);
                        client_connections[client_slot_idx].in_use = false;
                        client_connections[client_slot_idx].client_fd = -1;
                        client_connections[client_slot_idx].correlation_id = -1;
                        memset(client_connections[client_slot_idx].client_ip, 0, sizeof(client_connections[client_slot_idx].client_ip));
                        LOG_INFO("[Server IO Worker %d]: Closed client FD %d (ID %ld, IP %s) after response.",
                               worker_idx, target_client_fd, resp->client_correlation_id, client_ip_for_response);

                        // No need to send disconnect to Master here, Master already marks session as unused
                        // when it forwards the response from Logic Worker to SIO Worker.
                        // The Master's logic for IPC_LOGIC_RESPONSE_TO_SIO already handles marking session as not in use.
                        // This prevents double-counting disconnects.

                    } else {
                        LOG_WARN("[Server IO Worker %d]: Logic response for unknown client ID %ld. Perhaps already disconnected?",
                                worker_idx, resp->client_correlation_id);
                    }
                } 
                */
                else {
                     LOG_ERROR("[Server IO Worker %d]: Unknown message type %d from Master.", worker_idx, received_protocol->type);
                }
            }
            // Handle client TCP connections
            else {
                char client_buffer[MAX_DATA_BUFFER_IN_STRUCT];
                ssize_t bytes_read = read(current_fd, client_buffer, sizeof(client_buffer) - 1);

                if (bytes_read <= 0) {
                    if (bytes_read == 0 || (events[n].events & (EPOLLHUP | EPOLLERR))) {
                        // Client disconnected or error
                        long disconnected_client_id = -1;
                        char disconnected_client_ip[INET6_ADDRSTRLEN];
                        memset(disconnected_client_ip, 0, sizeof(disconnected_client_ip));

                        int client_slot_idx = -1;
                        for(int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
                            if(client_connections[i].in_use && client_connections[i].client_fd == current_fd) {
                                disconnected_client_id = client_connections[i].correlation_id;
                                strncpy(disconnected_client_ip, client_connections[i].client_ip, sizeof(disconnected_client_ip) - 1);
                                disconnected_client_ip[sizeof(disconnected_client_ip) - 1] = '\0';
                                client_slot_idx = i;
                                break;
                            }
                        }
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, NULL);
                        close(current_fd);
                        LOG_INFO("[Server IO Worker %d]: Client FD %d (ID %ld, IP %s) disconnected.", worker_idx, current_fd, disconnected_client_id, disconnected_client_ip);

                        // Only send disconnect to Master if the session wasn't already completed by a response
                        // (Master already handles marking session as unused on successful response)
                        if (disconnected_client_id != -1 && client_connections[client_slot_idx].in_use) { // Check in_use before marking
                             client_connections[client_slot_idx].in_use = false; // Mark as not in use here
                             client_connections[client_slot_idx].client_fd = -1;
                             client_connections[client_slot_idx].correlation_id = -1;
                             memset(client_connections[client_slot_idx].client_ip, 0, sizeof(client_connections[client_slot_idx].client_ip));

                            client_disconnect_info_t disconnect_msg;
                            disconnect_msg.client_correlation_id = disconnected_client_id;
                            strncpy(disconnect_msg.client_ip, disconnected_client_ip, sizeof(disconnect_msg.client_ip) - 1);
                            disconnect_msg.client_ip[sizeof(disconnect_msg.client_ip) - 1] = '\0';
                            send_ipc_message(master_uds_fd, IPC_CLIENT_DISCONNECTED, &disconnect_msg, sizeof(disconnect_msg), -1);
                            LOG_INFO("[Server IO Worker %d]: Sent client disconnect signal for ID %ld (IP %s) to Master.", worker_idx, disconnected_client_id, disconnected_client_ip);
                        }


                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("read from client (SIO)");
                    }
                    continue;
                }

                client_buffer[bytes_read] = '\0';

                long client_id_for_request = -1;
                int client_idx = -1;
                char client_ip_for_request[INET6_ADDRSTRLEN];
                memset(client_ip_for_request, 0, sizeof(client_ip_for_request));

                for(int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
                    if(client_connections[i].in_use && client_connections[i].client_fd == current_fd) {
                        client_id_for_request = client_connections[i].correlation_id;
                        client_idx = i;
                        strncpy(client_ip_for_request, client_connections[i].client_ip, sizeof(client_ip_for_request) - 1);
                        client_ip_for_request[sizeof(client_ip_for_request) - 1] = '\0';
                        break;
                    }
                }

                if (client_id_for_request == -1 || client_idx == -1) {
                    LOG_ERROR("[Server IO Worker %d]: Received data from unknown client FD %d. Ignoring.", worker_idx, current_fd);
                    continue;
                }

                message_type_t message_to_master_type = IPC_CLIENT_REQUEST_TASK;
                LOG_INFO("[Server IO Worker %d]: Received data from client/peer FD %d (ID %ld, IP %s): '%.*s'",
                       worker_idx, current_fd, client_id_for_request, client_ip_for_request, (int)bytes_read, client_buffer);

                client_request_task_t client_req;
                client_req.client_correlation_id = client_id_for_request;
                strncpy(client_req.request_data, client_buffer, sizeof(client_req.request_data) - 1);
                client_req.request_data[sizeof(client_req.request_data) - 1] = '\0';
                client_req.request_data_len = bytes_read;

                send_ipc_message(master_uds_fd, message_to_master_type, &client_req, sizeof(client_req), -1);
                LOG_INFO("[Server IO Worker %d]: Sent client request (ID %ld) to Master for Logic Worker.",
                       worker_idx, client_id_for_request);
            }
        }
    }
    close(epoll_fd);
    close(master_uds_fd);
}


void run_server_io_worker(int worker_idx, int master_uds_fd) {
    LOG_INFO("[Server IO Worker %d, PID %d]: Started.", worker_idx, getpid());

    for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
        client_connections[i].in_use = false;
        client_connections[i].client_fd = -1;
        client_connections[i].correlation_id = -1;
        memset(client_connections[i].client_ip, 0, sizeof(client_connections[i].client_ip));
        client_connections[i].awaiting_challenge_response = false;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        LOG_ERROR("epoll_create1 (SIO Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET; // Edge-triggered
    event.data.fd = master_uds_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_uds_fd, &event) == -1) {
        LOG_ERROR("epoll_ctl: add master_uds_fd (SIO Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }
    LOG_INFO("[Server IO Worker %d]: Master UDS %d added to epoll.", worker_idx, master_uds_fd);
    LOG_INFO("[Server IO Worker %d]: Entering event loop.", worker_idx);

    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait (SIO)");
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; ++n) {
            int current_fd = events[n].data.fd;

            // Handle UDS from Master
            if (current_fd == master_uds_fd) {
				/*
                ipc_msg_header_t master_msg_header;
                char master_msg_data[sizeof(client_request_task_t) > sizeof(logic_response_t) ?
                                     sizeof(client_request_task_t) : sizeof(logic_response_t)]; // Max size of expected messages
                int received_client_fd = -1;

                ssize_t bytes_read = recv_ipc_message(master_uds_fd, &master_msg_header, master_msg_data, sizeof(master_msg_data), &received_client_fd);
                if (bytes_read == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recv_ipc_message from master (SIO)");
                    }
                    continue;
                }
                */
                int received_client_fd = -1;
                ipc_protocol_t_status_t deserialized_result = receive_and_deserialize_ipc_message(master_uds_fd, &received_client_fd);
                if (deserialized_result.status != SUCCESS) {
                    fprintf(stderr, "[Server IO Worker %d]: Error receiving or deserializing IPC message from Master: %d\n", worker_idx, deserialized_result.status);
                    continue;
                }
                ipc_protocol_t* received_protocol = deserialized_result.r_ipc_protocol_t;
                printf("[Server IO Worker %d]: Received message type: 0x%02x\n", worker_idx, received_protocol->type);
                printf("[Server IO Worker %d]: Received FD: %d\n", worker_idx, received_client_fd);
                

                if (received_protocol->type == IPC_CLIENT_REQUEST_TASK) {
                    ipc_client_request_task_t *req = received_protocol->payload.ipc_client_request_task;

                    if (received_client_fd == -1) {
                        LOG_ERROR("[Server IO Worker %d]: Error: No client FD received with IPC_CLIENT_REQUEST_TASK for ID %ld. Skipping.", worker_idx, req->correlation_id);
                        continue;
                    }

                    if (set_nonblocking("[SIO Worker]: ", received_client_fd) == -1) {
                        LOG_ERROR("[Server IO Worker %d]: Failed to set non-blocking for FD %d. Closing.", worker_idx, received_client_fd);
                        close(received_client_fd);
                        continue;
                    }

                    event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                    event.data.fd = received_client_fd;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, received_client_fd, &event) == -1) {
                        LOG_ERROR("epoll_ctl: add client FD to SIO worker %d epoll: %s", worker_idx, strerror(errno));
                        close(received_client_fd);
                        continue;
                    }

                    // Get client IP and store client state
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    char client_ip_str[INET6_ADDRSTRLEN];
                    if (getpeername(received_client_fd, (struct sockaddr*)&client_addr, &client_len) == 0) {
                        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, sizeof(client_ip_str));
                    } else {
                        perror("getpeername (SIO Worker)");
                        strncpy(client_ip_str, "UNKNOWN_IP", sizeof(client_ip_str) - 1);
                        client_ip_str[sizeof(client_ip_str) - 1] = '\0';
                    }

                    int slot_found = -1;
                    for (int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
                        if (!client_connections[i].in_use) {
                            client_connections[i].in_use = true;
                            client_connections[i].client_fd = received_client_fd;
                            client_connections[i].correlation_id = req->correlation_id;
                            strncpy(client_connections[i].client_ip, client_ip_str, sizeof(client_connections[i].client_ip) - 1);
                            client_connections[i].client_ip[sizeof(client_connections[i].client_ip) - 1] = '\0';
                            client_connections[i].awaiting_challenge_response = false;
                            slot_found = i;
                            break;
                        }
                    }

                    if (slot_found != -1) {
                        LOG_INFO("[Server IO Worker %d]: Received client FD %d (ID %ld, IP %s) from Master and added to epoll. Slot %d.",
                               worker_idx, received_client_fd, req->correlation_id, client_ip_str, slot_found);
                    } else {
                        LOG_ERROR("[Server IO Worker %d]: No free slots for new client FD %d. Closing.", worker_idx, received_client_fd);
                        close(received_client_fd);
                    }

                }
                else {
                     LOG_ERROR("[Server IO Worker %d]: Unknown message type %d from Master.", worker_idx, received_protocol->type);
                }
            }
            // Handle client TCP connections
            else {
                char client_buffer[MAX_DATA_BUFFER_IN_STRUCT];
                ssize_t bytes_read = read(current_fd, client_buffer, sizeof(client_buffer) - 1);

                if (bytes_read <= 0) {
                    if (bytes_read == 0 || (events[n].events & (EPOLLHUP | EPOLLERR))) {
                        // Client disconnected or error
                        long disconnected_client_id = -1;
                        char disconnected_client_ip[INET6_ADDRSTRLEN];
                        memset(disconnected_client_ip, 0, sizeof(disconnected_client_ip));

                        int client_slot_idx = -1;
                        for(int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
                            if(client_connections[i].in_use && client_connections[i].client_fd == current_fd) {
                                disconnected_client_id = client_connections[i].correlation_id;
                                strncpy(disconnected_client_ip, client_connections[i].client_ip, sizeof(disconnected_client_ip) - 1);
                                disconnected_client_ip[sizeof(disconnected_client_ip) - 1] = '\0';
                                client_slot_idx = i;
                                break;
                            }
                        }
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, NULL);
                        close(current_fd);
                        LOG_INFO("[Server IO Worker %d]: Client FD %d (ID %ld, IP %s) disconnected.", worker_idx, current_fd, disconnected_client_id, disconnected_client_ip);

                        // Only send disconnect to Master if the session wasn't already completed by a response
                        // (Master already handles marking session as unused on successful response)
                        if (disconnected_client_id != -1 && client_connections[client_slot_idx].in_use) { // Check in_use before marking
                             client_connections[client_slot_idx].in_use = false; // Mark as not in use here
                             client_connections[client_slot_idx].client_fd = -1;
                             client_connections[client_slot_idx].correlation_id = -1;
                             memset(client_connections[client_slot_idx].client_ip, 0, sizeof(client_connections[client_slot_idx].client_ip));

                            client_disconnect_info_t disconnect_msg;
                            disconnect_msg.client_correlation_id = disconnected_client_id;
                            strncpy(disconnect_msg.client_ip, disconnected_client_ip, sizeof(disconnect_msg.client_ip) - 1);
                            disconnect_msg.client_ip[sizeof(disconnect_msg.client_ip) - 1] = '\0';
                            send_ipc_message(master_uds_fd, IPC_CLIENT_DISCONNECTED, &disconnect_msg, sizeof(disconnect_msg), -1);
                            LOG_INFO("[Server IO Worker %d]: Sent client disconnect signal for ID %ld (IP %s) to Master.", worker_idx, disconnected_client_id, disconnected_client_ip);
                        }


                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("read from client (SIO)");
                    }
                    continue;
                }

                client_buffer[bytes_read] = '\0';

                long client_id_for_request = -1;
                int client_idx = -1;
                char client_ip_for_request[INET6_ADDRSTRLEN];
                memset(client_ip_for_request, 0, sizeof(client_ip_for_request));

                for(int i = 0; i < MAX_CLIENTS_PER_SIO_WORKER; ++i) {
                    if(client_connections[i].in_use && client_connections[i].client_fd == current_fd) {
                        client_id_for_request = client_connections[i].correlation_id;
                        client_idx = i;
                        strncpy(client_ip_for_request, client_connections[i].client_ip, sizeof(client_ip_for_request) - 1);
                        client_ip_for_request[sizeof(client_ip_for_request) - 1] = '\0';
                        break;
                    }
                }

                if (client_id_for_request == -1 || client_idx == -1) {
                    LOG_ERROR("[Server IO Worker %d]: Received data from unknown client FD %d. Ignoring.", worker_idx, current_fd);
                    continue;
                }

                message_type_t message_to_master_type = IPC_CLIENT_REQUEST_TASK;
                LOG_INFO("[Server IO Worker %d]: Received data from client/peer FD %d (ID %ld, IP %s): '%.*s'",
                       worker_idx, current_fd, client_id_for_request, client_ip_for_request, (int)bytes_read, client_buffer);

                client_request_task_t client_req;
                client_req.client_correlation_id = client_id_for_request;
                strncpy(client_req.request_data, client_buffer, sizeof(client_req.request_data) - 1);
                client_req.request_data[sizeof(client_req.request_data) - 1] = '\0';
                client_req.request_data_len = bytes_read;

                send_ipc_message(master_uds_fd, message_to_master_type, &client_req, sizeof(client_req), -1);
                LOG_INFO("[Server IO Worker %d]: Sent client request (ID %ld) to Master for Logic Worker.",
                       worker_idx, client_id_for_request);
            }
        }
    }
    close(epoll_fd);
    close(master_uds_fd);
}

// Logic Worker (processes client requests, decides what to do)
void run_logic_worker(int worker_idx, int master_uds_fd) {
    LOG_INFO("[Logic Worker %d, PID %d]: Started.", worker_idx, getpid());

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        LOG_ERROR("epoll_create1 (Logic Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET; // Edge-triggered
    event.data.fd = master_uds_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_uds_fd, &event) == -1) {
        LOG_ERROR("epoll_ctl: add master_uds_fd (Logic Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }
    LOG_INFO("[Logic Worker %d]: Master UDS %d added to epoll.", worker_idx, master_uds_fd);
    LOG_INFO("[Logic Worker %d]: Entering event loop.", worker_idx);

    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait (Logic)");
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; ++n) {
            int current_fd = events[n].data.fd;

            if (current_fd == master_uds_fd) {
                ipc_msg_header_t master_msg_header;
                char master_msg_data[sizeof(client_request_task_t) > sizeof(outbound_response_t) ?
                                     sizeof(client_request_task_t) : sizeof(outbound_response_t)];
                int received_fd = -1;

                ssize_t bytes_read = recv_ipc_message(master_uds_fd, &master_msg_header, master_msg_data, sizeof(master_msg_data), &received_fd);
                if (bytes_read == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recv_ipc_message from master (Logic)");
                    }
                    continue;
                }

                if (master_msg_header.type == IPC_LOGIC_TASK) {
                    client_request_task_t *task = (client_request_task_t *)master_msg_data;
                    LOG_INFO("[Logic Worker %d]: Received client request (ID %ld) from Master. Data: '%.*s'",
                           worker_idx, task->client_correlation_id, (int)task->request_data_len, task->request_data);

                    logic_response_t response;
                    response.client_correlation_id = task->client_correlation_id;

                    if (task->request_data_len > 0 && task->request_data[task->request_data_len - 1] == '\n') {
                        task->request_data[task->request_data_len - 1] = '\0';
                        task->request_data_len--;
                    }


                    if (strstr(task->request_data, "Halo saya adalah") != NULL) {
                        snprintf(response.response_data, sizeof(response.response_data),
                                 "Logic Worker %d received: '%.*s'. Thanks for the greeting!",
                                 worker_idx, (int)task->request_data_len, task->request_data);
                        response.response_data_len = strlen(response.response_data);
                        send_ipc_message(master_uds_fd, IPC_LOGIC_RESPONSE_TO_SIO, &response, sizeof(response), -1);
                        LOG_INFO("[Logic Worker %d]: Sending direct response for client ID %ld to Master for SIO.",
                               worker_idx, task->client_correlation_id);
                    }
                    else if (strstr(task->request_data, "Kirim pesan ke node lain") != NULL) {
                        LOG_INFO("[Logic Worker %d]: Client ID %ld requested sending message to peer node. Preparing outbound task.",
                               worker_idx, task->client_correlation_id);

                        char peer_message[MAX_DATA_BUFFER_IN_STRUCT];
                        snprintf(peer_message, sizeof(peer_message), "Halo ini dari Node1 ke %s:%d\n",
                                 node_config.bootstrap_peers[0].ip, node_config.bootstrap_peers[0].port); // Use first bootstrap peer
                        
                        peer_message[sizeof(peer_message) - 1] = '\0';

                        LOG_INFO("[Logic Worker %d]: Prepared peer message: '%s'", worker_idx, peer_message);

                        outbound_task_t *outbound_task = malloc(sizeof(outbound_task_t));
                        if (!outbound_task) {
                            perror("malloc outbound_task");
                            snprintf(response.response_data, sizeof(response.response_data),
                                     "ERROR: Failed to allocate outbound task memory.");
                            response.response_data_len = strlen(response.response_data);
                            send_ipc_message(master_uds_fd, IPC_LOGIC_RESPONSE_TO_SIO, &response, sizeof(response), -1);
                            continue;
                        }
                        outbound_task->client_correlation_id = task->client_correlation_id;
                        strncpy(outbound_task->peer_ip, node_config.bootstrap_peers[0].ip, sizeof(outbound_task->peer_ip) - 1);
                        outbound_task->peer_ip[sizeof(outbound_task->peer_ip) - 1] = '\0';
                        outbound_task->peer_port = node_config.bootstrap_peers[0].port;
                        strncpy(outbound_task->request_data, peer_message, sizeof(outbound_task->request_data) - 1);
                        outbound_task->request_data[sizeof(outbound_task->request_data) - 1] = '\0';
                        outbound_task->request_data_len = strlen(outbound_task->request_data);

                        send_ipc_message(master_uds_fd, IPC_OUTBOUND_TASK, outbound_task, sizeof(outbound_task_t), -1);
                        free(outbound_task);
                        LOG_INFO("[Logic Worker %d]: Sent outbound task for client ID %ld to Master for COW.",
                               worker_idx, task->client_correlation_id);

                    } else {
                        snprintf(response.response_data, sizeof(response.response_data),
                                 "Echo from Logic Worker %d for Client ID %ld: '%.*s'",
                                 worker_idx, task->client_correlation_id,
                                 (int)task->request_data_len, task->request_data);
                        response.response_data_len = strlen(response.response_data);
                        send_ipc_message(master_uds_fd, IPC_LOGIC_RESPONSE_TO_SIO, &response, sizeof(response), -1);
                        LOG_INFO("[Logic Worker %d]: Sending echo response for client ID %ld to Master for SIO.",
                               worker_idx, task->client_correlation_id);
                    }
                }
                else if (master_msg_header.type == IPC_OUTBOUND_RESPONSE) {
                    outbound_response_t *resp = (outbound_response_t *)master_msg_data;
                    LOG_INFO("[Logic Worker %d]: Received outbound response for client ID %ld. Success: %s, Data: '%.*s'",
                           worker_idx, resp->client_correlation_id, resp->success ? "true" : "false",
                           (int)resp->response_data_len, resp->response_data);

                    logic_response_t response_to_sio;
                    response_to_sio.client_correlation_id = resp->client_correlation_id;
                    if (resp->success) {
                        snprintf(response_to_sio.response_data, sizeof(response_to_sio.response_data),
                                 "Peer responded: '%.*s'", (int)resp->response_data_len, resp->response_data);
                    } else {
                        snprintf(response_to_sio.response_data, sizeof(response_to_sio.response_data),
                                 "Peer communication failed: '%.*s'", (int)resp->response_data_len, resp->response_data);
                    }
                    response_to_sio.response_data_len = strlen(response_to_sio.response_data);
                    send_ipc_message(master_uds_fd, IPC_LOGIC_RESPONSE_TO_SIO, &response_to_sio, sizeof(response_to_sio), -1);
                    LOG_INFO("[Logic Worker %d]: Notifying original client ID %ld (via SIO) about outbound communication result.",
                           worker_idx, resp->client_correlation_id);
                } else {
                    LOG_ERROR("[Logic Worker %d]: Unknown message type %d from Master.", worker_idx, master_msg_header.type);
                }
            }
        }
    }
    close(epoll_fd);
    close(master_uds_fd);
}

// Client Outbound Worker (makes outgoing TCP connections to other nodes)
void run_client_outbound_worker(int worker_idx, int master_uds_fd) {
    LOG_INFO("[Client Outbound Worker %d, PID %d]: Started.", worker_idx, getpid());

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        LOG_ERROR("epoll_create1 (COW Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET; // Edge-triggered
    event.data.fd = master_uds_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_uds_fd, &event) == -1) {
        LOG_ERROR("epoll_ctl: add master_uds_fd (COW Worker %d): %s", worker_idx, strerror(errno));
        exit(EXIT_FAILURE);
    }
    LOG_INFO("[Client Outbound Worker %d]: Master UDS %d added to epoll.", worker_idx, master_uds_fd);
    LOG_INFO("[Client Outbound Worker %d]: Entering event loop.", worker_idx);

    struct epoll_event events[MAX_EVENTS];

    // State for the single active outbound connection this worker manages at a time
    int active_outbound_fd = -1;
    long active_outbound_correlation_id = -1;
    char active_outbound_target_ip[INET6_ADDRSTRLEN];
    int active_outbound_target_port;
    char active_outbound_request_data[MAX_DATA_BUFFER_IN_STRUCT];
    size_t active_outbound_request_data_len = 0;

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait (COW)");
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; ++n) {
            int current_fd = events[n].data.fd;

            // Handle UDS from Master
            if (current_fd == master_uds_fd) {
                ipc_msg_header_t master_msg_header;
                char master_msg_data[sizeof(outbound_task_t)];
                int received_fd = -1;

                ssize_t bytes_read = recv_ipc_message(master_uds_fd, &master_msg_header, master_msg_data, sizeof(master_msg_data), &received_fd);
                if (bytes_read == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recv_ipc_message from master (COW)");
                    }
                    continue;
                }

                if (master_msg_header.type == IPC_OUTBOUND_TASK) {
                    if (active_outbound_fd != -1) {
                        LOG_WARN("[Client Outbound Worker %d]: WARNING: Received new outbound task but one is already active (FD %d). Ignoring.", worker_idx, active_outbound_fd);
                        outbound_response_t busy_resp;
                        busy_resp.client_correlation_id = ((outbound_task_t *)master_msg_data)->client_correlation_id;
                        busy_resp.success = false;
                        snprintf(busy_resp.response_data, sizeof(busy_resp.response_data), "COW busy.");
                        busy_resp.response_data_len = strlen(busy_resp.response_data);
                        send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &busy_resp, sizeof(busy_resp), -1);
                        active_outbound_fd = -1;
                        continue;
                    }

                    outbound_task_t *outbound_task = (outbound_task_t *)master_msg_data;
                    
                    active_outbound_correlation_id = outbound_task->client_correlation_id;
                    strncpy(active_outbound_target_ip, outbound_task->peer_ip, sizeof(active_outbound_target_ip) - 1);
                    active_outbound_target_ip[sizeof(active_outbound_target_ip) - 1] = '\0';
                    active_outbound_target_port = outbound_task->peer_port;
                    strncpy(active_outbound_request_data, outbound_task->request_data, sizeof(active_outbound_request_data) - 1);
                    active_outbound_request_data[sizeof(active_outbound_request_data) - 1] = '\0';
                    active_outbound_request_data_len = outbound_task->request_data_len;

                    LOG_INFO("[Client Outbound Worker %d]: Received outbound task (ID %ld): Connect to %s:%d, Send: '%.*s'",
                           worker_idx, active_outbound_correlation_id, active_outbound_target_ip, active_outbound_target_port,
                           (int)active_outbound_request_data_len, active_outbound_request_data);

                    int new_fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (new_fd == -1) {
                        perror("socket (COW)");
                        outbound_response_t fail_resp;
                        fail_resp.client_correlation_id = active_outbound_correlation_id;
                        fail_resp.success = false;
                        snprintf(fail_resp.response_data, sizeof(fail_resp.response_data), "Socket creation failed.");
                        fail_resp.response_data_len = strlen(fail_resp.response_data);
                        send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &fail_resp, sizeof(fail_resp), -1);
                        active_outbound_fd = -1;
                        continue;
                    }

                    set_nonblocking("[COW Worker]: ", new_fd);

                    struct sockaddr_in server_addr;
                    memset(&server_addr, 0, sizeof(server_addr));
                    server_addr.sin_family = AF_INET;
                    server_addr.sin_port = htons(active_outbound_target_port);
                    if (inet_pton(AF_INET, active_outbound_target_ip, &server_addr.sin_addr) <= 0) {
                        perror("inet_pton (COW)");
                        close(new_fd);
                        outbound_response_t fail_resp;
                        fail_resp.client_correlation_id = active_outbound_correlation_id;
                        fail_resp.success = false;
                        snprintf(fail_resp.response_data, sizeof(fail_resp.response_data), "Invalid peer IP.");
                        fail_resp.response_data_len = strlen(fail_resp.response_data);
                        send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &fail_resp, sizeof(fail_resp), -1);
                        active_outbound_fd = -1;
                        continue;
                    }

                    LOG_INFO("[Client Outbound Worker %d]: Initiated connection to %s:%d (FD %d) for ID %ld.",
                           worker_idx, active_outbound_target_ip, active_outbound_target_port, new_fd, active_outbound_correlation_id);

                    if (connect(new_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
                        if (errno != EINPROGRESS) {
                            perror("connect (COW)");
                            close(new_fd);
                            outbound_response_t fail_resp;
                            fail_resp.client_correlation_id = active_outbound_correlation_id;
                            fail_resp.success = false;
                            snprintf(fail_resp.response_data, sizeof(fail_resp.response_data), "Connect failed: %s", strerror(errno));
                            fail_resp.response_data_len = strlen(fail_resp.response_data);
                            send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &fail_resp, sizeof(fail_resp), -1);
                            active_outbound_fd = -1;
                            continue;
                        }
                        LOG_INFO("[Client Outbound Worker %d]: Connecting to %s:%d (EINPROGRESS) for ID %ld. Waiting for EPOLLOUT.",
                               worker_idx, active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);
                        active_outbound_fd = new_fd;
                        event.events = EPOLLOUT | EPOLLET | EPOLLRDHUP;
                        event.data.fd = active_outbound_fd;
                        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, active_outbound_fd, &event);
                    } else {
                        LOG_INFO("[Client Outbound Worker %d]: Connected immediately to %s:%d for ID %ld. Sending data.",
                               worker_idx, active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);
                        active_outbound_fd = new_fd;
                        LOG_INFO("[Client Outbound Worker %d]: Attempting to send '%.*s' to peer %s:%d for ID %ld.",
                               worker_idx, (int)active_outbound_request_data_len, active_outbound_request_data,
                               active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);
                        ssize_t bytes_sent_immediate = write(active_outbound_fd, active_outbound_request_data, active_outbound_request_data_len);
                        if (bytes_sent_immediate == -1) {
                            perror("write to peer (COW)");
                            close(active_outbound_fd);
                            outbound_response_t fail_resp;
                            fail_resp.client_correlation_id = active_outbound_correlation_id;
                            fail_resp.success = false;
                            snprintf(fail_resp.response_data, sizeof(fail_resp.response_data), "Write to peer failed: %s", strerror(errno));
                            fail_resp.response_data_len = strlen(fail_resp.response_data);
                            send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &fail_resp, sizeof(fail_resp), -1);
                            active_outbound_fd = -1;
                        } else {
                            LOG_INFO("[Client Outbound Worker %d]: Sent %zd bytes to peer %s:%d for ID %ld. Waiting for response.",
                                   worker_idx, bytes_sent_immediate, active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);
                            event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                            event.data.fd = active_outbound_fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, active_outbound_fd, &event);
                        }
                    }
                } else {
                    LOG_ERROR("[Client Outbound Worker %d]: Unknown message type %d from Master.", worker_idx, master_msg_header.type);
                }
            }
            // Handle active outbound TCP connection
            else if (current_fd == active_outbound_fd) {
                ssize_t bytes_sent = 0;

                if (events[n].events & EPOLLOUT) {
                    int so_error;
                    socklen_t len = sizeof(so_error);
                    if (getsockopt(current_fd, SOL_SOCKET, SO_ERROR, &so_error, &len) == -1) {
                        perror("getsockopt SO_ERROR (COW)");
                        so_error = EIO;
                    }

                    if (so_error == 0) {
                        LOG_INFO("[Client Outbound Worker %d]: Connection to %s:%d established. Sending data for ID %ld.",
                               worker_idx, active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);

                        LOG_INFO("[Client Outbound Worker %d]: Attempting to send '%.*s' to peer %s:%d for ID %ld.",
                               worker_idx, (int)active_outbound_request_data_len, active_outbound_request_data,
                               active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);

                        bytes_sent = write(current_fd, active_outbound_request_data, active_outbound_request_data_len);
                        if (bytes_sent == -1) {
                            perror("write to peer (COW)");
                            outbound_response_t fail_resp;
                            fail_resp.client_correlation_id = active_outbound_correlation_id;
                            fail_resp.success = false;
                            snprintf(fail_resp.response_data, sizeof(fail_resp.response_data), "Write to peer failed after connect: %s", strerror(errno));
                            fail_resp.response_data_len = strlen(fail_resp.response_data);
                            send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &fail_resp, sizeof(fail_resp), -1);
                        } else {
                            LOG_INFO("[Client Outbound Worker %d]: Sent %zd bytes to peer %s:%d for ID %ld. Waiting for response.",
                                   worker_idx, bytes_sent, active_outbound_target_ip, active_outbound_target_port, active_outbound_correlation_id);
                            event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                            event.data.fd = current_fd;
                            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, current_fd, &event);
                        }
                    } else {
                        LOG_ERROR("[Client Outbound Worker %d]: Connect error to %s:%d: %s (FD %d).",
                                worker_idx, active_outbound_target_ip, active_outbound_target_port, strerror(so_error), current_fd);
                        outbound_response_t fail_resp;
                        fail_resp.client_correlation_id = active_outbound_correlation_id;
                        fail_resp.success = false;
                        snprintf(fail_resp.response_data, sizeof(fail_resp.response_data), "Connect error: %s", strerror(so_error));
                        fail_resp.response_data_len = strlen(fail_resp.response_data);
                        send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &fail_resp, sizeof(fail_resp), -1);
                    }
                    if (bytes_sent == -1 || so_error != 0) {
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, NULL);
                        close(current_fd);
                        active_outbound_fd = -1;
                        LOG_INFO("[Client Outbound Worker %d]: Cleared failed outbound connection (FD %d, ID %ld).", worker_idx, current_fd, active_outbound_correlation_id);
                    }
                }
                if (events[n].events & EPOLLIN) {
                    char response_buffer[MAX_DATA_BUFFER_IN_STRUCT];
                    ssize_t bytes_read = read(current_fd, response_buffer, sizeof(response_buffer) - 1);

                    outbound_response_t outbound_resp;
                    outbound_resp.client_correlation_id = active_outbound_correlation_id;

                    if (bytes_read <= 0) {
                        if (bytes_read == 0 || (events[n].events & (EPOLLHUP | EPOLLERR))) {
                            LOG_INFO("[Client Outbound Worker %d]: Peer %s:%d disconnected or error (FD %d).",
                                   worker_idx, active_outbound_target_ip, active_outbound_target_port, current_fd);
                            outbound_resp.success = false;
                            snprintf(outbound_resp.response_data, sizeof(outbound_resp.response_data), "Peer disconnected prematurely.");
                        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            perror("read from peer (COW)");
                            outbound_resp.success = false;
                            snprintf(outbound_resp.response_data, sizeof(outbound_resp.response_data), "Read error from peer: %s", strerror(errno));
                        } else {
                            continue;
                        }
                    } else {
                        response_buffer[bytes_read] = '\0';
                        outbound_resp.success = true;
                        strncpy(outbound_resp.response_data, response_buffer, sizeof(outbound_resp.response_data) - 1);
                        outbound_resp.response_data[sizeof(outbound_resp.response_data) - 1] = '\0';
                        outbound_resp.response_data_len = bytes_read;
                        LOG_INFO("[Client Outbound Worker %d]: Received %zd bytes from peer FD %d (ID %ld): '%.*s'",
                               worker_idx, bytes_read, current_fd, active_outbound_correlation_id,
                               (int)outbound_resp.response_data_len, outbound_resp.response_data);
                    }

                    send_ipc_message(master_uds_fd, IPC_OUTBOUND_RESPONSE, &outbound_resp, sizeof(outbound_resp), -1);
                    LOG_INFO("[Client Outbound Worker %d]: Sent outbound response for ID %ld to Master.",
                           worker_idx, active_outbound_correlation_id);

                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, NULL);
                    close(current_fd);
                    active_outbound_fd = -1;
                    LOG_INFO("[Client Outbound Worker %d]: Closed peer FD %d (ID %ld) after response.",
                           worker_idx, current_fd, outbound_resp.client_correlation_id);
                }
            } else {
                LOG_ERROR("[Client Outbound Worker %d]: Event on unknown FD %d. Ignoring.", worker_idx, current_fd);
            }
        }
    }
    close(epoll_fd);
    close(master_uds_fd);
}


// --- Setup and Cleanup (from setup.h/cleanup.h) ---
// Placeholder for setup_socket_listenner
status_t setup_socket_listenner(int *listen_sock) {
    *listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (*listen_sock == -1) {
        perror("socket (Master)");
        return FAILURE;
    }
    set_nonblocking("[Master]: ", *listen_sock); // Use label
    int opt = 1;
    if (setsockopt(*listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt SO_REUSEADDR");
        close(*listen_sock);
        return FAILURE;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(node_config.listen_port); // Use global node_config.listen_port

    if (bind(*listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind (Master)");
        close(*listen_sock);
        return FAILURE;
    }
    if (listen(*listen_sock, SOMAXCONN) == -1) {
        perror("listen (Master)");
        close(*listen_sock);
        return FAILURE;
    }
    return SUCCESS;
}

// Placeholder for install_sigint_handler
volatile sig_atomic_t shutdown_requested = 0; // from global.h
void sigint_handler(int signum) {
    shutdown_requested = 1;
    LOG_INFO("SIGINT received. Initiating graceful shutdown...");
}
void install_sigint_handler() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);
    LOG_INFO("SIGINT handler installed.");
}

// Placeholder for orisium_cleanup
void orisium_cleanup(void *cleaner_thread_ptr, int *listen_sock_ptr, int *async_fd_ptr,
                     int uds_sio_fds_master_side[], int uds_logic_fds_master_side[], int uds_cow_fds_master_side[],
                     int uds_sio_fds_worker_side[], int uds_logic_fds_worker_side[], int uds_cow_fds_worker_side[],
                     pid_t sio_pids[], pid_t logic_pids[], pid_t cow_pids[]) {
    LOG_INFO("Performing cleanup...");
    if (*listen_sock_ptr != -1) close(*listen_sock_ptr);
    if (*async_fd_ptr != -1) close(*async_fd_ptr);

    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        if (uds_sio_fds_master_side[i] != 0) close(uds_sio_fds_master_side[i]);
        if (uds_sio_fds_worker_side[i] != 0) close(uds_sio_fds_worker_side[i]); // Close worker side in Master too
        if (sio_pids[i] > 0) waitpid(sio_pids[i], NULL, 0);
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        if (uds_logic_fds_master_side[i] != 0) close(uds_logic_fds_master_side[i]);
        if (uds_logic_fds_worker_side[i] != 0) close(uds_logic_fds_worker_side[i]); // Close worker side in Master too
        if (logic_pids[i] > 0) waitpid(logic_pids[i], NULL, 0);
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        if (uds_cow_fds_master_side[i] != 0) close(uds_cow_fds_master_side[i]);
        if (uds_cow_fds_worker_side[i] != 0) close(uds_cow_fds_worker_side[i]); // Close worker side in Master too
        if (cow_pids[i] > 0) waitpid(cow_pids[i], NULL, 0);
    }

    #if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
    if (cleaner_thread_ptr != NULL) {
        pthread_join(*(pthread_t*)cleaner_thread_ptr, NULL);
    }
    #endif
    LOG_INFO("Cleanup complete.");
}


// --- Fungsi Pembaca JSON Konfigurasi Jaringan (dari config.c/config.h) ---
status_t read_network_config_from_json(const char* filename, node_config_t* config_out) {
    FILE *fp = NULL;
    char buffer[MAX_FILE_SIZE];
    struct json_object *parsed_json = NULL;
    struct json_object *listen_port_obj = NULL;
    struct json_object *bootstrap_peers_array = NULL;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        LOG_ERROR("Gagal membuka file konfigurasi: %s", strerror(errno));
        return FAILURE;
    }

    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, fp);
    if (bytes_read == 0 && !feof(fp)) {
        LOG_ERROR("Gagal membaca file atau file kosong: %s", filename);
        fclose(fp);
        return FAILURE;
    }
    buffer[bytes_read] = '\0';
    fclose(fp);

    parsed_json = json_tokener_parse(buffer);
    if (parsed_json == NULL) {
        LOG_ERROR("Gagal mem-parsing JSON dari file: %s", filename);
        return FAILURE;
    }

    if (!json_object_object_get_ex(parsed_json, "listen_port", &listen_port_obj) || !json_object_is_type(listen_port_obj, json_type_int)) {
        LOG_ERROR("Kunci 'listen_port' tidak ditemukan atau tidak valid.");
        json_object_put(parsed_json);
        return FAILURE;
    }
    config_out->listen_port = json_object_get_int(listen_port_obj);

    if (!json_object_object_get_ex(parsed_json, "bootstrap_peers", &bootstrap_peers_array) || !json_object_is_type(bootstrap_peers_array, json_type_array)) {
        LOG_ERROR("Kunci 'bootstrap_peers' tidak ditemukan atau tidak valid.");
        json_object_put(parsed_json);
        return FAILURE;
    }

    int array_len = json_object_array_length(bootstrap_peers_array);
    if (array_len > MAX_PEERS) {
        LOG_WARN("Jumlah bootstrap peers (%d) melebihi MAX_PEERS (%d). Hanya %d yang akan dibaca.",
                array_len, MAX_PEERS, MAX_PEERS);
        array_len = MAX_PEERS;
    }

    config_out->num_bootstrap_peers = 0;
    for (int i = 0; i < array_len; i++) {
        struct json_object *peer_obj = json_object_array_get_idx(bootstrap_peers_array, i);
        if (!json_object_is_type(peer_obj, json_type_object)) {
            LOG_WARN("Elemen array bootstrap_peers bukan objek pada indeks %d. Melewatkan.", i);
            continue;
        }

        struct json_object *ip_obj = NULL;
        struct json_object *port_obj = NULL;

        if (!json_object_object_get_ex(peer_obj, "ip", &ip_obj) || !json_object_is_type(ip_obj, json_type_string)) {
            LOG_WARN("Kunci 'ip' tidak ditemukan atau bukan string pada peer indeks %d. Melewatkan.", i);
            continue;
        }
        strncpy(config_out->bootstrap_peers[config_out->num_bootstrap_peers].ip,
                json_object_get_string(ip_obj), IP_STRLEN - 1);
        config_out->bootstrap_peers[config_out->num_bootstrap_peers].ip[IP_STRLEN - 1] = '\0';

        if (!json_object_object_get_ex(peer_obj, "port", &port_obj) || !json_object_is_type(port_obj, json_type_int)) {
            LOG_WARN("Kunci 'port' tidak ditemukan atau bukan integer pada peer indeks %d. Melewatkan.", i);
            continue;
        }
        config_out->bootstrap_peers[config_out->num_bootstrap_peers].port = json_object_get_int(port_obj);

        config_out->num_bootstrap_peers++;
    }

    json_object_put(parsed_json);
    return SUCCESS;
}

// --- Placeholder for async_type_t and async_create_incoming_event ---
// This struct would typically be defined in async.h
typedef struct {
    int async_fd; // The epoll instance FD
    // Add other async-related members if needed
} async_type_t;

// This function would typically be defined in async.c/async.h
status_t async_create_incoming_event(const char* label, async_type_t *async, int *fd_to_add) {
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = *fd_to_add;
    if (epoll_ctl(async->async_fd, EPOLL_CTL_ADD, *fd_to_add, &event) == -1) {
        LOG_ERROR("%sepoll_ctl: add UDS FD %d to epoll: %s", label, *fd_to_add, strerror(errno));
        return FAILURE;
    }
    return SUCCESS;
}


// --- Fungsi setup_fork_workers yang direfaktor ---
status_t setup_fork_workers(
    const char* label,
    int listen_sock, // listen_sock passed by value, as it's closed in child
    async_type_t *async,
    int master_uds_sio_fds[], // Arrays for Master's side of UDS
    int master_uds_logic_fds[],
    int master_uds_cow_fds[],
    int worker_uds_sio_fds[], // Arrays for Worker's side of UDS
    int worker_uds_logic_fds[],
    int worker_uds_cow_fds[],
    pid_t sio_pids[],
    pid_t logic_pids[],
    pid_t cow_pids[]
) {
    // Create and fork SIO workers
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        sio_pids[i] = fork();
        if (sio_pids[i] == -1) {
            LOG_ERROR("%sfork (SIO): %s", label, strerror(errno));
            return FAILURE;
        } else if (sio_pids[i] == 0) {
            // Child (SIO Worker)
            // Close all FDs inherited from Master that this child does NOT need
            close(listen_sock); // Master's TCP listening socket
            close(async->async_fd); // Master's epoll instance

            // Close all Master's side UDS FDs (this child doesn't use them)
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_uds_sio_fds[j] != 0) close(master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_uds_logic_fds[j] != 0) close(master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_uds_cow_fds[j] != 0) close(master_uds_cow_fds[j]); }
            
            // Close all Worker's side UDS FDs that are NOT for this specific worker
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) {
                if (j != i && worker_uds_sio_fds[j] != 0) close(worker_uds_sio_fds[j]);
            }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (worker_uds_logic_fds[j] != 0) close(worker_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (worker_uds_cow_fds[j] != 0) close(worker_uds_cow_fds[j]); }
            
            run_server_io_worker(i, worker_uds_sio_fds[i]);
            exit(EXIT_SUCCESS); // Child exits after running worker function
        } else {
            // Parent (Master)
            // Close the worker's side of the UDS for this worker, as Master only uses its own side
            if (worker_uds_sio_fds[i] != 0) close(worker_uds_sio_fds[i]);
            LOG_INFO("%sForked Server IO Worker %d (PID %d).", label, i, sio_pids[i]);
        }
    }

    // Create and fork Logic workers
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        logic_pids[i] = fork();
        if (logic_pids[i] == -1) {
            LOG_ERROR("%sfork (Logic): %s", label, strerror(errno));
            return FAILURE;
        } else if (logic_pids[i] == 0) {
            // Child (Logic Worker)
            // Close all FDs inherited from Master that this child does NOT need
            close(listen_sock); // Master's TCP listening socket
            close(async->async_fd); // Master's epoll instance

            // Close all Master's side UDS FDs (this child doesn't use them)
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_uds_sio_fds[j] != 0) close(master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_uds_logic_fds[j] != 0) close(master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_uds_cow_fds[j] != 0) close(master_uds_cow_fds[j]); }
            
            // Close all Worker's side UDS FDs that are NOT for this specific worker
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (worker_uds_sio_fds[j] != 0) close(worker_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) {
                if (j != i && worker_uds_logic_fds[j] != 0) close(worker_uds_logic_fds[j]);
            }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (worker_uds_cow_fds[j] != 0) close(worker_uds_cow_fds[j]); }
            
            run_logic_worker(i, worker_uds_logic_fds[i]);
            exit(EXIT_SUCCESS); // Child exits
        } else {
            // Parent (Master)
            // Close the worker's side of the UDS for this worker, as Master only uses its own side
            if (worker_uds_logic_fds[i] != 0) close(worker_uds_logic_fds[i]);
            LOG_INFO("%sForked Logic Worker %d (PID %d).", label, i, logic_pids[i]);
        }
    }

    // Create and fork Client Outbound workers
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        cow_pids[i] = fork();
        if (cow_pids[i] == -1) {
            LOG_ERROR("%sfork (COW): %s", label, strerror(errno));
            return FAILURE;        
        } else if (cow_pids[i] == 0) {
            // Child (Client Outbound Worker)
            // Close all FDs inherited from Master that this child does NOT need
            close(listen_sock); // Master's TCP listening socket
            close(async->async_fd); // Master's epoll instance

            // Close all Master's side UDS FDs (this child doesn't use them)
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (master_uds_sio_fds[j] != 0) close(master_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (master_uds_logic_fds[j] != 0) close(master_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) { if (master_uds_cow_fds[j] != 0) close(master_uds_cow_fds[j]); }
            
            // Close all Worker's side UDS FDs that are NOT for this specific worker
            for (int j = 0; j < MAX_SIO_WORKERS; ++j) { if (worker_uds_sio_fds[j] != 0) close(worker_uds_sio_fds[j]); }
            for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) { if (worker_uds_logic_fds[j] != 0) close(worker_uds_logic_fds[j]); }
            for (int j = 0; j < MAX_COW_WORKERS; ++j) {
                if (j != i && worker_uds_cow_fds[j] != 0) close(worker_uds_cow_fds[j]);
            }
            
            run_client_outbound_worker(i, worker_uds_cow_fds[i]);
            exit(EXIT_SUCCESS); // Child exits
        } else {
            // Parent (Master)
            // Close the worker's side of the UDS for this worker, as Master only uses its own side
            if (worker_uds_cow_fds[i] != 0) close(worker_uds_cow_fds[i]);
            LOG_INFO("%sForked Client Outbound Worker %d (PID %d).", label, i, cow_pids[i]);
        }
    }
    return SUCCESS;
}


// --- Fungsi Main (master process) ---
// master_client_session_t didefinisikan di sini karena terhubung dengan MAX_MASTER_CONCURRENT_SESSIONS
typedef struct {
    bool in_use;
    long correlation_id;
    int sio_uds_fd; // UDS FD of the SIO worker handling this client
    char client_ip[INET6_ADDRSTRLEN]; // Tambahkan ini untuk melacak IP klien
} master_client_session_t;

// Global instance of master client sessions
master_client_session_t master_client_sessions[MAX_MASTER_CONCURRENT_SESSIONS];


int main() {
    memset(&node_config, 0, sizeof(node_config_t));
    strncpy(node_config.node_id, "Node1", sizeof(node_config.node_id) - 1);
    node_config.node_id[sizeof(node_config.node_id) - 1] = '\0';

#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
    log_init();
#endif
    LOG_INFO("[Master]: ==========================================================");
    LOG_INFO("[Master]: orisium dijalankan.");
    LOG_INFO("[Master]: ==========================================================");
#if defined(PRODUCTION) || defined(TOFILE)
    pthread_t cleaner_thread;
    pthread_create(&cleaner_thread, NULL, log_cleaner_thread, NULL);
#endif
    install_sigint_handler();

    int master_pid = -1;
    int listen_sock = -1;
    async_type_t master_async_ctx; // Use the struct for master's epoll
    master_async_ctx.async_fd = -1; // Initialize to -1

    // Worker UDS FDs (Master's side of the UDS) - Sized by their specific MAX_*_WORKERS
    int master_uds_sio_fds[MAX_SIO_WORKERS];
    int master_uds_logic_fds[MAX_LOGIC_WORKERS];
    int master_uds_cow_fds[MAX_COW_WORKERS];

    // Worker UDS FDs (Worker's side of the UDS) - Sized by their specific MAX_*_WORKERS
    int worker_uds_sio_fds[MAX_SIO_WORKERS];
    int worker_uds_logic_fds[MAX_LOGIC_WORKERS];
    int worker_uds_cow_fds[MAX_COW_WORKERS];

    // Worker PIDs (to keep track for waitpid later) - Sized by their specific MAX_*_WORKERS
    pid_t sio_pids[MAX_SIO_WORKERS];
    pid_t logic_pids[MAX_LOGIC_WORKERS];
    pid_t cow_pids[MAX_COW_WORKERS];
    
    if (read_network_config_from_json("config.json", &node_config) != SUCCESS) {
        LOG_ERROR("[Master]: Gagal membaca konfigurasi dari %s.", "config.json");
        goto exit;
    }
    
    LOG_INFO("[Master]: --- Node Configuration ---");
    LOG_INFO("[Master]: Node ID: %s", node_config.node_id);
    LOG_INFO("[Master]: Listen Port: %d", node_config.listen_port);
    LOG_INFO("[Master]: Bootstrap Peers (%d):", node_config.num_bootstrap_peers);
    for (int i = 0; i < node_config.num_bootstrap_peers; i++) {
        LOG_INFO("[Master]:   - Peer %d: IP %s, Port %d",
                 i + 1, node_config.bootstrap_peers[i].ip, node_config.bootstrap_peers[i].port);
    }
    LOG_INFO("[Master]: -------------------------");

    master_pid = getpid();
    LOG_INFO("[Master]: PID %d TCP Server listening on port %d.", master_pid, node_config.listen_port);

    if (setup_socket_listenner(&listen_sock) != SUCCESS) {
        goto exit;
    }
    
    master_async_ctx.async_fd = epoll_create1(0); // Initialize master's epoll instance
    if (master_async_ctx.async_fd == -1) {
        LOG_ERROR("epoll_create1 (Master): %s", strerror(errno));
        goto exit;
    }

    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = listen_sock;
    if (epoll_ctl(master_async_ctx.async_fd, EPOLL_CTL_ADD, listen_sock, &event) == -1) {
        LOG_ERROR("epoll_ctl: add listen_sock (Master): %s", strerror(errno));
        goto exit;
    }
    LOG_INFO("[Master]: Listening socket %d added to epoll.", listen_sock);

    // Initialize UDS FDs arrays
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) { master_uds_sio_fds[i] = 0; worker_uds_sio_fds[i] = 0; }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) { master_uds_logic_fds[i] = 0; worker_uds_logic_fds[i] = 0; }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) { master_uds_cow_fds[i] = 0; worker_uds_cow_fds[i] = 0; }

    // Create all UDS pairs and add Master's side to epoll BEFORE forking
    // This ensures child processes inherit a complete (though mostly irrelevant) set of FDs,
    // making explicit closing easier.

    // Create UDS for SIO workers
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
            LOG_ERROR("[Master]: socketpair (SIO) creation failed: %s", strerror(errno));
            goto exit;
        }
        set_nonblocking("[Master]: ", sv[0]);
        set_nonblocking("[Master]: ", sv[1]);
        master_uds_sio_fds[i] = sv[0]; // Master's side
        worker_uds_sio_fds[i] = sv[1]; // Worker's side
        if (async_create_incoming_event("[Master]: ", &master_async_ctx, &master_uds_sio_fds[i]) != SUCCESS) {
            goto exit;
        }
        LOG_INFO("[Master]: Created UDS pair for SIO Worker %d (Master side: %d, Worker side: %d).", i, master_uds_sio_fds[i], worker_uds_sio_fds[i]);
    }

    // Create UDS for Logic workers
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
            LOG_ERROR("[Master]: socketpair (Logic) creation failed: %s", strerror(errno));
            goto exit;
        }
        set_nonblocking("[Master]: ", sv[0]);
        set_nonblocking("[Master]: ", sv[1]);
        master_uds_logic_fds[i] = sv[0]; // Master's side
        worker_uds_logic_fds[i] = sv[1]; // Worker's side
        if (async_create_incoming_event("[Master]: ", &master_async_ctx, &master_uds_logic_fds[i]) != SUCCESS) {
            goto exit;
        }
        LOG_INFO("[Master]: Created UDS pair for Logic Worker %d (Master side: %d, Worker side: %d).", i, master_uds_logic_fds[i], worker_uds_logic_fds[i]);
    }

    // Create UDS for COW workers
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
            LOG_ERROR("[Master]: socketpair (COW) creation failed: %s", strerror(errno));
            goto exit;
        }
        set_nonblocking("[Master]: ", sv[0]);
        set_nonblocking("[Master]: ", sv[1]);
        master_uds_cow_fds[i] = sv[0]; // Master's side
        worker_uds_cow_fds[i] = sv[1]; // Worker's side
        if (async_create_incoming_event("[Master]: ", &master_async_ctx, &master_uds_cow_fds[i]) != SUCCESS) {
            goto exit;
        }
        LOG_INFO("[Master]: Created UDS pair for COW Worker %d (Master side: %d, Worker side: %d).", i, master_uds_cow_fds[i], worker_uds_cow_fds[i]);
    }


    // Call the refactored function to fork workers
    if (setup_fork_workers(
        "[Master]: ",
        listen_sock,
        &master_async_ctx, // Pass address of master's async context
        master_uds_sio_fds,
        master_uds_logic_fds,
        master_uds_cow_fds,
        worker_uds_sio_fds,
        worker_uds_logic_fds,
        worker_uds_cow_fds,
        sio_pids,
        logic_pids,
        cow_pids
    ) != SUCCESS) {
        LOG_ERROR("[Master]: Gagal mem-fork worker.");
        goto exit;
    }

    LOG_INFO("[Master]: Starting main event loop. Waiting for clients and worker communications...");

    struct epoll_event events[MAX_EVENTS];
    long next_client_id = 0; // Global unique client ID

    // Initialize master_client_sessions
    for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
        master_client_sessions[i].in_use = false;
        memset(master_client_sessions[i].client_ip, 0, sizeof(master_client_sessions[i].client_ip));
    }

    while (!shutdown_requested) {
        int nfds = epoll_wait(master_async_ctx.async_fd, events, MAX_EVENTS, -1); // Use master's epoll FD
        if (nfds == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait (Master)");
            goto exit;
        }

        for (int n = 0; n < nfds; ++n) {
            int current_fd = events[n].data.fd;

            if (current_fd == listen_sock) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_len);
                if (client_sock == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("accept (Master)");
                    }
                    continue;
                }
                
                char client_ip_str[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, sizeof(client_ip_str)) == NULL) {
                    perror("inet_ntop");
                    close(client_sock);
                    continue;
                }

                // --- Filter: Check if IP is already connected ---
                bool ip_already_connected = false;
                for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
                    if (master_client_sessions[i].in_use &&
                        strcmp(master_client_sessions[i].client_ip, client_ip_str) == 0) {
                        ip_already_connected = true;
                        break;
                    }
                }

                if (ip_already_connected) {
                    LOG_WARN("[Master]: Koneksi ditolak dari IP %s. Sudah ada koneksi aktif dari IP ini.", client_ip_str);
                    close(client_sock);
                    continue;
                }
                // --- End Filter ---

                LOG_INFO("[Master]: New client connected from IP %s on FD %d.", client_ip_str, client_sock);

                long current_client_id = next_client_id++;
                int sio_worker_idx = (int)(current_client_id % MAX_SIO_WORKERS);
                int sio_worker_uds_fd = master_uds_sio_fds[sio_worker_idx]; // Master uses its side of UDS

                int slot_found = -1;
                for(int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
                    if(!master_client_sessions[i].in_use) {
                        master_client_sessions[i].in_use = true;
                        master_client_sessions[i].correlation_id = current_client_id;
                        master_client_sessions[i].sio_uds_fd = sio_worker_uds_fd;
                        strncpy(master_client_sessions[i].client_ip, client_ip_str, sizeof(master_client_sessions[i].client_ip) - 1);
                        master_client_sessions[i].client_ip[sizeof(master_client_sessions[i].client_ip) - 1] = '\0';
                        slot_found = i;
                        break;
                    }
                }
                if (slot_found == -1) {
                    LOG_ERROR("[Master]: WARNING: No free session slots in master_client_sessions. Rejecting client FD %d.", client_sock);
                    close(client_sock);
                    continue;
                }
                
                
                
                ipc_protocol_t p;
				memset(&p, 0, sizeof(ipc_protocol_t)); // Inisialisasi dengan nol
				p.version[0] = 0x01;
				p.version[1] = 0x00;
				p.type = IPC_CLIENT_REQUEST_TASK;
				ipc_client_request_task_t *ipc_req_payload = (ipc_client_request_task_t *)calloc(1, sizeof(ipc_client_request_task_t));
				if (!ipc_req_payload) {
					perror("Failed to allocate ipc_client_request_task_t payload");
					close(client_sock);
					continue;
				}
				ipc_req_payload->correlation_id = (uint64_t)current_client_id; // Cast ke uint64_t
				ipc_req_payload->len = 1; // Karena request_data_len 0
				uint8_t b = 0x09;
				memcpy(ipc_req_payload->data, &b, 1);
				p.payload.ipc_client_request_task = ipc_req_payload;
				ssize_t bytes_sent = send_ipc_protocol_message(sio_worker_uds_fd, &p, client_sock);
				if (bytes_sent == -1) {
					LOG_ERROR("[Master]: Failed to forward client FD %d (ID %ld) to Server IO Worker %d.",
							  client_sock, current_client_id, sio_worker_idx);
				} else {
					LOG_INFO("[Master]: Forwarding client FD %d (ID %ld) from IP %s to Server IO Worker %d (UDS FD %d). Bytes sent: %zd.",
							 client_sock, current_client_id, client_ip_str, sio_worker_idx, sio_worker_uds_fd, bytes_sent);
				}
				if (ipc_req_payload) {
					free(ipc_req_payload);
					p.payload.ipc_client_request_task = NULL;
				}
				if (bytes_sent != -1) {
					close(client_sock);
				}
               
/*                
                
                client_request_task_t new_client_req;
                new_client_req.client_correlation_id = current_client_id;
                new_client_req.request_data_len = 0;

                send_ipc_message(sio_worker_uds_fd, IPC_CLIENT_REQUEST_TASK, &new_client_req, sizeof(new_client_req), client_sock);
                LOG_INFO("[Master]: Forwarding client FD %d (ID %ld) from IP %s to Server IO Worker %d (UDS FD %d).",
                       client_sock, current_client_id, client_ip_str, sio_worker_idx, sio_worker_uds_fd);
                
                close(client_sock); 
*/

            }
            else { 
                ipc_msg_header_t msg_header;
                char master_rcv_buffer[MASTER_RECEIVE_BUFFER_SIZE]; 
                int received_fd = -1;

                ssize_t bytes_read = recv_ipc_message(current_fd, &msg_header, master_rcv_buffer, sizeof(master_rcv_buffer), &received_fd);
                if (bytes_read == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recv_ipc_message from worker (Master)");
                    }
                    continue;
                }

                switch (msg_header.type) {
                    case IPC_CLIENT_REQUEST_TASK: {
                        client_request_task_t *req = (client_request_task_t *)master_rcv_buffer;
                        LOG_INFO("[Master]: Received Client Request Task (ID %ld) from Server IO Worker (UDS FD %d).", req->client_correlation_id, current_fd);

                        int logic_worker_idx = (int)(req->client_correlation_id % MAX_LOGIC_WORKERS);
                        int logic_worker_uds_fd = master_uds_logic_fds[logic_worker_idx]; // Master uses its side of UDS

                        send_ipc_message(logic_worker_uds_fd, IPC_LOGIC_TASK, req, sizeof(client_request_task_t), -1);
                        LOG_INFO("[Master]: Forwarding client request (ID %ld) to Logic Worker %d (UDS FD %d).",
                               req->client_correlation_id, logic_worker_idx, logic_worker_uds_fd);
                        break;
                    }
                    case IPC_LOGIC_RESPONSE_TO_SIO: {
                        logic_response_t *resp = (logic_response_t *)master_rcv_buffer;
                        LOG_INFO("[Master]: Received Client Response (ID %ld) from Logic Worker (UDS FD %d).", resp->client_correlation_id, current_fd);

                        int target_sio_uds_fd = -1;
                        for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
                            if (master_client_sessions[i].in_use && master_client_sessions[i].correlation_id == resp->client_correlation_id) {
                                target_sio_uds_fd = master_client_sessions[i].sio_uds_fd;
                                master_client_sessions[i].in_use = false;
                                master_client_sessions[i].correlation_id = -1;
                                master_client_sessions[i].sio_uds_fd = -1;
                                memset(master_client_sessions[i].client_ip, 0, sizeof(master_client_sessions[i].client_ip));
                                break;
                            }
                        }

                        if (target_sio_uds_fd != -1) {
                            send_ipc_message(target_sio_uds_fd, IPC_LOGIC_RESPONSE_TO_SIO, resp, sizeof(logic_response_t), -1);
                            LOG_INFO("[Master]: Forwarding client response (ID %ld) to Server IO Worker (UDS FD %d).",
                                   resp->client_correlation_id, target_sio_uds_fd);
                        } else {
                            LOG_ERROR("[Master]: No SIO worker found for client ID %ld for response. Ignoring.", resp->client_correlation_id);
                        }
                        break;
                    }
                    case IPC_OUTBOUND_TASK: {
                        outbound_task_t *task = (outbound_task_t *)master_rcv_buffer;
                        LOG_INFO("[Master]: Received Outbound Task (ID %ld) from Logic Worker (UDS FD %d) for peer %s:%d.",
                               task->client_correlation_id, current_fd, task->peer_ip, task->peer_port);

                        int cow_worker_idx = (int)(task->client_correlation_id % MAX_COW_WORKERS);
                        int cow_uds_fd = master_uds_cow_fds[cow_worker_idx]; // Master uses its side of UDS

                        send_ipc_message(cow_uds_fd, IPC_OUTBOUND_TASK, task, sizeof(outbound_task_t), -1);
                        LOG_INFO("[Master]: Forwarding outbound task (ID %ld) to Client Outbound Worker %d (UDS FD %d).",
                               task->client_correlation_id, cow_worker_idx, cow_uds_fd);
                        break;
                    }
                    case IPC_OUTBOUND_RESPONSE: {
                        outbound_response_t *resp = (outbound_response_t *)master_rcv_buffer;
                        LOG_INFO("[Master]: Received Outbound Response (ID %ld) from Client Outbound Worker (UDS FD %d). Success: %s, Data: '%.*s'",
                               resp->client_correlation_id, current_fd, resp->success ? "true" : "false",
                               (int)resp->response_data_len, resp->response_data);

                        int logic_worker_idx_for_response = (int)(resp->client_correlation_id % MAX_LOGIC_WORKERS);
                        int logic_worker_uds_fd = master_uds_logic_fds[logic_worker_idx_for_response]; // Master uses its side of UDS

                        send_ipc_message(logic_worker_uds_fd, IPC_OUTBOUND_RESPONSE, resp, sizeof(outbound_response_t), -1);
                        LOG_INFO("[Master]: Forwarding outbound response (ID %ld) to Logic Worker %d (UDS FD %d).",
                               resp->client_correlation_id, logic_worker_idx_for_response, logic_worker_uds_fd);
                        break;
                    }
                    case IPC_CLIENT_DISCONNECTED: {
                        client_disconnect_info_t *disconnect_info = (client_disconnect_info_t *)master_rcv_buffer;
                        LOG_INFO("[Master]: Received Client Disconnected signal for ID %ld from IP %s (from SIO Worker UDS FD %d).",
                                 disconnect_info->client_correlation_id, disconnect_info->client_ip, current_fd);

                        for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
                            if (master_client_sessions[i].in_use &&
                                master_client_sessions[i].correlation_id == disconnect_info->client_correlation_id &&
                                strcmp(master_client_sessions[i].client_ip, disconnect_info->client_ip) == 0) {
                                master_client_sessions[i].in_use = false;
                                master_client_sessions[i].correlation_id = -1;
                                master_client_sessions[i].sio_uds_fd = -1;
                                memset(master_client_sessions[i].client_ip, 0, sizeof(master_client_sessions[i].client_ip));
                                LOG_INFO("[Master]: IP %s (ID %ld) dihapus dari daftar koneksi aktif.",
                                         disconnect_info->client_ip, disconnect_info->client_correlation_id);
                                break;
                            }
                        }
                        break;
                    }
                    default:
                        LOG_ERROR("[Master]: Unknown message type %d from UDS FD %d. Ignoring.", msg_header.type, current_fd);
                        break;
                }
            }
        }
    }

exit:
    orisium_cleanup(
    #if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))
        &cleaner_thread,
    #else
        NULL,
    #endif
        &listen_sock,
        &master_async_ctx.async_fd, // Pass address of the FD
        master_uds_sio_fds,
        master_uds_logic_fds,
        master_uds_cow_fds,
        worker_uds_sio_fds, // Pass worker sides for cleanup
        worker_uds_logic_fds,
        worker_uds_cow_fds,
        sio_pids,
        logic_pids,
        cow_pids
    );
    LOG_INFO("[Master]: ==========================================================");
    LOG_INFO("[Master]: orisium selesai dijalankan.");
    LOG_INFO("[Master]: ==========================================================\n\n\n");
#if defined(PRODUCTION) || (defined(DEVELOPMENT) && defined(TOFILE))    
    log_close();
#endif
    return 0;
}
