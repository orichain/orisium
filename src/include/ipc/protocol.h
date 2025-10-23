#ifndef IPC_PROTOCOL_H
#define IPC_PROTOCOL_H

#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "constants.h"
#include "pqc.h"
#include "utilities.h"

typedef enum {
    IPC_WORKER_MASTER_HELLO1 = (uint8_t)0x00,
    IPC_MASTER_WORKER_HELLO1_ACK = (uint8_t)0x01,
    IPC_WORKER_MASTER_HELLO2 = (uint8_t)0x02,
    IPC_MASTER_WORKER_HELLO2_ACK = (uint8_t)0x03,
    
    IPC_MASTER_COW_CONNECT = (uint8_t)0x10,
    
    IPC_WORKER_MASTER_TASK_INFO = (uint8_t)0xfb,
    IPC_UDP_DATA = (uint8_t)0xfc,
    IPC_UDP_DATA_ACK = (uint8_t)0xfd,
    IPC_WORKER_MASTER_HEARTBEAT = (uint8_t)0xfe,
    IPC_MASTER_WORKER_INFO = (uint8_t)0xff
} ipc_protocol_type_t;

typedef struct {
    uint8_t session_index;
    task_info_type_t flag;
} ipc_worker_master_task_info_t;

typedef struct {
    uint8_t session_index;
    uint8_t orilink_protocol;
    uint8_t trycount;
    uint8_t inc_ctr;
    struct sockaddr_in6 remote_addr;
    uint16_t len;
//----------------------------------------------------------------------
//FAM (Flexible Array Member)    
//----------------------------------------------------------------------
    uint8_t data[];
//----------------------------------------------------------------------
} ipc_udp_data_t;

typedef struct {
    uint8_t session_index;
    uint8_t orilink_protocol;
    uint8_t trycount;
    uint8_t inc_ctr;
    status_t status;
} ipc_udp_data_ack_t;

typedef struct {
    uint8_t session_index;
    uint64_t id_connection;
    struct sockaddr_in6 remote_addr;
} ipc_master_cow_connect_t;

typedef struct {
    info_type_t flag;
} ipc_master_worker_info_t;

typedef struct {
    double hb_interval;
} ipc_worker_master_heartbeat_t;

typedef struct {
    uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
} ipc_worker_master_hello1_t;

typedef struct {
    uint8_t encrypted_wot_index[AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES];
} ipc_worker_master_hello2_t;

typedef struct {
    uint8_t nonce[AES_NONCE_BYTES];
    uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES];
} ipc_master_worker_hello1_ack_t;

typedef struct {
    uint8_t encrypted_wot_index[sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES];
} ipc_master_worker_hello2_ack_t;

typedef struct {
    uint8_t mac[AES_TAG_BYTES];
    uint32_t ctr;
	uint8_t version[IPC_VERSION_BYTES];
    ipc_protocol_type_t type;
    worker_type_t wot;
    uint8_t index;
	union {
        ipc_worker_master_task_info_t *ipc_worker_master_task_info;
		ipc_master_worker_info_t *ipc_master_worker_info;
		ipc_worker_master_heartbeat_t *ipc_worker_master_heartbeat;
        ipc_master_cow_connect_t *ipc_master_cow_connect;
        ipc_udp_data_t *ipc_udp_data;
        ipc_udp_data_ack_t *ipc_udp_data_ack;
        ipc_worker_master_hello1_t *ipc_worker_master_hello1;
        ipc_master_worker_hello1_ack_t *ipc_master_worker_hello1_ack;
        ipc_worker_master_hello2_t *ipc_worker_master_hello2;
        ipc_master_worker_hello2_ack_t *ipc_master_worker_hello2_ack;
	} payload;
} ipc_protocol_t;

typedef struct ipc_protocol_queue_t {
    uint64_t queue_id;
    worker_type_t wot;
    uint8_t index;
    int *uds_fd;
    ipc_protocol_t *p;
    struct ipc_protocol_queue_t *next;
} ipc_protocol_queue_t;
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_IPC_PAYLOAD(void **ptr) {
    if (ptr != NULL && *ptr != NULL) {
        free(*ptr);
        *ptr = NULL;
    }
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_IPC_PROTOCOL(ipc_protocol_t **protocol_ptr) {
    if (protocol_ptr != NULL && *protocol_ptr != NULL) {
        ipc_protocol_t *x = *protocol_ptr;
        if (x->type == IPC_WORKER_MASTER_HEARTBEAT) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_worker_master_heartbeat);
        } else if (x->type == IPC_MASTER_WORKER_INFO) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_master_worker_info);
        } else if (x->type == IPC_WORKER_MASTER_TASK_INFO) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_worker_master_task_info);
        } else if (x->type == IPC_MASTER_COW_CONNECT) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_master_cow_connect);
        } else if (x->type == IPC_UDP_DATA) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_udp_data);
        } else if (x->type == IPC_UDP_DATA_ACK) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_udp_data_ack);
        } else if (x->type == IPC_WORKER_MASTER_HELLO1) {
            memset(x->payload.ipc_worker_master_hello1->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_worker_master_hello1);
        } else if (x->type == IPC_MASTER_WORKER_HELLO1_ACK) {
            memset(x->payload.ipc_master_worker_hello1_ack->nonce, 0, AES_NONCE_BYTES);
            memset(x->payload.ipc_master_worker_hello1_ack->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_master_worker_hello1_ack);
        } else if (x->type == IPC_WORKER_MASTER_HELLO2) {
            memset(x->payload.ipc_worker_master_hello2->encrypted_wot_index, 0, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES);
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_worker_master_hello2);
        } else if (x->type == IPC_MASTER_WORKER_HELLO2_ACK) {
            memset(x->payload.ipc_master_worker_hello2_ack->encrypted_wot_index, 0, sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES);
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_master_worker_hello2_ack);
        }
        free(x);
        *protocol_ptr = NULL;
    }
}

typedef struct {
    uint8_t *recv_buffer;
    uint32_t n;
    uint8_t mac[AES_TAG_BYTES];
    uint32_t ctr;
    uint8_t version[IPC_VERSION_BYTES];
    ipc_protocol_type_t type;
    worker_type_t wot;
    uint8_t index;
} ipc_raw_protocol_t;
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_IPC_RAW_PAYLOAD(void **ptr) {
    if (ptr != NULL && *ptr != NULL) {
        free(*ptr);
        *ptr = NULL;
    }
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_IPC_RAW_PROTOCOL(ipc_raw_protocol_t **protocol_ptr) {
    if (protocol_ptr != NULL && *protocol_ptr != NULL) {
        ipc_raw_protocol_t *x = *protocol_ptr;
        CLOSE_IPC_RAW_PAYLOAD((void **)&x->recv_buffer);
        free(x);
        *protocol_ptr = NULL;
    }
}

typedef struct {
	ipc_protocol_t *r_ipc_protocol_t;
    status_t status;
} ipc_protocol_t_status_t;

typedef struct {
	ipc_raw_protocol_t *r_ipc_raw_protocol_t;
    status_t status;
} ipc_raw_protocol_t_status_t;

static inline status_t ipc_check_mac(const char *label, uint8_t* key_mac, ipc_raw_protocol_t *r) {
    uint8_t *key0 = (uint8_t *)calloc(1, HASHES_BYTES * sizeof(uint8_t));
    if (memcmp(
            key_mac, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        uint8_t *data_4mac = r->recv_buffer;
        const size_t data_offset = AES_TAG_BYTES;
        const size_t data_len = r->n - AES_TAG_BYTES;
        uint8_t *data = r->recv_buffer + data_offset;
        if (compare_mac(
                key_mac,
                data,
                data_len,
                data_4mac
            ) != SUCCESS
        )
        {
            LOG_ERROR("%sIpc Mac mismatch!", label);
            free(key0);
            return FAILURE_MACMSMTCH;
        }
    }
    free(key0);
    return SUCCESS;
}

static inline status_t ipc_check_ctr(const char *label, uint8_t* key_aes, uint32_t* ctr, ipc_raw_protocol_t *r) {
    uint8_t *key0 = (uint8_t *)calloc(1, HASHES_BYTES * sizeof(uint8_t));
    if (memcmp(
            key_aes, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        if (r->ctr != *(uint32_t *)ctr) {
            LOG_ERROR("%sIpc Counter not match. Protocol %d, data_ctr: %u, *ctr: %u", label, r->type, r->ctr, *(uint32_t *)ctr);
            free(key0);
            return FAILURE_CTRMSMTCH;
        }
    }
    free(key0);
    return SUCCESS;
}

static inline status_t ipc_read_header(const char *label, uint8_t* key_mac, uint8_t* nonce, ipc_raw_protocol_t *r) {
    size_t current_offset = 0;
    size_t total_buffer_len = (size_t)r->n;
    uint8_t *cursor = r->recv_buffer + current_offset;
    uint8_t *key0 = (uint8_t *)calloc(1, HASHES_BYTES * sizeof(uint8_t));
    if (memcmp(
            key_mac, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        
    }
    free(key0);
    if (current_offset + AES_TAG_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading mac.", label);
        return FAILURE_OOBUF;
    }
    memcpy(r->mac, cursor, AES_TAG_BYTES);
    cursor += AES_TAG_BYTES;
    current_offset += AES_TAG_BYTES;
    if (current_offset + sizeof(uint32_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading ctr.", label);
        return FAILURE_OOBUF;
    }
    uint32_t ctr_be;
    memcpy(&ctr_be, cursor, sizeof(uint32_t));
    r->ctr = be32toh(ctr_be);
    cursor += sizeof(uint32_t);
    current_offset += sizeof(uint32_t);
    if (current_offset + IPC_VERSION_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading version.", label);
        return FAILURE_OOBUF;
    }
    memcpy(r->version, cursor, IPC_VERSION_BYTES);
    cursor += IPC_VERSION_BYTES;
    current_offset += IPC_VERSION_BYTES;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading type.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&r->type, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading wot.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&r->wot, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->index, cursor, sizeof(uint8_t));
    return SUCCESS;
}

static inline status_t ipc_read_cleartext_header(const char *label, ipc_raw_protocol_t *r) {
    size_t current_offset = 0;
    size_t total_buffer_len = (size_t)r->n;
    uint8_t *cursor = r->recv_buffer + current_offset;
    if (current_offset + AES_TAG_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading mac.", label);
        return FAILURE_OOBUF;
    }
    cursor += AES_TAG_BYTES;
    current_offset += AES_TAG_BYTES;
    if (current_offset + sizeof(uint32_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading ctr.", label);
        return FAILURE_OOBUF;
    }
    cursor += sizeof(uint32_t);
    current_offset += sizeof(uint32_t);
    if (current_offset + IPC_VERSION_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading version.", label);
        return FAILURE_OOBUF;
    }
    cursor += IPC_VERSION_BYTES;
    current_offset += IPC_VERSION_BYTES;
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading type.", label);
        return FAILURE_OOBUF;
    }
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading wot.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&r->wot, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->index, cursor, sizeof(uint8_t));
    return SUCCESS;
}

static inline ipc_raw_protocol_t_status_t receive_ipc_raw_protocol_message(const char *label, int *uds_fd) {
    ipc_raw_protocol_t_status_t result;
    result.status = FAILURE;
    result.r_ipc_raw_protocol_t = NULL;
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
            LOG_ERROR("%sreceive_ipc_raw_protocol_message recvmsg (length prefix + FD). %s", label, strerror(errno));
        }
        return result;
    }
    if (bytes_read_prefix_and_fd != (ssize_t)IPC_LENGTH_PREFIX_BYTES) {
        LOG_ERROR("%sGagal membaca length prefix sepenuhnya. Diharapkan %zu byte, diterima %zd.",
                label, IPC_LENGTH_PREFIX_BYTES, bytes_read_prefix_and_fd);
        result.status = FAILURE_OOBUF;
        return result;
    }
    memcpy(&total_ipc_payload_len_be, temp_len_prefix_buf, IPC_LENGTH_PREFIX_BYTES);
    uint32_t total_ipc_payload_len = be32toh(total_ipc_payload_len_be);
    LOG_DEBUG("%sDitemukan panjang payload IPC: %u byte.", label, total_ipc_payload_len);
    if (total_ipc_payload_len == 0) {
        LOG_ERROR("%sPanjang payload IPC adalah 0. Tidak ada data untuk dibaca.", label);
        result.status = FAILURE_BAD_PROTOCOL;
        return result;
    }
    uint8_t *full_ipc_payload_buffer = (uint8_t *)malloc(total_ipc_payload_len);
    if (!full_ipc_payload_buffer) {
        LOG_ERROR("%sreceive_ipc_raw_protocol_message: malloc failed for full_ipc_payload_buffer. %s", label, strerror(errno));
        result.status = FAILURE_NOMEM;
        return result;
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
    const size_t min_size = AES_TAG_BYTES +
                            sizeof(uint32_t) +
                            IPC_VERSION_BYTES +
                            sizeof(uint8_t) +
                            sizeof(uint8_t) +
                            sizeof(uint8_t);
    if (bytes_read_payload < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
			LOG_ERROR("%sreceive_ipc_raw_protocol_message recvmsg (payload). %s", label, strerror(errno));
			free(full_ipc_payload_buffer);
			result.status = FAILURE_EAGNEWBLK;
            return result;
        } else {
			LOG_ERROR("%sreceive_ipc_raw_protocol_message recvmsg (payload). %s", label, strerror(errno));
			free(full_ipc_payload_buffer);
			result.status = FAILURE;
			return result;
		}
    } else if (bytes_read_payload < (ssize_t)min_size) {
        LOG_ERROR("%sreceive_ipc_raw_protocol_message received 0 bytes (unexpected for IPC).", label);
        free(full_ipc_payload_buffer);
        result.status = FAILURE_OOBUF;
        return result;
    } else if (bytes_read_payload != (ssize_t)total_ipc_payload_len) {
        LOG_ERROR("%sPayload IPC tidak lengkap. Diharapkan %u byte, diterima %zd.", label, total_ipc_payload_len, bytes_read_payload);
        free(full_ipc_payload_buffer);
        result.status = FAILURE_OOBUF;
        return result;
    }
    ipc_raw_protocol_t* r = (ipc_raw_protocol_t*)calloc(1, sizeof(ipc_raw_protocol_t));
    if (!r) {
        LOG_ERROR("%sFailed to allocate ipc_raw_protocol_t. %s", label, strerror(errno));
        free(full_ipc_payload_buffer);
        result.status = FAILURE_NOMEM;
        return result;
    }
    r->recv_buffer = full_ipc_payload_buffer;
    r->n = (uint32_t)bytes_read_payload;
    full_ipc_payload_buffer = NULL;
    bytes_read_payload = 0;
    result.r_ipc_raw_protocol_t = r;
    result.status = SUCCESS;
    return result;
}

static inline status_t ipc_add_protocol_queue(const char *label, uint64_t queue_id, worker_type_t wot, uint8_t index, int *uds_fd, ipc_protocol_t *p, ipc_protocol_queue_t **head) {
    ipc_protocol_queue_t *new_queue = (ipc_protocol_queue_t *)calloc(1, sizeof(ipc_protocol_queue_t));
    if (!new_queue) {
        LOG_ERROR("%sFailed to allocate ipc_protocol_queue_t buffer. %s", label, strerror(errno));
        return FAILURE;
    }    
    new_queue->queue_id = queue_id;
    new_queue->wot = wot;
    new_queue->index = index;
    new_queue->uds_fd = uds_fd;
    new_queue->p = p;
    new_queue->next = *head;
    *head = new_queue;
    return SUCCESS;
}

static inline void ipc_remove_protocol_queue(uint64_t queue_id, ipc_protocol_queue_t **head) {
    ipc_protocol_queue_t *current = *head;
    ipc_protocol_queue_t *previous = NULL;
    while (current != NULL && current->queue_id != queue_id) {
        previous = current;
        current = current->next;
    }
    if (current != NULL) {
        if (previous == NULL) {
            *head = current->next;
        } else {
            previous->next = current->next;
        }
        CLOSE_IPC_PROTOCOL(&current->p);
        free(current);
    }
}

static inline void ipc_cleanup_protocol_queue(ipc_protocol_queue_t **head) {
    ipc_protocol_queue_t *current = *head;
    ipc_protocol_queue_t *next;
    while (current != NULL) {
        next = current->next;
        CLOSE_IPC_PROTOCOL(&current->p);
        free(current);
        current = next;
    }
    *head = NULL;
}

ssize_t_status_t send_ipc_protocol_message(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint8_t* nonce, uint32_t *ctr, int *uds_fd, const ipc_protocol_t* p);
ipc_protocol_t_status_t ipc_deserialize(const char *label, uint8_t *key_aes, uint8_t *nonce, uint32_t *ctr, uint8_t *buffer, size_t len);

#endif
