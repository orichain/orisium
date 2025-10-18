#ifndef IPC_PROTOCOL_H
#define IPC_PROTOCOL_H

#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "constants.h"
#include "pqc.h"

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
    uint8_t salt1;
    worker_type_t wot;
    uint8_t salt2;
    uint8_t index;
    uint8_t salt3;
    uint8_t salt4;
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
    uint8_t salt1;
    worker_type_t wot;
    uint8_t salt2;
    uint8_t index;
    uint8_t salt3;
    uint8_t salt4;
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

ssize_t_status_t send_ipc_protocol_message(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint8_t* nonce, uint32_t *ctr, int *uds_fd, const ipc_protocol_t* p);
ipc_raw_protocol_t_status_t receive_ipc_raw_protocol_message(const char *label, int *uds_fd);
status_t ipc_read_cleartext_header(const char *label, ipc_raw_protocol_t *r);
status_t ipc_read_header(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint8_t* nonce, ipc_raw_protocol_t *r);
status_t ipc_check_mac(const char *label, uint8_t* key_mac, ipc_raw_protocol_t *r);
status_t ipc_check_ctr(const char *label, uint8_t* key_aes, uint32_t* ctr, ipc_raw_protocol_t *r);
ipc_protocol_t_status_t ipc_deserialize(const char *label, uint8_t *key_aes, uint8_t *nonce, uint32_t *ctr, uint8_t *buffer, size_t len);
status_t ipc_add_protocol_queue(const char *label, uint64_t queue_id, worker_type_t wot, uint8_t index, int *uds_fd, ipc_protocol_t *p, ipc_protocol_queue_t **head);
void ipc_remove_protocol_queue(uint64_t queue_id, ipc_protocol_queue_t **head);
void ipc_cleanup_protocol_queue(ipc_protocol_queue_t **head);

#endif
