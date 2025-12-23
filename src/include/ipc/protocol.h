#ifndef IPC_PROTOCOL_H
#define IPC_PROTOCOL_H

#include <netinet/in.h>
#include <stdint.h>

#if defined(__clang__)
    #if __clang_major__ < 21
        #include <stdlib.h>
    #endif
#endif

#include <string.h>

#include "constants.h"
#include "pqc.h"
#include "types.h"
#include "oritlsf.h"

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
    worker_type_t wot;
    uint8_t index;
    int *uds_fd;
    et_buffer_t *buffer;
    ipc_protocol_t *p;
    struct ipc_protocol_queue_t *next;
    struct ipc_protocol_queue_t *prev;
} ipc_protocol_queue_t;
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_IPC_PROTOCOL(oritlsf_pool_t *pool, ipc_protocol_t **protocol_ptr) {
    if (protocol_ptr != NULL && *protocol_ptr != NULL) {
        ipc_protocol_t *x = *protocol_ptr;
        if (x) {
			if (x->type == IPC_WORKER_MASTER_HEARTBEAT) {
				oritlsf_free(pool, (void **)&x->payload.ipc_worker_master_heartbeat);
			} else if (x->type == IPC_MASTER_WORKER_INFO) {
				oritlsf_free(pool, (void **)&x->payload.ipc_master_worker_info);
			} else if (x->type == IPC_WORKER_MASTER_TASK_INFO) {
				oritlsf_free(pool, (void **)&x->payload.ipc_worker_master_task_info);
			} else if (x->type == IPC_MASTER_COW_CONNECT) {
				oritlsf_free(pool, (void **)&x->payload.ipc_master_cow_connect);
			} else if (x->type == IPC_UDP_DATA) {
				oritlsf_free(pool, (void **)&x->payload.ipc_udp_data);
			} else if (x->type == IPC_UDP_DATA_ACK) {
				oritlsf_free(pool, (void **)&x->payload.ipc_udp_data_ack);
			} else if (x->type == IPC_WORKER_MASTER_HELLO1) {
				memset(x->payload.ipc_worker_master_hello1->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
				oritlsf_free(pool, (void **)&x->payload.ipc_worker_master_hello1);
			} else if (x->type == IPC_MASTER_WORKER_HELLO1_ACK) {
				memset(x->payload.ipc_master_worker_hello1_ack->nonce, 0, AES_NONCE_BYTES);
				memset(x->payload.ipc_master_worker_hello1_ack->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
				oritlsf_free(pool, (void **)&x->payload.ipc_master_worker_hello1_ack);
			} else if (x->type == IPC_WORKER_MASTER_HELLO2) {
				memset(x->payload.ipc_worker_master_hello2->encrypted_wot_index, 0, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES);
				oritlsf_free(pool, (void **)&x->payload.ipc_worker_master_hello2);
			} else if (x->type == IPC_MASTER_WORKER_HELLO2_ACK) {
				memset(x->payload.ipc_master_worker_hello2_ack->encrypted_wot_index, 0, sizeof(uint8_t) + sizeof(uint8_t) + AES_TAG_BYTES);
				oritlsf_free(pool, (void **)&x->payload.ipc_master_worker_hello2_ack);
			}
		}
        oritlsf_free(pool, (void **)protocol_ptr);
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
static inline void CLOSE_IPC_RAW_PROTOCOL(oritlsf_pool_t *pool, ipc_raw_protocol_t **protocol_ptr) {
    if (protocol_ptr != NULL && *protocol_ptr != NULL) {
		if (*protocol_ptr) oritlsf_free(pool, (void **)&((*protocol_ptr)->recv_buffer));
		oritlsf_free(pool, (void **)protocol_ptr);
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

#endif
