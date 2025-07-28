#ifndef IPC_PROTOCOL_H
#define IPC_PROTOCOL_H

#include <stdlib.h>
#include "types.h"
#include "constants.h"
#include "pqc.h"

typedef enum {
    IPC_MASTER_SIO_ORILINK_IDENTITY = (uint8_t)0x00,
    
    IPC_MASTER_COW_CONNECT = (uint8_t)0x10,
    IPC_MASTER_COW_DATA = (uint8_t)0x11,
    IPC_COW_MASTER_DATA = (uint8_t)0x12,
    IPC_COW_MASTER_CONNECTION = (uint8_t)0x13,
    
    IPC_WORKER_MASTER_HEARTBEAT = (uint8_t)0xfe,
    IPC_MASTER_WORKER_SHUTDOWN = (uint8_t)0xff
} ipc_protocol_type_t;

typedef struct {  
    struct sockaddr_in6 server_addr;
} ipc_master_cow_connect_t;

typedef struct {
    struct sockaddr_in6 remote_addr;
    uint64_t server_id;
    uint64_t client_id;
    uint16_t port;
    uint8_t kem_privatekey[KEM_PRIVATEKEY_BYTES];
    uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
    uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES];
    uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
    uint8_t local_nonce[AES_NONCE_BYTES];
    uint32_t local_ctr;
    uint8_t remote_nonce[AES_NONCE_BYTES];
    uint32_t remote_ctr;
    double rtt_pn;
    double rtt_mn;
    double rtt_ee;
    double rtt_se;
    uint8_t rtt_ii;    
    uint8_t rtt_fc;
    uint8_t rtt_kic;
    double rtt_iv;
    double rtt_tev;
    double rtt_vp;
    double retry_pn;
    double retry_mn;
    double retry_ee;
    double retry_se;
    uint8_t retry_ii;    
    uint8_t retry_fc;
    uint8_t retry_kic;
    double retry_iv;
    double retry_tev;
    double retry_vp;
    uint8_t rtt_kcs_len;
    uint8_t retry_kcs_len;
    double rtt_retry_kcs[];
} ipc_master_sio_orilink_identity_t;

typedef struct {
    worker_type_t wot;
    uint8_t index;
    struct sockaddr_in6 server_addr;
    connection_type_t flag;
} ipc_cow_master_connection_t;

typedef struct {
    shutdown_type_t flag;
} ipc_master_worker_shutdown_t;

typedef struct {
    worker_type_t wot;
    uint8_t index;
    double hbtime;
} ipc_worker_master_heartbeat_t;

typedef struct {
	uint8_t version[IPC_VERSION_BYTES];
	ipc_protocol_type_t type;
	union {
		ipc_master_worker_shutdown_t *ipc_master_worker_shutdown;
		ipc_worker_master_heartbeat_t *ipc_worker_master_heartbeat;
        ipc_master_cow_connect_t *ipc_master_cow_connect;
        ipc_cow_master_connection_t *ipc_cow_master_connection;
        ipc_master_sio_orilink_identity_t *ipc_master_sio_orilink_identity;
	} payload;
} ipc_protocol_t;
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
        } else if (x->type == IPC_MASTER_WORKER_SHUTDOWN) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_master_worker_shutdown);
        } else if (x->type == IPC_MASTER_COW_CONNECT) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_master_cow_connect);
        } else if (x->type == IPC_COW_MASTER_CONNECTION) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_cow_master_connection);
        } else if (x->type == IPC_MASTER_SIO_ORILINK_IDENTITY) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_master_sio_orilink_identity);
        }
        free(x);
        *protocol_ptr = NULL;
    }
}

typedef struct {
    uint8_t *recv_buffer;
    uint32_t n;
    uint8_t version[IPC_VERSION_BYTES];
	ipc_protocol_type_t type;
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

ssize_t_status_t send_ipc_protocol_message(const char *label, int *uds_fd, const ipc_protocol_t* p);
ssize_t_status_t send_ipc_protocol_message_wfdtopass(const char *label, int *uds_fd, const ipc_protocol_t* p, int *fd_to_pass);
ipc_raw_protocol_t_status_t receive_ipc_raw_protocol_message(const char *label, int *uds_fd);
ipc_raw_protocol_t_status_t receive_ipc_raw_protocol_message_wfdrcvd(const char *label, int *uds_fd, int *fd_received);
ipc_protocol_t_status_t ipc_deserialize(const char *label, const uint8_t* buffer, size_t len);

#endif
