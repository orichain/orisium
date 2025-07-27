#ifndef IPC_PROTOCOL_H
#define IPC_PROTOCOL_H

#include <stdlib.h>
#include "types.h"
#include "constants.h"

typedef enum {
    IPC_MASTER_SIO_CONNECT = (uint8_t)0x00,
    IPC_MASTER_SIO_DATA = (uint8_t)0x01,
    IPC_SIO_MASTER_DATA = (uint8_t)0x02,
    IPC_SIO_MASTER_CONNECTION = (uint8_t)0x03,
    
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
