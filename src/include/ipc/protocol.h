#ifndef IPC_PROTOCOL_H
#define IPC_PROTOCOL_H

#include <arpa/inet.h>
#include <stdlib.h>
#include "types.h"
#include "constants.h"

typedef enum {
    IPC_CLIENT_REQUEST_TASK = (uint8_t)0x00,
    IPC_CLIENT_DISCONNECTED = (uint8_t)0x01,
    IPC_SHUTDOWN = (uint8_t)0x02,
    IPC_HEARTBEAT = (uint8_t)0x03
} ipc_protocol_type_t;

typedef struct {
    uint8_t ip[IP_ADDRESS_LEN];
    uint16_t len;
    uint8_t data[];
} ipc_client_request_task_t;

typedef struct {
    uint8_t ip[IP_ADDRESS_LEN];
} ipc_client_disconnect_info_t;

typedef struct {
    shutdown_type_t flag;
} ipc_shutdown_t;

typedef struct {
    worker_type_t wot;
    uint8_t index;
} ipc_heartbeat_t;

typedef struct {
	uint8_t version[IPC_VERSION_BYTES];
	ipc_protocol_type_t type;
	union {
		ipc_client_request_task_t *ipc_client_request_task;
		ipc_client_disconnect_info_t *ipc_client_disconnect_info;
		ipc_shutdown_t *ipc_shutdown;
        ipc_heartbeat_t *ipc_heartbeat;
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
        if (x->type == IPC_CLIENT_REQUEST_TASK) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_client_request_task);
        } else if (x->type == IPC_CLIENT_DISCONNECTED) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_client_disconnect_info);
        } else if (x->type == IPC_SHUTDOWN) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_shutdown);
        } else if (x->type == IPC_HEARTBEAT) {
            CLOSE_IPC_PAYLOAD((void **)&x->payload.ipc_heartbeat);
        }
        free(x);
        *protocol_ptr = NULL;
    }
}

typedef struct {
	ipc_protocol_t *r_ipc_protocol_t;
    status_t status;
} ipc_protocol_t_status_t;

#include "ipc/client_request_task.h"
#include "ipc/client_disconnect_info.h"
#include "ipc/shutdown.h"
#include "ipc/heartbeat.h"

ssize_t_status_t send_ipc_protocol_message(const char *label, int *uds_fd, const ipc_protocol_t* p, int *fd_to_pass);
ipc_protocol_t_status_t receive_and_deserialize_ipc_message(const char *label, int *uds_fd, int *actual_fd_received);

#endif
