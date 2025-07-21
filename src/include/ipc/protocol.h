#ifndef IPC_PROTOCOL_H
#define IPC_PROTOCOL_H

#include <stdlib.h>
#include "types.h"
#include "constants.h"

typedef enum {
    IPC_WORKER_MASTER_HEARTBEAT = (uint8_t)0xfe,
    IPC_MASTER_WORKER_SHUTDOWN = (uint8_t)0xff
} ipc_protocol_type_t;

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
        }
        free(x);
        *protocol_ptr = NULL;
    }
}

typedef struct {
	ipc_protocol_t *r_ipc_protocol_t;
    status_t status;
} ipc_protocol_t_status_t;

ssize_t_status_t send_ipc_protocol_message(const char *label, int *uds_fd, const ipc_protocol_t* p);
ipc_protocol_t_status_t receive_and_deserialize_ipc_message(const char *label, int *uds_fd);

#endif
