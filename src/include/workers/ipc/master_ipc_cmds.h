#ifndef WORKERS_IPC_MASTER_IPC_CMDS_H
#define WORKERS_IPC_MASTER_IPC_CMDS_H

#include "workers/workers.h"

status_t worker_master_heartbeat(worker_context_t *ctx, double new_heartbeat_interval_double);
status_t worker_master_hello1(worker_context_t *ctx);
status_t worker_master_hello2(worker_context_t *ctx, uint8_t encrypted_wot_index2[]);
status_t cow_master_connection(worker_context_t *ctx, struct sockaddr_in6 *addr, connection_type_t flag);
status_t worker_master_udp_data(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    struct sockaddr_in6 *addr,
    puint8_t_size_t_status_t *r,
    hello_t *h
);
status_t worker_master_udp_data_ack(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    struct sockaddr_in6 *addr,
    puint8_t_size_t_status_t *r,
    hello_ack_t *h
);

#endif
