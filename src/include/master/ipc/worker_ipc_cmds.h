#ifndef MASTER_IPC_WORKER_IPC_CMDS_H
#define MASTER_IPC_WORKER_IPC_CMDS_H

#include "master/master.h"

status_t master_worker_info(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, info_type_t flag);
status_t master_workers_info(const char *label, master_context_t *master_ctx, info_type_t flag);
status_t master_cow_connect(const char *label, master_context_t *master_ctx, struct sockaddr_in6 *addr, uint8_t index, uint8_t session_index);
status_t master_worker_hello1_ack(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, uint8_t local_nonce[]);
status_t master_worker_hello2_ack(const char *label, master_context_t *master_ctx, worker_type_t wot, int index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, uint8_t encrypted_wot_index1[]);
status_t master_worker_udp_data(
    const char *label, 
    master_context_t *master_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    struct sockaddr_in6 *addr,
    orilink_raw_protocol_t *r
);

#endif
