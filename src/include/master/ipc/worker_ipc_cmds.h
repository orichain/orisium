#ifndef MASTER_IPC_WORKER_IPC_CMDS_H
#define MASTER_IPC_WORKER_IPC_CMDS_H

#include <stdint.h>

#include "master/master.h"
#include "orilink/protocol.h"
#include "types.h"

struct sockaddr_in6;

status_t master_worker_info(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, info_type_t flag);
status_t master_workers_info(const char *label, master_context_t *master_ctx, info_type_t flag);
status_t master_cow_connect(const char *label, master_context_t *master_ctx, struct sockaddr_in6 *addr, uint8_t index, uint8_t session_index, uint64_t id_addr);
status_t master_worker_hello1_ack(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, uint8_t local_nonce[]);
status_t master_worker_hello2_ack(const char *label, master_context_t *master_ctx, worker_type_t wot, int index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, uint8_t encrypted_wot_index1[]);
status_t master_worker_udp_data(
    const char *label, 
    master_context_t *master_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    uint8_t orilink_protocol, 
    uint8_t trycount,
    struct sockaddr_in6 *addr,
    orilink_raw_protocol_t *r
);
status_t master_worker_udp_data_ack(
    const char *label, 
    master_context_t *master_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    uint8_t orilink_protocol,
    uint8_t trycount,
    status_t status
);

#endif
