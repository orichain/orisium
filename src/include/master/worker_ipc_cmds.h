#ifndef MASTER_WORKER_IPC_CMDS_H
#define MASTER_WORKER_IPC_CMDS_H

#include "master/process.h"

status_t master_workers_info(master_context_t *master_ctx, info_type_t flag);
status_t master_cow_connect(master_context_t *master_ctx, struct sockaddr_in6 *addr, uint8_t index);
status_t master_worker_hello1_ack(master_context_t *master_ctx, worker_type_t wot, uint8_t index);
status_t master_worker_hello2_ack(master_context_t *master_ctx, worker_type_t wot, uint8_t index);

#endif
