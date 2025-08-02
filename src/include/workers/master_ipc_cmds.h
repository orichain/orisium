#ifndef WORKERS_MASTER_IPC_CMDS_H
#define WORKERS_MASTER_IPC_CMDS_H

#include "workers/workers.h"

status_t worker_master_heartbeat(worker_context_t *ctx, double new_heartbeat_interval_double);
status_t worker_master_hello1(worker_context_t *ctx);
status_t worker_master_hello2(worker_context_t *ctx);
status_t cow_master_connection(worker_context_t *ctx, struct sockaddr_in6 *addr, connection_type_t flag);

#endif
