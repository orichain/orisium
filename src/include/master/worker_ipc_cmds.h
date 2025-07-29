#ifndef MASTER_WORKER_IPC_CMDS_H
#define MASTER_WORKER_IPC_CMDS_H

#include "master/process.h"

status_t master_workers_shutdown(master_context_t *master_ctx, shutdown_type_t flag);
status_t master_cow_connect(master_context_t *master_ctx, struct sockaddr_in6 *addr, int index);

#endif
