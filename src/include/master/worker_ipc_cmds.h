#ifndef MASTER_WORKER_IPC_CMDS_H
#define MASTER_WORKER_IPC_CMDS_H

#include "master/process.h"

status_t broadcast_shutdown(master_context *master_ctx);
status_t cow_connect(master_context *master_ctx, struct sockaddr_in6 *addr, int index);

#endif
