#ifndef MASTER_PROCESS_H
#define MASTER_PROCESS_H

#include <sys/types.h>

#include "async.h"
#include "constants.h"
#include "types.h"

typedef struct {
	int master_pid;
    int listen_sock;
    async_type_t master_async;
    int master_uds_sio_fds[MAX_SIO_WORKERS];
    int master_uds_logic_fds[MAX_LOGIC_WORKERS];
    int master_uds_cow_fds[MAX_COW_WORKERS];
    int worker_uds_sio_fds[MAX_SIO_WORKERS];
    int worker_uds_logic_fds[MAX_LOGIC_WORKERS];
    int worker_uds_cow_fds[MAX_COW_WORKERS];
    pid_t sio_pids[MAX_SIO_WORKERS];
    pid_t logic_pids[MAX_LOGIC_WORKERS];
    pid_t cow_pids[MAX_COW_WORKERS];
} master_context;

void run_master_process(master_context *master_ctx);
status_t setup_master(master_context *master_ctx);
status_t setup_workers(master_context *master_ctx);

#endif
