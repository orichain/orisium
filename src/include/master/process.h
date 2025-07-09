#ifndef MASTER_PROCESS_H
#define MASTER_PROCESS_H

#include <sys/types.h>

#include "async.h"
#include "constants.h"
#include "types.h"

typedef int uds_pair[2];

typedef struct {
	uds_pair uds;
	pid_t pid;
} uds_pair_pid_t;

typedef struct {
	int master_pid;
    int listen_sock;
    int master_timer_fd;
    int shutdown_event_fd;
    async_type_t master_async;
    uds_pair_pid_t sio[MAX_SIO_WORKERS];
    uds_pair_pid_t logic[MAX_LOGIC_WORKERS];
    uds_pair_pid_t cow[MAX_COW_WORKERS];
} master_context;

void run_master_process(master_context *master_ctx);
status_t setup_master(master_context *master_ctx);
status_t setup_workers(master_context *master_ctx);

#endif
