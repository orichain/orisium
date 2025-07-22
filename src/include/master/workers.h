#ifndef MASTER_WORKERS_H
#define MASTER_WORKERS_H

#include "master/process.h"

status_t close_worker(const char *label, master_context *master_ctx, worker_type_t wot, int index);
status_t create_socket_pair(const char *label, master_context *master_ctx, worker_type_t wot, int index);
status_t setup_fork_worker(const char* label, master_context *master_ctx, worker_type_t wot, int index);
status_t setup_workers(master_context *master_ctx);
void workers_cleanup(master_context *master_ctx);

#endif
