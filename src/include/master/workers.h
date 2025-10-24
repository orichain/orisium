#ifndef MASTER_WORKERS_H
#define MASTER_WORKERS_H

#include <stdint.h>

#include "master/master.h"
#include "types.h"

status_t close_worker(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index);
status_t create_socket_pair(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index);
status_t setup_fork_worker(const char* label, master_context_t *master_ctx, worker_type_t wot, uint8_t index);
status_t setup_workers(const char *label, master_context_t *master_ctx);
void cleanup_workers(const char *label, master_context_t *master_ctx);
status_t calculate_avgtt(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index);
status_t check_workers_healthy(const char *label, master_context_t *master_ctx);
status_t recreate_worker(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index);

#endif
