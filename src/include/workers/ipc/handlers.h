#ifndef WORKERS_IPC_HANDLERS_H
#define WORKERS_IPC_HANDLERS_H

#include "workers/workers.h"

void handle_workers_ipc_closed_event(worker_context_t *worker_ctx);
status_t handle_workers_ipc_event(worker_context_t *worker_ctx, void *worker_sessions, double *initial_delay_ms);

#endif
