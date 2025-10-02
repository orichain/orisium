#ifndef WORKERS_TIMER_HANDLERS_H
#define WORKERS_TIMER_HANDLERS_H

#include "workers/workers.h"

status_t handle_workers_timer_event(worker_context_t *worker_ctx, void *sessions, int *current_fd);

#endif
