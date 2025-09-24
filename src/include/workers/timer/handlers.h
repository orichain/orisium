#ifndef WORKERS_TIMER_HANDLERS_H
#define WORKERS_TIMER_HANDLERS_H

#include "workers/workers.h"

status_t retry_cow_connect(worker_context_t *worker_ctx, cow_c_session_t *session);

#endif
