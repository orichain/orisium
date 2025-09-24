#ifndef WORKERS_TIMER_HANDLERS_H
#define WORKERS_TIMER_HANDLERS_H

#include "workers/workers.h"

status_t retry_hello(worker_context_t *worker_ctx, cow_c_session_t *session, hello_t *hello);
status_t retry_hello_ack(worker_context_t *worker_ctx, sio_c_session_t *session, hello_ack_t *hello_ack);

#endif
