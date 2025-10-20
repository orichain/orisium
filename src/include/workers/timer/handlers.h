#ifndef WORKERS_TIMER_HANDLERS_H
#define WORKERS_TIMER_HANDLERS_H

#include "workers/workers.h"

status_t handle_workers_timer_event(worker_context_t *worker_ctx, void *sessions, int *current_fd);

static inline status_t create_polling_1ms(worker_context_t *worker_ctx, control_packet_t *h, double total_polling_interval) {
    h->syinching = true;
    double polling_interval = (double)1000000 / (double)1e9;
    h->polling_1ms_max_cnt = (uint16_t)ceil((total_polling_interval * (double)1e9) / (double)1000000);
    status_t ctmr = create_timer_oneshot(worker_ctx->label, &worker_ctx->async, &h->polling_timer_fd, polling_interval);
    if (ctmr != SUCCESS) {
        return FAILURE;
    }
    return SUCCESS;
}

#endif
