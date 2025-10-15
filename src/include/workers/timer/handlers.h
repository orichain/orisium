#ifndef WORKERS_TIMER_HANDLERS_H
#define WORKERS_TIMER_HANDLERS_H

#include "workers/workers.h"

status_t handle_workers_timer_event(worker_context_t *worker_ctx, void *sessions, int *current_fd);

static inline status_t create_timer(worker_context_t *worker_ctx, int *file_descriptor, double timer_interval) {
    if (async_create_timerfd(worker_ctx->label, file_descriptor) != SUCCESS) {
        return FAILURE;
    }
    if (async_set_timerfd_time(worker_ctx->label, file_descriptor,
        (time_t)timer_interval,
        (long)((timer_interval - (time_t)timer_interval) * 1e9),
        (time_t)timer_interval,
        (long)((timer_interval - (time_t)timer_interval) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, file_descriptor) != SUCCESS) {
        return FAILURE;
    }
    return SUCCESS;
}

static inline status_t create_polling_1ms(worker_context_t *worker_ctx, control_packet_t *h, double total_polling_interval) {
    h->polling = true;
    if (async_create_timerfd(worker_ctx->label, &h->polling_timer_fd) != SUCCESS) {
        return FAILURE;
    }
    double polling_interval = (double)1000000 / (double)1e9;
    h->polling_1ms_max_cnt = (uint16_t)ceil((total_polling_interval * (double)1e9) / (double)1000000);
    printf("%sRetransmit Scheduled In %d Polling 1ms\n", worker_ctx->label, h->polling_1ms_max_cnt);
    if (async_set_timerfd_time(worker_ctx->label, &h->polling_timer_fd,
        (time_t)polling_interval,
        (long)((polling_interval - (time_t)polling_interval) * 1e9),
        (time_t)polling_interval,
        (long)((polling_interval - (time_t)polling_interval) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &h->polling_timer_fd) != SUCCESS) {
        return FAILURE;
    }
    return SUCCESS;
}

static inline status_t update_timer(worker_context_t *worker_ctx, int *file_descriptor, double timer_interval) {
    if (async_set_timerfd_time(worker_ctx->label, file_descriptor,
        (time_t)timer_interval,
        (long)((timer_interval - (time_t)timer_interval) * 1e9),
        (time_t)timer_interval,
        (long)((timer_interval - (time_t)timer_interval) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    return SUCCESS;
}

#endif
