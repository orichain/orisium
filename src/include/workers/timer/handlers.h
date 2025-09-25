#ifndef WORKERS_TIMER_HANDLERS_H
#define WORKERS_TIMER_HANDLERS_H

#include "workers/workers.h"
#include "workers/ipc/master_ipc_cmds.h"

status_t handle_workers_timer_event(worker_context_t *worker_ctx, void *sessions, int *current_fd);

static inline status_t retry_hello(worker_context_t *worker_ctx, cow_c_session_t *session, hello_t *hello) {
    orilink_identity_t *identity = &session->identity;
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_realtime_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        return FAILURE;
    }
    hello->sent_try_count++;
    hello->sent_time = current_time.r_uint64_t;
    if (async_set_timerfd_time(worker_ctx->label, &hello->timer_fd,
        (time_t)hello->interval_timer_fd,
        (long)((hello->interval_timer_fd - (time_t)hello->interval_timer_fd) * 1e9),
        (time_t)hello->interval_timer_fd,
        (long)((hello->interval_timer_fd - (time_t)hello->interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
//======================================================================
    puint8_t_size_t_status_t udp_data;
    udp_data.status = SUCCESS;
    udp_data.r_size_t = hello->len;
    udp_data.r_puint8_t = (uint8_t *)calloc(1, hello->len);
    memcpy(udp_data.r_puint8_t, hello->data, hello->len);
    free(hello->data);
    hello->data = NULL;
    hello->len = 0;
    if (udp_data.status != SUCCESS) {
        return FAILURE;
    }
    if (worker_master_udp_data(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &identity->remote_addr, &udp_data, hello) != SUCCESS) {
        return FAILURE;
    }
//======================================================================
    return SUCCESS;
}

static inline status_t retry_hello_ack(worker_context_t *worker_ctx, sio_c_session_t *session, hello_ack_t *hello_ack) {
    orilink_identity_t *identity = &session->identity;
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_realtime_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        return FAILURE;
    }
    hello_ack->ack_sent_try_count++;
    hello_ack->ack_sent_time = current_time.r_uint64_t;
    if (async_set_timerfd_time(worker_ctx->label, &hello_ack->ack_timer_fd,
        (time_t)hello_ack->interval_ack_timer_fd,
        (long)((hello_ack->interval_ack_timer_fd - (time_t)hello_ack->interval_ack_timer_fd) * 1e9),
        (time_t)hello_ack->interval_ack_timer_fd,
        (long)((hello_ack->interval_ack_timer_fd - (time_t)hello_ack->interval_ack_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
//======================================================================
    puint8_t_size_t_status_t udp_data;
    udp_data.status = SUCCESS;
    udp_data.r_size_t = hello_ack->len;
    udp_data.r_puint8_t = (uint8_t *)calloc(1, hello_ack->len);
    memcpy(udp_data.r_puint8_t, hello_ack->data, hello_ack->len);
    free(hello_ack->data);
    hello_ack->data = NULL;
    hello_ack->len = 0;
    if (udp_data.status != SUCCESS) {
        return FAILURE;
    }
    if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &identity->remote_addr, &udp_data, hello_ack) != SUCCESS) {
        return FAILURE;
    }
//======================================================================
    return SUCCESS;
}

#endif
