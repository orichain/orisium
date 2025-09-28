#ifndef WORKERS_TIMER_HANDLERS_H
#define WORKERS_TIMER_HANDLERS_H

#include "workers/workers.h"
#include "workers/ipc/master_ipc_cmds.h"

status_t handle_workers_timer_event(worker_context_t *worker_ctx, void *sessions, int *current_fd);

static inline status_t retry_packet(worker_context_t *worker_ctx, cow_c_session_t *session, packet_t *packet) {
    orilink_identity_t *identity = &session->identity;
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        return FAILURE;
    }
    packet->sent_try_count++;
    packet->sent_time = current_time.r_uint64_t;
    if (async_set_timerfd_time(worker_ctx->label, &packet->timer_fd,
        (time_t)packet->interval_timer_fd,
        (long)((packet->interval_timer_fd - (time_t)packet->interval_timer_fd) * 1e9),
        (time_t)packet->interval_timer_fd,
        (long)((packet->interval_timer_fd - (time_t)packet->interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
//======================================================================
    puint8_t_size_t_status_t udp_data;
    udp_data.status = SUCCESS;
    udp_data.r_size_t = packet->len;
    udp_data.r_puint8_t = (uint8_t *)calloc(1, packet->len);
    memcpy(udp_data.r_puint8_t, packet->data, packet->len);
    free(packet->data);
    packet->data = NULL;
    packet->len = 0;
    if (udp_data.status != SUCCESS) {
        return FAILURE;
    }
    if (worker_master_udp_data(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &identity->remote_addr, &udp_data, packet) != SUCCESS) {
        return FAILURE;
    }
//======================================================================
    return SUCCESS;
}

static inline status_t retry_packet_ack(worker_context_t *worker_ctx, sio_c_session_t *session, packet_ack_t *packet_ack) {
    orilink_identity_t *identity = &session->identity;
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        return FAILURE;
    }
    packet_ack->ack_sent_try_count++;
    packet_ack->ack_sent_time = current_time.r_uint64_t;
    if (async_set_timerfd_time(worker_ctx->label, &packet_ack->ack_timer_fd,
        (time_t)packet_ack->interval_ack_timer_fd,
        (long)((packet_ack->interval_ack_timer_fd - (time_t)packet_ack->interval_ack_timer_fd) * 1e9),
        (time_t)packet_ack->interval_ack_timer_fd,
        (long)((packet_ack->interval_ack_timer_fd - (time_t)packet_ack->interval_ack_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
//======================================================================
    puint8_t_size_t_status_t udp_data;
    udp_data.status = SUCCESS;
    udp_data.r_size_t = packet_ack->len;
    udp_data.r_puint8_t = (uint8_t *)calloc(1, packet_ack->len);
    memcpy(udp_data.r_puint8_t, packet_ack->data, packet_ack->len);
    free(packet_ack->data);
    packet_ack->data = NULL;
    packet_ack->len = 0;
    if (udp_data.status != SUCCESS) {
        return FAILURE;
    }
    if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &identity->remote_addr, &udp_data, packet_ack) != SUCCESS) {
        return FAILURE;
    }
//======================================================================
    return SUCCESS;
}

#endif
