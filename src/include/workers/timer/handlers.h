#ifndef WORKERS_TIMER_HANDLERS_H
#define WORKERS_TIMER_HANDLERS_H

#include "workers/workers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "orilink/heartbeat_fin.h"
#include "poly1305-donna.h"

status_t handle_workers_timer_event(worker_context_t *worker_ctx, void *sessions, int *current_fd);

static inline status_t retry_heartbeat_fin(worker_context_t *worker_ctx, cow_c_session_t *session) {
    orilink_identity_t *identity = &session->identity;
    orilink_security_t *security = &session->security;
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        return FAILURE;
    }
    session->heartbeat_fin.sent_try_count++;
    session->heartbeat_fin.sent_time = current_time.r_uint64_t;
    if (async_set_timerfd_time(worker_ctx->label, &session->heartbeat_fin.timer_fd,
        (time_t)session->heartbeat_fin.interval_timer_fd,
        (long)((session->heartbeat_fin.interval_timer_fd - (time_t)session->heartbeat_fin.interval_timer_fd) * 1e9),
        (time_t)session->heartbeat_fin.interval_timer_fd,
        (long)((session->heartbeat_fin.interval_timer_fd - (time_t)session->heartbeat_fin.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
//======================================================================
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat_fin(
        worker_ctx->label,
        0xFF,
        identity->remote_wot,
        identity->remote_index,
        identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        identity->local_id,
        identity->remote_id,
        session->heartbeat_fin.sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    puint8_t_size_t_status_t udp_data = create_orilink_raw_protocol_packet(
        worker_ctx->label,
        security->aes_key,
        security->mac_key,
        security->local_nonce,
        &security->local_ctr,
        orilink_cmd_result.r_orilink_protocol_t
    );
    CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
    if (udp_data.status != SUCCESS) {
        return FAILURE;
    }
    if (worker_master_udp_data_noretry(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &identity->remote_addr, &udp_data) != SUCCESS) {
        return FAILURE;
    }
//======================================================================
    return SUCCESS;
}

static inline status_t retry_packet(worker_context_t *worker_ctx, cow_c_session_t *session, packet_t *packet) {
    orilink_identity_t *identity = &session->identity;
    orilink_security_t *security = &session->security;
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
//----------------------------------------------------------------------
// Update trycount
//----------------------------------------------------------------------
    memcpy(udp_data.r_puint8_t + AES_TAG_BYTES + sizeof(uint32_t), &packet->sent_try_count, sizeof(uint8_t));
    size_t data_4mac_len = packet->len - AES_TAG_BYTES;
    uint8_t *data_4mac = (uint8_t *)calloc(1, data_4mac_len);
    if (!data_4mac) {
        LOG_ERROR("%sError calloc data_4mac for mac: %s", worker_ctx->label, strerror(errno));
        free(packet->data);
        packet->data = NULL;
        packet->len = 0;
        return FAILURE_NOMEM;
    }
    memcpy(data_4mac, udp_data.r_puint8_t + AES_TAG_BYTES, data_4mac_len);
    uint8_t mac[AES_TAG_BYTES];
    poly1305_context ctx;
    poly1305_init(&ctx, security->mac_key);
    poly1305_update(&ctx, data_4mac, data_4mac_len);
    poly1305_finish(&ctx, mac);
    memcpy(udp_data.r_puint8_t, mac, AES_TAG_BYTES);
    free(data_4mac);
//----------------------------------------------------------------------    
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
    orilink_security_t *security = &session->security;
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
//----------------------------------------------------------------------
// Update trycount
//----------------------------------------------------------------------
    memcpy(udp_data.r_puint8_t + AES_TAG_BYTES + sizeof(uint32_t), &packet_ack->ack_sent_try_count, sizeof(uint8_t));
    size_t data_4mac_len = packet_ack->len - AES_TAG_BYTES;
    uint8_t *data_4mac = (uint8_t *)calloc(1, data_4mac_len);
    if (!data_4mac) {
        LOG_ERROR("%sError calloc data_4mac for mac: %s", worker_ctx->label, strerror(errno));
        free(packet_ack->data);
        packet_ack->data = NULL;
        packet_ack->len = 0;
        return FAILURE_NOMEM;
    }
    memcpy(data_4mac, udp_data.r_puint8_t + AES_TAG_BYTES, data_4mac_len);
    uint8_t mac[AES_TAG_BYTES];
    poly1305_context ctx;
    poly1305_init(&ctx, security->mac_key);
    poly1305_update(&ctx, data_4mac, data_4mac_len);
    poly1305_finish(&ctx, mac);
    memcpy(udp_data.r_puint8_t, mac, AES_TAG_BYTES);
    free(data_4mac);
//----------------------------------------------------------------------
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
