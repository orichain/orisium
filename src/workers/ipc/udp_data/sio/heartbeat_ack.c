#include <stdio.h>
#include <inttypes.h>
#include <time.h>

#include "log.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "orilink/protocol.h"
#include "stdbool.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "orilink/heartbeat.h"
#include "async.h"

struct sockaddr_in6;

status_t handle_workers_ipc_udp_data_sio_heartbeat_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
//======================================================================
// + Security
//======================================================================
    if (!session->heartbeat.sent) {
        LOG_ERROR("%sReceive Heartbeat_Ack But This Worker Session Is Never Sending Heartbeat.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (session->heartbeat.ack_rcvd) {
        LOG_ERROR("%sHeartbeat_Ack Received Already.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//======================================================================
    orilink_protocol_t_status_t deserialized_oudp_datao = orilink_deserialize(worker_ctx->label,
        security->aes_key, security->remote_nonce, &security->remote_ctr,
        (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n
    );
    if (deserialized_oudp_datao.status != SUCCESS) {
        LOG_ERROR("%sorilink_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_oudp_datao.status);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_heartbeat_t *oheartbeat_ack = received_orilink_protocol->payload.orilink_heartbeat_ack;
//======================================================================
// + Security
//======================================================================
    if (identity->local_id != oheartbeat_ack->remote_id || identity->remote_id != oheartbeat_ack->local_id) {
        LOG_ERROR("%sLocal Id And Or Remote Id Mismatch.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_realtime_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
    double try_count = (double)session->heartbeat.sent_try_count-(double)1;
    calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    session->heartbeat.ack_rcvd = true;
    session->heartbeat.ack_rcvd_time = current_time.r_uint64_t;
    uint64_t interval_ull = session->heartbeat.ack_rcvd_time - session->heartbeat.sent_time;
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    cleanup_packet_timer(worker_ctx->label, &worker_ctx->async, &session->heartbeat);

    printf("%sRTT Heartbeat = %f\n", worker_ctx->label, session->rtt.value_prediction);
//----------------------------------------------------------------------    
    current_time = get_realtime_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    if (async_create_timerfd(worker_ctx->label, &session->heartbeat.timer_fd) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    session->heartbeat.sent_try_count++;
    session->heartbeat.sent_time = current_time.r_uint64_t;
    if (async_set_timerfd_time(worker_ctx->label, &session->heartbeat.timer_fd,
        (time_t)session->heartbeat.interval_timer_fd,
        (long)((session->heartbeat.interval_timer_fd - (time_t)session->heartbeat.interval_timer_fd) * 1e9),
        (time_t)session->heartbeat.interval_timer_fd,
        (long)((session->heartbeat.interval_timer_fd - (time_t)session->heartbeat.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat.timer_fd) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat(
        worker_ctx->label,
        0x01,
        identity->remote_wot,
        identity->remote_index,
        identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        identity->local_id,
        identity->remote_id,
        session->heartbeat.interval_timer_fd
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
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
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    if (worker_master_udp_data(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, remote_addr, &udp_data, &session->heartbeat) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    session->heartbeat.sent = true;
//======================================================================
    return SUCCESS;
}
