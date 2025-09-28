#include <stdio.h>
#include <inttypes.h>
#include <time.h>

#include "log.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "types.h"
#include "workers/workers.h"
#include "orilink/protocol.h"
#include "stdbool.h"
#include "async.h"
#include "constants.h"
#include "orilink/heartbeat_fin_ack.h"
#include "workers/ipc/master_ipc_cmds.h"

struct sockaddr_in6;

status_t handle_workers_ipc_udp_data_cow_heartbeat_fin(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
//======================================================================
// + Security
//======================================================================
    if (!session->heartbeat_ack.ack_sent) {
        LOG_ERROR("%sReceive Heartbeat_Fin But This Worker Session Is Never Sending Heartbeat_Ack.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (session->heartbeat_closed) {
        LOG_ERROR("%Heartbeat_Fin Received Already.", worker_ctx->label);
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
    orilink_heartbeat_fin_t *oheartbeat_fin = received_orilink_protocol->payload.orilink_heartbeat_fin;
//======================================================================
// + Security
//======================================================================
    if (identity->local_id != oheartbeat_fin->remote_id || identity->remote_id != oheartbeat_fin->local_id) {
        LOG_ERROR("%sLocal Id And Or Remote Id Mismatch.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    double hb_interval = session->heartbeat_ack.interval_ack_timer_fd;
    if (hb_interval < (double)NODE_HEARTBEAT_INTERVAL) {
        hb_interval = (double)NODE_HEARTBEAT_INTERVAL;
    }
    if (hb_interval > (double)NODE_CHECK_HEALTHY) {
        hb_interval = (double)NODE_CHECK_HEALTHY;
    }
    double hb_openner_interval = hb_interval - ((double)10 * (double)(session->rtt.value_prediction / 1e9));
    if (hb_openner_interval < (double)0) {
        hb_openner_interval = (double)0;
    }
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat_fin_ack(
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
        identity->remote_id
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
    if (worker_master_udp_data_noretry(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, remote_addr, &udp_data) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    double try_count = (double)session->heartbeat_ack.ack_sent_try_count-(double)1;
    calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    session->heartbeat_ack.rcvd = true;
    session->heartbeat_ack.rcvd_time = current_time.r_uint64_t;
    
    printf("Ack Rcvd Time %" PRIu64 "\n", session->heartbeat_ack.rcvd_time);
    
    uint64_t interval_ull = session->heartbeat_ack.rcvd_time - session->heartbeat_ack.ack_sent_time;
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    cleanup_packet_ack_timer(worker_ctx->label, &worker_ctx->async, &session->heartbeat_ack);
    
    printf("%sRTT Heartbeat Ack = %f\n", worker_ctx->label, session->rtt.value_prediction);
//======================================================================
    if (hb_openner_interval != (double)0) {
        if (async_create_timerfd(worker_ctx->label, &session->heartbeat_openner_fd) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
        }
        if (async_set_timerfd_time(worker_ctx->label, &session->heartbeat_openner_fd,
            (time_t)hb_openner_interval,
            (long)((hb_openner_interval - (time_t)hb_openner_interval) * 1e9),
            (time_t)hb_openner_interval,
            (long)((hb_openner_interval - (time_t)hb_openner_interval) * 1e9)) != SUCCESS)
        {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
        }
        if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_openner_fd) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
        }
//======================================================================
        session->heartbeat_closed = true;
//======================================================================
    }
    return SUCCESS;
}
