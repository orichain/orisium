#include <inttypes.h>

#include "log.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "orilink/protocol.h"
#include "stdbool.h"

struct sockaddr_in6;

status_t handle_workers_ipc_udp_data_cow_heartbeat_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
    uint32_t oudp_datao_ctr = oudp_datao->ctr;
//======================================================================
// + Security
//======================================================================
    if (!session->heartbeat.sent) {
        LOG_ERROR("%sReceive Heartbeat_Ack But This Worker Session Is Never Sending Heartbeat.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (session->heartbeat.ack_rcvd) {
        status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
        if (cmac != SUCCESS) {
            LOG_ERROR("%sHeartbeat_Ack Received Already(1). Protocol %d, data_ctr: %u, *ctr: %u", worker_ctx->label, oudp_datao->type, oudp_datao->ctr, security->remote_ctr);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        if (!is_1lower_ctr(&oudp_datao_ctr, &security->remote_ctr, security->remote_nonce)) {
            LOG_ERROR("%sHeartbeat_Ack Received Already(2). Protocol %d, data_ctr: %u, *ctr: %u", worker_ctx->label, oudp_datao->type, oudp_datao->ctr, security->remote_ctr);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        LOG_ERROR("%sHeartbeat_Ack Received Already(3). Protocol %d, data_ctr: %u, *ctr: %u", worker_ctx->label, oudp_datao->type, oudp_datao->ctr, security->remote_ctr);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//======================================================================
    status_t cmac = orilink_check_mac_ctr(
        worker_ctx->label, 
        security->aes_key, 
        security->mac_key, 
        security->remote_nonce,
        &security->remote_ctr, 
        oudp_datao
    );
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return cmac;
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
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_heartbeat_ack_t *oheartbeat_ack = received_orilink_protocol->payload.orilink_heartbeat_ack;
//======================================================================
// + Security
//======================================================================
    if (identity->local_id != oheartbeat_ack->remote_id || identity->remote_id != oheartbeat_ack->local_id) {
        LOG_ERROR("%sLocal Id And Or Remote Id Mismatch.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    //async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
    //CLOSE_FD(&session->heartbeat_sender_timer_fd);
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
// 
//----------------------------------------------------------------------
    if (session->heartbeat.sent_try_count > (uint8_t)0) {
        double try_count = (double)session->heartbeat.sent_try_count-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
//======================================================================
    session->heartbeat.ack_rcvd = true;
    session->heartbeat.ack_rcvd_time = current_time.r_uint64_t;
    uint64_t interval_ull = session->heartbeat.ack_rcvd_time - session->heartbeat.sent_time;
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    //cleanup_control_packet(worker_ctx->label, &worker_ctx->async, &session->heartbeat, false);

    LOG_DEVEL_DEBUG("%sRTT Heartbeat = %f", worker_ctx->label, session->rtt.value_prediction);
//======================================================================
// Heartbeat Security 2 Open
//======================================================================
    session->heartbeat_ack.rcvd = false;
//======================================================================
    //session->metrics.last_ack = current_time.r_uint64_t;
    //session->metrics.count_ack += (double)1;
    //session->metrics.sum_hb_interval += session->heartbeat_interval;
    //session->metrics.hb_interval = session->heartbeat_interval;
//======================================================================
    return SUCCESS;
}
