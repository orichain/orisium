#include <inttypes.h>
#include <time.h>
#include <stdio.h>

#include "log.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "orilink/protocol.h"
#include "stdbool.h"
#include "async.h"
#include "constants.h"

struct sockaddr_in6;

status_t handle_workers_ipc_udp_data_sio_heartbeat_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
    uint8_t trycount = oudp_datao->trycount;
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
    if (trycount > (uint8_t)MAX_RETRY) {
        LOG_ERROR("%sMax Retry Reached.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE_MAXTRY;
    }
    if (trycount <= session->heartbeat.last_trycount) {
        LOG_ERROR("%sRetry Invalid.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE_IVLDTRY;
    }
    session->heartbeat.last_trycount = trycount;
//======================================================================
    if (security->remote_ctr != oudp_datao->ctr && inc_ctr != 0xFF) {
        status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
        if (cmac != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return cmac;
        }
        printf("COW Remote Counter Decrement 1\n");
        decrement_ctr(&security->remote_ctr, security->remote_nonce);
        status_t cctr = orilink_check_ctr(worker_ctx->label, security->aes_key, &security->remote_ctr, oudp_datao);
        if (cctr != SUCCESS) {
            increment_ctr(&security->remote_ctr, security->remote_nonce);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return cctr;
        }
        printf("COW Local Counter Decrement 1\n");
        decrement_ctr(&security->local_ctr, security->local_nonce);
    } else {
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
    orilink_heartbeat_t *oheartbeat_ack = received_orilink_protocol->payload.orilink_heartbeat_ack;
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
    session->heartbeat_interval = oheartbeat_ack->hb_interval;
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
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    if (async_create_timerfd(worker_ctx->label, &session->heartbeat_sender_timer_fd) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    if (async_set_timerfd_time(worker_ctx->label, &session->heartbeat_sender_timer_fd,
        (time_t)session->heartbeat_interval,
        (long)((session->heartbeat_interval - (time_t)session->heartbeat_interval) * 1e9),
        (time_t)session->heartbeat_interval,
        (long)((session->heartbeat_interval - (time_t)session->heartbeat_interval) * 1e9)) != SUCCESS)
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    double try_count = (double)session->heartbeat.sent_try_count-(double)1;
    calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    session->heartbeat.ack_rcvd = true;
    session->heartbeat.ack_rcvd_time = current_time.r_uint64_t;
    uint64_t interval_ull = session->heartbeat.ack_rcvd_time - session->heartbeat.sent_time;
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    cleanup_packet(worker_ctx->label, &worker_ctx->async, &session->heartbeat, false);

    printf("%sCOW RTT Heartbeat = %f\n", worker_ctx->label, session->rtt.value_prediction);
//======================================================================
    //session->metrics.last_ack = current_time.r_uint64_t;
    //session->metrics.count_ack += (double)1;
    //session->metrics.sum_hb_interval += session->heartbeat_interval;
    //session->metrics.hb_interval = session->heartbeat_interval;
//======================================================================
    return SUCCESS;
}
