#include <inttypes.h>
#include <time.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "orilink/protocol.h"
#include "stdbool.h"
#include "async.h"
#include "orilink/heartbeat_finalize.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "constants.h"

status_t handle_workers_ipc_udp_data_sio_heartbeat_finalize(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
//----------------------------------------------------------------------
    async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_timer_fd);
    CLOSE_FD(&session->heartbeat_timer_fd);
//======================================================================
// + Security
//======================================================================
    if (!session->heartbeat_end.sent) {
        LOG_ERROR("%sReceive Heartbeat_Finalize But This Worker Session Is Never Sending Heartbeat_End.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (session->heartbeat_end.ack_rcvd) {
        if (oudp_datao->trycount > (uint8_t)MAX_RETRY) {
            LOG_ERROR("%sHeartbeat_Finalize Received Already.", worker_ctx->label);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (oudp_datao->trycount <= session->heartbeat_finalize_saved_trycount) {
            LOG_ERROR("%sHeartbeat_Finalize Received Already.", worker_ctx->label);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
    }
//----------------------------------------------------------------------
    session->heartbeat_finalize_saved_trycount = oudp_datao->trycount;
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
    orilink_heartbeat_finalize_t *oheartbeat_finalize = received_orilink_protocol->payload.orilink_heartbeat_finalize;
//======================================================================
// + Security
//======================================================================
    if (identity->local_id != oheartbeat_finalize->remote_id || identity->remote_id != oheartbeat_finalize->local_id) {
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
    session->heartbeat_finalize.sent_try_count++;
//======================================================================
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat_finalize(
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
        session->heartbeat_finalize.sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    uint8_t l_inc_ctr = orilink_cmd_result.r_orilink_protocol_t->inc_ctr;
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
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        if (l_inc_ctr != 0xFF) {
            decrement_ctr(&security->local_ctr, security->local_nonce);
        }
        return FAILURE;
    }
//======================================================================
// Test Packet Dropped
//======================================================================
    session->test_drop_heartbeat_finalize++;
    if (session->test_drop_heartbeat_finalize == 13) {
        printf("[Debug Here Helper]: COW Heartbeat Finalize Packet Number %d. Sending To Fake Addr To Force Retry\n", session->test_drop_heartbeat_finalize);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_finalize(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &fake_addr, &udp_data) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            if (inc_ctr != 0xFF) {
                decrement_ctr(&security->remote_ctr, security->remote_nonce);
            }
            if (l_inc_ctr != 0xFF) {
                decrement_ctr(&security->local_ctr, security->local_nonce);
            }
            return FAILURE;
        }
    } else {
        printf("[Debug Here Helper]: COW Heartbeat Finalize Packet Number %d\n", session->test_drop_heartbeat_finalize);
        if (worker_master_udp_data_finalize(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, remote_addr, &udp_data) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            if (inc_ctr != 0xFF) {
                decrement_ctr(&security->remote_ctr, security->remote_nonce);
            }
            if (l_inc_ctr != 0xFF) {
                decrement_ctr(&security->local_ctr, security->local_nonce);
            }
            return FAILURE;
        }
        if (session->test_drop_heartbeat_finalize >= 1000000) {
            session->test_drop_heartbeat_finalize = 0;
        }
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    if (async_create_timerfd(worker_ctx->label, &session->heartbeat_timer_fd) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        if (l_inc_ctr != 0xFF) {
            decrement_ctr(&security->local_ctr, security->local_nonce);
        }
        return FAILURE;
    }
    if (async_set_timerfd_time(worker_ctx->label, &session->heartbeat_timer_fd,
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
        if (l_inc_ctr != 0xFF) {
            decrement_ctr(&security->local_ctr, security->local_nonce);
        }
        return FAILURE;
    }
    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_timer_fd) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        if (l_inc_ctr != 0xFF) {
            decrement_ctr(&security->local_ctr, security->local_nonce);
        }
        return FAILURE;
    }
//======================================================================
    session->heartbeat_finalize.sent = true;
//======================================================================
    double try_count = (double)session->heartbeat_end.sent_try_count-(double)1;
    calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    session->heartbeat_end.ack_rcvd = true;
    session->heartbeat_end.ack_rcvd_time = current_time.r_uint64_t;
    uint64_t interval_ull = session->heartbeat_end.ack_rcvd_time - session->heartbeat_end.sent_time;
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    cleanup_packet_timer(worker_ctx->label, &worker_ctx->async, &session->heartbeat_end);

    LOG_DEVEL_DEBUG("%sRTT Heartbeat End = %f", worker_ctx->label, session->rtt.value_prediction);
//======================================================================
    return SUCCESS;
}
