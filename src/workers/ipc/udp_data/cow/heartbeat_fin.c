#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <netinet/in.h>
#include <string.h>

#include "log.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "types.h"
#include "workers/workers.h"
#include "orilink/protocol.h"
#include "stdbool.h"
#include "async.h"
#include "orilink/heartbeat_fin_ack.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "constants.h"

status_t handle_workers_ipc_udp_data_cow_heartbeat_fin(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
//======================================================================
// + Security
//======================================================================
    if (!session->heartbeat_ack.ack_sent) {
        LOG_ERROR("%sReceive Heartbeat_Fin But This Worker Session Is Never Sending Heartbeat_Ack.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    
    printf("Rcv Fin Try Count %d\n", oudp_datao->trycount);
    
    if (session->heartbeat_ack.rcvd) {
        if (oudp_datao->trycount > (uint8_t)MAX_RETRY) {
            LOG_ERROR("%sHeartbeat_Fin Received Already.", worker_ctx->label);
            session->remote_heartbeat_fin_ack_not_reveived = true;
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        if (oudp_datao->trycount <= session->last_heartbeat_fin_trycount) {
            LOG_ERROR("%sHeartbeat_Fin Received Already.", worker_ctx->label);
            session->remote_heartbeat_fin_ack_not_reveived = true;
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
    }
//======================================================================
    session->last_heartbeat_fin_trycount = oudp_datao->trycount;
    printf("Save Fin Try Count %d\n", session->last_heartbeat_fin_trycount);
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
    double hb_openner_interval = session->heartbeat_interval - ((double)5 * (double)(session->rtt.value_prediction / 1e9));
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
    session->heartbeat_fin_ack.ack_sent_try_count++;
//======================================================================
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat_fin_ack(
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
        session->heartbeat_fin_ack.ack_sent_try_count
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
//======================================================================
// Test Packet Dropped
//======================================================================
    session->test_drop_heartbeat_fin_ack++;
    if (session->test_drop_heartbeat_fin_ack == 11) {
        printf("[Debug Here Helper]: Heartbeat Fin Ack Packet Number %d. Sending To Fake Addr To Force Retry\n", session->test_drop_heartbeat_fin_ack);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_noretry(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &fake_addr, &udp_data) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
        }
    } else {
        printf("[Debug Here Helper]: Heartbeat Fin Ack Packet Number %d\n", session->test_drop_heartbeat_fin_ack);
        if (worker_master_udp_data_noretry(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, remote_addr, &udp_data) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            return FAILURE;
        }
        if (session->test_drop_heartbeat_fin_ack >= 25) {
            session->test_drop_heartbeat_fin_ack = 0;
        }
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    double try_count = (double)session->heartbeat_ack.ack_sent_try_count-(double)1;
    calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    session->heartbeat_ack.rcvd = true;
    session->heartbeat_ack.rcvd_time = current_time.r_uint64_t;
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
    }
    return SUCCESS;
}
