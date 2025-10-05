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
#include "orilink/heartbeat_ack.h"
#include "async.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "constants.h"

static inline status_t create_heartbeat_sender_timer_fd(worker_context_t *worker_ctx, cow_c_session_t *session) {
//======================================================================
// Acumulate Different RTT Between Peers
//======================================================================
    double timer_interval = session->heartbeat_interval;
    timer_interval += session->rtt.value_prediction / (double)1e9;
    if (async_create_timerfd(worker_ctx->label, &session->heartbeat_sender_timer_fd) != SUCCESS) {
        return FAILURE;
    }
//======================================================================
    if (async_create_timerfd(worker_ctx->label, &session->heartbeat_sender_timer_fd) != SUCCESS) {
        return FAILURE;
    }
    //printf("Hereeeeeeeeeeeeeeeeeeeee....... cow_heartbeat.c create_heartbeat_sender_timer_fd FD %d\n", session->heartbeat_sender_timer_fd);
    if (async_set_timerfd_time(worker_ctx->label, &session->heartbeat_sender_timer_fd,
        (time_t)timer_interval,
        (long)((timer_interval - (time_t)timer_interval) * 1e9),
        (time_t)timer_interval,
        (long)((timer_interval - (time_t)timer_interval) * 1e9)) != SUCCESS)
    {
        return FAILURE;
    }
    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd) != SUCCESS) {
        return FAILURE;
    }
    return SUCCESS;
}

static inline status_t last_execution(worker_context_t *worker_ctx, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, uint64_t_status_t *current_time, uint8_t *trycount) {
    async_delete_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd);
    CLOSE_FD(&session->heartbeat_sender_timer_fd);
    status_t chst = create_heartbeat_sender_timer_fd(worker_ctx, session);
    if (chst != SUCCESS) {
        return FAILURE;
    }
//======================================================================
// Heartbeat Security 2 Close
//======================================================================
    session->heartbeat_ack.rcvd = true;
//======================================================================
    session->heartbeat_ack.ack_sent = true;
//----------------------------------------------------------------------
    session->packet_anchor.last_rcvd_ctr = security->remote_ctr;
    memcpy(session->packet_anchor.last_rcvd_nonce, security->remote_nonce, AES_NONCE_BYTES);
//----------------------------------------------------------------------
// -1 Because Of Passing Deserialize Process that is +1
//----------------------------------------------------------------------
    decrement_ctr(&session->packet_anchor.last_rcvd_ctr, session->packet_anchor.last_rcvd_nonce);
//======================================================================
//session->metrics.last_ack = current_time->r_uint64_t;
//session->metrics.count_ack += (double)1;
//session->metrics.sum_hb_interval += session->heartbeat_interval;
//session->metrics.hb_interval = session->heartbeat_interval;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_sio_heartbeat(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
//======================================================================
// + Security
//======================================================================
    if (!session->heartbeat_ack.ack_sent) {
        LOG_ERROR("%sReceive Heartbeat But This Worker Session Is Never Sending Heartbeat_Ack.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (session->heartbeat_ack.rcvd) {
        if (trycount != (uint8_t)1) {
            if (trycount > (uint8_t)MAX_RETRY) {
                LOG_ERROR("%sHeartbeat Received Already.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE_MAXTRY;
            }
            if (trycount <= session->heartbeat_ack.last_trycount) {
                LOG_ERROR("%sHeartbeat Received Already.", worker_ctx->label);
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE_IVLDTRY;
            }
        } else {
            LOG_ERROR("%sHeartbeat Received Already.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
    }
    session->heartbeat_ack.last_trycount = trycount;
//======================================================================
    if (trycount != (uint8_t)1 && inc_ctr != 0xFF && security->remote_ctr != oudp_datao->ctr) {
        status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
        if (cmac != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return cmac;
        }
        if (!is_same_ctr(&session->packet_anchor.last_rcvd_ctr, session->packet_anchor.last_rcvd_nonce, &oudp_datao->ctr, security->remote_nonce)) {
            LOG_ERROR("%sHeartbeat Received Already.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        printf("%sRetry Detected\n", worker_ctx->label);
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
    session->heartbeat_ack.ack_sent = false;
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//======================================================================
    if (trycount > (uint8_t)1 && session->heartbeat_ack.data != NULL) {
        if (retry_packet_ack(worker_ctx, identity, security, &session->heartbeat_ack) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return last_execution(
            worker_ctx, 
            session, 
            identity, 
            security,
            &current_time, 
            &trycount
        );
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
    orilink_heartbeat_t *oheartbeat = received_orilink_protocol->payload.orilink_heartbeat;
//======================================================================
// + Security
//======================================================================
    if (identity->local_id != oheartbeat->remote_id || identity->remote_id != oheartbeat->local_id) {
        LOG_ERROR("%sLocal Id And Or Remote Id Mismatch.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    session->heartbeat_interval = oheartbeat->hb_interval;
    if (session->heartbeat_interval < (double)NODE_HEARTBEAT_INTERVAL) {
        session->heartbeat_interval = (double)NODE_HEARTBEAT_INTERVAL;
    }
    if (session->heartbeat_interval > (double)NODE_CHECK_HEALTHY) {
        session->heartbeat_interval = (double)NODE_CHECK_HEALTHY;
    }
//======================================================================
    session->heartbeat_ack.ack_sent_try_count++;
    session->heartbeat_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
    l_inc_ctr = 0x01;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat_ack(
        worker_ctx->label,
        l_inc_ctr,
        identity->remote_wot,
        identity->remote_index,
        identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        identity->local_id,
        identity->remote_id,
        session->heartbeat_ack.ack_sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
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
    cleanup_packet_ack(worker_ctx->label, &worker_ctx->async, &session->heartbeat_ack, false);
//======================================================================
// Test Packet Dropped
//======================================================================
    session->test_drop_heartbeat_ack++;
    if (
        session->test_drop_heartbeat_ack == 3 ||
        session->test_drop_heartbeat_ack == 5 ||
        session->test_drop_heartbeat_ack == 7 ||
        session->test_drop_heartbeat_ack == 9
    )
    {
        printf("[Debug Here Helper]: Heartbeat Ack Packet Number %d. Sending To Fake Addr To Force Retry\n", session->test_drop_heartbeat_ack);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, &fake_addr, &udp_data, &session->heartbeat_ack) != SUCCESS) {
//----------------------------------------------------------------------
// No Error Here
// This Is A Test Drop Packet
//----------------------------------------------------------------------
        /*
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        if (l_inc_ctr != 0xFF) {
            decrement_ctr(&security->local_ctr, security->local_nonce);
        }
        return FAILURE;
        */
//----------------------------------------------------------------------
        }
    } else {
        if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, remote_addr, &udp_data, &session->heartbeat_ack) != SUCCESS) {
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
        if (session->test_drop_heartbeat_ack >= 1000000) {
            session->test_drop_heartbeat_ack = 0;
        }
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    return last_execution(
        worker_ctx, 
        session, 
        identity, 
        security,
        &current_time, 
        &trycount
    );
}
