#include <stdio.h>
#include <inttypes.h>
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
#include "workers/ipc/master_ipc_cmds.h"
#include "constants.h"

status_t handle_workers_ipc_udp_data_sio_heartbeat(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = 0xFF;
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
    bool isretry = false;
    bool from_retry_timer = false;
//======================================================================
// + Security
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        LOG_ERROR("%sError orilink_check_mac.", worker_ctx->label);
        return FAILURE;
    }
//----------------------------------------------------------------------
    //print_hex("COW Receiving Heartbeat ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (trycount != (uint8_t)1) {
        if (trycount > (uint8_t)MAX_RETRY_CNT) {
            LOG_ERROR("%sHeartbeat Max Retry.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->heartbeat_ack.last_trycount) {
            LOG_ERROR("%sHeartbeat Try Count Invalid Last: %d, Rcvd: %d.", worker_ctx->label, session->heartbeat_ack.last_trycount, trycount);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
        bool _1l_ = is_1lower_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
        if (_1l_) {
            LOG_DEVEL_DEBUG("%sHeartbeat Retry From Peer", worker_ctx->label);
            isretry = true;
        } else {
            bool _same_ = is_equal_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
            if (!_same_) {
                bool _1g_ = is_1greater_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
                if (_1g_) {
                    LOG_ERROR("%sCounter Is Greater.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return FAILURE;
                } else {
                    LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return FAILURE;
                }
            }
            LOG_DEVEL_DEBUG("%sHeartbeat From Peer's Retry Timer", worker_ctx->label);
            from_retry_timer = true;
        }
    }
//----------------------------------------------------------------------
    session->heartbeat_ack.last_trycount = trycount;
//======================================================================
    if (!isretry && !from_retry_timer) {
        if (!session->heartbeat_ack.ack_sent) {
            LOG_ERROR("%sReceive Heartbeat But This Worker Session Is Never Sending Heartbeat_Ack.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        bool _1l_ = is_1lower_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
        if (_1l_) {
            LOG_ERROR("%sHeartbeat With Lower Counter.", worker_ctx->label);
            isretry = true;
        } else {
            bool _same_ = is_equal_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
            if (!_same_) {
                bool _1g_ = is_1greater_ctr(worker_ctx->label, (uint8_t*)oudp_datao->recv_buffer, security->mac_key, security->remote_nonce, &security->remote_ctr);
                if (_1g_) {
                    LOG_ERROR("%sHeartbeat With Greater Counter.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return FAILURE;
                } else {
                    LOG_ERROR("%sCounter Invalid.", worker_ctx->label);
                    CLOSE_IPC_PROTOCOL(&received_protocol);
                    CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                    return FAILURE;
                }
            }
        }
    }
//----------------------------------------------------------------------
    session->heartbeat_ack.last_trycount = trycount;
//----------------------------------------------------------------------
    status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        LOG_ERROR("%sError orilink_read_header.", worker_ctx->label);
        return FAILURE;
    }
//----------------------------------------------------------------------
    inc_ctr = oudp_datao->inc_ctr;
//----------------------------------------------------------------------
    if (isretry) {
        if (session->heartbeat_ack.data != NULL) {
            //print_hex("COW Sending Heartbeat Ack Retry Response ", session->heartbeat_ack.data, session->heartbeat_ack.len, 1);
            if (retry_control_packet_ack(
                    worker_ctx, 
                    identity, 
                    security, 
                    &session->heartbeat_ack,
                    ORILINK_HEARTBEAT_ACK
                ) != SUCCESS
            )
            {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                LOG_ERROR("%sError retry_control_packet_ack.", worker_ctx->label);
                return FAILURE;
            }
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return SUCCESS;
    }
//======================================================================
    if (!session->heartbeat.ack_rcvd) {
        LOG_ERROR("%sTry Again Until My Previous Heartbeat Ack Received.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        LOG_ERROR("%sError get_monotonic_time_ns.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    uint64_t hb_time_from_last_ack_rcvd = current_time.r_uint64_t - session->heartbeat.ack_rcvd_time;
    printf("%sInterval From Last Ack Received %" PRIu64 "\n", worker_ctx->label, hb_time_from_last_ack_rcvd);
    if (hb_time_from_last_ack_rcvd < (uint64_t)1000000) {
        LOG_ERROR("%sNeed Minimal 1ms Delay For New Hearbeat.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
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
    if (session->heartbeat_interval < (double)0.001) {
        session->heartbeat_interval = (double)0.001;
    }
    if (session->heartbeat_interval > (double)100) {
        session->heartbeat_interval = (double)100;
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
        LOG_ERROR("%sError orilink_prepare_cmd_heartbeat_ack.", worker_ctx->label);
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
        LOG_ERROR("%sError create_orilink_raw_protocol_packet.", worker_ctx->label);
        return FAILURE;
    }
    //print_hex("COW Sending Heartbeat Ack ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
//======================================================================
// Test Packet Dropped
//======================================================================
    //session->test_drop_heartbeat_ack++;
    if (
        session->test_drop_heartbeat_ack == 1 ||
        session->test_drop_heartbeat_ack == 3 ||
        session->test_drop_heartbeat_ack == 5 ||
        session->test_drop_heartbeat_ack == 7
    )
    {
        LOG_DEVEL_DEBUG("[Debug Here Helper]: Heartbeat Ack Packet Number %d. Sending To Fake Addr To Force Retry", session->test_drop_heartbeat_ack);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HEARTBEAT_ACK,
                session->heartbeat_ack.ack_sent_try_count,
                &fake_addr, 
                &udp_data, 
                &session->heartbeat_ack
            ) != SUCCESS
        )
        {
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
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HEARTBEAT_ACK,
                session->heartbeat_ack.ack_sent_try_count,
                remote_addr, 
                &udp_data, 
                &session->heartbeat_ack
            ) != SUCCESS
        )
        {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            if (inc_ctr != 0xFF) {
                decrement_ctr(&security->remote_ctr, security->remote_nonce);
            }
            if (l_inc_ctr != 0xFF) {
                decrement_ctr(&security->local_ctr, security->local_nonce);
            }
            LOG_ERROR("%sError worker_master_udp_data_ack.", worker_ctx->label);
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
    if (session->heartbeat_ack.ack_sent_try_count > (uint8_t)0) {
        double try_count = (double)session->heartbeat_ack.ack_sent_try_count-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    cleanup_control_packet_ack(&session->heartbeat_ack, false, CDT_NOACTION);
    session->heartbeat.sent = false;
//----------------------------------------------------------------------
// Set session->heartbeat_ack.ack_sent = true; In Heartbeat Openner
//----------------------------------------------------------------------
    session->heartbeat_ack.ack_sent = false;
//======================================================================
//session->metrics.last_ack = current_time->r_uint64_t;
//session->metrics.count_ack += (double)1;
//session->metrics.sum_hb_interval += session->heartbeat_interval;
//session->metrics.hb_interval = session->heartbeat_interval;
//======================================================================
    double timer_interval = session->heartbeat_interval;
//======================================================================
    status_t chst = create_timer_oneshot(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd, timer_interval);
    if (chst != SUCCESS) {
        return FAILURE;
    }
    if (create_timer_oneshot(worker_ctx->label, &worker_ctx->async, &session->heartbeat_openner_timer_fd, timer_interval) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
    return SUCCESS;
}
