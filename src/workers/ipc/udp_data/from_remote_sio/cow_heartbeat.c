#include <stdio.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

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

static inline status_t last_execution(worker_context_t *worker_ctx, cow_c_session_t *session, orilink_identity_t *identity, uint8_t *trycount) {
    if (session->heartbeat_ack.ack_sent_try_count > (uint8_t)0) {
        double try_count = (double)session->heartbeat_ack.ack_sent_try_count-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    cleanup_control_packet_ack(&session->heartbeat_ack, false, CDT_NOACTION);
    session->heartbeat.sent = false;
//----------------------------------------------------------------------
// Set session->heartbeat_ack.ack_sent = true in the heartbeat openner timer event
//----------------------------------------------------------------------
    session->heartbeat_ack.ack_sent = false;
//======================================================================
//session->metrics.last_ack = current_time->r_uint64_t;
//session->metrics.count_ack += (double)1;
//session->metrics.sum_hb_interval += session->heartbeat_interval;
//session->metrics.hb_interval = session->heartbeat_interval;
//======================================================================
    return SUCCESS;
}

/*
COW
After rcv Heartbeat
1. Recv the hb interval from peer
2. Fill in session->hb_interval for use by the hb opener
3. Create Timer Heartbeat Sender with rcvd hb interval
4. After the heartbeat timer sender sends a heartbeat, it will automatically be followed by the creation of a heartbeat timer opener.
5. Set the heartbeat_ack.ack_sent flag = false;
5. Set the heartbeat_ack.ack_sent flag = true in the heartbeat timer opener event;
6. Set the heartbeat.sent flag = false
7. If there is a retry, extend the sender timer as long as the sender timer has not sent a heartbeat.
*/

status_t handle_workers_ipc_udp_data_sio_heartbeat(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
    uint32_t oudp_datao_ctr = oudp_datao->ctr;
    bool isretry = false;
    bool is_loss_1st_pkt = false;
//======================================================================
// + Security
//======================================================================
    //print_hex("COW Receiving Heartbeat ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (trycount != (uint8_t)1) {
        if (trycount > (uint8_t)MAX_RETRY_CNT) {
            LOG_ERROR("%sHeartbeat Max Retry.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->heartbeat_ack.last_trycount) {
            LOG_ERROR("%sHeartbeat Try Count Invalid.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
        status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
        if (cmac != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
        if (rhd != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
//----------------------------------------------------------------------
        inc_ctr = oudp_datao->inc_ctr;
        oudp_datao_ctr = oudp_datao->ctr;
//----------------------------------------------------------------------
        if (oudp_datao_ctr == security->remote_ctr) {
            LOG_DEVEL_DEBUG("%sHeartbeat From Peer's Retry Timer", worker_ctx->label);
            isretry = false;
            is_loss_1st_pkt = true;
        } else {
            LOG_DEVEL_DEBUG("%sHeartbeat Retry From Peer", worker_ctx->label);
            isretry = true;
        }
    } else {
        if (trycount <= session->heartbeat_ack.last_trycount) {
            LOG_ERROR("%sHeartbeat Try Count Invalid.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
    }
    if (session->heartbeat_ack.rcvd && !isretry) {
        if (!session->heartbeat_ack.ack_sent && trycount == (uint8_t)1) {
            LOG_ERROR("%sReceive Heartbeat But This Worker Session Is Never Sending Heartbeat_Ack.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
    }
    session->heartbeat_ack.last_trycount = trycount;
//======================================================================
    if (!isretry) {
        if (!is_loss_1st_pkt) {
            status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
            if (cmac != SUCCESS) {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE;
            }
            status_t rhd = orilink_read_header(worker_ctx->label, security->mac_key, security->remote_nonce, &security->remote_ctr, oudp_datao);
            if (rhd != SUCCESS) {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE;
            }
//----------------------------------------------------------------------
            inc_ctr = oudp_datao->inc_ctr;
            oudp_datao_ctr = oudp_datao->ctr;
//----------------------------------------------------------------------
        }
        status_t cctr = orilink_check_ctr(worker_ctx->label, security->aes_key, &security->remote_ctr, oudp_datao);
        if (cctr != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
    }
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
                return FAILURE;
            }
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        status_t le = last_execution(
            worker_ctx, 
            session, 
            identity, 
            &trycount
        );
        if (le != SUCCESS) {
            return le;
        }
        return SUCCESS;
    }
//======================================================================
// only on the first initiator this is done
//======================================================================
    if (!session->heartbeat.ack_rcvd) {
        LOG_ERROR("%sTry Again Until My Previous Heartbeat Ack Received.", worker_ctx->label);
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
    if (session->heartbeat_interval < (double)1) {
        session->heartbeat_interval = (double)1;
    }
    if (session->heartbeat_interval > (double)100) {
        session->heartbeat_interval = (double)100;
    }
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
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
    //print_hex("COW Sending Heartbeat Ack ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
//======================================================================
// Test Packet Dropped
//======================================================================
    session->test_drop_heartbeat_ack++;
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
    status_t le = last_execution(
        worker_ctx, 
        session, 
        identity, 
        &trycount
    );
    if (le != SUCCESS) {
        return le;
    }
//======================================================================
    double timer_interval = session->heartbeat_interval;
//======================================================================
    status_t chst = create_timer_oneshot(worker_ctx->label, &worker_ctx->async, &session->heartbeat_sender_timer_fd, timer_interval);
    if (chst != SUCCESS) {
        return FAILURE;
    }
    return SUCCESS;
}
