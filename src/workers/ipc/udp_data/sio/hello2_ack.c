#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <time.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "pqc.h"
#include "orilink/hello3.h"
#include "orilink/protocol.h"
#include "async.h"
#include "stdbool.h"
#include "utilities.h"
#include "constants.h"

status_t handle_workers_ipc_udp_data_sio_hello2_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
//======================================================================
// + Security
//======================================================================
    if (!session->hello2.sent) {
        LOG_ERROR("%sReceive Hello2_Ack But This Worker Session Is Never Sending Hello2.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (session->hello2.ack_rcvd) {
        LOG_ERROR("%sHello2_Ack Received Already.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (trycount > (uint8_t)MAX_RETRY) {
        LOG_ERROR("%sMax Retry Reached.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE_MAXTRY;
    }
    if (trycount <= session->hello2.last_trycount) {
        LOG_ERROR("%sRetry Invalid.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE_IVLDTRY;
    }
    session->hello2.last_trycount = trycount;
//======================================================================
    if (security->remote_ctr != oudp_datao->ctr && inc_ctr != 0xFF) {
        status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
        if (cmac != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return cmac;
        }
        uint8_t imax = 0;
        do {
            imax++;
            printf("COW Remote Counter Decrement 1\n");
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
            printf("COW Local Counter Decrement 1\n");
            decrement_ctr(&security->local_ctr, security->local_nonce);
            if (imax >= (uint8_t)MAX_RETRY) {
                break;
            }
        }
        while (security->remote_ctr != oudp_datao->ctr);
        status_t cctr = orilink_check_ctr(worker_ctx->label, security->aes_key, &security->remote_ctr, oudp_datao);
        if (cctr != SUCCESS) {
            for (uint8_t jmax=0;jmax<imax;++jmax) {
                increment_ctr(&security->remote_ctr, security->remote_nonce);
                increment_ctr(&security->local_ctr, security->local_nonce);
            }
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return cctr;
        }
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
    orilink_hello2_ack_t *ohello2_ack = received_orilink_protocol->payload.orilink_hello2_ack;
    uint64_t local_id = ohello2_ack->remote_id;
//======================================================================
// + Security
//======================================================================
    if (local_id != identity->local_id) {
        LOG_ERROR("%sReceive Different Id Between Hello2_Ack And Hello2.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES / 2];
    memcpy(kem_ciphertext, ohello2_ack->ciphertext1, KEM_CIPHERTEXT_BYTES / 2);
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
    if (async_create_timerfd(worker_ctx->label, &session->hello3.timer_fd) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    session->hello3.sent_try_count++;
    session->hello3.sent_time = current_time.r_uint64_t;
    if (async_set_timerfd_time(worker_ctx->label, &session->hello3.timer_fd,
        (time_t)session->hello3.interval_timer_fd,
        (long)((session->hello3.interval_timer_fd - (time_t)session->hello3.interval_timer_fd) * 1e9),
        (time_t)session->hello3.interval_timer_fd,
        (long)((session->hello3.interval_timer_fd - (time_t)session->hello3.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->hello3.timer_fd) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello3(
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
        session->hello3.sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    l_inc_ctr = orilink_cmd_result.r_orilink_protocol_t->inc_ctr;
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
    if (worker_master_udp_data(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, remote_addr, &udp_data, &session->hello3) != SUCCESS) {
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
//----------------------------------------------------------------------
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    memcpy(security->kem_ciphertext, kem_ciphertext, KEM_CIPHERTEXT_BYTES / 2);
    memset(kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES / 2);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    double try_count = (double)session->hello2.sent_try_count-(double)1;
    calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    session->hello2.ack_rcvd = true;
    session->hello2.ack_rcvd_time = current_time.r_uint64_t;
    uint64_t interval_ull = session->hello2.ack_rcvd_time - session->hello2.sent_time;
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    cleanup_packet(worker_ctx->label, &worker_ctx->async, &session->hello2, false);
    
    printf("%sRTT Hello-2 = %f\n", worker_ctx->label, session->rtt.value_prediction);
    
//======================================================================
    session->hello3.sent = true;
//======================================================================
    return SUCCESS;
}
