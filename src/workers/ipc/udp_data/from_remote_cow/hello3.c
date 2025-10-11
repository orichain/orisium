#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>

#include "log.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "orilink/hello3_ack.h"
#include "orilink/protocol.h"
#include "stdbool.h"

static inline status_t last_execution(worker_context_t *worker_ctx, sio_c_session_t *session, orilink_identity_t *identity, uint8_t *trycount) {
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        return FAILURE;
    }
    session->hello3_ack.rcvd_time = current_time.r_uint64_t;
    uint64_t interval_ull;
    uint8_t strycount;
    if (!session->hello3_ack.rcvd) {
        session->hello3_ack.rcvd = true;
        interval_ull = session->hello3_ack.rcvd_time - session->hello2_ack.ack_sent_time;
        session->hello3_ack.ack_sent_time = session->hello2_ack.ack_sent_time;
        strycount = session->hello2_ack.ack_sent_try_count;
        cleanup_control_packet_ack(&session->hello2_ack, false, CDT_RESET);
    } else {
        interval_ull = session->hello3_ack.rcvd_time - session->hello3_ack.ack_sent_time;
        strycount = session->hello3_ack.ack_sent_try_count;
    }
    if (strycount > (uint8_t)0) {
        double try_count = (double)strycount-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    
    printf("%sRTT Hello-2 Ack = %f\n", worker_ctx->label, session->rtt.value_prediction);
//======================================================================
    session->hello3_ack.ack_sent = true;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_cow_hello3(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
    uint32_t oudp_datao_ctr = oudp_datao->ctr;
    bool isretry = false;
    uint8_t tmp_local_nonce[AES_NONCE_BYTES];
    uint8_t tmp_aes_key[HASHES_BYTES];
//======================================================================
// + Security
//======================================================================
    print_hex("SIO Receiving Hello3 ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (!session->hello2_ack.ack_sent) {
        LOG_ERROR("%sReceive Hello3 But This Worker Session Is Never Sending Hello2_Ack.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (trycount != (uint8_t)1) {
        if (trycount > (uint8_t)MAX_RETRY) {
            LOG_ERROR("%sHello3 Max Retry.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->hello3_ack.last_trycount) {
            LOG_ERROR("%sHello3 Try Count Invalid.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
//======================================================================
// Retry Initialization
//======================================================================
        memcpy(tmp_local_nonce, security->local_nonce, AES_NONCE_BYTES);
        memset(security->local_nonce, 0, AES_NONCE_BYTES);
        memset(security->mac_key, 0, HASHES_BYTES);
//======================================================================
        status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
        if (cmac != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        bool _1le_ = is_1lower_equal_ctr(&oudp_datao_ctr, &security->remote_ctr, security->remote_nonce);
        if (!_1le_) {
            LOG_ERROR("%sHello3 Received Already.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE;
        }
        if (oudp_datao_ctr != (uint32_t)0 && oudp_datao_ctr == security->remote_ctr) {
            LOG_DEVEL_DEBUG("%sHello3 From Peer's Retry Timer", worker_ctx->label);
            isretry = false;
        } else {
            LOG_DEVEL_DEBUG("%sHello3 Retry From Peer", worker_ctx->label);
            isretry = true;
        }
    } else {
        if (trycount <= session->hello3_ack.last_trycount) {
            LOG_ERROR("%sHello3 Try Count Invalid.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
    }
    if (session->hello3_ack.rcvd && !isretry) {
        LOG_ERROR("%sHello3 Closed.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    session->hello3_ack.last_trycount = trycount;
    uint64_t_status_t current_time_rcvd = get_monotonic_time_ns(worker_ctx->label);
    if (current_time_rcvd.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    uint64_t intv_rcvd = current_time_rcvd.r_uint64_t - session->hello3_ack.last_receive;
    double intv_rcvd_value = (double)intv_rcvd;
    if (intv_rcvd_value < (double)1) {
        LOG_ERROR("%sHello3 Burst Detected. Ignoring.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    session->hello3_ack.last_receive = current_time_rcvd.r_uint64_t;
//======================================================================
    if (!isretry) {
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
//----------------------------------------------------------------------
    if (isretry) {
        if (session->hello3_ack.data != NULL) {
            print_hex("SIO Sending Hello3 Ack Retry Response ", session->hello3_ack.data, session->hello3_ack.len, 1);
            if (retry_control_packet_ack(worker_ctx, identity, security, &session->hello3_ack) != SUCCESS) {
                CLOSE_IPC_PROTOCOL(&received_protocol);
                CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
                return FAILURE;
            }
        }
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
//======================================================================
        memcpy(security->local_nonce, tmp_local_nonce, AES_NONCE_BYTES);
        memset(tmp_local_nonce, 0, AES_NONCE_BYTES);
        kdf1(security->kem_sharedsecret, tmp_aes_key);
        kdf2(tmp_aes_key, security->mac_key);
        memset(tmp_aes_key, 0, HASHES_BYTES);
//----------------------------------------------------------------------
        return last_execution(
            worker_ctx, 
            session, 
            identity, 
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
//----------------------------------------------------------------------
// No Counter Yet
//----------------------------------------------------------------------
            //decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    } else {
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_hello3_t *ohello3 = received_orilink_protocol->payload.orilink_hello3;
    uint64_t remote_id = ohello3->local_id;
//======================================================================
// + Security
//======================================================================
    if (remote_id != identity->remote_id) {
        LOG_ERROR("%sReceive Different Id Between Hello3 And Hello2_Ack.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
//----------------------------------------------------------------------
// No Counter Yet
//----------------------------------------------------------------------
            //decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    uint8_t local_nonce[AES_NONCE_BYTES];
    if (generate_nonce(worker_ctx->label, local_nonce) != SUCCESS) {
        LOG_ERROR("%sFailed to generate_nonce.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
//----------------------------------------------------------------------
// No Counter Yet
//----------------------------------------------------------------------
            //decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    session->hello3_ack.ack_sent_try_count++;
    session->hello3_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
    l_inc_ctr = 0x01;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello3_ack(
        worker_ctx->label,
        l_inc_ctr,
        identity->remote_wot,
        identity->remote_index,
        identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        identity->remote_id,
        local_nonce,
        security->kem_ciphertext,
        session->hello3_ack.ack_sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
//----------------------------------------------------------------------
// No Counter Yet
//----------------------------------------------------------------------
            //decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        if (l_inc_ctr != 0xFF) {
//----------------------------------------------------------------------
// No Counter Yet
//----------------------------------------------------------------------
            //decrement_ctr(&security->local_ctr, security->local_nonce);
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
//----------------------------------------------------------------------
// No Counter Yet
//----------------------------------------------------------------------
            //decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        if (l_inc_ctr != 0xFF) {
//----------------------------------------------------------------------
// No Counter Yet
//----------------------------------------------------------------------
            //decrement_ctr(&security->local_ctr, security->local_nonce);
        }
        return FAILURE;
    }
    print_hex("SIO Sending Hello3 Ack ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
//======================================================================
// Test Packet Dropped
//======================================================================
    session->test_drop_hello3_ack++;
    if (
        session->test_drop_hello3_ack == 1
    )
    {
        printf("[Debug Here Helper]: Hello3 Ack Packet Number %d. Sending To Fake Addr To Force Retry\n", session->test_drop_hello3_ack);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, identity->local_session_index, &fake_addr, &udp_data, &session->hello3_ack) != SUCCESS) {
//----------------------------------------------------------------------
// No Error Here
// This Is A Test Drop Packet
//----------------------------------------------------------------------
            /*
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            if (inc_ctr != 0xFF) {
//----------------------------------------------------------------------
// No Counter Yet
//----------------------------------------------------------------------
                //decrement_ctr(&security->remote_ctr, security->remote_nonce);
            }
            if (l_inc_ctr != 0xFF) {
//----------------------------------------------------------------------
// No Counter Yet
//----------------------------------------------------------------------
                //decrement_ctr(&security->local_ctr, security->local_nonce);
            }
            return FAILURE;
            */
        }
    } else {
        if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, identity->local_session_index, remote_addr, &udp_data, &session->hello3_ack) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
            if (inc_ctr != 0xFF) {
//----------------------------------------------------------------------
// No Counter Yet
//----------------------------------------------------------------------
                //decrement_ctr(&security->remote_ctr, security->remote_nonce);
            }
            if (l_inc_ctr != 0xFF) {
//----------------------------------------------------------------------
// No Counter Yet
//----------------------------------------------------------------------
                //decrement_ctr(&security->local_ctr, security->local_nonce);
            }
            return FAILURE;
        }
        if (session->test_drop_hello3_ack >= 1000000) {
            session->test_drop_hello3_ack = 0;
        }
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    memcpy(security->local_nonce, local_nonce, AES_NONCE_BYTES);
    memset(local_nonce, 0, AES_NONCE_BYTES);
    uint8_t aes_key[HASHES_BYTES];
    kdf1(security->kem_sharedsecret, aes_key);
//----------------------------------------------------------------------
// Di Remote COW
// 1. HELLO4 harus sudah pakai mac_key baru
// 2. HELLO4 harus masih memakai aes_key lama
//----------------------------------------------------------------------
    kdf2(aes_key, security->mac_key);
//----------------------------------------------------------------------
    memset(aes_key, 0, HASHES_BYTES);
//======================================================================
    return last_execution(
        worker_ctx, 
        session, 
        identity, 
        &trycount
    );
}
