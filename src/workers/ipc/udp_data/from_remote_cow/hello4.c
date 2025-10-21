#include <string.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdio.h>
#include <inttypes.h>

#include "log.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "orilink/hello4_ack.h"
#include "orilink/protocol.h"
#include "stdbool.h"

static inline status_t last_execution(worker_context_t *worker_ctx, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, uint8_t *trycount) {
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        return FAILURE;
    }
    session->hello4_ack.rcvd_time = current_time.r_uint64_t;
    uint64_t interval_ull;
    uint8_t strycount;
    if (!session->hello4_ack.rcvd) {
        session->hello4_ack.rcvd = true;
        interval_ull = session->hello4_ack.rcvd_time - session->hello3_ack.ack_sent_time;
        session->hello4_ack.ack_sent_time = session->hello3_ack.ack_sent_time;
        strycount = session->hello3_ack.ack_sent_try_count;
        cleanup_control_packet_ack(&session->hello3_ack, false, CDT_RESET);
    } else {
        interval_ull = session->hello4_ack.rcvd_time - session->hello4_ack.ack_sent_time;
        strycount = session->hello4_ack.ack_sent_try_count;
    }
    if (strycount > (uint8_t)0) {
        double try_count = (double)strycount-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
    if (strycount == (uint8_t)1) {
        double rtt_value = (double)interval_ull;
        calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    
        printf("%sRTT Hello-3 Ack = %f ms\n", worker_ctx->label, session->rtt.value_prediction / 1e6);
    }
//======================================================================
    session->hello4_ack.ack_sent = true;
    session->heartbeat_cnt = 0x00;
    session->heartbeat.ack_rcvd = true;
//======================================================================
    return SUCCESS;
}

status_t handle_workers_ipc_udp_data_cow_hello4(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
    uint32_t oudp_datao_ctr = oudp_datao->ctr;
    bool isretry = false;
    uint8_t aes_key[HASHES_BYTES];
    uint32_t remote_ctr = (uint32_t)0;
    uint32_t local_ctr = (uint32_t)0;
    uint8_t remote_nonce[AES_NONCE_BYTES];
    bool is_loss_1st_pkt = false;
//======================================================================
// + Security
//======================================================================
    //print_hex("SIO Receiving Hello4 ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (!session->hello3_ack.ack_sent) {
        LOG_ERROR("%sReceive Hello4 But This Worker Session Is Never Sending Hello3_Ack.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    
    if (!session->hello3_ack.ack_sent) {
        LOG_ERROR("%sReceive Hello4 But This Worker Session Is Never Sending Hello4_Ack.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (trycount != (uint8_t)1) {
        if (trycount > (uint8_t)MAX_RETRY_CNT) {
            LOG_ERROR("%sHello4 Max Retry.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->hello4_ack.last_trycount) {
            LOG_ERROR("%sHello4 Try Count Invalid.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
//======================================================================
// Retry Initialization
//======================================================================
        memcpy(aes_key, security->aes_key, HASHES_BYTES);
        memcpy(remote_nonce, security->remote_nonce, AES_NONCE_BYTES);
        remote_ctr = security->remote_ctr;
        local_ctr = security->local_ctr;
        memset(security->aes_key, 0, HASHES_BYTES);
        memset(security->remote_nonce, 0, AES_NONCE_BYTES);
        security->remote_ctr = (uint32_t)0;
        security->local_ctr = (uint32_t)0;
//======================================================================
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
        if (oudp_datao_ctr != (uint32_t)0 && oudp_datao_ctr == security->remote_ctr) {
            LOG_DEVEL_DEBUG("%sHello4 From Peer's Retry Timer", worker_ctx->label);
            isretry = false;
            is_loss_1st_pkt = true;
        } else {
            LOG_DEVEL_DEBUG("%sHello4 Retry From Peer", worker_ctx->label);
            isretry = true;
        }
    } else {
        if (trycount <= session->hello4_ack.last_trycount) {
            LOG_ERROR("%sHello4 Try Count Invalid.", worker_ctx->label);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
    }
    if (session->hello4_ack.rcvd && !isretry) {
        LOG_ERROR("%sHello4 Closed.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    session->hello4_ack.last_trycount = trycount;
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
        if (session->hello4_ack.data != NULL) {
            //print_hex("SIO Sending Hello4 Ack Retry Response ", session->hello4_ack.data, session->hello4_ack.len, 1);
            if (retry_control_packet_ack(
                    worker_ctx, 
                    identity, 
                    security, 
                    &session->hello4_ack,
                    ORILINK_HELLO4_ACK
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
//======================================================================
        memcpy(security->aes_key, aes_key, HASHES_BYTES);
        memcpy(security->remote_nonce, remote_nonce, AES_NONCE_BYTES);
        security->remote_ctr = remote_ctr;
        security->local_ctr = local_ctr;
        memset(aes_key, 0, HASHES_BYTES);
        memset(remote_nonce, 0, AES_NONCE_BYTES);
        remote_ctr = (uint32_t)0;
        local_ctr = (uint32_t)0;
//----------------------------------------------------------------------
        return last_execution(
            worker_ctx, 
            session, 
            identity,
            security, 
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
    orilink_hello4_t *ohello4 = received_orilink_protocol->payload.orilink_hello4;
//======================================================================
// Ambil remote_nonce
// Set remote_ctr = 0
// Ambil encrypter wot+index
// Ambil Mac
// Cocokkan MAc
// Decrypt wot dan index
//======================================================================
    memcpy(remote_nonce, ohello4->encrypted_local_identity, AES_NONCE_BYTES);
    uint8_t encrypted_remote_identity_rcvd[
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    memcpy(encrypted_remote_identity_rcvd, ohello4->encrypted_local_identity + AES_NONCE_BYTES, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    uint8_t data_mac[AES_TAG_BYTES];
    memcpy(data_mac, ohello4->encrypted_local_identity + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// Temporary Key
//----------------------------------------------------------------------
    kdf1(security->kem_sharedsecret, aes_key);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
    uint8_t encrypted_remote_identity_rcvd1[
        AES_NONCE_BYTES +
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    memcpy(encrypted_remote_identity_rcvd1, ohello4->encrypted_local_identity, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    const size_t data_len_0 = AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
    if (compare_mac(
            security->mac_key,
            encrypted_remote_identity_rcvd1,
            data_len_0,
            data_mac
        ) != SUCCESS
    )
    {
        LOG_ERROR("%sORILINK Hello4 Mac mismatch!", worker_ctx->label);
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
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
    uint8_t decrypted_remote_identity_rcvd[
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    const size_t data_len = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
    if (encrypt_decrypt_256(
            worker_ctx->label,
            aes_key,
            remote_nonce,
            &remote_ctr,
            encrypted_remote_identity_rcvd,
            decrypted_remote_identity_rcvd,
            data_len
        ) != SUCCESS
    )
    {
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
// + Security
//======================================================================
    worker_type_t data_wot;
    memcpy((uint8_t *)&data_wot, decrypted_remote_identity_rcvd, sizeof(uint8_t));
    if (*(uint8_t *)&identity->remote_wot != *(uint8_t *)&data_wot) {
        LOG_ERROR("%sberbeda wot.", worker_ctx->label);
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
    uint8_t data_index;
    memcpy(&data_index, decrypted_remote_identity_rcvd + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->remote_index != data_index) {
        LOG_ERROR("%sberbeda index.", worker_ctx->label);
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
    uint8_t data_session_index;
    memcpy(&data_session_index, decrypted_remote_identity_rcvd + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->remote_session_index != data_session_index) {
        LOG_ERROR("%sberbeda session_index.", worker_ctx->label);
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
    uint64_t remote_id_be0;
    memcpy(&remote_id_be0, decrypted_remote_identity_rcvd + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint64_t));
    uint64_t remote_id = be64toh(remote_id_be0);
    if (remote_id != identity->remote_id) {
        LOG_ERROR("%sberbeda id.", worker_ctx->label);
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
    uint8_t remote_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
    uint8_t encrypted_remote_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];   
    uint8_t encrypted_remote_identity1[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t) + AES_TAG_BYTES];
    memcpy(
        remote_identity, 
        (uint8_t *)&identity->remote_wot, 
        sizeof(uint8_t)
    );
    memcpy(
        remote_identity + sizeof(uint8_t), 
        (uint8_t *)&identity->remote_index, 
        sizeof(uint8_t)
    );
    memcpy(
        remote_identity + sizeof(uint8_t) + sizeof(uint8_t), 
        (uint8_t *)&identity->remote_session_index, 
        sizeof(uint8_t)
    );
    uint64_t remote_id_be1 = htobe64(remote_id);
    memcpy(
        remote_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), 
        &remote_id_be1, 
        sizeof(uint64_t)
    );
//======================================================================    
    if (encrypt_decrypt_256(
            worker_ctx->label,
            aes_key,
            security->local_nonce,
            &local_ctr,
            remote_identity,
            encrypted_remote_identity,
            data_len
        ) != SUCCESS
    )
    {
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
    uint8_t mac1[AES_TAG_BYTES];
    const size_t data_4mac_len = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
    calculate_mac(security->mac_key, encrypted_remote_identity, mac1, data_4mac_len);
//====================================================================== 
    memcpy(encrypted_remote_identity1, encrypted_remote_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    memcpy(encrypted_remote_identity1 + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), mac1, AES_TAG_BYTES);
//======================================================================
    uint8_t local_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
    uint8_t encrypted_local_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];   
    uint8_t encrypted_local_identity1[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t) + AES_TAG_BYTES];
    memcpy(
        local_identity, 
        (uint8_t *)&identity->local_wot, 
        sizeof(uint8_t)
    );
    memcpy(
        local_identity + sizeof(uint8_t), 
        (uint8_t *)&identity->local_index, 
        sizeof(uint8_t)
    );
    memcpy(
        local_identity + sizeof(uint8_t) + sizeof(uint8_t), 
        (uint8_t *)&identity->local_session_index, 
        sizeof(uint8_t)
    );
    uint64_t local_id_be = htobe64(identity->local_id);
    memcpy(
        local_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), 
        &local_id_be, 
        sizeof(uint64_t)
    );
//======================================================================    
    if (encrypt_decrypt_256(
            worker_ctx->label,
            aes_key,
            security->local_nonce,
            &local_ctr,
            local_identity,
            encrypted_local_identity,
            data_len
        ) != SUCCESS
    )
    {
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
    uint8_t mac2[AES_TAG_BYTES];
    calculate_mac(security->mac_key, encrypted_local_identity, mac2, data_4mac_len);
//====================================================================== 
    memcpy(encrypted_local_identity1, encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    memcpy(encrypted_local_identity1 + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), mac2, AES_TAG_BYTES);
//======================================================================
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
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
//----------------------------------------------------------------------
    session->hello4_ack.ack_sent_try_count++;
    session->hello4_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
    l_inc_ctr = 0x01;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello4_ack(
        worker_ctx->label,
        l_inc_ctr,
        identity->remote_wot,
        identity->remote_index,
        identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        encrypted_remote_identity1,
        encrypted_local_identity1,
        session->hello4_ack.ack_sent_try_count
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
    //print_hex("SIO Sending Hello4 Ack ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
//======================================================================
// Test Packet Dropped
//======================================================================
    //session->test_drop_hello4_ack++;
    if (
        session->test_drop_hello4_ack == 1
    )
    {
        printf("[Debug Here Helper]: Hello4 Ack Packet Number %d. Sending To Fake Addr To Force Retry\n", session->test_drop_hello4_ack);
        struct sockaddr_in6 fake_addr;
        memset(&fake_addr, 0, sizeof(struct sockaddr_in6));
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HELLO4_ACK,
                session->hello4_ack.ack_sent_try_count,
                &fake_addr, 
                &udp_data, 
                &session->hello4_ack
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
        if (worker_master_udp_data_ack(
                worker_ctx->label, 
                worker_ctx, 
                identity->local_wot, 
                identity->local_index, 
                identity->local_session_index, 
                (uint8_t)ORILINK_HELLO4_ACK,
                session->hello4_ack.ack_sent_try_count,
                remote_addr, 
                &udp_data, 
                &session->hello4_ack
            ) != SUCCESS
        )
        {
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
        if (session->test_drop_hello4_ack >= 1000000) {
            session->test_drop_hello4_ack = 0;
        }
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    memcpy(security->aes_key, aes_key, HASHES_BYTES);
    memcpy(security->remote_nonce, remote_nonce, AES_NONCE_BYTES);
    security->remote_ctr = remote_ctr;
    security->local_ctr = local_ctr;
    memset(aes_key, 0, HASHES_BYTES);
    memset(remote_nonce, 0, AES_NONCE_BYTES);
//======================================================================
    return last_execution(
        worker_ctx, 
        session, 
        identity, 
        security,
        &trycount
    );
}
