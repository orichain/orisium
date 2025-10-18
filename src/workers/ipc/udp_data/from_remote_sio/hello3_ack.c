#include <stdint.h>
#include <string.h>
#include <endian.h>
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
#include "pqc.h"
#include "orilink/hello4.h"
#include "orilink/protocol.h"
#include "stdbool.h"

status_t handle_workers_ipc_udp_data_sio_hello3_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
    uint8_t l_inc_ctr = 0xFF;
//======================================================================
// + Security
//======================================================================
    //print_hex("COW Receiving Hello3 Ack ", (uint8_t*)oudp_datao->recv_buffer, oudp_datao->n, 1);
    if (!session->hello3.sent) {
        LOG_ERROR("%sReceive Hello3_Ack But This Worker Session Is Never Sending Hello3.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (session->hello3.ack_rcvd) {
        LOG_ERROR("%sHello3_Ack Received Already.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//======================================================================
    status_t cmac = orilink_check_mac(worker_ctx->label, security->mac_key, oudp_datao);
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    status_t rhd = orilink_read_header(worker_ctx->label, security->aes_key, security->mac_key, security->remote_nonce, oudp_datao);
    if (rhd != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//----------------------------------------------------------------------
    inc_ctr = oudp_datao->inc_ctr;
//----------------------------------------------------------------------
    status_t cctr = orilink_check_ctr(worker_ctx->label, security->aes_key, &security->remote_ctr, oudp_datao);
    if (cctr != SUCCESS) {
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
    orilink_hello3_ack_t *ohello3_ack = received_orilink_protocol->payload.orilink_hello3_ack;
    uint64_t local_id = ohello3_ack->remote_id;
//======================================================================
// + Security
//======================================================================
    if (local_id != identity->local_id) {
        LOG_ERROR("%sReceive Different Id Between Hello3_Ack And Hello3.", worker_ctx->label);
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
    uint8_t remote_nonce[AES_NONCE_BYTES];
    uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES];
    uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
    uint8_t aes_key[HASHES_BYTES];
    uint8_t mac_key[HASHES_BYTES];
    uint8_t local_nonce[AES_NONCE_BYTES];
    uint32_t local_ctr = (uint32_t)0;
    memcpy(remote_nonce, ohello3_ack->nonce, AES_NONCE_BYTES);
    memcpy(kem_ciphertext, security->kem_ciphertext, KEM_CIPHERTEXT_BYTES / 2);
    memcpy(kem_ciphertext + (KEM_CIPHERTEXT_BYTES / 2), ohello3_ack->ciphertext2, KEM_CIPHERTEXT_BYTES / 2);
    if (KEM_DECODE_SHAREDSECRET(kem_sharedsecret, kem_ciphertext, session->kem_privatekey) != 0) {
        LOG_ERROR("%sFailed to KEM_DECODE_SHAREDSECRET.", worker_ctx->label);
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
// Temporary Key
//----------------------------------------------------------------------
    kdf1(kem_sharedsecret, aes_key);
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
//----------------------------------------------------------------------
// HELLO4 Memakai mac_key baru
//----------------------------------------------------------------------
    kdf2(aes_key, mac_key);
//----------------------------------------------------------------------
    uint8_t local_identity[
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    uint8_t encrypted_local_identity[
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];   
    uint8_t encrypted_local_identity1[
        AES_NONCE_BYTES +
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    uint8_t encrypted_local_identity2[
        AES_NONCE_BYTES +
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t) +
        AES_TAG_BYTES
    ];
    memcpy(encrypted_local_identity1, local_nonce, AES_NONCE_BYTES);
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
    const size_t data_len = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
    if (encrypt_decrypt_256(
            worker_ctx->label,
            aes_key,
            local_nonce,
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
    memcpy(encrypted_local_identity1 + AES_NONCE_BYTES, encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
//======================================================================
    uint8_t mac[AES_TAG_BYTES];
    const size_t data_4mac_len = AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t);
    calculate_mac(mac_key, encrypted_local_identity1, mac, data_4mac_len);
//====================================================================== 
    memcpy(encrypted_local_identity2, encrypted_local_identity1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    memcpy(encrypted_local_identity2 + AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), mac, AES_TAG_BYTES);
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
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
    session->hello4.sent_try_count++;
    session->hello4.sent_time = current_time.r_uint64_t;
//======================================================================
    l_inc_ctr = 0x01;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello4(
        worker_ctx->label,
        l_inc_ctr,
        identity->remote_wot,
        identity->remote_index,
        identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        encrypted_local_identity2,
        session->hello4.sent_try_count
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
        mac_key,
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
    if (worker_master_udp_data(
            worker_ctx->label, 
            worker_ctx, 
            identity->local_wot, 
            identity->local_index, 
            identity->local_session_index, 
            (uint8_t)ORILINK_HELLO4,
            session->hello4.sent_try_count,
            remote_addr, 
            &udp_data, 
            &session->hello4
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
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    memcpy(security->remote_nonce, remote_nonce, AES_NONCE_BYTES);
    memcpy(security->kem_ciphertext + (KEM_CIPHERTEXT_BYTES / 2), kem_ciphertext + (KEM_CIPHERTEXT_BYTES / 2), KEM_CIPHERTEXT_BYTES / 2);
    memcpy(security->kem_sharedsecret, kem_sharedsecret, KEM_SHAREDSECRET_BYTES);
    memcpy(security->mac_key, mac_key, HASHES_BYTES);
    memcpy(security->local_nonce, local_nonce, AES_NONCE_BYTES);
    security->local_ctr = local_ctr;
    memset(remote_nonce, 0, AES_NONCE_BYTES);
    memset(kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    memset(aes_key, 0, HASHES_BYTES);
    memset(mac_key, 0, HASHES_BYTES);
    memset(local_nonce, 0, AES_NONCE_BYTES);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
// 
//----------------------------------------------------------------------
    if (session->hello3.sent_try_count > (uint8_t)0) {
        double try_count = (double)session->hello3.sent_try_count-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    }
//======================================================================
    session->hello3.ack_rcvd = true;
    session->hello3.ack_rcvd_time = current_time.r_uint64_t;
    uint64_t interval_ull = session->hello3.ack_rcvd_time - session->hello3.sent_time;
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    //cleanup_control_packet(worker_ctx->label, &worker_ctx->async, &session->hello3, false);
    
    printf("%sRTT Hello-3 = %f\n", worker_ctx->label, session->rtt.value_prediction);
    
//======================================================================
    session->hello4.sent = true;
//======================================================================
    return SUCCESS;
}
