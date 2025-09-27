#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdio.h>
#include <time.h>

#include "log.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "poly1305-donna.h"
#include "aes.h"
#include "orilink/hello4_ack.h"
#include "orilink/protocol.h"
#include "async.h"
#include "stdbool.h"

status_t handle_workers_ipc_udp_data_cow_hello4(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
//======================================================================
// + Security
//======================================================================
    if (!session->hello3_ack.ack_sent) {
        LOG_ERROR("%sReceive Hello4 But This Worker Session Is Never Sending Hello3_Ack.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (session->hello3_ack.rcvd) {
        LOG_ERROR("%sHello4 Received Already.", worker_ctx->label);
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
    uint32_t remote_ctr = (uint32_t)0;
    uint32_t local_ctr = (uint32_t)0;
    uint8_t remote_nonce[AES_NONCE_BYTES];
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
    uint8_t aes_key[HASHES_BYTES];
    kdf1(security->kem_sharedsecret, aes_key);
    
    print_hex("SIO MAC = ", security->mac_key, HASHES_BYTES, 1);
    
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
    uint8_t encrypted_remote_identity_rcvd1[
        AES_NONCE_BYTES +
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    memcpy(encrypted_remote_identity_rcvd1, ohello4->encrypted_local_identity, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    uint8_t mac0[AES_TAG_BYTES];
    poly1305_context mac_ctx0;
    poly1305_init(&mac_ctx0, security->mac_key);
    poly1305_update(&mac_ctx0, encrypted_remote_identity_rcvd1, AES_NONCE_BYTES + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    poly1305_finish(&mac_ctx0, mac0);
    
    print_hex("SIO mac = ", mac0, AES_TAG_BYTES, 1);
    
    if (!poly1305_verify(mac0, data_mac)) {
        LOG_ERROR("%sFailed to Mac Tidak Sesuai.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
    uint8_t decrypted_remote_identity_rcvd[
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    aes256ctx aes_ctx0;
    aes256_ctr_keyexp(&aes_ctx0, aes_key);
//=========================================IV===========================    
    uint8_t keystream_buffer0[
        sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)
    ];
    uint8_t iv0[AES_IV_BYTES];
    memcpy(iv0, remote_nonce, AES_NONCE_BYTES);
    uint32_t remote_ctr_be = htobe32(remote_ctr);
    memcpy(iv0 + AES_NONCE_BYTES, &remote_ctr_be, sizeof(uint32_t));
//=========================================IV===========================    
    aes256_ctr(keystream_buffer0, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), iv0, &aes_ctx0);
    for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t); i++) {
        decrypted_remote_identity_rcvd[i] = encrypted_remote_identity_rcvd[i] ^ keystream_buffer0[i];
    }
    aes256_ctx_release(&aes_ctx0);
//======================================================================
// + Security
//======================================================================
    worker_type_t data_wot;
    memcpy((uint8_t *)&data_wot, decrypted_remote_identity_rcvd, sizeof(uint8_t));
    if (*(uint8_t *)&identity->remote_wot != *(uint8_t *)&data_wot) {
        LOG_ERROR("%sberbeda wot.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    uint8_t data_index;
    memcpy(&data_index, decrypted_remote_identity_rcvd + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->remote_index != data_index) {
        LOG_ERROR("%sberbeda index.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    uint8_t data_session_index;
    memcpy(&data_session_index, decrypted_remote_identity_rcvd + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->remote_session_index != data_session_index) {
        LOG_ERROR("%sberbeda session_index.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }      
    uint64_t remote_id_be0;
    memcpy(&remote_id_be0, decrypted_remote_identity_rcvd + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint64_t));
    uint64_t remote_id = be64toh(remote_id_be0);
    if (remote_id != identity->remote_id) {
        LOG_ERROR("%sberbeda id.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
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
    aes256ctx aes_ctx1;
    aes256_ctr_keyexp(&aes_ctx1, aes_key);
//=========================================IV===========================    
    uint8_t keystream_buffer1[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
    uint8_t iv1[AES_IV_BYTES];
    memcpy(iv1, security->local_nonce, AES_NONCE_BYTES);
    uint32_t local_ctr_be1 = htobe32(local_ctr);
    memcpy(iv1 + AES_NONCE_BYTES, &local_ctr_be1, sizeof(uint32_t));
//=========================================IV===========================    
    aes256_ctr(keystream_buffer1, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), iv1, &aes_ctx1);
    for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t); i++) {
        encrypted_remote_identity[i] = remote_identity[i] ^ keystream_buffer1[i];
    }
    aes256_ctx_release(&aes_ctx1);
//======================================================================    
    uint8_t mac1[AES_TAG_BYTES];
    poly1305_context mac_ctx1;
    poly1305_init(&mac_ctx1, security->mac_key);
    poly1305_update(&mac_ctx1, encrypted_remote_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    poly1305_finish(&mac_ctx1, mac1);
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
    aes256ctx aes_ctx2;
    aes256_ctr_keyexp(&aes_ctx2, aes_key);
//=========================================IV===========================    
    uint8_t keystream_buffer2[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
    uint8_t iv2[AES_IV_BYTES];
    memcpy(iv2, security->local_nonce, AES_NONCE_BYTES);
    uint32_t local_ctr_be2 = htobe32(security->local_ctr);
    memcpy(iv2 + AES_NONCE_BYTES, &local_ctr_be2, sizeof(uint32_t));
//=========================================IV===========================    
    aes256_ctr(keystream_buffer2, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), iv2, &aes_ctx2);
    for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t); i++) {
        encrypted_local_identity[i] = local_identity[i] ^ keystream_buffer2[i];
    }
    aes256_ctx_release(&aes_ctx2);
//======================================================================    
    uint8_t mac2[AES_TAG_BYTES];
    poly1305_context mac_ctx2;
    poly1305_init(&mac_ctx2, security->mac_key);
    poly1305_update(&mac_ctx2, encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    poly1305_finish(&mac_ctx2, mac2);
//====================================================================== 
    memcpy(encrypted_local_identity1, encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    memcpy(encrypted_local_identity1 + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), mac2, AES_TAG_BYTES);
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_realtime_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    if (async_create_timerfd(worker_ctx->label, &session->hello4_ack.ack_timer_fd) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    session->hello4_ack.ack_sent_try_count++;
    session->hello4_ack.ack_sent_time = current_time.r_uint64_t;
    if (async_set_timerfd_time(worker_ctx->label, &session->hello4_ack.ack_timer_fd,
        (time_t)session->hello4_ack.interval_ack_timer_fd,
        (long)((session->hello4_ack.interval_ack_timer_fd - (time_t)session->hello4_ack.interval_ack_timer_fd) * 1e9),
        (time_t)session->hello4_ack.interval_ack_timer_fd,
        (long)((session->hello4_ack.interval_ack_timer_fd - (time_t)session->hello4_ack.interval_ack_timer_fd) * 1e9)) != SUCCESS)
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->hello4_ack.ack_timer_fd) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//======================================================================
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello4_ack(
        worker_ctx->label,
        0x01,
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
    if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, remote_addr, &udp_data, &session->hello4_ack) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        return FAILURE;
    }
//----------------------------------------------------------------------
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    memcpy(security->aes_key, aes_key, HASHES_BYTES);
    memcpy(security->remote_nonce, remote_nonce, AES_NONCE_BYTES);
    security->remote_ctr = remote_ctr;
    security->local_ctr = local_ctr;
    memset(aes_key, 0, HASHES_BYTES);
    memset(remote_nonce, 0, AES_NONCE_BYTES);
    //identity->remote_wot = remote_wot;
    //identity->remote_index = remote_index;
    //identity->remote_session_index = remote_session_index;
    //identity->remote_id = remote_id;
    CLOSE_IPC_PROTOCOL(&received_protocol);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    double try_count = (double)session->hello3_ack.ack_sent_try_count-(double)1;
    calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    session->hello3_ack.rcvd = true;
    session->hello3_ack.rcvd_time = current_time.r_uint64_t;
    uint64_t interval_ull = session->hello3_ack.rcvd_time - session->hello3_ack.ack_sent_time;
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    cleanup_packet_ack_timer(worker_ctx->label, &worker_ctx->async, &session->hello3_ack);
    
    printf("%sRTT Hello-3 Ack = %f\n", worker_ctx->label, session->rtt.value_prediction);
    
//======================================================================
    session->hello4_ack.ack_sent = true;
//======================================================================
    return SUCCESS;
}
