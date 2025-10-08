#include <string.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <math.h>

#include "log.h"
#include "ipc/protocol.h"
#include "utilities.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "poly1305-donna.h"
#include "aes.h"
#include "orilink/protocol.h"
#include "stdbool.h"
#include "async.h"
#include "orilink/heartbeat.h"
#include "workers/ipc/master_ipc_cmds.h"

status_t handle_workers_ipc_udp_data_sio_hello4_ack(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, cow_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
    uint8_t l_inc_ctr = 0xFF;
//======================================================================
// + Security
//======================================================================
    if (!session->hello4.sent) {
        LOG_ERROR("%sReceive Hello4_Ack But This Worker Session Is Never Sending Hello4.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (session->hello4.ack_rcvd) {
        LOG_ERROR("%sHello4_Ack Received Already.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
//======================================================================
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
    orilink_hello4_ack_t *ohello4_ack = received_orilink_protocol->payload.orilink_hello4_ack;
//======================================================================
// Ambil remote_nonce
// Set remote_ctr = 0
// Ambil encrypter wot+index
// Ambil Mac
// Cocokkan MAc
// Decrypt wot dan index
//======================================================================
    uint32_t remote_ctr = (uint32_t)0;
    uint8_t encrypted_local_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];   
    memcpy(encrypted_local_identity, ohello4_ack->encrypted_remote_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    uint8_t data_mac0[AES_TAG_BYTES];
    memcpy(data_mac0, ohello4_ack->encrypted_remote_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// Tmp aes_key
//----------------------------------------------------------------------
    uint8_t aes_key[HASHES_BYTES];
    kdf1(security->kem_sharedsecret, aes_key);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
    uint8_t mac0[AES_TAG_BYTES];
    poly1305_context mac_ctx0;
    poly1305_init(&mac_ctx0, security->mac_key);
    poly1305_update(&mac_ctx0, encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    poly1305_finish(&mac_ctx0, mac0);
    if (!poly1305_verify(mac0, data_mac0)) {
        LOG_ERROR("%sFailed to Mac Tidak Sesuai. Worker error...", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }            
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
    uint8_t decrypted_local_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
    aes256ctx aes_ctx0;
    aes256_ctr_keyexp(&aes_ctx0, aes_key);
//=========================================IV===========================    
    uint8_t keystream_buffer0[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
    uint8_t iv0[AES_IV_BYTES];
    memcpy(iv0, security->remote_nonce, AES_NONCE_BYTES);
    uint32_t remote_ctr_be0 = htobe32(remote_ctr);
    memcpy(iv0 + AES_NONCE_BYTES, &remote_ctr_be0, sizeof(uint32_t));
//=========================================IV===========================    
    aes256_ctr(keystream_buffer0, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), iv0, &aes_ctx0);
    for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t); i++) {
        decrypted_local_identity[i] = encrypted_local_identity[i] ^ keystream_buffer0[i];
    }
    aes256_ctx_release(&aes_ctx0);
//======================================================================
// + Security
//======================================================================
    worker_type_t data_wot0;
    memcpy((uint8_t *)&data_wot0, decrypted_local_identity, sizeof(uint8_t));
    if (*(uint8_t *)&identity->local_wot != *(uint8_t *)&data_wot0) {
        LOG_ERROR("%sberbeda wot %d <=> %d. Worker error...", worker_ctx->label, data_wot0, identity->local_wot);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    uint8_t data_index0;
    memcpy(&data_index0, decrypted_local_identity + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->local_index != data_index0) {
        LOG_ERROR("%sberbeda index. Worker error...", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    uint8_t data_session_index0;
    memcpy(&data_session_index0, decrypted_local_identity + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->local_session_index != data_session_index0) {
        LOG_ERROR("%sberbeda session_index.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }      
    uint64_t local_id_be;
    memcpy(&local_id_be, decrypted_local_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint64_t));
    uint64_t local_id = be64toh(local_id_be);
    if (local_id != identity->local_id) {
        LOG_ERROR("%sberbeda id.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
    uint8_t encrypted_remote_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];   
    memcpy(encrypted_remote_identity, ohello4_ack->encrypted_local_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    uint8_t data_mac1[AES_TAG_BYTES];
    memcpy(data_mac1, ohello4_ack->encrypted_local_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), AES_TAG_BYTES);
//----------------------------------------------------------------------
// cek Mac
//----------------------------------------------------------------------  
    uint8_t mac1[AES_TAG_BYTES];
    poly1305_context mac_ctx1;
    poly1305_init(&mac_ctx1, security->mac_key);
    poly1305_update(&mac_ctx1, encrypted_remote_identity, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t));
    poly1305_finish(&mac_ctx1, mac1);
    if (!poly1305_verify(mac1, data_mac1)) {
        LOG_ERROR("%sFailed to Mac Tidak Sesuai. Worker error...", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }            
//----------------------------------------------------------------------
// Decrypt
//---------------------------------------------------------------------- 
    uint8_t decrypted_remote_identity[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
    aes256ctx aes_ctx1;
    aes256_ctr_keyexp(&aes_ctx1, aes_key);
//=========================================IV===========================    
    uint8_t keystream_buffer1[sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t)];
    uint8_t iv1[AES_IV_BYTES];
    memcpy(iv1, security->remote_nonce, AES_NONCE_BYTES);
    uint32_t remote_ctr_be1 = htobe32(remote_ctr);
    memcpy(iv1 + AES_NONCE_BYTES, &remote_ctr_be1, sizeof(uint32_t));
//=========================================IV===========================    
    aes256_ctr(keystream_buffer1, sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t), iv1, &aes_ctx1);
    for (size_t i = 0; i < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t); i++) {
        decrypted_remote_identity[i] = encrypted_remote_identity[i] ^ keystream_buffer1[i];
    }
    aes256_ctx_release(&aes_ctx1);
//----------------------------------------------------------------------
// Mencocokkan wot index
//----------------------------------------------------------------------
    worker_type_t data_wot1;
    memcpy((uint8_t *)&data_wot1, decrypted_remote_identity, sizeof(uint8_t));
    if (*(uint8_t *)&identity->remote_wot != *(uint8_t *)&data_wot1) {
        LOG_ERROR("%sberbeda wot %d <=> %d. Worker error...", worker_ctx->label, data_wot1, identity->local_wot);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    uint8_t data_index1;
    memcpy(&data_index1, decrypted_remote_identity + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->remote_index != data_index1) {
        LOG_ERROR("%sberbeda index. Worker error...", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    uint8_t data_session_index1;
    memcpy(&data_session_index1, decrypted_remote_identity + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint8_t));
    if (identity->remote_session_index != data_session_index1) {
        LOG_ERROR("%sberbeda session_index.", worker_ctx->label);
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    uint64_t remote_id_be;
    memcpy(&remote_id_be, decrypted_remote_identity + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t), sizeof(uint64_t));
    uint64_t remote_id = be64toh(remote_id_be);
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
    if (async_create_timerfd(worker_ctx->label, &session->heartbeat.timer_fd) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    session->heartbeat.sent_try_count++;
    session->heartbeat.sent_time = current_time.r_uint64_t;
    if (async_set_timerfd_time(worker_ctx->label, &session->heartbeat.timer_fd,
        (time_t)session->heartbeat.interval_timer_fd,
        (long)((session->heartbeat.interval_timer_fd - (time_t)session->heartbeat.interval_timer_fd) * 1e9),
        (time_t)session->heartbeat.interval_timer_fd,
        (long)((session->heartbeat.interval_timer_fd - (time_t)session->heartbeat.interval_timer_fd) * 1e9)) != SUCCESS)
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
    if (async_create_incoming_event(worker_ctx->label, &worker_ctx->async, &session->heartbeat.timer_fd) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        if (inc_ctr != 0xFF) {
            decrement_ctr(&security->remote_ctr, security->remote_nonce);
        }
        return FAILURE;
    }
//======================================================================
// Acumulate Different RTT Between Peers
//======================================================================
    double hb_interval = (double)NODE_HEARTBEAT_INTERVAL * pow((double)2, (double)session->retry.value_prediction);
    hb_interval += session->rtt.value_prediction / (double)1e9;
//======================================================================
    l_inc_ctr = 0x01;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_heartbeat(
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
        remote_id,
        hb_interval,
        session->heartbeat.sent_try_count
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
        aes_key,
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
    if (worker_master_udp_data(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, remote_addr, &udp_data, &session->heartbeat) != SUCCESS) {
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
    memcpy(security->aes_key, aes_key, HASHES_BYTES);
    security->remote_ctr = remote_ctr;
    memset(aes_key, 0, HASHES_BYTES);
    identity->remote_id = remote_id;
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    double try_count = (double)session->hello4.sent_try_count-(double)1;
    calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
    session->hello4.ack_rcvd = true;
    session->hello4.ack_rcvd_time = current_time.r_uint64_t;
    uint64_t interval_ull = session->hello4.ack_rcvd_time - session->hello4.sent_time;
    double rtt_value = (double)interval_ull;
    calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
    //cleanup_control_packet(worker_ctx->label, &worker_ctx->async, &session->hello4, false);
    
    printf("%sRTT Hello-4 = %f\n", worker_ctx->label, session->rtt.value_prediction);
//======================================================================
// Heartbeat Ack Security 1 & Security 2 Open
//======================================================================
    session->heartbeat.sent = true;
    session->heartbeat.ack_rcvd = false;
//======================================================================
// Heartbeat Security 1 & Security 2 Open
//======================================================================
    session->heartbeat_ack.ack_sent = true;
    session->heartbeat_ack.rcvd = false;
//======================================================================
    return SUCCESS;
}
