#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "pqc.h"
#include "orilink/hello2_ack.h"
#include "orilink/protocol.h"
#include "stdbool.h"
#include "utilities.h"
#include "constants.h"

struct sockaddr_in6;

status_t handle_workers_ipc_udp_data_cow_hello2(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
//======================================================================
// + Security
//======================================================================
    if (!session->hello1_ack.ack_sent) {
        LOG_ERROR("%sReceive Hello2 But This Worker Session Is Never Sending Hello1_Ack.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    if (session->hello1_ack.rcvd) {
        if (trycount > (uint8_t)MAX_RETRY) {
            LOG_ERROR("%sHello2 Received Already.", worker_ctx->label);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->hello1_ack.last_trycount) {
            LOG_ERROR("%sHello2 Received Already.", worker_ctx->label);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_IVLDTRY;
        }
    }
    if (trycount > (uint8_t)1) {
        if (inc_ctr != 0xFF) {
            if (security->remote_ctr != oudp_datao->ctr) {
//----------------------------------------------------------------------
// No Counter Yet
//----------------------------------------------------------------------
                //decrement_ctr(&security->remote_ctr, security->remote_nonce);
            }
        }
        session->hello1_ack.ack_sent = false;
    }
    session->hello1_ack.last_trycount = trycount;
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
    orilink_hello2_t *ohello2 = received_orilink_protocol->payload.orilink_hello2;
    uint64_t remote_id = ohello2->local_id;
//======================================================================
// + Security
//======================================================================
    if (remote_id != identity->remote_id) {
        LOG_ERROR("%sReceive Different Id Between Hello2 And Hello1_Ack.", worker_ctx->label);
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
    uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
    uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES];
    uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
    memcpy(kem_publickey, security->kem_publickey, KEM_PUBLICKEY_BYTES / 2);
    memcpy(kem_publickey + (KEM_PUBLICKEY_BYTES / 2), ohello2->publickey2, KEM_PUBLICKEY_BYTES / 2);
    if (KEM_ENCODE_SHAREDSECRET(
        kem_ciphertext, 
        kem_sharedsecret, 
        kem_publickey
    ) != 0)
    {
        LOG_ERROR("%sFailed to KEM_ENCODE_SHAREDSECRET.", worker_ctx->label);
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
    session->hello2_ack.ack_sent_try_count++;
    session->hello2_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
    if (trycount > (uint8_t)1) {
        if (retry_packet_ack(worker_ctx, session, &session->hello2_ack) != SUCCESS) {
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
    } else {
        orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello2_ack(
            worker_ctx->label,
            0x01,
            identity->remote_wot,
            identity->remote_index,
            identity->remote_session_index,
            identity->local_wot,
            identity->local_index,
            identity->local_session_index,
            identity->id_connection,
            identity->remote_id,
            kem_ciphertext,
            session->hello2_ack.ack_sent_try_count
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
        cleanup_packet_ack_timer(worker_ctx->label, &worker_ctx->async, &session->hello2_ack);
        if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, remote_addr, &udp_data, &session->hello2_ack) != SUCCESS) {
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
    }
//----------------------------------------------------------------------
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    memcpy(security->kem_publickey + (KEM_PUBLICKEY_BYTES / 2), kem_publickey + (KEM_PUBLICKEY_BYTES / 2), KEM_PUBLICKEY_BYTES / 2);
    memcpy(security->kem_ciphertext, kem_ciphertext, KEM_CIPHERTEXT_BYTES);
    memcpy(security->kem_sharedsecret, kem_sharedsecret, KEM_SHAREDSECRET_BYTES);
    memset(kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    if (trycount > (uint8_t)1) {
        double try_count = (double)session->hello1_ack.ack_sent_try_count;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
        session->hello1_ack.rcvd = true;
        session->hello1_ack.rcvd_time = current_time.r_uint64_t;
    } else {
        double try_count = (double)session->hello1_ack.ack_sent_try_count-(double)1;
        calculate_retry(worker_ctx->label, session, identity->local_wot, try_count);
        session->hello1_ack.rcvd = true;
        session->hello1_ack.rcvd_time = current_time.r_uint64_t;
        uint64_t interval_ull = session->hello1_ack.rcvd_time - session->hello1_ack.ack_sent_time;
        double rtt_value = (double)interval_ull;
        calculate_rtt(worker_ctx->label, session, identity->local_wot, rtt_value);
        cleanup_packet_ack_timer(worker_ctx->label, &worker_ctx->async, &session->hello1_ack);
        
        printf("%sRTT Hello-1 Ack = %f\n", worker_ctx->label, session->rtt.value_prediction);
    }
//======================================================================
    session->hello2_ack.ack_sent = true;
//======================================================================
    return SUCCESS;
}
