#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "pqc.h"
#include "orilink/hello1_ack.h"
#include "orilink/protocol.h"
#include "stdbool.h"
#include "utilities.h"
#include "constants.h"

status_t handle_workers_ipc_udp_data_cow_hello1(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    uint8_t inc_ctr = oudp_datao->inc_ctr;
    uint8_t l_inc_ctr = 0xFF;
    uint8_t trycount = oudp_datao->trycount;
//======================================================================
// + Security
//======================================================================
    if (!session->hello1_ack.ack_sent) {
        if (trycount > (uint8_t)MAX_RETRY) {
            LOG_ERROR("%sHello1 Received Already.", worker_ctx->label);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
            return FAILURE_MAXTRY;
        }
        if (trycount <= session->hello1_ack.last_trycount) {
            LOG_ERROR("%sHello1 Received Already.", worker_ctx->label);
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
    worker_type_t remote_wot;
    uint8_t remote_index;
    uint8_t remote_session_index;
    uint64_t rcvd_id_connection;
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
        remote_wot = oudp_datao->local_wot;
        remote_index = oudp_datao->local_index;
        remote_session_index = oudp_datao->local_session_index;
        rcvd_id_connection = oudp_datao->id_connection;
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_hello1_t *ohello1 = received_orilink_protocol->payload.orilink_hello1;
    uint64_t remote_id = ohello1->local_id;
    uint8_t kem_publickey[KEM_PUBLICKEY_BYTES / 2];
    memcpy(kem_publickey, ohello1->publickey1, KEM_PUBLICKEY_BYTES / 2);
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
    session->hello1_ack.ack_sent_try_count++;
    session->hello1_ack.ack_sent_time = current_time.r_uint64_t;
//======================================================================
    if (trycount > (uint8_t)1) {
        if (retry_packet_ack(worker_ctx, session, &session->hello1_ack) != SUCCESS) {
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
        identity->id_connection = rcvd_id_connection;
        orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello1_ack(
            worker_ctx->label,
            0x01,
            remote_wot,
            remote_index,
            remote_session_index,
            identity->local_wot,
            identity->local_index,
            identity->local_session_index,
            identity->id_connection,
            remote_id,
            session->hello1_ack.ack_sent_try_count
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
        cleanup_packet_ack_timer(worker_ctx->label, &worker_ctx->async, &session->hello1_ack);
        if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, remote_addr, &udp_data, &session->hello1_ack) != SUCCESS) {
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
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    identity->remote_wot = remote_wot;
    identity->remote_index = remote_index;
    identity->remote_session_index = remote_session_index;
    identity->remote_id = remote_id;
    memcpy(security->kem_publickey, kem_publickey, KEM_PUBLICKEY_BYTES / 2);
    memset(kem_publickey, 0, KEM_PUBLICKEY_BYTES / 2);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
//======================================================================
    session->hello1_ack.ack_sent = true;
//======================================================================
    return SUCCESS;
}
