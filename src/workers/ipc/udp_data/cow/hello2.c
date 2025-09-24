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
#include "orilink/hello2_ack.h"
#include "orilink/protocol.h"

status_t handle_workers_ipc_udp_data_cow_hello2(worker_context_t *worker_ctx, ipc_protocol_t* received_protocol, sio_c_session_t *session, orilink_identity_t *identity, orilink_security_t *security, struct sockaddr_in6 *remote_addr, orilink_raw_protocol_t *oudp_datao) {
    worker_type_t remote_wot;
    uint8_t remote_index;
    uint8_t remote_session_index;
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
        remote_wot = oudp_datao->local_wot;
        remote_index = oudp_datao->local_index;
        remote_session_index = oudp_datao->local_session_index;
        LOG_DEBUG("%sorilink_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    orilink_protocol_t *received_orilink_protocol = deserialized_oudp_datao.r_orilink_protocol_t;
    orilink_hello2_t *ohello2 = received_orilink_protocol->payload.orilink_hello2;
    uint64_t remote_id = ohello2->local_id;
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
        return FAILURE;
    }
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello2_ack(
        worker_ctx->label,
        0x01,
        remote_wot,
        remote_index,
        remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        remote_id,
        kem_ciphertext,
        session->hello2_ack.ack_sent_try_count
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
    if (udp_data.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
        return FAILURE;
    }
    if (worker_master_udp_data_ack(worker_ctx->label, worker_ctx, identity->local_wot, identity->local_index, remote_addr, &udp_data, &session->hello2_ack) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
        CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
        return FAILURE;
    }
//----------------------------------------------------------------------
    CLOSE_IPC_PROTOCOL(&received_protocol);
//----------------------------------------------------------------------                            
    memcpy(&identity->remote_addr, remote_addr, sizeof(struct sockaddr_in6));
    identity->remote_wot = remote_wot;
    identity->remote_index = remote_index;
    identity->remote_session_index = remote_session_index;
    identity->remote_id = remote_id;
    memcpy(security->kem_publickey + (KEM_PUBLICKEY_BYTES / 2), kem_publickey + (KEM_PUBLICKEY_BYTES / 2), KEM_PUBLICKEY_BYTES / 2);
    memcpy(security->kem_ciphertext, kem_ciphertext, KEM_CIPHERTEXT_BYTES);
    memcpy(security->kem_sharedsecret, kem_sharedsecret, KEM_SHAREDSECRET_BYTES);
    memset(kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    CLOSE_ORILINK_PROTOCOL(&received_orilink_protocol);
    CLOSE_ORILINK_PROTOCOL(&orilink_cmd_result.r_orilink_protocol_t);
    return SUCCESS;
}
