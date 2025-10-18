#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "orilink/hello1.h"
#include "orilink/protocol.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "utilities.h"
#include "stdbool.h"

status_t handle_workers_ipc_cow_connect(worker_context_t *worker_ctx, void *worker_sessions, ipc_raw_protocol_t_status_t *ircvdi) {
    ipc_protocol_t_status_t deserialized_ircvdi = ipc_deserialize(worker_ctx->label,
        worker_ctx->aes_key, worker_ctx->remote_nonce, &worker_ctx->remote_ctr,
        (uint8_t*)ircvdi->r_ipc_raw_protocol_t->recv_buffer, ircvdi->r_ipc_raw_protocol_t->n
    );
    if (deserialized_ircvdi.status != SUCCESS) {
        LOG_ERROR("%sipc_deserialize gagal dengan status %d.", worker_ctx->label, deserialized_ircvdi.status);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    } else {
        LOG_DEBUG("%sipc_deserialize BERHASIL.", worker_ctx->label);
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
    }           
    ipc_protocol_t* received_protocol = deserialized_ircvdi.r_ipc_protocol_t;
    ipc_master_cow_connect_t *icow_connecti = received_protocol->payload.ipc_master_cow_connect;            
//----------------------------------------------------------------------
    uint16_t slot_found = icow_connecti->session_index;
    cow_c_session_t *cow_c_session = (cow_c_session_t *)worker_sessions;
    cow_c_session_t *session = &cow_c_session[slot_found];
    orilink_identity_t *identity = &session->identity;
    orilink_security_t *security = &session->security;
    memcpy(&identity->remote_addr, &icow_connecti->remote_addr, sizeof(struct sockaddr_in6));
//======================================================================
// Initalize Or FAILURE Now
//----------------------------------------------------------------------
    uint64_t_status_t current_time = get_monotonic_time_ns(worker_ctx->label);
    if (current_time.status != SUCCESS) {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi->r_ipc_raw_protocol_t);
        return FAILURE;
    }
    session->hello1.sent_try_count++;
    session->hello1.sent_time = current_time.r_uint64_t;
//======================================================================
    identity->id_connection = icow_connecti->id_connection;
    orilink_protocol_t_status_t orilink_cmd_result = orilink_prepare_cmd_hello1(
        worker_ctx->label,
        0x01,
//----------------------------------------------------------------------
        //identity->remote_wot,
        //identity->remote_index,
        //identity->remote_session_index,
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
//----------------------------------------------------------------------
        identity->local_wot,
        identity->local_index,
        identity->local_session_index,
        identity->id_connection,
        identity->local_id,
        security->kem_publickey,
        session->hello1.sent_try_count
    );
    if (orilink_cmd_result.status != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
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
        return FAILURE;
    }
    print_hex("COW Sending Hello1 ", udp_data.r_puint8_t, udp_data.r_size_t, 1);
    if (worker_master_udp_data(
            worker_ctx->label, 
            worker_ctx, 
            identity->local_wot, 
            identity->local_index, 
            identity->local_session_index, 
            (uint8_t)ORILINK_HELLO1,
            session->hello1.sent_try_count,
            &identity->remote_addr, 
            &udp_data, 
            &session->hello1
        ) != SUCCESS
    )
    {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE;
    }
//======================================================================
    CLOSE_IPC_PROTOCOL(&received_protocol);
//======================================================================
    session->hello1.sent = true;
//======================================================================
    return SUCCESS;
}
