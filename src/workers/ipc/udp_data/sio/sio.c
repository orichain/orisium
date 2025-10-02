#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <errno.h>

#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "orilink/protocol.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "stdbool.h"

status_t handle_workers_ipc_udp_data_sio(worker_context_t *worker_ctx, void *worker_sessions, ipc_protocol_t* received_protocol) {
    ipc_udp_data_t *iudp_datai = received_protocol->payload.ipc_udp_data;
    uint16_t slot_found = iudp_datai->session_index;
    cow_c_session_t *cow_c_session = (cow_c_session_t *)worker_sessions;
    cow_c_session_t *session = &cow_c_session[slot_found];
    orilink_identity_t *identity = &session->identity;
    orilink_security_t *security = &session->security;
//----------------------------------------------------------------------
    struct sockaddr_in6 remote_addr;
    memcpy(&remote_addr, &iudp_datai->remote_addr, sizeof(struct sockaddr_in6));
//----------------------------------------------------------------------
    orilink_raw_protocol_t *oudp_datao = (orilink_raw_protocol_t*)calloc(1, sizeof(orilink_raw_protocol_t));
    if (!oudp_datao) {
        LOG_ERROR("%sFailed to allocate orilink_raw_protocol_t. %s", worker_ctx->label, strerror(errno));
        CLOSE_IPC_PROTOCOL(&received_protocol);
        return FAILURE_NOMEM;
    }
    if (udp_data_to_orilink_raw_protocol_packet(worker_ctx->label, iudp_datai, oudp_datao) != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
        return FAILURE;
    }
    bool is_need_ack = (oudp_datao->type < (uint8_t)0x80);
    status_t cmac = orilink_check_mac_ctr(
        worker_ctx->label, 
        is_need_ack,
        &session->last_trycount,
        security->aes_key, 
        security->mac_key, 
        security->remote_nonce,
        &security->remote_ctr, 
        oudp_datao
    );
    if (cmac != SUCCESS) {
        CLOSE_IPC_PROTOCOL(&received_protocol);
        CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
//----------------------------------------------------------------------
        if (cmac == FAILURE_MAXTRY || cmac == FAILURE_IVLDTRY) {
            worker_type_t c_wot = session->identity.local_wot;
            uint8_t c_index = session->identity.local_index;
            uint8_t c_session_index = session->identity.local_session_index;
//----------------------------------------------------------------------
// Disconnected => 1. Reset Session
//                 2. Send Info To Master
//----------------------------------------------------------------------
            cleanup_cow_session(worker_ctx->label, &worker_ctx->async, session);
            if (setup_cow_session(worker_ctx->label, session, c_wot, c_index, c_session_index) != SUCCESS) {
                return cmac;
            }
            if (worker_master_task_info(worker_ctx, c_session_index, TIT_TIMEOUT) != SUCCESS) {
                return cmac;
            }
//----------------------------------------------------------------------
        }
        return cmac;
    }
    switch (oudp_datao->type) {
        case ORILINK_HELLO1_ACK: {
            if (handle_workers_ipc_udp_data_sio_hello1_ack(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HELLO2_ACK: {
            if (handle_workers_ipc_udp_data_sio_hello2_ack(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HELLO3_ACK: {
            if (handle_workers_ipc_udp_data_sio_hello3_ack(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HELLO4_ACK: {
            if (handle_workers_ipc_udp_data_sio_hello4_ack(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case ORILINK_HEARTBEAT_ACK: {
            if (handle_workers_ipc_udp_data_sio_heartbeat_ack(worker_ctx, received_protocol, session, identity, security, &remote_addr, oudp_datao) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        default:
            LOG_ERROR("%sUnknown ORILINK protocol type %d from Remote SIO-%d[%d]. Ignoring.", worker_ctx->label, oudp_datao->type, oudp_datao->local_index, oudp_datao->local_session_index);
            CLOSE_IPC_PROTOCOL(&received_protocol);
            CLOSE_ORILINK_RAW_PROTOCOL(&oudp_datao);
    }
    return SUCCESS;
}
