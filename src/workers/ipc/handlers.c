#include "log.h"
#include "ipc/protocol.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"

void handle_workers_ipc_closed_event(worker_context_t *worker_ctx) {
    LOG_INFO("%sMaster disconnected. Initiating graceful shutdown...", worker_ctx->label);
    worker_ctx->shutdown_requested = 1;
}

status_t handle_workers_ipc_event(worker_context_t *worker_ctx, void *worker_sessions, double *initial_delay_ms) {
    ipc_raw_protocol_t_status_t ircvdi = receive_ipc_raw_protocol_message(worker_ctx->label, worker_ctx->master_uds_fd);
    if (ircvdi.status != SUCCESS) {
        LOG_ERROR("%sError receiving or deserializing IPC message from Master: %d", worker_ctx->label, ircvdi.status);
        return ircvdi.status;
    }
    if (ipc_check_mac(
            worker_ctx->label,
            worker_ctx->mac_key, 
            ircvdi.r_ipc_raw_protocol_t
        ) != SUCCESS
    )
    {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
    if (ipc_read_header(
            worker_ctx->label, 
            worker_ctx->mac_key, 
            worker_ctx->remote_nonce, 
            ircvdi.r_ipc_raw_protocol_t
        ) != SUCCESS
    )
    {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
    if (ipc_check_ctr(
            worker_ctx->label,
            worker_ctx->aes_key, 
            &worker_ctx->remote_ctr, 
            ircvdi.r_ipc_raw_protocol_t
        ) != SUCCESS
    )
    {
        CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
        return FAILURE;
    }
    switch (ircvdi.r_ipc_raw_protocol_t->type) {
        case IPC_MASTER_WORKER_INFO: {
            if (handle_workers_ipc_info(worker_ctx, initial_delay_ms, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case IPC_MASTER_WORKER_HELLO1_ACK: {
            if (handle_workers_ipc_hello1_ack(worker_ctx, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case IPC_MASTER_WORKER_HELLO2_ACK: {
            if (handle_workers_ipc_hello2_ack(worker_ctx, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case IPC_MASTER_COW_CONNECT: {
            if (handle_workers_ipc_cow_connect(worker_ctx, worker_sessions, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case IPC_UDP_DATA: {
            if (handle_workers_ipc_udp_data(worker_ctx, worker_sessions, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        case IPC_UDP_DATA_ACK: {
            if (handle_workers_ipc_udp_data_ack(worker_ctx, worker_sessions, &ircvdi) != SUCCESS) {
                return FAILURE;
            }
            break;
        }
        default:
            LOG_ERROR("%sUnknown IPC protocol type %d from Master. Ignoring.", worker_ctx->label, ircvdi.r_ipc_raw_protocol_t->type);
            CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
    }
    return SUCCESS;
}
