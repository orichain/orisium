#include <stdint.h>

#include "log.h"
#include "types.h"
#include "ipc/protocol.h"
#include "ipc/worker_master_heartbeat.h"
#include "ipc/worker_master_hello1.h"
#include "ipc/cow_master_connection.h"
#include "workers/worker.h"

struct sockaddr_in6;

status_t worker_master_heartbeat(worker_context_t *ctx, double new_heartbeat_interval_double) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_heartbeat(ctx->label, ctx->wot, ctx->idx, new_heartbeat_interval_double);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(ctx->label, &ctx->master_uds_fd, cmd_result.r_ipc_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_heartbeat to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_heartbeat to Master.", ctx->label);
    }
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t worker_master_hello1(worker_context_t *ctx, uint8_t *kem_publickey) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_hello1(ctx->label, ctx->wot, ctx->idx, kem_publickey);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(ctx->label, &ctx->master_uds_fd, cmd_result.r_ipc_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_hello1 to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_hello1 to Master.", ctx->label);
    }
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t cow_master_connection(worker_context_t *ctx, struct sockaddr_in6 *addr, connection_type_t flag) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_cow_master_connection(ctx->label, ctx->wot, ctx->idx, addr, flag);
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(ctx->label, &ctx->master_uds_fd, cmd_result.r_ipc_protocol_t);
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent cow_master_connection to master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent cow_master_connection to master.", ctx->label);
    }
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	return SUCCESS;
}
