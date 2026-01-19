#ifndef WORKERS_MASTER_IPC_CMDS_H
#define WORKERS_MASTER_IPC_CMDS_H

#include <inttypes.h>
#include <stdio.h>

#include "constants.h"
#include "ipc/protocol.h"
#include "log.h"
#include "types.h"
#include "workers/workers.h"
#include "workers/worker_ipc.h"
#include "utilities.h"
#include "orilink/heartbeat.h"
#include "orilink/protocol.h"
#include "orilink.h"
#include "stdbool.h"
#include "orilink/heartbeat_ack.h"

static inline status_t worker_master_hello1(worker_context_t *ctx) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_hello1(
        ctx->label,
        &ctx->oritlsf_pool,  
        *ctx->wot, 
        *ctx->index, 
        ctx->kem_publickey
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        ctx->label, 
        &ctx->oritlsf_pool, 
        ctx->aes_key,
        ctx->mac_key,
        ctx->local_nonce,
        &ctx->local_ctr,
        ctx->master_uds_fd, 
        ctx->buffer,
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_hello1 to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_hello1 to Master.", ctx->label);
    }
    ctx->hello1_sent = true;
    CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

static inline status_t worker_master_worker_info(worker_context_t *ctx, worker_type_t dst_wot, uint8_t dst_index, info_type_t flag) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_worker_info(
        ctx->label,
        &ctx->oritlsf_pool,  
        *ctx->wot, 
        *ctx->index, 
        *ctx->wot,
        *ctx->index, 
        0xff,
        dst_wot,
        dst_index,
        0xff,
        flag
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        ctx->label, 
        &ctx->oritlsf_pool, 
        ctx->aes_key,
        ctx->mac_key,
        ctx->local_nonce,
        &ctx->local_ctr,
        ctx->master_uds_fd, 
        ctx->buffer,
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_worker_info to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_worker_info to Master.", ctx->label);
    }
    CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

#endif
