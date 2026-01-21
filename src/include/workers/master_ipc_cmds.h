#ifndef WORKERS_MASTER_IPC_CMDS_H
#define WORKERS_MASTER_IPC_CMDS_H

#include <inttypes.h>

#include "ipc.h"
#include "ipc/protocol.h"
#include "ipc/udp_data.h"
#include "ipc/worker_master_heartbeat.h"
#include "ipc/worker_master_hello2.h"
#include "ipc/worker_master_info.h"
#include "ipc/worker_master_hello1.h"
#include "ipc/worker_worker_info.h"
#include "log.h"
#include "types.h"
#include "utilities.h"
#include "stdbool.h"
#include "oritlsf.h"

struct sockaddr_in6;

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

static inline status_t worker_master_hello2(worker_context_t *ctx, uint8_t encrypted_wot_index2[]) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_hello2(
        ctx->label, 
        &ctx->oritlsf_pool, 
        *ctx->wot, 
        *ctx->index, 
        encrypted_wot_index2
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
        LOG_ERROR("%sFailed to sent worker_master_hello2 to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_hello2 to Master.", ctx->label);
    }
    ctx->hello2_sent = true;
    CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

static inline status_t worker_master_heartbeat(worker_context_t *ctx, double new_heartbeat_interval_double) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_heartbeat(
        ctx->label, 
        &ctx->oritlsf_pool, 
        *ctx->wot, 
        *ctx->index, 
        new_heartbeat_interval_double
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (ctx->is_rekeying) {
        if (ipc_add_tail_protocol_queue(ctx->label, &ctx->oritlsf_pool, *ctx->wot, *ctx->index, ctx->master_uds_fd, ctx->buffer, cmd_result.r_ipc_protocol_t, &ctx->rekeying_queue_head, &ctx->rekeying_queue_tail) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
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
            LOG_ERROR("%sFailed to sent worker_master_heartbeat to Master.", ctx->label);
            CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent worker_master_heartbeat to Master.", ctx->label);
        }
        CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

static inline status_t worker_master_udp_data_ack_send_ipc(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    uint8_t orilink_protocol, 
    uint8_t trycount,
    struct sockaddr_in6 *addr,
    packet_ack_t *h
) 
{
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_udp_data(
        label,
        &worker_ctx->oritlsf_pool, 
        wot,
        index,
        session_index,
        orilink_protocol,
        trycount,
        addr,
        h->udp_data->len,
        h->udp_data->data
    );
    if (cmd_result.status != SUCCESS) {
		if (h->udp_data) oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&h->udp_data->data);
        oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&h->udp_data);
        return FAILURE;
    }
    if (worker_ctx->is_rekeying) {
        if (ipc_add_tail_protocol_queue(worker_ctx->label, &worker_ctx->oritlsf_pool, *worker_ctx->wot, *worker_ctx->index, worker_ctx->master_uds_fd, worker_ctx->buffer, cmd_result.r_ipc_protocol_t, &worker_ctx->rekeying_queue_head, &worker_ctx->rekeying_queue_tail) != SUCCESS) {
			if (h->udp_data) oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&h->udp_data->data);
			oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&h->udp_data);
            CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            worker_ctx->label,
            &worker_ctx->oritlsf_pool, 
            worker_ctx->aes_key,
            worker_ctx->mac_key,
            worker_ctx->local_nonce,
            &worker_ctx->local_ctr,
            worker_ctx->master_uds_fd, 
            worker_ctx->buffer,
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
            if (h->udp_data) oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&h->udp_data->data);
            oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&h->udp_data);
            CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
        }
        CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

static inline status_t worker_master_udp_data_send_ipc(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    uint8_t session_index,
    uint8_t orilink_protocol, 
    uint8_t trycount,
    struct sockaddr_in6 *addr,
    packet_t *h
) 
{
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_udp_data(
        label,
        &worker_ctx->oritlsf_pool, 
        wot,
        index,
        session_index,
        orilink_protocol,
        trycount,
        addr,
        h->udp_data->len,
        h->udp_data->data
    );
    if (cmd_result.status != SUCCESS) {
		if (h->udp_data) oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&h->udp_data->data);
		oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&h->udp_data);
        return FAILURE;
    }
    if (worker_ctx->is_rekeying) {
        if (ipc_add_tail_protocol_queue(worker_ctx->label, &worker_ctx->oritlsf_pool, *worker_ctx->wot, *worker_ctx->index, worker_ctx->master_uds_fd, worker_ctx->buffer, cmd_result.r_ipc_protocol_t, &worker_ctx->rekeying_queue_head, &worker_ctx->rekeying_queue_tail) != SUCCESS) {
			if (h->udp_data) oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&h->udp_data->data);
			oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&h->udp_data);
            CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            worker_ctx->label,
            &worker_ctx->oritlsf_pool, 
            worker_ctx->aes_key,
            worker_ctx->mac_key,
            worker_ctx->local_nonce,
            &worker_ctx->local_ctr,
            worker_ctx->master_uds_fd, 
            worker_ctx->buffer,
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
            if (h->udp_data) oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&h->udp_data->data);
            oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&h->udp_data);
            CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
        }
        CLOSE_IPC_PROTOCOL(&worker_ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

static inline status_t worker_master_info(worker_context_t *ctx, uint8_t session_index, info_type_t flag) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_info(
        ctx->label, 
        &ctx->oritlsf_pool, 
        *ctx->wot, 
        *ctx->index,
        session_index,
        flag
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (ctx->is_rekeying) {
        if (ipc_add_tail_protocol_queue(ctx->label, &ctx->oritlsf_pool, *ctx->wot, *ctx->index, ctx->master_uds_fd, ctx->buffer, cmd_result.r_ipc_protocol_t, &ctx->rekeying_queue_head, &ctx->rekeying_queue_tail) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
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
            LOG_ERROR("%sFailed to sent worker_master_info to Master.", ctx->label);
            CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent worker_master_info to Master.", ctx->label);
        }
        CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
    }
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
    if (ctx->is_rekeying) {
        if (ipc_add_tail_protocol_queue(ctx->label, &ctx->oritlsf_pool, *ctx->wot, *ctx->index, ctx->master_uds_fd, ctx->buffer, cmd_result.r_ipc_protocol_t, &ctx->rekeying_queue_head, &ctx->rekeying_queue_tail) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&ctx->oritlsf_pool, &cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
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
    }
    return SUCCESS;
}

#endif
