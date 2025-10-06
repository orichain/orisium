#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

#include "log.h"
#include "types.h"
#include "ipc/protocol.h"
#include "ipc/worker_master_heartbeat.h"
#include "ipc/worker_master_task_info.h"
#include "ipc/worker_master_hello1.h"
#include "ipc/worker_master_hello2.h"
#include "workers/workers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "stdbool.h"
#include "ipc/udp_data.h"
#include "utilities.h"

struct sockaddr_in6;

status_t worker_master_heartbeat(worker_context_t *ctx, double new_heartbeat_interval_double) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_heartbeat(
        ctx->label, 
        *ctx->wot, 
        *ctx->index, 
        new_heartbeat_interval_double
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (ctx->is_rekeying) {
        uint64_t queue_id;
        if (generate_uint64_t_id(ctx->label, &queue_id) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        if (ipc_add_protocol_queue(ctx->label, queue_id, *ctx->wot, *ctx->index, ctx->master_uds_fd, cmd_result.r_ipc_protocol_t, &ctx->rekeying_queue) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            ctx->label, 
            ctx->aes_key,
            ctx->mac_key,
            ctx->local_nonce,
            &ctx->local_ctr,
            ctx->master_uds_fd, 
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent worker_master_heartbeat to Master.", ctx->label);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent worker_master_heartbeat to Master.", ctx->label);
        }
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

status_t worker_master_hello1(worker_context_t *ctx) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_hello1(
        ctx->label, 
        *ctx->wot, 
        *ctx->index, 
        ctx->kem_publickey
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        ctx->label, 
        ctx->aes_key,
        ctx->mac_key,
        ctx->local_nonce,
        &ctx->local_ctr,
        ctx->master_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_hello1 to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_hello1 to Master.", ctx->label);
    }
    ctx->hello1_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t worker_master_hello2(worker_context_t *ctx, uint8_t encrypted_wot_index2[]) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_hello2(
        ctx->label, 
        *ctx->wot, 
        *ctx->index, 
        encrypted_wot_index2
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    ssize_t_status_t send_result = send_ipc_protocol_message(
        ctx->label, 
        ctx->aes_key,
        ctx->mac_key,
        ctx->local_nonce,
        &ctx->local_ctr,
        ctx->master_uds_fd, 
        cmd_result.r_ipc_protocol_t
    );
    if (send_result.status != SUCCESS) {
        LOG_ERROR("%sFailed to sent worker_master_hello2 to Master.", ctx->label);
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
        return send_result.status;
    } else {
        LOG_DEBUG("%sSent worker_master_hello2 to Master.", ctx->label);
    }
    ctx->hello2_sent = true;
    CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    return SUCCESS;
}

status_t worker_master_udp_data(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    struct sockaddr_in6 *addr,
    puint8_t_size_t_status_t *r,
    control_packet_t *h
) 
{
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_udp_data(
        label,
        wot,
        index,
        0xff,
        addr,
        r->r_size_t,
        r->r_puint8_t
    );
    if (cmd_result.status != SUCCESS) {
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
        return FAILURE;
    }
    if (worker_ctx->is_rekeying) {
        uint64_t queue_id;
        if (generate_uint64_t_id(worker_ctx->label, &queue_id) != SUCCESS) {
            free(r->r_puint8_t);
            r->r_puint8_t = NULL;
            r->r_size_t = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        if (ipc_add_protocol_queue(worker_ctx->label, queue_id, *worker_ctx->wot, *worker_ctx->index, worker_ctx->master_uds_fd, cmd_result.r_ipc_protocol_t, &worker_ctx->rekeying_queue) != SUCCESS) {
            free(r->r_puint8_t);
            r->r_puint8_t = NULL;
            r->r_size_t = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        h->len = r->r_size_t;
        h->data = (uint8_t *)calloc(1, r->r_size_t);
        memcpy(h->data, r->r_puint8_t, h->len);
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            worker_ctx->label,
            worker_ctx->aes_key,
            worker_ctx->mac_key,
            worker_ctx->local_nonce,
            &worker_ctx->local_ctr,
            worker_ctx->master_uds_fd, 
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
            free(r->r_puint8_t);
            r->r_puint8_t = NULL;
            r->r_size_t = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
        }
        h->len = r->r_size_t;
        h->data = (uint8_t *)calloc(1, r->r_size_t);
        memcpy(h->data, r->r_puint8_t, h->len);
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

status_t worker_master_udp_data_ack(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    struct sockaddr_in6 *addr,
    puint8_t_size_t_status_t *r,
    control_packet_ack_t *h
) 
{
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_udp_data(
        label,
        wot,
        index,
        0xff,
        addr,
        r->r_size_t,
        r->r_puint8_t
    );
    if (cmd_result.status != SUCCESS) {
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
        return FAILURE;
    }
    if (worker_ctx->is_rekeying) {
        uint64_t queue_id;
        if (generate_uint64_t_id(worker_ctx->label, &queue_id) != SUCCESS) {
            free(r->r_puint8_t);
            r->r_puint8_t = NULL;
            r->r_size_t = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        if (ipc_add_protocol_queue(worker_ctx->label, queue_id, *worker_ctx->wot, *worker_ctx->index, worker_ctx->master_uds_fd, cmd_result.r_ipc_protocol_t, &worker_ctx->rekeying_queue) != SUCCESS) {
            free(r->r_puint8_t);
            r->r_puint8_t = NULL;
            r->r_size_t = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        h->len = r->r_size_t;
        h->data = (uint8_t *)calloc(1, r->r_size_t);
        memcpy(h->data, r->r_puint8_t, h->len);
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            worker_ctx->label,
            worker_ctx->aes_key,
            worker_ctx->mac_key,
            worker_ctx->local_nonce,
            &worker_ctx->local_ctr,
            worker_ctx->master_uds_fd, 
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
            free(r->r_puint8_t);
            r->r_puint8_t = NULL;
            r->r_size_t = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
        }
        h->len = r->r_size_t;
        h->data = (uint8_t *)calloc(1, r->r_size_t);
        memcpy(h->data, r->r_puint8_t, h->len);
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

status_t worker_master_task_info(worker_context_t *ctx, uint8_t session_index, task_info_type_t flag) {
	ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_worker_master_task_info(
        ctx->label, 
        *ctx->wot, 
        *ctx->index,
        session_index,
        flag
    );
    if (cmd_result.status != SUCCESS) {
        return FAILURE;
    }
    if (ctx->is_rekeying) {
        uint64_t queue_id;
        if (generate_uint64_t_id(ctx->label, &queue_id) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        if (ipc_add_protocol_queue(ctx->label, queue_id, *ctx->wot, *ctx->index, ctx->master_uds_fd, cmd_result.r_ipc_protocol_t, &ctx->rekeying_queue) != SUCCESS) {
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            ctx->label, 
            ctx->aes_key,
            ctx->mac_key,
            ctx->local_nonce,
            &ctx->local_ctr,
            ctx->master_uds_fd, 
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent worker_master_task_info to Master.", ctx->label);
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent worker_master_task_info to Master.", ctx->label);
        }
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}

status_t worker_master_udp_data_finalize(
    const char *label, 
    worker_context_t *worker_ctx, 
    worker_type_t wot, 
    uint8_t index,
    struct sockaddr_in6 *addr,
    puint8_t_size_t_status_t *r
) 
{
    ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_udp_data(
        label,
        wot,
        index,
        0xff,
        addr,
        r->r_size_t,
        r->r_puint8_t
    );
    if (cmd_result.status != SUCCESS) {
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
        return FAILURE;
    }
    if (worker_ctx->is_rekeying) {
        uint64_t queue_id;
        if (generate_uint64_t_id(worker_ctx->label, &queue_id) != SUCCESS) {
            free(r->r_puint8_t);
            r->r_puint8_t = NULL;
            r->r_size_t = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        if (ipc_add_protocol_queue(worker_ctx->label, queue_id, *worker_ctx->wot, *worker_ctx->index, worker_ctx->master_uds_fd, cmd_result.r_ipc_protocol_t, &worker_ctx->rekeying_queue) != SUCCESS) {
            free(r->r_puint8_t);
            r->r_puint8_t = NULL;
            r->r_size_t = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return FAILURE;
        }
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
    } else {
        ssize_t_status_t send_result = send_ipc_protocol_message(
            worker_ctx->label,
            worker_ctx->aes_key,
            worker_ctx->mac_key,
            worker_ctx->local_nonce,
            &worker_ctx->local_ctr,
            worker_ctx->master_uds_fd, 
            cmd_result.r_ipc_protocol_t
        );
        if (send_result.status != SUCCESS) {
            LOG_ERROR("%sFailed to sent udp_data to Master.", worker_ctx->label);
            free(r->r_puint8_t);
            r->r_puint8_t = NULL;
            r->r_size_t = 0;
            CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
            return send_result.status;
        } else {
            LOG_DEBUG("%sSent udp_data to Master.", worker_ctx->label);
        }
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
        CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
    }
    return SUCCESS;
}
